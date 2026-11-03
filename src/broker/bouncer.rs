//! Bouncer on a Jev-compatible decision model (ADR 0007, ADR 0035).
//!
//! The bouncer sends one `POST /v1/systemone` request with `noul` questions
//! and reads the probabilities. Laya (`laya-serve`) and Jev use this protocol;
//! contract `bouncer-brain-v1` adds pinned head sets and the shadow head set in
//! the same request. The bouncer brain is on this Mac (loopback `http://`) or on a
//! remote server ([`BouncerClient::remote`], `https://` with a credential only).
//! Any failure gives [`BouncerVerdict::Unavailable`]. Unavailable is never an
//! allowance.

use super::route_diagnostics::ReasonKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::http::{self, DestinationUrl, TlsClient, parse_destination};
use super::shell_risk::Analysis;
use crate::vault::{
    CALIBRATION_FLOOR, Declaration, PATTERN_APPROVALS_NEEDED, Scope, valid_model_version,
};

/// Version of the question set and the decision policy. Change it when either changes.
/// Version 3 adds the production rule (ADR 0010). Version 4 adds remembered patterns and
/// the calibrated `task_match` level at the model step (ADR 0009). Version 5 lets a
/// certain "does not change state" answer replace `task_match` only for a command that
/// the built-in packs know (`Analysis::known_command`). Version 6 sets the default
/// `task_match` level to 0.75. Version 7 (dev round 3) needs 80% certainty that the
/// command does not break the owner instruction of the grant, and a known write
/// (`Analysis::known_write`) is never a certain read. Version 8 routes by default
/// and requires 80% task match for default classifications (ADR 0031).
/// Version 9 permits declared read-only production with mandatory task and leak checks.
pub const BOUNCER_CONTRACT: &str = "apassy-bouncer-v9";
/// Default address of `laya-serve` in the operations guide.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8770";
/// Environment variable that changes the bouncer address.
pub const URL_ENV: &str = "APASSY_BOUNCER_URL";
/// The owner must decide when a needed answer is less certain than this (ADR 0008).
pub const MIN_CONFIDENCE: f64 = 0.8;
/// The default `task_match` level (policy v6). With the base model, this level gave no
/// violation and no critical case without the owner on all development sets
/// (`docs/evaluation/dev-round2.md`). A calibration can change it in
/// [`CALIBRATION_FLOOR`, [`MIN_CONFIDENCE`]].
pub const DEFAULT_TASK_MATCH: f64 = 0.75;
/// A "destroy" answer at or above this vetoes a command that is not known safe.
const DESTROY_VETO: f64 = 0.9;
const PATH: &str = "/v1/systemone";
/// A warmed inference normally finishes in under a second, but the first real
/// decision can take over five seconds. One timeout retry gives at most 20 seconds
/// by default. `with_timeout` overrides each attempt's whole-exchange budget.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The time limit of each attempt to a remote bouncer brain (ADR 0035 decision 3,
/// contract bouncer-brain-v1 section 8): name lookup, connect, TLS handshake, the
/// credential, request, and answer. With the one retry after a transport timeout,
/// a request waits at most twice this long.
pub const REMOTE_TIMEOUT: Duration = Duration::from_secs(20);

/// Facts that the model answers. A decision model classifies facts well. A direct
/// "allow or ask" question gave probabilities near 0.5 in a probe on 2026-09-26.
const FACTS: [(&str, &str); 5] = [
    (
        "task_match",
        "Is the shell command a normal step to do what the user asked?",
    ),
    (
        "writes",
        "Does the shell command change data, files, settings, or state? Reading, listing, testing, and building do not change state.",
    ),
    (
        "remote",
        "Does the shell command act on a remote server, database, or cloud service?",
    ),
    (
        "leak",
        "Does the shell command print, encode, save, or send the value of a secret variable?",
    ),
    (
        "destroy",
        "Does the shell command delete, drop, truncate, reset, or overwrite data?",
    ),
];
const RULE_FACT: (&str, &str) = ("rule_break", "Does the shell command break the owner rule?");

/// What the bouncer sees. It has no secret value and no absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BouncerRequest {
    /// The user's words that led the agent to this request. The agent supplies it.
    pub user_request: String,
    pub command: String,
    /// Working directory relative to the project directory. "." is the project root.
    pub relative_dir: String,
    pub purpose: String,
    pub env_names: Vec<String>,
    pub instruction: String,
}

/// One model answer: the probability that the fact is true.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub name: String,
    pub probability: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BouncerVerdict {
    /// All answers are present.
    Scored {
        facts: Vec<Fact>,
        /// The model version from the `model` field of the answer, for example
        /// `apassy-base-v1+1a2b3c4d` or `laya-rl-agent`. `None` when the field is
        /// missing or not a short version text.
        model: Option<String>,
    },
    /// The model did not give a valid answer. The reason has no request data.
    Unavailable(String),
}

/// A model version is short (`vault::MAX_MODEL_VERSION`) and has only letters, digits,
/// and `.`, `_`, `+`, `-`.
fn model_version(value: &Value) -> Option<String> {
    let text = value.get("model")?.as_str()?;
    valid_model_version(text).then(|| text.to_owned())
}

impl BouncerVerdict {
    pub fn fact(&self, name: &str) -> Option<f64> {
        match self {
            Self::Scored { facts, .. } => {
                facts.iter().find(|f| f.name == name).map(|f| f.probability)
            }
            Self::Unavailable(_) => None,
        }
    }

    /// The version of the model that answered, if it sent one.
    pub fn model(&self) -> Option<&str> {
        match self {
            Self::Scored { model, .. } => model.as_deref(),
            Self::Unavailable(_) => None,
        }
    }

    /// Short text for the activity log. No request data.
    pub fn summary(&self) -> String {
        match self {
            Self::Unavailable(reason) => format!("Bouncer unavailable: {reason}"),
            Self::Scored { facts, model } => {
                let answers = facts
                    .iter()
                    .map(|f| format!("{} {:.0}%", f.name, f.probability * 100.0))
                    .collect::<Vec<_>>()
                    .join(", ");
                match model {
                    Some(model) => format!("{answers}. Model: {model}"),
                    None => answers,
                }
            }
        }
    }
}

/// What a short health check found at the bouncer address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// The server answers `GET /health` with status 200 and `"ok"`.
    Healthy,
    /// Nothing listens on the port.
    NoServer,
    /// Something listens on the port, but it is not a healthy decision server.
    NotBouncer,
}

/// `APASSY_BOUNCER_URL`, if it is set and not empty.
pub fn env_url() -> Option<String> {
    std::env::var(URL_ENV)
        .ok()
        .filter(|url| !url.trim().is_empty())
}

/// A head set hash of the wire: 64 lowercase hexadecimal characters (contract
/// bouncer-brain-v1 section 3.1). The client checks every hash before it sends it.
pub fn is_heads_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The bearer of a remote bouncer brain (ADR 0035). It is not a vault credential:
/// a bouncer brain never receives a secret value. The owner's server has a static
/// token ([`StaticBearer`]); Apassy Connect signs in with the device key (unit C3).
pub trait BrainCredential: Send + Sync {
    /// The bearer for the next request, or `None` when there is none before
    /// `deadline`. Without a bearer the client sends nothing.
    fn bearer(&self, deadline: Instant) -> Option<Zeroizing<String>>;

    /// The server answered 401 to the last bearer. The request that got the 401 is
    /// unavailable; it is never sent again with another bearer.
    fn invalidate(&self);
}

/// The token of the owner's server (`LAYA_API_KEY` there). After a 401 it gives no
/// bearer any more: the owner enters the right token, which makes a new client.
pub struct StaticBearer {
    bearer: Zeroizing<String>,
    refused: AtomicBool,
}

impl StaticBearer {
    /// `None` when the token is empty or has a character that a header cannot carry.
    pub fn new(token: Zeroizing<String>) -> Option<Self> {
        let valid = !token.is_empty() && token.bytes().all(|b| (0x21..0x7f).contains(&b));
        valid.then(|| Self {
            bearer: token,
            refused: AtomicBool::new(false),
        })
    }

    /// The server refused this token (401).
    pub fn is_refused(&self) -> bool {
        self.refused.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for StaticBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticBearer")
            .field("refused", &self.is_refused())
            .finish_non_exhaustive()
    }
}

impl BrainCredential for StaticBearer {
    fn bearer(&self, _deadline: Instant) -> Option<Zeroizing<String>> {
        (!self.is_refused()).then(|| self.bearer.clone())
    }

    fn invalidate(&self) {
        self.refused.store(true, Ordering::SeqCst);
    }
}

/// The shadow head set of a request (contract bouncer-brain-v1 section 3): its hash
/// goes as `shadow_heads`, and its answer must name `model`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowPin {
    /// The SHA-256 of the shadow head file, 64 lowercase hex characters.
    pub heads: String,
    /// The version of the shadow head set: `<name>+<first 8 hex of heads>`.
    pub model: String,
}

impl ShadowPin {
    pub fn new(heads: &str, model: &str) -> Self {
        Self {
            heads: heads.to_owned(),
            model: model.to_owned(),
        }
    }
}

/// The transport of a remote bouncer brain.
#[derive(Clone)]
struct Remote {
    credential: Arc<dyn BrainCredential>,
    tls: Arc<TlsClient>,
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Remote")
    }
}

/// Why one attempt sent no request or got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendFailure {
    Http(http::HttpFailure),
    /// A remote bouncer brain without a bearer: nothing was sent.
    NoCredential,
}

/// Client for one decision service: on this Mac, or remote over `https://`.
#[derive(Debug, Clone)]
pub struct BouncerClient {
    destination: DestinationUrl,
    url: String,
    api_key: Option<String>,
    timeout: Duration,
    /// The model version that the answers must name (goal item B9). A promoted model is
    /// pinned, so another model at the same address cannot change the policy silently.
    expected_model: Option<String>,
    /// The SHA-256 of the active head file. It goes as `heads`, and the answer must
    /// name it (contract bouncer-brain-v1 section 3.4).
    expected_heads: Option<String>,
    /// `Some` for a remote bouncer brain ([`BouncerClient::remote`]).
    remote: Option<Remote>,
}

impl BouncerClient {
    /// A bouncer brain on this Mac: only a loopback `http://` address. A remote
    /// bouncer brain needs [`BouncerClient::remote`].
    pub fn new(url: &str) -> Result<Self, &'static str> {
        let destination = parse_destination(url)?;
        if !matches!(destination, DestinationUrl::Loopback { .. }) {
            return Err("The bouncer must run on this computer (http://127.0.0.1:PORT).");
        }
        Ok(Self {
            destination,
            url: url.trim().trim_end_matches('/').to_owned(),
            api_key: None,
            timeout: TIMEOUT,
            expected_model: None,
            expected_heads: None,
            remote: None,
        })
    }

    /// A remote bouncer brain (ADR 0035): an `https://` address only, with a
    /// credential, and [`REMOTE_TIMEOUT`] for each attempt. Only the owner's hosting
    /// choice in the vault makes one; `APASSY_BOUNCER_URL` and `bouncer.json` never
    /// name a remote host ([`BouncerClient::from_env_or`] stays loopback-only).
    pub fn remote(
        url: &str,
        credential: Arc<dyn BrainCredential>,
        tls: Arc<TlsClient>,
    ) -> Result<Self, &'static str> {
        let destination = parse_destination(url)?;
        if !matches!(destination, DestinationUrl::Https { .. }) {
            return Err("A remote bouncer brain must use https://.");
        }
        Ok(Self {
            destination,
            url: url.trim().trim_end_matches('/').to_owned(),
            api_key: None,
            timeout: REMOTE_TIMEOUT,
            expected_model: None,
            expected_heads: None,
            remote: Some(Remote { credential, tls }),
        })
    }

    /// True for a remote bouncer brain.
    pub fn is_remote(&self) -> bool {
        self.remote.is_some()
    }

    /// A client for another loopback address, with the same key and time limit. It does
    /// not pin a model version.
    pub fn at_url(&self, url: &str) -> Result<Self, &'static str> {
        let mut client = Self::new(url)?;
        client.api_key.clone_from(&self.api_key);
        client.timeout = self.timeout;
        Ok(client)
    }

    /// Accept only answers that name `version` in their `model` field. Another version
    /// or no version gives [`BouncerVerdict::Unavailable`], so the owner decides.
    pub fn expect_model(mut self, version: &str) -> Self {
        self.expected_model = Some(version.to_owned());
        self
    }

    /// The pinned model version, if there is one.
    pub fn expected_model(&self) -> Option<&str> {
        self.expected_model.as_deref()
    }

    /// Pin the active head set: each request sends `heads`, and an answer from
    /// another head set is [`BouncerVerdict::Unavailable`] (contract
    /// bouncer-brain-v1 section 3.4). A pin that is not 64 lowercase hex characters
    /// makes every request unavailable, with nothing sent.
    pub fn expect_heads(mut self, sha256: &str) -> Self {
        self.expected_heads = Some(sha256.to_owned());
        self
    }

    /// The pinned head hash, if there is one.
    pub fn expected_heads(&self) -> Option<&str> {
        self.expected_heads.as_deref()
    }

    /// The time limit of one attempt.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The longest wait of one request: two attempts.
    pub fn max_wait(&self) -> Duration {
        self.timeout.saturating_mul(2)
    }

    /// `APASSY_BOUNCER_URL`, or the default address.
    pub fn from_env() -> Result<Self, &'static str> {
        Self::from_env_or(DEFAULT_URL)
    }

    /// `APASSY_BOUNCER_URL`, or `url` (the address in `bouncer.json`). The environment
    /// wins, as in [`BouncerClient::from_env`]. Loopback only: any process of the user
    /// can set these, so a remote address here would bypass the owner check of the
    /// hosting choice (ADR 0035).
    pub fn from_env_or(url: &str) -> Result<Self, &'static str> {
        Self::from_sources(env_url(), url, std::env::var("APASSY_BOUNCER_KEY").ok())
    }

    /// [`BouncerClient::from_env_or`] with the environment values as arguments.
    fn from_sources(
        env_url: Option<String>,
        url: &str,
        key: Option<String>,
    ) -> Result<Self, &'static str> {
        let url = env_url.unwrap_or_else(|| url.to_owned());
        let mut client = Self::new(&url)?;
        client.api_key = key.filter(|key| !key.is_empty());
        Ok(client)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The bearer key from `APASSY_BOUNCER_KEY`, if set. A remote bouncer brain has
    /// its credential instead, so this is `None` for it.
    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    /// The same client with the bearer `key`: the random key of this start of Apassy,
    /// which a server that Apassy starts gets as `LAYA_API_KEY` (plan 0035 C2).
    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_owned());
        self
    }

    /// The TCP port of the address.
    pub fn port(&self) -> Option<u16> {
        match &self.destination {
            DestinationUrl::Loopback { addr, .. } => Some(addr.port()),
            DestinationUrl::Https { .. } => None,
        }
    }

    /// A short `GET /health` check (the health route of `laya-serve` and `serve.py`).
    /// It sends no request data and no key. A remote bouncer brain is checked over
    /// TLS with the same time limit.
    pub fn probe_health(&self, timeout: Duration) -> Health {
        use std::io::{Read, Write};

        let DestinationUrl::Loopback { addr, host_header } = &self.destination else {
            return self.probe_remote_health(timeout);
        };
        let Ok(mut stream) = std::net::TcpStream::connect_timeout(addr, timeout) else {
            return Health::NoServer;
        };
        if stream.set_read_timeout(Some(timeout)).is_err()
            || stream.set_write_timeout(Some(timeout)).is_err()
        {
            return Health::NotBouncer;
        }
        let request = format!(
            "GET /health HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(request.as_bytes()).is_err() {
            return Health::NotBouncer;
        }
        let mut raw = Vec::new();
        let _ = stream.take(16 * 1024).read_to_end(&mut raw);
        let ok_status = raw.starts_with(b"HTTP/1.1 200") || raw.starts_with(b"HTTP/1.0 200");
        let body = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map_or(&[][..], |at| &raw[at + 4..]);
        let ok_body = body.windows(4).any(|window| window == b"\"ok\"");
        if ok_status && ok_body {
            Health::Healthy
        } else {
            Health::NotBouncer
        }
    }

    fn probe_remote_health(&self, timeout: Duration) -> Health {
        let Some(remote) = &self.remote else {
            return Health::NoServer;
        };
        match http::get_health(
            &self.destination,
            "/health",
            timeout,
            Some(remote.tls.as_ref()),
        ) {
            Ok(response) => {
                let ok = response.status == 200
                    && serde_json::from_slice::<Value>(&response.body)
                        .is_ok_and(|body| body["status"] == "ok");
                if ok {
                    Health::Healthy
                } else {
                    Health::NotBouncer
                }
            }
            Err(http::HttpFailure::Connect | http::HttpFailure::Timeout) => Health::NoServer,
            Err(_) => Health::NotBouncer,
        }
    }

    /// One attempt: the credential of a remote bouncer brain and one POST, all
    /// within `timeout`.
    fn send_once(&self, body: &[u8], timeout: Duration) -> Result<http::HttpResponse, SendFailure> {
        let Some(remote) = &self.remote else {
            return http::post_json_loopback(
                &self.destination,
                PATH,
                body,
                self.api_key.as_deref(),
                timeout,
            )
            .map_err(SendFailure::Http);
        };
        let deadline = Instant::now() + timeout;
        let bearer = remote
            .credential
            .bearer(deadline)
            .ok_or(SendFailure::NoCredential)?;
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(SendFailure::Http(http::HttpFailure::Timeout))?;
        http::post_json(
            &self.destination,
            PATH,
            body,
            Some(bearer.as_str()),
            left,
            Some(remote.tls.as_ref()),
        )
        .map_err(SendFailure::Http)
    }

    /// A 401 of a remote bouncer brain ends its credential.
    fn note_status(&self, status: u16) {
        if status == 401
            && let Some(remote) = &self.remote
        {
            remote.credential.invalidate();
        }
    }

    /// The pinned head hash for the wire, or a reason when the pin is malformed.
    fn heads_for_wire(&self) -> Result<Option<&str>, String> {
        match self.expected_heads.as_deref() {
            Some(heads) if !is_heads_hash(heads) => {
                Err("the pinned head hash is not valid; nothing was sent".to_owned())
            }
            heads => Ok(heads),
        }
    }

    /// Ask one neutral question, so the server loads the model, and read the model
    /// version from the answer. The question has no request data.
    pub fn warm_up(&self, timeout: Duration) -> Result<Option<String>, String> {
        const READY: (&str, &str) = ("ready", "Is this a readiness check?");
        let heads = self.heads_for_wire()?;
        let mut body = json!({
            "state": "Apassy checks that the decision model answers.",
            "questions": { READY.0: { "type": "noul", "instructions": READY.1 } },
        });
        if let Some(heads) = heads {
            body["heads"] = json!(heads);
        }
        let bytes = serde_json::to_vec(&body).map_err(|err| err.to_string())?;
        let response = self
            .send_once(&bytes, timeout)
            .map_err(|failure| match failure {
                SendFailure::Http(failure) => {
                    format!("readiness request to {} failed ({failure:?})", self.url)
                }
                SendFailure::NoCredential => {
                    format!("readiness request to {} has no credential", self.url)
                }
            })?;
        self.note_status(response.status);
        if response.status != 200 {
            return Err(format!("status {}", response.status));
        }
        let Ok(value) = serde_json::from_slice::<Value>(&response.body) else {
            return Err("the answer is not JSON".to_owned());
        };
        match self.check_pins(answers_in(&value, &[READY]), &value) {
            BouncerVerdict::Scored { model, .. } => Ok(model),
            BouncerVerdict::Unavailable(reason) => Err(reason),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn evaluate(&self, request: &BouncerRequest) -> BouncerVerdict {
        self.evaluate_with_shadow(request, None).0
    }

    /// The active verdict and, with `shadow`, the verdict of the shadow head set from
    /// the same request (contract bouncer-brain-v1 section 3). The shadow part never
    /// changes the active verdict: a missing shadow, a `shadow.error`, or a failed
    /// check of `shadow.heads` or `shadow.model` makes only the shadow verdict
    /// unavailable. With `shadow`, the second value is always `Some`.
    pub fn evaluate_with_shadow(
        &self,
        request: &BouncerRequest,
        shadow: Option<&ShadowPin>,
    ) -> (BouncerVerdict, Option<BouncerVerdict>) {
        let both = |reason: String| {
            (
                BouncerVerdict::Unavailable(reason.clone()),
                shadow.map(|_| BouncerVerdict::Unavailable(reason)),
            )
        };
        let heads = match self.heads_for_wire() {
            Ok(heads) => heads,
            Err(reason) => return both(reason),
        };
        // A malformed shadow hash is a client defect: it is not sent, and only the
        // shadow verdict is unavailable.
        let shadow_heads = shadow
            .map(|pin| pin.heads.as_str())
            .filter(|heads| is_heads_hash(heads));
        let mut body = request_body(request);
        if let Some(heads) = heads {
            body["heads"] = json!(heads);
        }
        if let Some(shadow_heads) = shadow_heads {
            body["shadow_heads"] = json!(shadow_heads);
        }
        let Ok(bytes) = serde_json::to_vec(&body) else {
            return both("the request did not encode".to_owned());
        };
        // Inference is read-only: retry at most once, and only when its transport
        // timed out. This never retries a command, HTTP error, or invalid answer.
        let send = || self.send_once(&bytes, self.timeout);
        let response = match send().or_else(|failure| {
            if failure == SendFailure::Http(http::HttpFailure::Timeout) {
                send()
            } else {
                Err(failure)
            }
        }) {
            Ok(response) => response,
            Err(SendFailure::Http(http::HttpFailure::Timeout)) => {
                return both(format!(
                    "the model at {} timed out after two inference attempts (up to {} ms total)",
                    self.url,
                    self.max_wait().as_millis()
                ));
            }
            Err(SendFailure::NoCredential) => {
                return both(format!(
                    "no credential for the bouncer brain at {}; nothing was sent",
                    self.url
                ));
            }
            Err(SendFailure::Http(_)) => {
                return both(format!("no answer from {}", self.url));
            }
        };
        self.note_status(response.status);
        if response.status != 200 {
            let code = serde_json::from_slice::<Value>(&response.body)
                .ok()
                .and_then(|body| body["detail"]["code"].as_str().map(str::to_owned));
            return both(match (response.status, code.as_deref()) {
                (422, Some("input_too_long")) => {
                    "the complete request does not fit the model context; the model did not decide"
                        .to_owned()
                }
                (401, _) => format!(
                    "the bouncer brain at {} refused the credential (status 401)",
                    self.url
                ),
                (409, _) => format!(
                    "the bouncer brain at {} does not have the pinned head set (status 409)",
                    self.url
                ),
                (status, _) => format!("status {status}"),
            });
        }
        let Ok(value) = serde_json::from_slice::<Value>(&response.body) else {
            return both("the answer is not JSON".to_owned());
        };
        let asked = facts_for(request);
        let active = self.check_pins(answers_in(&value, &asked), &value);
        let shadow = shadow.map(|pin| {
            if shadow_heads.is_none() {
                BouncerVerdict::Unavailable(
                    "the shadow head hash is not valid; it was not sent".to_owned(),
                )
            } else {
                shadow_verdict(&value, pin, &asked)
            }
        });
        (active, shadow)
    }

    /// The pins of the active head set: the model version and the head hash.
    fn check_pins(&self, verdict: BouncerVerdict, answer: &Value) -> BouncerVerdict {
        let verdict = self.check_model(verdict);
        match (&self.expected_heads, &verdict) {
            (Some(expected), BouncerVerdict::Scored { .. })
                if answer.get("heads").and_then(Value::as_str) != Some(expected.as_str()) =>
            {
                BouncerVerdict::Unavailable(format!(
                    "the answer of the model at {} is not from the pinned head set",
                    self.url
                ))
            }
            _ => verdict,
        }
    }

    fn check_model(&self, verdict: BouncerVerdict) -> BouncerVerdict {
        match (&self.expected_model, &verdict) {
            (Some(expected), BouncerVerdict::Scored { model, .. })
                if model.as_deref() != Some(expected.as_str()) =>
            {
                BouncerVerdict::Unavailable(format!(
                    "the model at {} is {}, not the active version {expected}",
                    self.url,
                    model.as_deref().unwrap_or("unnamed")
                ))
            }
            _ => verdict,
        }
    }
}

/// The shadow part of an answer, checked against its pin (contract bouncer-brain-v1
/// sections 3.2 and 3.4). Any failure is "no answer" for the shadow head set.
fn shadow_verdict(answer: &Value, pin: &ShadowPin, asked: &[(&str, &str)]) -> BouncerVerdict {
    let Some(shadow) = answer.get("shadow").filter(|shadow| shadow.is_object()) else {
        return BouncerVerdict::Unavailable("the answer has no shadow part".to_owned());
    };
    if shadow.get("heads").and_then(Value::as_str) != Some(pin.heads.as_str()) {
        return BouncerVerdict::Unavailable(
            "the shadow part is not from the shadow head set".to_owned(),
        );
    }
    if let Some(error) = shadow.get("error") {
        // Only the codes of the contract are named; other server text is not logged.
        let code = match error.as_str() {
            Some(code @ ("unknown_heads" | "shadow_failed")) => code,
            _ => "another error",
        };
        return BouncerVerdict::Unavailable(format!("the shadow head set failed ({code})"));
    }
    match answers_in(shadow, asked) {
        BouncerVerdict::Scored { model, .. } if model.as_deref() != Some(pin.model.as_str()) => {
            BouncerVerdict::Unavailable(format!(
                "the shadow model is {}, not the shadow version {}",
                model.as_deref().unwrap_or("unnamed"),
                pin.model
            ))
        }
        verdict => verdict,
    }
}

/// Every question that the bouncer can ask, by name, in the order of the request. The
/// owner-rule question is last. The local fine-tune uses the same texts (goal item B9).
pub fn questions() -> Vec<(&'static str, &'static str)> {
    let mut all = FACTS.to_vec();
    all.push(RULE_FACT);
    all
}

fn facts_for(request: &BouncerRequest) -> Vec<(&'static str, &'static str)> {
    let mut facts = FACTS.to_vec();
    if !request.instruction.trim().is_empty() {
        facts.push(RULE_FACT);
    }
    facts
}

/// The Jev wire request. A short state with the user request gave the best
/// separation in the probe: normal commands 0.69 to 0.93 for `task_match`, risky
/// commands 0.04 to 0.28.
pub fn request_body(request: &BouncerRequest) -> Value {
    let mut questions = Map::new();
    for (name, text) in facts_for(request) {
        questions.insert(
            name.to_owned(),
            json!({ "type": "noul", "instructions": text }),
        );
    }
    json!({ "state": state_text(request), "questions": questions })
}

/// The state text that the model reads. The local fine-tune builds its examples with
/// this function, so a training state is the state that the broker sends.
pub fn state_text(request: &BouncerRequest) -> String {
    let mut state = format!(
        "User request: \"{}\". Shell command: `{}`.",
        request.user_request.trim(),
        request.command,
    );
    if !request.purpose.trim().is_empty() {
        state.push_str(&format!(
            " Agent's stated purpose: {}",
            request.purpose.trim()
        ));
    }
    if !request.instruction.trim().is_empty() {
        state.push_str(&format!(" Owner rule: {}", request.instruction.trim()));
    }
    state
}

/// Read `answers.<name>.noul` for every fact. A missing or bad value is unavailable.
/// The `model` field names the model version for the activity log (goal B8).
pub fn parse_answers(body: &[u8], asked: &[(&str, &str)]) -> BouncerVerdict {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return BouncerVerdict::Unavailable("the answer is not JSON".to_owned());
    };
    answers_in(&value, asked)
}

/// [`parse_answers`] of a parsed answer, or of its `shadow` part.
fn answers_in(value: &Value, asked: &[(&str, &str)]) -> BouncerVerdict {
    let mut facts = Vec::new();
    for (name, _) in asked {
        let probability = value
            .get("answers")
            .and_then(|answers| answers.get(*name))
            .and_then(|answer| answer.get("noul"))
            .and_then(Value::as_f64)
            .filter(|p| (0.0..=1.0).contains(p));
        match probability {
            Some(probability) => facts.push(Fact {
                name: (*name).to_owned(),
                probability,
            }),
            None => return BouncerVerdict::Unavailable(format!("no valid answer for {name}")),
        }
    }
    BouncerVerdict::Scored {
        facts,
        model: model_version(value),
    }
}

/// The bouncer decision for one request.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub reason: ReasonKind,
    pub ask_owner: bool,
    /// Lowest certainty among the answers that the decision needed. `None` when the
    /// model did not decide.
    pub confidence: Option<f64>,
    /// Short text for the activity log and the approval card. No secret values.
    pub note: String,
}

/// What the policy knows besides the model answers.
#[derive(Debug, Clone)]
pub struct DecisionContext<'a> {
    pub analysis: &'a Analysis,
    /// One entry per requested item. `None` means that the item has no declaration.
    pub declarations: &'a [Option<Declaration>],
    pub has_user_request: bool,
}

/// Hard owner rules (ADR 0010). A run that matches one always waits for the owner.
///
/// [`decide`] checks these rules first. The model, remembered patterns, and calibrated
/// thresholds come after this check, so they cannot change its result. The broker does
/// not call the model for such a run.
pub fn owner_required(context: &DecisionContext<'_>) -> Option<String> {
    let production = context
        .declarations
        .iter()
        .flatten()
        .any(|d| d.is_production() && d.scope != Scope::ReadOnly);
    production.then(|| {
        "Production credential: the owner approves every run with it (ADR 0010).".to_owned()
    })
}

/// Levels that the owner can change with a calibration (ADR 0009 step 3). The production
/// rule, the rule flags, the vetoes, and the read-only check are not here, so a
/// calibration cannot change them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// A command that is not known safe and not certainly read-only needs `task_match`
    /// at or above this level.
    pub task_match: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            task_match: DEFAULT_TASK_MATCH,
        }
    }
}

impl Thresholds {
    /// The `task_match` level inside the calibration range: never lower than the floor,
    /// never higher than [`MIN_CONFIDENCE`].
    pub fn task_match_level(&self) -> f64 {
        if self.task_match.is_nan() {
            DEFAULT_TASK_MATCH
        } else {
            self.task_match.clamp(CALIBRATION_FLOOR, MIN_CONFIDENCE)
        }
    }

    /// Text for the decision log.
    pub fn policy_label(&self) -> String {
        format!(
            "{BOUNCER_CONTRACT}; task_match {:.2}",
            self.task_match_level()
        )
    }
}

/// What learning gives one decision (ADR 0009). Both parts act only at the model step.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Learned {
    pub thresholds: Thresholds,
    /// An active remembered pattern that matches the request, as the owner sees it.
    pub pattern: Option<String>,
}

/// Combine the command analysis, the owner declarations, and the model facts (ADR 0008),
/// without learning. See [`decide_learned`].
pub fn decide(verdict: &BouncerVerdict, context: &DecisionContext<'_>) -> Decision {
    decide_learned(verdict, context, &Learned::default())
}

/// Combine the command analysis, the owner declarations, the model facts, and learning.
///
/// 1. A hard owner rule asks the owner: a production declaration ([`owner_required`]).
///    No later step can change this.
/// 2. A rule flag asks the owner. The model is not needed.
/// 3. A missing user request or declaration asks the owner.
/// 4. An active remembered pattern allows the run. It replaces only the model step
///    (steps 5 and 6), so it cannot change steps 1 to 3.
/// 5. The model decides. A command that is not known safe must match the user request
///    at the `task_match` level (75%, or another level that the owner applied). Only
///    for a known command (`Analysis::known_command`: the built-in packs know the
///    program, and it does not run project code) that is not a known write
///    (`Analysis::known_write`) can 80% certainty that the command does not change
///    state replace the match. Unknown programs, project scripts, package scripts, make
///    targets, custom framework subcommands, and known writes always need the match.
///    A high-risk or irreversible credential also needs 80% certainty that the command
///    does not change state, unless the command is known safe. A known write never
///    has this certainty.
///    When the grant has an owner instruction, every command also needs 80% certainty
///    that it does not break the instruction (`rule_break` at or below 0.2, policy v7).
///    The model answers `rule_break` only for a grant with an instruction, and a
///    verdict without an asked answer is unavailable, so the answer is present exactly
///    when the grant has an instruction.
/// 6. Model veto: "destroy" at 90% for a command that is not known safe.
///
/// The hard rules of the grant (ADR 0007) run before this function. A failure there is
/// a denial, so no step here can change it.
pub fn decide_learned(
    verdict: &BouncerVerdict,
    context: &DecisionContext<'_>,
    learned: &Learned,
) -> Decision {
    if let Some(decision) = before_model(context) {
        return decision;
    }
    if let Some(pattern) = &learned.pattern {
        return Decision {
            reason: ReasonKind::Other,
            ask_owner: false,
            confidence: None,
            note: format!(
                "Remembered pattern allowed: {pattern}. The owner approved it {PATTERN_APPROVALS_NEEDED} times."
            ),
        };
    }
    model_step(verdict, context, learned.thresholds, false)
}

/// Model step after `run::route` has checked the production write/admin veto (every
/// source) and all other hard checks. Default classifications always need 80% task match,
/// including known safe commands and reads; calibration cannot lower this check.
pub(super) fn decide_routed(
    verdict: &BouncerVerdict,
    context: &DecisionContext<'_>,
    learned: &Learned,
    default_source: bool,
) -> Decision {
    model_step(verdict, context, learned.thresholds, default_source)
}

/// Steps 1 to 3 of [`decide_learned`]. `Some` when the owner decides before any model
/// or learning step.
pub fn before_model(context: &DecisionContext<'_>) -> Option<Decision> {
    let ask = |note: String| {
        Some(Decision {
            reason: ReasonKind::Other,
            ask_owner: true,
            confidence: None,
            note,
        })
    };
    if let Some(mut note) = owner_required(context) {
        if !context.analysis.flags.is_empty() {
            note.push_str(&format!(
                " Rule flags: {}.",
                context.analysis.flags.join(", ")
            ));
        }
        return ask(note);
    }
    if !context.analysis.flags.is_empty() {
        return ask(format!("Rule flags: {}", context.analysis.flags.join(", ")));
    }
    if !context.has_user_request {
        return ask("The agent did not send the user request.".to_owned());
    }
    if context.declarations.iter().any(Option::is_none) {
        return ask("An item has no declaration.".to_owned());
    }
    None
}

fn model_step(
    verdict: &BouncerVerdict,
    context: &DecisionContext<'_>,
    thresholds: Thresholds,
    default_source: bool,
) -> Decision {
    let ask = |confidence, note: String| Decision {
        reason: ReasonKind::ModelUnsure,
        ask_owner: true,
        confidence,
        note,
    };
    let BouncerVerdict::Scored { .. } = verdict else {
        let mut decision = ask(None, verdict.summary());
        decision.reason = if matches!(verdict, BouncerVerdict::Unavailable(reason) if reason.contains("timed out"))
        {
            ReasonKind::ModelTimeout
        } else {
            ReasonKind::ModelUnavailable
        };
        return decision;
    };
    let sensitive = context
        .declarations
        .iter()
        .flatten()
        .any(Declaration::is_sensitive);
    let known_safe = context.analysis.known_safe;
    // Policy v5: the model's "writes" answer can replace the task match only for a
    // command that the packs know. For unknown code (an unknown program, a project
    // script, a package script, or a custom subcommand) the model gave a low "writes" to
    // commands that print secrets or change data (held-out v2), so the match is needed.
    let known_command = known_safe || context.analysis.known_command;
    // Policy v7: a known write (`gh pr comment`, `git push`, SQL `INSERT`) changes state
    // by the knowledge of the packs. On held-out v3 the base model gave `writes` 0.08 and
    // 0.10 to `gh pr comment` and `gh issue close`, so the answer cannot make it a read.
    let known_write = !known_safe && context.analysis.known_write;
    let certain_read = known_command
        && !known_write
        && verdict
            .fact("writes")
            .is_some_and(|p| 1.0 - p >= MIN_CONFIDENCE);
    // Needed facts: (fact, must be true, needed certainty).
    // - A command that is not known safe and not a certain read of a known command must
    //   match the user request. A read cannot change anything, so it does not need the
    //   match.
    // - A sensitive credential needs a certain "does not change state", unless the
    //   command is known safe (local work or a read by rule). A known write fails it.
    // - Policy v7: a grant with an owner instruction needs a certain "does not break the
    //   rule", also for a known safe command. The model answers `rule_break` only for a
    //   grant with an instruction (`facts_for`). Before v7 a `rule_break` of 0.8 was a
    //   veto, and the base model answered 0.25 to 0.53 for commands that broke the rule
    //   (held-out v3).
    let mut needed: Vec<(&str, bool, f64)> = Vec::new();
    let production = context
        .declarations
        .iter()
        .flatten()
        .any(Declaration::is_production);
    let task_level = thresholds.task_match_level();
    if production || default_source || (!known_safe && !certain_read) {
        needed.push((
            "task_match",
            true,
            if default_source {
                MIN_CONFIDENCE
            } else {
                task_level
            },
        ));
    }
    if production {
        for name in ["leak", "destroy"] {
            needed.push((name, false, MIN_CONFIDENCE));
        }
    }
    if sensitive && !known_safe {
        needed.push(("writes", false, MIN_CONFIDENCE));
    }
    if verdict.fact("rule_break").is_some() {
        needed.push(("rule_break", false, MIN_CONFIDENCE));
    }
    let mut failed = Vec::new();
    let mut task_match_failed = false;
    let mut confidence: f64 = 1.0;
    for (name, want_true, level) in needed {
        let p = if name == "writes" && known_write {
            // The packs know that the command changes state.
            1.0
        } else {
            verdict.fact(name).unwrap_or(0.5)
        };
        let support = if want_true { p } else { 1.0 - p };
        confidence = confidence.min(support);
        if name == "writes" && known_write {
            failed.push("writes: a known write".to_owned());
        } else if support < level {
            task_match_failed |= name == "task_match";
            failed.push(format!(
                "{name} {}{:.0}% (needs {:.0}%)",
                if want_true { "" } else { "not " },
                support * 100.0,
                level * 100.0
            ));
        }
    }
    // Vetoes. The rules find secret output and cache removal, so the model's "leak"
    // answer is not a veto: it gave 0.8 or more for plain file reads on real commands.
    // "destroy" is a veto at 90% for commands that the rules do not know. The
    // `rule_break` veto of policy v6 is now a needed answer (above).
    let mut vetoes: Vec<(&str, f64)> = Vec::new();
    if !known_safe {
        vetoes.push(("destroy", DESTROY_VETO));
    }
    for (name, level) in vetoes {
        if let Some(p) = verdict.fact(name)
            && p >= level
        {
            failed.push(format!("{name} {:.0}%", p * 100.0));
            confidence = confidence.min(1.0 - p);
        }
    }
    let scope = if sensitive {
        "sensitive credential"
    } else {
        "normal credential"
    };
    let source_note = if default_source {
        " Classification is unconfirmed or has a default source; task_match needs 80% even for a known safe command or read."
    } else {
        ""
    };
    let calibrated = if (task_level - DEFAULT_TASK_MATCH).abs() > f64::EPSILON {
        format!(" Calibrated task_match level: {:.0}%.", task_level * 100.0)
    } else {
        String::new()
    };
    if failed.is_empty() {
        Decision {
            reason: ReasonKind::Other,
            ask_owner: false,
            confidence: Some(confidence),
            note: format!(
                "Model allowed at {:.0}% certainty ({scope}{}). {}{calibrated}{source_note}",
                confidence * 100.0,
                if known_safe {
                    ", known safe command"
                } else {
                    ""
                },
                verdict.summary()
            ),
        }
    } else {
        let mut decision = ask(
            Some(confidence),
            format!(
                "Below the needed certainty: {}. {}{calibrated}{source_note}",
                failed.join(", "),
                verdict.summary()
            ),
        );
        decision.reason = if task_match_failed {
            ReasonKind::LowTaskMatch
        } else {
            ReasonKind::ModelUnsure
        };
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Environment, Reversibility, RiskLevel, Scope};

    fn request(instruction: &str) -> BouncerRequest {
        BouncerRequest {
            user_request: "Apply the staging migration".to_owned(),
            command: "npm run migrate".to_owned(),
            relative_dir: ".".to_owned(),
            purpose: "Apply migrations".to_owned(),
            env_names: vec!["DB_URL".to_owned()],
            instruction: instruction.to_owned(),
        }
    }

    fn verdict(pairs: &[(&str, f64)]) -> BouncerVerdict {
        BouncerVerdict::Scored {
            facts: pairs
                .iter()
                .map(|(n, p)| Fact {
                    name: (*n).to_owned(),
                    probability: *p,
                })
                .collect(),
            model: None,
        }
    }

    /// Goal B8: the activity log names the model version that answered.
    #[test]
    fn answer_names_the_model_version() {
        let asked = [("task_match", ""), ("writes", "")];
        let body = |model: &str| {
            format!(
                r#"{{"model":{model},"answers":{{"task_match":{{"noul":0.9}},"writes":{{"noul":0.1}}}}}}"#
            )
        };
        let base = parse_answers(body("\"apassy-base-v1+1a2b3c4d\"").as_bytes(), &asked);
        assert_eq!(base.model(), Some("apassy-base-v1+1a2b3c4d"));
        assert_eq!(
            base.summary(),
            "task_match 90%, writes 10%. Model: apassy-base-v1+1a2b3c4d"
        );
        let stock = parse_answers(body("\"laya-rl-agent\"").as_bytes(), &asked);
        assert_eq!(stock.model(), Some("laya-rl-agent"));
        // A missing, long, or odd model text is not recorded. The answers still count.
        let long = format!("\"{}\"", "a".repeat(crate::vault::MAX_MODEL_VERSION + 1));
        for odd in ["null", "7", "\"\"", "\"a b\"", "\"x\\ny\"", long.as_str()] {
            let verdict = parse_answers(body(odd).as_bytes(), &asked);
            assert_eq!(verdict.model(), None, "{odd}");
            assert_eq!(verdict.summary(), "task_match 90%, writes 10%");
        }
        let without = br#"{"answers":{"task_match":{"noul":0.9},"writes":{"noul":0.1}}}"#;
        assert_eq!(parse_answers(without, &asked).model(), None);
    }

    fn declaration(environment: Environment) -> Option<Declaration> {
        Some(Declaration {
            project: "odealo".to_owned(),
            environment,
            risk: RiskLevel::Medium,
            scope: Scope::ReadWrite,
            reversibility: Reversibility::Reversible,
        })
    }

    #[test]
    fn body_has_user_request_and_rule_fact_only_with_instruction() {
        let plain = request_body(&request(""));
        assert_eq!(plain["questions"].as_object().map(Map::len), Some(5));
        let state = plain["state"].as_str().unwrap_or_default();
        assert!(state.starts_with("User request: \"Apply the staging migration\""));
        let ruled = request_body(&request("Staging only."));
        assert_eq!(ruled["questions"].as_object().map(Map::len), Some(6));
        assert!(
            ruled["state"]
                .as_str()
                .unwrap_or_default()
                .ends_with("Owner rule: Staging only.")
        );
    }

    #[test]
    fn policy() {
        let analysis = Analysis {
            known_command: true,
            ..Analysis::default()
        };
        let staging = [declaration(Environment::Staging)];
        let high_risk = [Some(Declaration {
            risk: RiskLevel::High,
            ..declaration(Environment::Staging).expect("declaration")
        })];
        let run = |v: &BouncerVerdict, d: &[Option<Declaration>], user: bool| {
            decide(
                v,
                &DecisionContext {
                    analysis: &analysis,
                    declarations: d,
                    has_user_request: user,
                },
            )
        };
        let clean = verdict(&[
            ("task_match", 0.9),
            ("writes", 0.8),
            ("leak", 0.05),
            ("destroy", 0.1),
        ]);
        assert!(!run(&clean, &staging, true).ask_owner);
        // A high-risk credential needs a certain read-only command.
        assert!(run(&clean, &high_risk, true).ask_owner);
        let read = verdict(&[
            ("task_match", 0.9),
            ("writes", 0.1),
            ("leak", 0.05),
            ("destroy", 0.1),
        ]);
        assert!(!run(&read, &high_risk, true).ask_owner);
        // A certain read does not need the task match. A leak answer is not a veto.
        let read_unmatched = verdict(&[
            ("task_match", 0.3),
            ("writes", 0.1),
            ("leak", 0.9),
            ("destroy", 0.1),
        ]);
        assert!(!run(&read_unmatched, &staging, true).ask_owner);
        for bad in [
            verdict(&[("task_match", 0.7), ("writes", 0.5), ("destroy", 0.1)]),
            verdict(&[("task_match", 0.9), ("writes", 0.5), ("destroy", 0.95)]),
            verdict(&[
                ("task_match", 0.9),
                ("writes", 0.5),
                ("destroy", 0.1),
                ("rule_break", 0.85),
            ]),
        ] {
            let d = run(&bad, &staging, true);
            assert!(d.ask_owner, "{d:?}");
            assert!(d.confidence.is_some_and(|c| c < MIN_CONFIDENCE));
        }
        assert!(run(&clean, &staging, false).ask_owner, "no user request");
        assert!(run(&clean, &[None], true).ask_owner, "no declaration");
        assert!(run(&BouncerVerdict::Unavailable("x".into()), &staging, true).ask_owner);
    }

    /// Policy v5 (dev round 2): a certain "does not change state" answer replaces the task
    /// match only for a command that the packs know. On held-out v2 the base model gave
    /// `writes` 0.2 or lower to `php artisan queue:retry all`, `mix run x.exs`, and
    /// `airflow connections export`, so unknown code needs the match.
    #[test]
    fn a_certain_read_skips_the_task_match_only_for_a_known_command() {
        let staging = [declaration(Environment::Staging)];
        let read_unmatched = verdict(&[
            ("task_match", 0.3),
            ("writes", 0.05),
            ("leak", 0.2),
            ("destroy", 0.05),
        ]);
        let decide_with = |analysis: &Analysis, v: &BouncerVerdict| {
            decide(
                v,
                &DecisionContext {
                    analysis,
                    declarations: &staging,
                    has_user_request: true,
                },
            )
        };
        let known = Analysis {
            known_command: true,
            ..Analysis::default()
        };
        let unknown = Analysis::default();
        assert!(!decide_with(&known, &read_unmatched).ask_owner);
        let asked = decide_with(&unknown, &read_unmatched);
        assert!(asked.ask_owner, "{asked:?}");
        assert!(asked.note.contains("task_match 30%"), "{}", asked.note);
        assert_eq!(asked.confidence, Some(0.3));
        // Unknown code with a matching request still runs.
        let matched = verdict(&[("task_match", 0.85), ("writes", 0.05), ("destroy", 0.05)]);
        assert!(!decide_with(&unknown, &matched).ask_owner);
        // A known safe command is a known command, whatever the field says.
        let safe = Analysis {
            known_safe: true,
            known_command: false,
            ..Analysis::default()
        };
        assert!(!decide_with(&safe, &read_unmatched).ask_owner);
        // Without a certain read, a known command needs the match too.
        let write_unmatched = verdict(&[("task_match", 0.3), ("writes", 0.6), ("destroy", 0.05)]);
        assert!(decide_with(&known, &write_unmatched).ask_owner);
        // A writes answer at exactly 0.2 is a certain read.
        let edge = verdict(&[("task_match", 0.3), ("writes", 0.2), ("destroy", 0.05)]);
        assert!(!decide_with(&known, &edge).ask_owner);
        assert!(decide_with(&unknown, &edge).ask_owner);
    }

    /// Policy v7 (dev round 3): with an owner instruction, a run needs 80% certainty that
    /// the command does not break it (`rule_break` at or below 0.2), also for a known safe
    /// command and a certain read. On held-out v3 the base model answered `rule_break`
    /// 0.25 to 0.53 for commands that broke the rule, below the old veto of 0.8.
    #[test]
    fn an_owner_instruction_needs_a_certain_no_rule_break() {
        let staging = [declaration(Environment::Staging)];
        let decide_with = |analysis: &Analysis, v: &BouncerVerdict| {
            decide(
                v,
                &DecisionContext {
                    analysis,
                    declarations: &staging,
                    has_user_request: true,
                },
            )
        };
        let known_safe = Analysis {
            known_safe: true,
            known_command: true,
            ..Analysis::default()
        };
        let known = Analysis {
            known_command: true,
            ..Analysis::default()
        };
        let unknown = Analysis::default();
        let with_rule = |rule_break: f64| {
            verdict(&[
                ("task_match", 0.95),
                ("writes", 0.05),
                ("destroy", 0.02),
                ("rule_break", rule_break),
            ])
        };
        for analysis in [&known_safe, &known, &unknown] {
            // The v3 values: 0.25 (`gh pr comment`), 0.51 (`cargo run`), 0.53.
            for rule_break in [0.25, 0.51, 0.53, 0.79, 0.21] {
                let asked = decide_with(analysis, &with_rule(rule_break));
                assert!(asked.ask_owner, "{analysis:?} {rule_break}");
                assert!(
                    asked.note.contains("rule_break not"),
                    "{analysis:?} {}",
                    asked.note
                );
                assert!(asked.confidence.is_some_and(|c| c < MIN_CONFIDENCE));
            }
            for rule_break in [0.2, 0.05, 0.0] {
                let allowed = decide_with(analysis, &with_rule(rule_break));
                assert!(!allowed.ask_owner, "{analysis:?} {rule_break}: {allowed:?}");
            }
        }
        // Without an instruction the model does not answer `rule_break`, and nothing
        // changes.
        let plain = verdict(&[("task_match", 0.95), ("writes", 0.05), ("destroy", 0.02)]);
        assert!(!decide_with(&unknown, &plain).ask_owner);
        // A calibration does not change the needed rule answer.
        let calibrated = decide_learned(
            &with_rule(0.3),
            &DecisionContext {
                analysis: &known_safe,
                declarations: &staging,
                has_user_request: true,
            },
            &Learned {
                thresholds: Thresholds {
                    task_match: CALIBRATION_FLOOR,
                },
                pattern: None,
            },
        );
        assert!(calibrated.ask_owner, "{calibrated:?}");
    }

    /// Policy v7 (dev round 3): a known write never counts as a certain read, whatever
    /// the model answers for `writes`. On held-out v3 the base model gave `writes` 0.08
    /// and 0.10 to `gh pr comment` and `gh issue close`. A sensitive credential asks for
    /// a known write.
    #[test]
    fn a_known_write_is_never_a_certain_read() {
        let staging = [declaration(Environment::Staging)];
        let high_risk = [Some(Declaration {
            risk: RiskLevel::High,
            ..declaration(Environment::Staging).expect("declaration")
        })];
        let write = Analysis {
            known_command: true,
            known_write: true,
            ..Analysis::default()
        };
        let read = Analysis {
            known_command: true,
            ..Analysis::default()
        };
        let run = |analysis: &Analysis, d: &[Option<Declaration>], v: &BouncerVerdict| {
            decide(
                v,
                &DecisionContext {
                    analysis,
                    declarations: d,
                    has_user_request: true,
                },
            )
        };
        let low_writes_unmatched =
            verdict(&[("task_match", 0.38), ("writes", 0.08), ("destroy", 0.0)]);
        assert!(!run(&read, &staging, &low_writes_unmatched).ask_owner);
        let asked = run(&write, &staging, &low_writes_unmatched);
        assert!(asked.ask_owner, "{asked:?}");
        assert!(asked.note.contains("task_match 38%"), "{}", asked.note);
        // A matching request runs a known write on a normal credential.
        let matched = verdict(&[("task_match", 0.9), ("writes", 0.08), ("destroy", 0.0)]);
        assert!(!run(&write, &staging, &matched).ask_owner);
        // A sensitive credential needs a certain read: a known write never is one.
        let asked = run(&write, &high_risk, &matched);
        assert!(asked.ask_owner, "{asked:?}");
        assert!(
            asked.note.contains("writes: a known write"),
            "{}",
            asked.note
        );
        assert!(!run(&read, &high_risk, &matched).ask_owner);
        // A known safe command is never a known write.
        let safe = Analysis {
            known_safe: true,
            known_command: true,
            known_write: true,
            ..Analysis::default()
        };
        assert!(!run(&safe, &high_risk, &low_writes_unmatched).ask_owner);
    }

    #[test]
    fn production_read_only_requires_model_task_match_and_clean_flags() {
        let analysis = Analysis {
            known_safe: true,
            ..Analysis::default()
        };
        let mut d = declaration(Environment::Production).unwrap();
        d.scope = Scope::ReadOnly;
        let declarations = [Some(d)];
        let context = DecisionContext {
            analysis: &analysis,
            declarations: &declarations,
            has_user_request: true,
        };
        let clean = verdict(&[
            ("task_match", 0.95),
            ("writes", 0.0),
            ("leak", 0.0),
            ("destroy", 0.0),
            ("rule_break", 0.0),
        ]);
        assert!(!decide(&clean, &context).ask_owner);
        assert!(owner_required(&context).is_none());
        for (name, value) in [
            ("task_match", 0.1),
            ("leak", 0.95),
            ("destroy", 0.95),
            ("rule_break", 0.95),
        ] {
            let bad = verdict(&[
                (
                    "task_match",
                    if name == "task_match" { value } else { 0.95 },
                ),
                ("leak", if name == "leak" { value } else { 0.0 }),
                ("destroy", if name == "destroy" { value } else { 0.0 }),
                ("rule_break", if name == "rule_break" { value } else { 0.0 }),
            ]);
            assert!(decide(&bad, &context).ask_owner, "{name}");
        }
        assert!(decide(&BouncerVerdict::Unavailable("offline".into()), &context).ask_owner);
        for scope in [Scope::ReadWrite, Scope::Admin] {
            let mut declarations = declarations.clone();
            declarations[0].as_mut().unwrap().scope = scope;
            assert!(
                decide(
                    &clean,
                    &DecisionContext {
                        declarations: &declarations,
                        ..context.clone()
                    }
                )
                .ask_owner
            );
        }
    }

    /// ADR 0010: a production declaration always waits for the owner. Known safe and
    /// read-only commands and a fully certain model verdict do not change this.
    #[test]
    fn production_write_scopes_always_ask_the_owner() {
        let certain = verdict(&[
            ("task_match", 1.0),
            ("writes", 0.0),
            ("remote", 0.0),
            ("leak", 0.0),
            ("destroy", 0.0),
            ("rule_break", 0.0),
        ]);
        let read_only = verdict(&[
            ("task_match", 0.3),
            ("writes", 0.0),
            ("remote", 0.0),
            ("leak", 0.0),
            ("destroy", 0.0),
        ]);
        // The mildest production declaration: low risk, read-only, reversible.
        let mild = Declaration {
            project: "odealo".to_owned(),
            environment: Environment::Production,
            risk: RiskLevel::Low,
            scope: Scope::ReadWrite,
            reversibility: Reversibility::Reversible,
        };
        let sets: [&[Option<Declaration>]; 3] = [
            &[Some(mild.clone())],
            &[declaration(Environment::Staging), Some(mild.clone())],
            &[declaration(Environment::Production)],
        ];
        let known_safe = Analysis {
            flags: Vec::new(),
            known_safe: true,
            known_command: true,
            known_write: false,
        };
        let unknown = Analysis::default();
        for declarations in sets {
            for analysis in [&known_safe, &unknown] {
                for model in [
                    &certain,
                    &read_only,
                    &BouncerVerdict::Unavailable("not asked".into()),
                ] {
                    let context = DecisionContext {
                        analysis,
                        declarations,
                        has_user_request: true,
                    };
                    let decision = decide(model, &context);
                    assert!(
                        decision.ask_owner,
                        "{declarations:?} {analysis:?} {model:?}"
                    );
                    assert_eq!(decision.confidence, None, "the model did not decide");
                    assert!(decision.note.starts_with("Production credential"));
                    assert!(owner_required(&context).is_some());
                }
            }
        }
        // The same fully certain verdict runs a staging credential without the owner.
        let staging = [declaration(Environment::Staging)];
        let context = DecisionContext {
            analysis: &known_safe,
            declarations: &staging,
            has_user_request: true,
        };
        assert!(owner_required(&context).is_none());
        assert!(!decide(&certain, &context).ask_owner);
    }

    /// ADR 0010: a remembered pattern and a calibrated level act only at the model step.
    /// The production rule, a rule flag, a missing user request, and a missing
    /// declaration still ask the owner, with the same note as without learning.
    #[test]
    fn learning_replaces_only_the_model_step() {
        let learned = Learned {
            thresholds: Thresholds {
                task_match: CALIBRATION_FLOOR,
            },
            pattern: Some("npm run <string>".to_owned()),
        };
        let certain = verdict(&[("task_match", 1.0), ("writes", 0.0), ("destroy", 0.0)]);
        let staging = [declaration(Environment::Staging)];
        let production = [declaration(Environment::Production)];
        let clean = Analysis::default();
        let flagged = Analysis {
            flags: vec!["secret_output".to_owned()],
            ..Analysis::default()
        };
        let cases: [(&Analysis, &[Option<Declaration>], bool, &str); 4] = [
            (&clean, &production, true, "Production credential"),
            (&flagged, &staging, true, "Rule flags: secret_output"),
            (
                &clean,
                &staging,
                false,
                "The agent did not send the user request.",
            ),
            (&clean, &[None], true, "An item has no declaration."),
        ];
        for (analysis, declarations, has_user_request, note) in cases {
            let context = DecisionContext {
                analysis,
                declarations,
                has_user_request,
            };
            let with = decide_learned(&certain, &context, &learned);
            assert!(with.ask_owner, "{note}");
            assert_eq!(with.confidence, None);
            assert!(with.note.starts_with(note), "{}", with.note);
            assert_eq!(with, decide(&certain, &context), "learning changed {note}");
            assert!(before_model(&context).is_some());
        }

        // A clean request: the pattern replaces the model, also an unavailable model and
        // a model veto. Without the pattern, both ask.
        let context = DecisionContext {
            analysis: &clean,
            declarations: &staging,
            has_user_request: true,
        };
        let veto = verdict(&[("task_match", 0.9), ("writes", 0.5), ("destroy", 0.99)]);
        for model in [&veto, &BouncerVerdict::Unavailable("not asked".into())] {
            assert!(decide(model, &context).ask_owner);
            let allowed = decide_learned(model, &context, &learned);
            assert!(!allowed.ask_owner, "{allowed:?}");
            assert!(
                allowed
                    .note
                    .starts_with("Remembered pattern allowed: npm run <string>")
            );
        }
    }

    /// ADR 0009 step 3: a calibration changes only the `task_match` level, inside
    /// [`CALIBRATION_FLOOR`, 0.8]. The read-only check for a sensitive credential and
    /// the vetoes stay.
    #[test]
    fn calibration_changes_only_the_task_match_level() {
        let analysis = Analysis::default();
        let staging = [declaration(Environment::Staging)];
        let high_risk = [Some(Declaration {
            risk: RiskLevel::High,
            ..declaration(Environment::Staging).expect("declaration")
        })];
        let run = |v: &BouncerVerdict, d: &[Option<Declaration>], level: f64| {
            decide_learned(
                v,
                &DecisionContext {
                    analysis: &analysis,
                    declarations: d,
                    has_user_request: true,
                },
                &Learned {
                    thresholds: Thresholds { task_match: level },
                    pattern: None,
                },
            )
        };
        let general = verdict(&[("task_match", 0.65), ("writes", 0.5), ("destroy", 0.1)]);
        assert!(run(&general, &staging, 0.8).ask_owner);
        let calibrated = run(&general, &staging, 0.6);
        assert!(!calibrated.ask_owner, "{calibrated:?}");
        assert!(calibrated.note.contains("Calibrated task_match level: 60%"));
        // A level under the floor is the floor. A level over 0.8 is 0.8.
        let weak = verdict(&[("task_match", 0.45), ("writes", 0.5), ("destroy", 0.1)]);
        assert!(run(&weak, &staging, 0.1).ask_owner);
        assert!(run(&weak, &staging, f64::NAN).ask_owner);
        assert_eq!(
            Thresholds { task_match: 0.95 }.task_match_level(),
            MIN_CONFIDENCE
        );
        // The sensitive read-only check and the vetoes do not move.
        let writes = verdict(&[("task_match", 0.95), ("writes", 0.5), ("destroy", 0.1)]);
        assert!(run(&writes, &high_risk, CALIBRATION_FLOOR).ask_owner);
        let destroy = verdict(&[("task_match", 0.95), ("writes", 0.5), ("destroy", 0.95)]);
        assert!(run(&destroy, &staging, CALIBRATION_FLOOR).ask_owner);
        let rule = verdict(&[
            ("task_match", 0.95),
            ("writes", 0.5),
            ("destroy", 0.1),
            ("rule_break", 0.85),
        ]);
        assert!(run(&rule, &staging, CALIBRATION_FLOOR).ask_owner);
    }

    /// A loopback server that gives `body` to each of `requests` requests.
    fn answer_server(body: &'static str, requests: usize) -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            for stream in listener.incoming().take(requests).flatten() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut request = vec![0u8; length];
                let _ = reader.read_exact(&mut request);
                let mut stream = stream;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        url
    }

    /// Goal item B9: a promoted model is pinned to its version. An answer from another
    /// version is not a verdict, so the owner decides.
    #[test]
    fn a_pinned_client_accepts_only_its_model_version() {
        let body = r#"{"model":"apassy-local-v1+11111111","answers":{"task_match":{"noul":0.9},"writes":{"noul":0.1},"remote":{"noul":0.1},"leak":{"noul":0.1},"destroy":{"noul":0.1}}}"#;
        let url = answer_server(body, 3);
        let client = BouncerClient::new(&url).expect("loopback");
        assert_eq!(client.expected_model(), None);
        assert!(matches!(
            client.evaluate(&request("")),
            BouncerVerdict::Scored { .. }
        ));
        let pinned = client.clone().expect_model("apassy-local-v1+11111111");
        assert_eq!(pinned.expected_model(), Some("apassy-local-v1+11111111"));
        assert_eq!(
            pinned.evaluate(&request("")).model(),
            Some("apassy-local-v1+11111111")
        );
        let other = client.expect_model("apassy-local-v1+22222222");
        match other.evaluate(&request("")) {
            BouncerVerdict::Unavailable(reason) => assert!(
                reason.contains("is apassy-local-v1+11111111, not the active version"),
                "{reason}"
            ),
            verdict => panic!("a wrong version gave a verdict: {verdict:?}"),
        }
        // `at_url` keeps the key and the time limit, and drops the pin.
        let moved = other.at_url("http://127.0.0.1:9").expect("loopback");
        assert_eq!(moved.expected_model(), None);
        assert!(other.at_url("https://example.com").is_err());
    }

    /// Synthetic inference responses, with no vault, provider, or command execution.
    /// `None` holds a request open without replying, while accepting the next one.
    /// This forces a real client timeout without delaying the retry's response.
    fn scripted_inference_server(
        responses: Vec<(u16, &'static str, Option<Duration>)>,
    ) -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&calls);
        let stopped = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let mut held_requests = Vec::new();
            for (status, body, delay) in responses {
                let mut stream = loop {
                    if stopped.load(Ordering::SeqCst) {
                        return;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                };
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("timeout");
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().expect("length");
                    }
                }
                let mut request = vec![0; length];
                reader.read_exact(&mut request).expect("request body");
                seen.fetch_add(1, Ordering::SeqCst);
                let Some(delay) = delay else {
                    held_requests.push(stream);
                    continue;
                };
                std::thread::sleep(delay);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, calls, stop, server)
    }

    const VALID_INFERENCE: &str = r#"{"model":"synthetic-v1","answers":{"task_match":{"noul":0.9},"writes":{"noul":0.1},"remote":{"noul":0.1},"leak":{"noul":0.1},"destroy":{"noul":0.1}}}"#;

    #[test]
    fn the_default_inference_budget_accepts_a_slow_first_real_decision() {
        use std::sync::atomic::Ordering;
        // The default budget is ten seconds, over a first real decision of 5.2 s; below,
        // a decision of 520 ms gets a budget of 2 s.
        let (url, calls, stop, server) = scripted_inference_server(vec![(
            200,
            VALID_INFERENCE,
            Some(Duration::from_millis(520)),
        )]);
        let client = BouncerClient::new(&url).expect("client");
        assert_eq!(client.timeout, Duration::from_secs(10));
        let budget = client.timeout / 5;
        let client = client.with_timeout(budget);
        assert!(matches!(
            client.evaluate(&request("")),
            BouncerVerdict::Scored { .. }
        ));
        stop.store(true, Ordering::SeqCst);
        server.join().expect("server");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a slow first decision needs no retry"
        );
    }

    #[test]
    fn a_transient_inference_timeout_retries_once_with_the_configured_budget() {
        use std::sync::atomic::Ordering;
        let (url, calls, stop, server) = scripted_inference_server(vec![
            (200, VALID_INFERENCE, None),
            (200, VALID_INFERENCE, Some(Duration::ZERO)),
        ]);
        let client = BouncerClient::new(&url)
            .expect("client")
            .with_timeout(Duration::from_secs(1));
        let began = std::time::Instant::now();
        let verdict = client.evaluate(&request(""));
        let elapsed = began.elapsed();
        stop.store(true, Ordering::SeqCst);
        server.join().expect("server");
        assert!(
            matches!(verdict, BouncerVerdict::Scored { .. }),
            "{verdict:?}"
        );
        assert!(elapsed >= Duration::from_secs(1), "first attempt timed out");
        assert!(elapsed < Duration::from_secs(5), "retry stayed bounded");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn inference_timeouts_stop_after_two_attempts() {
        use std::sync::atomic::Ordering;
        let (url, calls, stop, server) = scripted_inference_server(vec![
            (200, VALID_INFERENCE, None),
            (200, VALID_INFERENCE, None),
            (200, VALID_INFERENCE, Some(Duration::ZERO)),
        ]);
        let client = BouncerClient::new(&url)
            .expect("client")
            .with_timeout(Duration::from_millis(200));
        let began = std::time::Instant::now();
        match client.evaluate(&request("")) {
            BouncerVerdict::Unavailable(reason) => assert!(
                reason.contains("two inference attempts (up to 400 ms total)"),
                "{reason}"
            ),
            verdict => panic!("timeouts gave a verdict: {verdict:?}"),
        }
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "total budget stayed bounded"
        );
        stop.store(true, Ordering::SeqCst);
        server.join().expect("server");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn invalid_or_wrong_version_inference_is_never_retried() {
        use std::sync::atomic::Ordering;
        for (status, body, pin) in [
            (500, "{}", "synthetic-v1"),
            (200, "not-json", "synthetic-v1"),
            (
                200,
                r#"{"answers":{"task_match":{"noul":0.9}}}"#,
                "synthetic-v1",
            ),
            (200, VALID_INFERENCE, "another-model"),
        ] {
            let (url, calls, stop, server) = scripted_inference_server(vec![
                (status, body, Some(Duration::ZERO)),
                (200, VALID_INFERENCE, Some(Duration::ZERO)),
            ]);
            let client = BouncerClient::new(&url).expect("client").expect_model(pin);
            assert!(matches!(
                client.evaluate(&request("")),
                BouncerVerdict::Unavailable(_)
            ));
            stop.store(true, Ordering::SeqCst);
            server.join().expect("server");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "invalid response was not retried"
            );
        }
    }

    #[test]
    fn readiness_also_checks_the_expected_model_version() {
        let url = answer_server(
            r#"{"model":"wrong-model","answers":{"ready":{"noul":0.5}}}"#,
            1,
        );
        let client = BouncerClient::new(&url)
            .expect("client")
            .expect_model("active-model");
        assert!(
            client
                .warm_up(Duration::from_secs(1))
                .expect_err("wrong version")
                .contains("not the active version active-model")
        );
    }

    /// A synthetic vault value and vault path. Neither may reach a bouncer brain.
    const SYNTHETIC_SECRET: &str = "FAKE-brain-secret-5521-canary";
    const SYNTHETIC_VAULT_PATH: &str =
        "/Users/synthetic/Library/Application Support/Apassy/vault.db";
    /// The bearer of the fake remote bouncer brain. It is not a vault credential.
    const BRAIN_TOKEN: &str = "synthetic-brain-token-not-a-secret";
    const ACTIVE_HEADS: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const ACTIVE_MODEL: &str = "apassy-local-v1+a1b2c3d4";
    const SHADOW_HEADS: &str = "0badc0de135724680badc0de135724680badc0de135724680badc0de13572468";
    const SHADOW_MODEL: &str = "apassy-local-v1+0badc0de";

    /// A remote bouncer brain over TLS on this computer (`https://localhost:PORT`).
    /// It answers each request with the current `answer` and keeps every request,
    /// head and body, after TLS decryption.
    struct FakeBrain {
        url: String,
        tls: Arc<TlsClient>,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        answer: Arc<std::sync::Mutex<(u16, String)>>,
    }

    impl FakeBrain {
        fn set_answer(&self, status: u16, body: &str) {
            *self.answer.lock().expect("answer") = (status, body.to_owned());
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("requests").clone()
        }

        /// The JSON body of request `index`.
        fn body(&self, index: usize) -> Value {
            let request = &self.requests()[index];
            let at = request.find("\r\n\r\n").expect("head end");
            serde_json::from_str(&request[at + 4..]).expect("JSON body")
        }

        /// Every request has the brain bearer in its head, and no request has the
        /// synthetic vault value or the vault path. The body has only contract
        /// fields and never the bearer.
        fn assert_clean(&self) {
            for request in self.requests() {
                let at = request.find("\r\n\r\n").expect("head end");
                let (head, body) = (&request[..at], &request[at + 4..]);
                assert!(
                    head.contains(&format!("\r\nAuthorization: Bearer {BRAIN_TOKEN}\r\n")),
                    "{head}"
                );
                for hidden in [SYNTHETIC_SECRET, SYNTHETIC_VAULT_PATH] {
                    assert!(!request.contains(hidden), "{hidden} reached the brain");
                }
                assert!(!body.contains(BRAIN_TOKEN));
                let value: Value = serde_json::from_str(body).expect("JSON body");
                for key in value.as_object().expect("object").keys() {
                    assert!(
                        ["state", "questions", "heads", "shadow_heads"].contains(&key.as_str()),
                        "a field outside the contract: {key}"
                    );
                }
            }
        }
    }

    fn fake_brain(delay: Duration) -> FakeBrain {
        use std::io::{Read, Write};
        let pki = crate::broker::http::test_support::test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!(
            "https://localhost:{}",
            listener.local_addr().expect("addr").port()
        );
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let answer = Arc::new(std::sync::Mutex::new((200, String::new())));
        let (seen, current, config) = (
            Arc::clone(&requests),
            Arc::clone(&answer),
            Arc::clone(&pki.config),
        );
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let complete = loop {
                    if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .map_or(0, |value| value.trim().parse::<usize>().unwrap_or(0));
                        if raw.len() >= end + 4 + length {
                            break true;
                        }
                    }
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => break false,
                        Ok(read) => raw.extend_from_slice(&buf[..read]),
                    }
                };
                if !complete {
                    continue;
                }
                seen.lock()
                    .expect("requests")
                    .push(String::from_utf8_lossy(&raw).into_owned());
                std::thread::sleep(delay);
                let (status, body) = current.lock().expect("answer").clone();
                let _ = write!(
                    tls,
                    "HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            }
        });
        FakeBrain {
            url,
            tls: Arc::new(pki.client),
            requests,
            answer,
        }
    }

    /// A bearer that keeps the deadline of each call.
    #[derive(Default)]
    struct RecordingBearer {
        calls: std::sync::Mutex<Vec<(Instant, Instant)>>,
        invalidated: AtomicBool,
    }

    impl BrainCredential for RecordingBearer {
        fn bearer(&self, deadline: Instant) -> Option<Zeroizing<String>> {
            self.calls
                .lock()
                .expect("calls")
                .push((Instant::now(), deadline));
            Some(Zeroizing::new(BRAIN_TOKEN.to_owned()))
        }

        fn invalidate(&self) {
            self.invalidated.store(true, Ordering::SeqCst);
        }
    }

    fn static_bearer() -> Arc<StaticBearer> {
        Arc::new(StaticBearer::new(Zeroizing::new(BRAIN_TOKEN.to_owned())).expect("token"))
    }

    /// A request whose context names the synthetic vault value and path nowhere:
    /// the state of ADR 0007 only.
    fn remote_request() -> BouncerRequest {
        BouncerRequest {
            user_request: "Run the staging checks".to_owned(),
            command: "npm test".to_owned(),
            relative_dir: ".".to_owned(),
            purpose: "Run the tests".to_owned(),
            env_names: vec!["DB_URL".to_owned()],
            instruction: String::new(),
        }
    }

    /// Active answers for the five facts, with `heads` and `model`, and an optional
    /// `shadow` part.
    fn brain_answer(heads: &str, model: &str, shadow: Option<Value>) -> String {
        let answers = json!({
            "task_match": {"type": "noul", "noul": 0.9},
            "writes": {"type": "noul", "noul": 0.1},
            "remote": {"type": "noul", "noul": 0.1},
            "leak": {"type": "noul", "noul": 0.1},
            "destroy": {"type": "noul", "noul": 0.1},
        });
        let mut body = json!({"model": model, "heads": heads, "answers": answers});
        if let Some(shadow) = shadow {
            body["shadow"] = shadow;
        }
        body.to_string()
    }

    fn shadow_answers(heads: &str, model: &str, noul: f64) -> Value {
        json!({
            "heads": heads,
            "model": model,
            "answers": {
                "task_match": {"type": "noul", "noul": noul},
                "writes": {"type": "noul", "noul": 0.2},
                "remote": {"type": "noul", "noul": 0.2},
                "leak": {"type": "noul", "noul": 0.2},
                "destroy": {"type": "noul", "noul": 0.2},
            },
        })
    }

    fn reason(verdict: &BouncerVerdict) -> &str {
        match verdict {
            BouncerVerdict::Unavailable(reason) => reason,
            BouncerVerdict::Scored { .. } => panic!("expected unavailable: {verdict:?}"),
        }
    }

    #[test]
    fn loopback_over_http_and_remote_only_over_https_with_a_credential() {
        // This Mac: loopback http:// only.
        assert!(BouncerClient::new("https://example.com").is_err());
        assert!(BouncerClient::new("http://10.0.0.1:8770").is_err());
        let client = BouncerClient::new("http://127.0.0.1:9")
            .expect("loopback")
            .with_timeout(Duration::from_millis(300));
        assert!(!client.is_remote());
        assert!(matches!(
            client.evaluate(&request("")),
            BouncerVerdict::Unavailable(_)
        ));
        // A remote bouncer brain: https:// only.
        let tls = Arc::new(TlsClient::platform().expect("platform TLS"));
        for url in [
            "http://127.0.0.1:8770",
            "http://10.0.0.1:8770",
            "http://brain.example.invalid:80",
            "ftp://brain.example.invalid",
        ] {
            assert!(
                BouncerClient::remote(url, static_bearer(), Arc::clone(&tls)).is_err(),
                "{url}"
            );
        }
        let remote = BouncerClient::remote(
            "https://brain.example.invalid/",
            static_bearer(),
            Arc::clone(&tls),
        )
        .expect("https");
        assert!(remote.is_remote());
        assert_eq!(remote.url(), "https://brain.example.invalid");
        assert_eq!(remote.api_key(), None);
        assert_eq!(remote.port(), None);
        // `at_url` gives a client on this Mac only.
        assert!(remote.at_url("https://brain.example.invalid").is_err());

        // Without a bearer, nothing goes to the server: no connection arrives.
        let brain = fake_brain(Duration::ZERO);
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        let refused = static_bearer();
        refused.invalidate();
        assert!(refused.is_refused());
        assert!(refused.bearer(Instant::now()).is_none());
        let client = BouncerClient::remote(&brain.url, refused, Arc::clone(&brain.tls))
            .expect("https")
            .with_timeout(Duration::from_secs(2));
        let verdict = client.evaluate(&remote_request());
        assert!(reason(&verdict).contains("no credential"), "{verdict:?}");
        assert!(
            client.warm_up(Duration::from_secs(2)).is_err(),
            "no readiness request without a bearer"
        );
        std::thread::sleep(Duration::from_millis(100));
        assert!(brain.requests().is_empty(), "nothing was sent");
        // With a bearer the same server answers, over TLS.
        let client = BouncerClient::remote(&brain.url, static_bearer(), Arc::clone(&brain.tls))
            .expect("https")
            .with_timeout(Duration::from_secs(2));
        assert!(matches!(
            client.evaluate(&remote_request()),
            BouncerVerdict::Scored { .. }
        ));
        brain.assert_clean();
        assert_eq!(brain.requests().len(), 1);
        // An empty token or one that a header cannot carry is not a credential.
        for token in ["", "two words", "line\r\nbreak"] {
            assert!(StaticBearer::new(Zeroizing::new(token.to_owned())).is_none());
        }
    }

    #[test]
    fn a_remote_brain_is_checked_over_tls() {
        let brain = fake_brain(Duration::ZERO);
        let client = BouncerClient::remote(&brain.url, static_bearer(), Arc::clone(&brain.tls))
            .expect("https");
        brain.set_answer(
            200,
            r#"{"status":"ok","loaded":["english"],"device":"cpu"}"#,
        );
        assert_eq!(client.probe_health(Duration::from_secs(2)), Health::Healthy);
        brain.set_answer(200, r#"{"status":"loading"}"#);
        assert_eq!(
            client.probe_health(Duration::from_secs(2)),
            Health::NotBouncer
        );
        brain.set_answer(503, r#"{"status":"ok"}"#);
        assert_eq!(
            client.probe_health(Duration::from_secs(2)),
            Health::NotBouncer
        );
        // The health check sends no bearer.
        for request in brain.requests() {
            assert!(request.starts_with("GET /health HTTP/1.1\r\n"), "{request}");
            assert!(!request.contains(BRAIN_TOKEN));
        }
        // A certificate that the client does not trust is not a bouncer brain.
        let untrusted = BouncerClient::remote(
            &brain.url,
            static_bearer(),
            Arc::new(TlsClient::platform().expect("platform TLS")),
        )
        .expect("https");
        assert_eq!(
            untrusted.probe_health(Duration::from_secs(2)),
            Health::NotBouncer
        );
        // A closed port is no server.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let nowhere = BouncerClient::remote(
            &format!("https://localhost:{port}"),
            static_bearer(),
            Arc::clone(&brain.tls),
        )
        .expect("https");
        assert_eq!(
            nowhere.probe_health(Duration::from_secs(2)),
            Health::NoServer
        );

        // The readiness question goes with the bearer and the head pin, and checks
        // both pins.
        let before = brain.requests().len();
        let pinned = client
            .clone()
            .expect_model(ACTIVE_MODEL)
            .expect_heads(ACTIVE_HEADS);
        brain.set_answer(
            200,
            &json!({"model": ACTIVE_MODEL, "heads": ACTIVE_HEADS, "answers": {"ready": {"type": "noul", "noul": 0.5}}})
                .to_string(),
        );
        assert_eq!(
            pinned.warm_up(Duration::from_secs(2)),
            Ok(Some(ACTIVE_MODEL.to_owned()))
        );
        assert_eq!(brain.body(before)["heads"], ACTIVE_HEADS);
        brain.set_answer(
            200,
            &json!({"model": ACTIVE_MODEL, "heads": SHADOW_HEADS, "answers": {"ready": {"type": "noul", "noul": 0.5}}})
                .to_string(),
        );
        assert!(
            pinned
                .warm_up(Duration::from_secs(2))
                .expect_err("another head set")
                .contains("not from the pinned head set")
        );
        brain.assert_clean_bodies_after(before);
    }

    impl FakeBrain {
        /// [`FakeBrain::assert_clean`] for the requests from `index` on (the health
        /// checks before have no bearer and no body).
        fn assert_clean_bodies_after(&self, index: usize) {
            let all = self.requests();
            let checked = FakeBrain {
                url: self.url.clone(),
                tls: Arc::clone(&self.tls),
                requests: Arc::new(std::sync::Mutex::new(all[index..].to_vec())),
                answer: Arc::clone(&self.answer),
            };
            checked.assert_clean();
        }
    }

    #[test]
    fn a_409_a_401_or_a_wrong_head_hash_is_unavailable() {
        let brain = fake_brain(Duration::ZERO);
        let bearer = static_bearer();
        let client = BouncerClient::remote(&brain.url, bearer.clone(), Arc::clone(&brain.tls))
            .expect("https")
            .with_timeout(Duration::from_secs(2))
            .expect_model(ACTIVE_MODEL)
            .expect_heads(ACTIVE_HEADS);
        assert_eq!(client.expected_heads(), Some(ACTIVE_HEADS));

        // The pinned answer is a verdict, and the request carries the pin.
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        let verdict = client.evaluate(&remote_request());
        assert!(
            matches!(verdict, BouncerVerdict::Scored { .. }),
            "{verdict:?}"
        );
        assert_eq!(verdict.model(), Some(ACTIVE_MODEL));
        assert_eq!(brain.body(0)["heads"], ACTIVE_HEADS);
        assert!(brain.body(0).get("shadow_heads").is_none());

        // 409 unknown_heads: the server has no such head set.
        brain.set_answer(
            409,
            r#"{"detail":{"code":"unknown_heads","message":"the head set is not on this server"}}"#,
        );
        let verdict = client.evaluate(&remote_request());
        assert!(reason(&verdict).contains("status 409"), "{verdict:?}");
        // Another head set, no head set named, or another model: unavailable.
        for (heads, model) in [
            (SHADOW_HEADS, ACTIVE_MODEL),
            ("", ACTIVE_MODEL),
            (ACTIVE_HEADS, SHADOW_MODEL),
        ] {
            let mut answer: Value =
                serde_json::from_str(&brain_answer(heads, model, None)).expect("JSON");
            if heads.is_empty() {
                answer.as_object_mut().expect("object").remove("heads");
            }
            brain.set_answer(200, &answer.to_string());
            assert!(
                matches!(
                    client.evaluate(&remote_request()),
                    BouncerVerdict::Unavailable(_)
                ),
                "{heads} {model}"
            );
        }
        // Other statuses, a 2xx other than 200 included, and a body that is not JSON.
        for (status, body) in [
            (201, brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None)),
            (
                422,
                r#"{"detail":{"code":"bad_heads","message":"x"}}"#.to_owned(),
            ),
            (500, "{}".to_owned()),
            (200, "not-json".to_owned()),
        ] {
            brain.set_answer(status, &body);
            assert!(
                matches!(
                    client.evaluate(&remote_request()),
                    BouncerVerdict::Unavailable(_)
                ),
                "{status}"
            );
        }
        // A malformed pin sends nothing.
        let sent = brain.requests().len();
        let malformed = client.clone().expect_heads("A1B2");
        let verdict = malformed.evaluate(&remote_request());
        assert!(reason(&verdict).contains("not valid"), "{verdict:?}");
        assert_eq!(brain.requests().len(), sent, "nothing was sent");

        // 401: unavailable, and the credential ends. The next request sends nothing.
        brain.set_answer(401, r#"{"detail":"Unauthorized"}"#);
        let verdict = client.evaluate(&remote_request());
        assert!(reason(&verdict).contains("status 401"), "{verdict:?}");
        assert!(bearer.is_refused());
        let sent = brain.requests().len();
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        let verdict = client.evaluate(&remote_request());
        assert!(reason(&verdict).contains("no credential"), "{verdict:?}");
        assert_eq!(
            brain.requests().len(),
            sent,
            "nothing was sent after the 401"
        );
        // A 401 is not retried with the same request.
        let recording = Arc::new(RecordingBearer::default());
        let client = BouncerClient::remote(&brain.url, recording.clone(), Arc::clone(&brain.tls))
            .expect("https")
            .with_timeout(Duration::from_secs(2));
        brain.set_answer(401, r#"{"detail":"Unauthorized"}"#);
        assert!(matches!(
            client.evaluate(&remote_request()),
            BouncerVerdict::Unavailable(_)
        ));
        assert!(recording.invalidated.load(Ordering::SeqCst));
        assert_eq!(recording.calls.lock().expect("calls").len(), 1);
        brain.assert_clean();
    }

    #[test]
    fn a_shadow_error_never_changes_the_active_verdict() {
        let brain = fake_brain(Duration::ZERO);
        let client = BouncerClient::remote(&brain.url, static_bearer(), Arc::clone(&brain.tls))
            .expect("https")
            .with_timeout(Duration::from_secs(2))
            .expect_model(ACTIVE_MODEL)
            .expect_heads(ACTIVE_HEADS);
        let pin = ShadowPin::new(SHADOW_HEADS, SHADOW_MODEL);
        // The active verdict of an answer without a shadow part.
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        let alone = client.evaluate(&remote_request());
        assert!(matches!(alone, BouncerVerdict::Scored { .. }), "{alone:?}");

        // A good shadow part: both verdicts, from one request.
        let sent = brain.requests().len();
        brain.set_answer(
            200,
            &brain_answer(
                ACTIVE_HEADS,
                ACTIVE_MODEL,
                Some(shadow_answers(SHADOW_HEADS, SHADOW_MODEL, 0.7)),
            ),
        );
        let (active, shadow) = client.evaluate_with_shadow(&remote_request(), Some(&pin));
        assert_eq!(active, alone);
        let shadow = shadow.expect("a shadow verdict");
        assert_eq!(shadow.model(), Some(SHADOW_MODEL));
        assert_eq!(shadow.fact("task_match"), Some(0.7));
        assert_eq!(brain.requests().len(), sent + 1, "one request");
        let body = brain.body(sent);
        assert_eq!(body["heads"], ACTIVE_HEADS);
        assert_eq!(body["shadow_heads"], SHADOW_HEADS);

        // Each shadow failure leaves the active verdict as it is.
        let mut out_of_range = shadow_answers(SHADOW_HEADS, SHADOW_MODEL, 0.7);
        out_of_range["answers"]["task_match"]["noul"] = json!(1.5);
        let mut missing = shadow_answers(SHADOW_HEADS, SHADOW_MODEL, 0.7);
        missing["answers"]
            .as_object_mut()
            .expect("answers")
            .remove("destroy");
        for (name, part) in [
            (
                "unknown",
                Some(json!({"heads": SHADOW_HEADS, "error": "unknown_heads"})),
            ),
            (
                "failed",
                Some(json!({"heads": SHADOW_HEADS, "error": "shadow_failed"})),
            ),
            (
                "other error",
                Some(json!({"heads": SHADOW_HEADS, "error": "out of memory at /srv/x"})),
            ),
            ("no shadow part", None),
            ("not an object", Some(json!("broken"))),
            (
                "other heads",
                Some(shadow_answers(ACTIVE_HEADS, SHADOW_MODEL, 0.7)),
            ),
            (
                "other model",
                Some(shadow_answers(SHADOW_HEADS, ACTIVE_MODEL, 0.7)),
            ),
            ("out of range", Some(out_of_range)),
            ("missing answer", Some(missing)),
        ] {
            brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, part));
            let (active, shadow) = client.evaluate_with_shadow(&remote_request(), Some(&pin));
            assert_eq!(active, alone, "{name}");
            let shadow = shadow.expect("a shadow verdict");
            assert!(
                matches!(shadow, BouncerVerdict::Unavailable(_)),
                "{name}: {shadow:?}"
            );
            assert!(
                !reason(&shadow).contains("/srv/x"),
                "server text is not kept"
            );
        }
        // A malformed shadow pin is not sent, and the active verdict stands.
        let sent = brain.requests().len();
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        let bad_pin = ShadowPin::new("0BADC0DE", SHADOW_MODEL);
        let (active, shadow) = client.evaluate_with_shadow(&remote_request(), Some(&bad_pin));
        assert_eq!(active, alone);
        assert!(reason(&shadow.expect("a shadow verdict")).contains("not valid"));
        assert!(brain.body(sent).get("shadow_heads").is_none());
        // An unavailable active answer is never replaced by a good shadow part.
        brain.set_answer(
            200,
            &brain_answer(
                SHADOW_HEADS,
                ACTIVE_MODEL,
                Some(shadow_answers(SHADOW_HEADS, SHADOW_MODEL, 0.99)),
            ),
        );
        let (active, _) = client.evaluate_with_shadow(&remote_request(), Some(&pin));
        assert!(
            matches!(active, BouncerVerdict::Unavailable(_)),
            "{active:?}"
        );
        // A failed request gives no shadow answer either.
        brain.set_answer(409, r#"{"detail":{"code":"unknown_heads","message":"x"}}"#);
        let (active, shadow) = client.evaluate_with_shadow(&remote_request(), Some(&pin));
        assert!(matches!(active, BouncerVerdict::Unavailable(_)));
        assert!(matches!(shadow, Some(BouncerVerdict::Unavailable(_))));
        // Without a shadow pin there is no shadow verdict.
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        assert_eq!(client.evaluate_with_shadow(&remote_request(), None).1, None);
        brain.assert_clean();
    }

    #[test]
    fn a_remote_url_from_the_environment_is_refused() {
        // `APASSY_BOUNCER_URL` and the address of `bouncer.json` name only this Mac.
        // `from_sources` is `from_env_or` with the environment values as arguments.
        for (env, file) in [
            (Some("https://brain.example.invalid"), DEFAULT_URL),
            (None, "https://brain.example.invalid"),
            (Some("http://10.0.0.1:8770"), DEFAULT_URL),
            (None, "http://brain.example.invalid:8770"),
            (Some("https://localhost:8443"), DEFAULT_URL),
        ] {
            assert!(
                BouncerClient::from_sources(
                    env.map(str::to_owned),
                    file,
                    Some("synthetic-key".to_owned())
                )
                .is_err(),
                "{env:?} {file}"
            );
        }
        let local = BouncerClient::from_sources(
            Some("http://127.0.0.1:8771".to_owned()),
            DEFAULT_URL,
            Some("synthetic-key".to_owned()),
        )
        .expect("loopback");
        assert!(!local.is_remote());
        assert_eq!(local.url(), "http://127.0.0.1:8771");
        assert_eq!(local.api_key(), Some("synthetic-key"));
        let file =
            BouncerClient::from_sources(None, DEFAULT_URL, Some(String::new())).expect("loopback");
        assert_eq!(file.url(), DEFAULT_URL);
        assert_eq!(file.api_key(), None);
    }

    #[test]
    fn the_remote_deadline_is_20_s_per_attempt_and_40_s_at_most() {
        assert_eq!(REMOTE_TIMEOUT, Duration::from_secs(20));
        let tls = Arc::new(TlsClient::platform().expect("platform TLS"));
        let remote = BouncerClient::remote("https://brain.example.invalid", static_bearer(), tls)
            .expect("https");
        assert_eq!(remote.timeout(), Duration::from_secs(20));
        assert_eq!(remote.max_wait(), Duration::from_secs(40));
        // This Mac keeps 10 s per attempt.
        let local = BouncerClient::new(DEFAULT_URL).expect("loopback");
        assert_eq!(local.timeout(), Duration::from_secs(10));
        assert_eq!(local.max_wait(), Duration::from_secs(20));

        // The same rule with a short attempt: a server that answers after two
        // attempts gives up after two attempts, and the bearer of each attempt has
        // the deadline of that attempt.
        let attempt = Duration::from_millis(400);
        let brain = fake_brain(Duration::from_millis(1500));
        brain.set_answer(200, &brain_answer(ACTIVE_HEADS, ACTIVE_MODEL, None));
        let recording = Arc::new(RecordingBearer::default());
        let client = BouncerClient::remote(&brain.url, recording.clone(), Arc::clone(&brain.tls))
            .expect("https")
            .with_timeout(attempt);
        let began = Instant::now();
        let verdict = client.evaluate(&remote_request());
        let elapsed = began.elapsed();
        assert!(
            reason(&verdict)
                .contains("timed out after two inference attempts (up to 800 ms total)"),
            "{verdict:?}"
        );
        assert!(elapsed >= attempt, "the first attempt waited: {elapsed:?}");
        assert!(
            elapsed < attempt * 2 + Duration::from_secs(1),
            "two attempts at most: {elapsed:?}"
        );
        let calls = recording.calls.lock().expect("calls").clone();
        assert_eq!(calls.len(), 2, "one retry after a transport timeout");
        for (asked, deadline) in calls {
            let budget = deadline.duration_since(asked);
            assert!(budget <= attempt, "{budget:?}");
            assert!(budget + Duration::from_millis(100) >= attempt, "{budget:?}");
        }
        assert!(!recording.invalidated.load(Ordering::SeqCst));
    }
}
