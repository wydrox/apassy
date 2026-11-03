//! The end-to-end test of remote agents on this Mac (plan "Bouncer section", unit U4;
//! docs/design/implementation-plan-bouncer-section.md, "End-to-end acceptance with Grok
//! Bot", the steps that can run on the loopback).
//!
//! The parts are the real ones of the app: the node service (`apassy::node::Node`) with
//! its host thread and the broker, and the embedded relay of this workspace
//! (`apassy_relay::embedded::EmbeddedRelay`) with its public listener. Only these are
//! test doubles:
//!
//! - Tailscale: a command line in memory that answers `status`, `serve status`, and the
//!   two `funnel` commands. "Funnel" is this test: it sends the agent's requests for the
//!   Funnel origin to the loopback public listener.
//! - The Keychain: a key store in memory.
//! - Touch ID: the owner check with the vault passphrase (`OwnerCheck::Passphrase`), the
//!   same proof that Touch ID gives.
//! - The remote agent: an OAuth 2.1 client written here (RFC 9728 and RFC 8414
//!   discovery, RFC 7591 registration, PKCE S256, the code, refresh), and an MCP client.
//! - The upstream host: an HTTPS server on 127.0.0.1 with its own test root, named
//!   `httpbingo.org`, that echoes the `Authorization` header it gets, raw, JSON-escaped,
//!   and HTML-escaped (the relay must scrub all three from the answer).
//!
//! Free loopback ports and temporary directories only: no fixed port, no Keychain, no
//! Tailscale, no network beyond the loopback. Synthetic values only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use apassy::broker::approvals::{
    AnswerKind, ApprovalQueue, OwnerAction, OwnerCheck, OwnerGate, PendingRun as Question,
};
use apassy::broker::decide::BrokerContext;
use apassy::broker::http::TlsClient;
use apassy::broker::prompts::PromptStore;
use apassy::broker::route_diagnostics::ReasonKind;
use apassy::broker::{CLOUD_REQUEST_SOURCE, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::node::backend::{
    AgentAccess, AuditRow, CatalogItem, ConnectDecision, CreatedAgent, NewCloudAgent, NodeAgentId,
    NodeBackend, NodeConfig, NodeError, NodeRunId, NodeSecret, NodeTeamId, PendingConnect,
    PendingRun, RunState, RunningNode, SyncReport,
};
use apassy::node::funnel::{CliOutput, TailscaleCli, public_origin};
use apassy::node::master_key::{KeyStore, KeyStoreError};
use apassy::node::{
    ACTIVITY_CONNECT_DENIED, ACTIVITY_CONNECTED, ACTIVITY_DISCONNECTED, ACTIVITY_ROUTE_ON, Node,
    NodeOptions,
};
use apassy::vault::exceptions::ExceptionKind;
use apassy::vault::{
    ActivityDecision, ConnectedWith, EnvDelivery, Field, ItemDraft, SecretValue, Vault,
};
use apassy_relay::config::UpstreamOptions;
use apassy_relay::embedded::EmbeddedRelay;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PASS: &str = "synthetic-e2e-passphrase";
/// The tailnet name of this Mac. Nothing resolves it: the test is Funnel.
const DNS: &str = "mac.e2e-tailnet.ts.net";
/// The upstream host of the item (plan step 2), resolved to the loopback mock.
const HOST: &str = "httpbingo.org";
const ENV: &str = "HTTPBIN_TOKEN";
/// The synthetic value of the item. `/`, `+`, and `&` have JSON and HTML escapes.
const VALUE: &str = "SYNTHe2eValue/0123456789+abcdefABCDEF&ghijKLMN";
/// A part of [`VALUE`] that a random placeholder never has.
const VALUE_CORE: &str = "Value/0123456789+abcdef";
/// Another item of the vault that the agent never gets.
const DECOY_HOST: &str = "api.stripe.com";
const DECOY_ENV: &str = "STRIPE_KEY";
const DECOY_VALUE: &str = "SYNTHe2eDecoy0123456789abcdefABCDEFghij";
/// The hosted relay: a remote agent of this Mac never hears of it (plan step 10).
const HOSTED_RELAY: &str = "wyderka.cc";
/// RFC 7636 appendix B.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const USER_REQUEST: &str = "Check my httpbin token.";

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn until<T>(what: &str, mut found: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(Instant::now() < end, "timed out: {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

// ---- What the test can read: log lines and answers. ----

/// Every tracing event and span of this process, as text (nextest runs each test in its
/// own process).
static LOG_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Every HTTP answer that the remote agent got: status, headers, body.
static ANSWERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Line<'a>(&'a mut String);

impl tracing::field::Visit for Line<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

/// A tracing subscriber that keeps every line in [`LOG_LINES`].
struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut line = span.metadata().name().to_owned();
        span.record(&mut Line(&mut line));
        lock(&LOG_LINES).push(line);
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut line = String::new();
        values.record(&mut Line(&mut line));
        lock(&LOG_LINES).push(line);
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = event.metadata().target().to_owned();
        event.record(&mut Line(&mut line));
        lock(&LOG_LINES).push(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// The forms of [`VALUE`] that an upstream echo can have: raw, JSON-escaped, and
/// HTML-escaped, and a part of it.
fn value_forms() -> Vec<String> {
    vec![
        VALUE.to_owned(),
        json_escaped(VALUE),
        html_escaped(VALUE),
        VALUE_CORE.to_owned(),
        DECOY_VALUE.to_owned(),
    ]
}

/// `text` with `/` as `\/`, `+` as `+`, and `&` as `&`.
fn json_escaped(text: &str) -> String {
    text.replace('/', "\\/")
        .replace('+', "\\u002B")
        .replace('&', "\\u0026")
}

/// `text` with `&` as `&amp;`, `/` as `&#x2F;`, and `+` as `&#43;`.
fn html_escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('/', "&#x2F;")
        .replace('+', "&#43;")
}

/// Fails when `text` has one of `secrets`. The message names the place, not the text.
fn assert_clean(place: &str, text: &str, secrets: &[String]) {
    for (index, secret) in secrets.iter().enumerate() {
        assert!(
            !secret.is_empty() && !text.contains(secret.as_str()),
            "{place} holds secret #{index}"
        );
    }
}

// ---- The OAuth and MCP client of the remote agent. ----

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding.
fn b64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let index = (n >> (18 - 6 * i)) & 63;
            out.push(char::from(B64URL[index as usize]));
        }
    }
    out
}

/// The S256 challenge of a PKCE verifier (RFC 7636 section 4.2).
fn challenge(verifier: &str) -> String {
    b64url(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

fn random_b64url(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new().fill(&mut buf).expect("randomness");
    b64url(&buf)
}

/// `application/x-www-form-urlencoded` encoding of one part.
fn pct(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", pct(name), pct(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The value of `name` in the query of `url`, decoded.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| decode(value))
    })
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8(out).expect("utf-8")
}

/// The text between `key="` and the next `"` in a header.
fn quoted(header: &str, key: &str) -> Option<String> {
    let start = header.find(&format!("{key}=\""))? + key.len() + 2;
    let end = header[start..].find('"')? + start;
    Some(header[start..end].to_owned())
}

/// An HTTP answer: status, headers (lowercase names), and body text.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::String(self.text.clone()))
    }
}

/// One request; `Err` when the listener does not answer (a stopped node). Every answer
/// is kept in [`ANSWERS`].
fn send(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, Vec<u8>)>,
) -> Result<Answer, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let bytes = match body {
        Some((kind, bytes)) => {
            builder = builder.header("Content-Type", kind);
            bytes
        }
        None => Vec::new(),
    };
    let mut response = agent
        .run(builder.body(bytes).expect("request"))
        .map_err(|error| error.to_string())?;
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let answer = Answer {
        status: response.status().as_u16(),
        headers,
        text: response.body_mut().read_to_string().unwrap_or_default(),
    };
    lock(&ANSWERS).push(format!(
        "{} {:?} {}",
        answer.status, answer.headers, answer.text
    ));
    Ok(answer)
}

fn call(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, Vec<u8>)>,
) -> Answer {
    send(method, url, headers, body).expect("an answer")
}

/// The tokens of one connection of the flow.
#[derive(Clone)]
struct Tokens {
    access: String,
    refresh: String,
}

/// What the remote agent learned from the metadata documents.
struct Discovered {
    /// The `/mcp` URL (the `resource`).
    mcp: String,
    authorize: String,
    token: String,
    register: String,
}

// ---- Tailscale, the Keychain, and the node spy. ----

fn status_json() -> String {
    format!(
        r#"{{"BackendState":"Running","Self":{{"DNSName":"{DNS}.","TailscaleIPs":["100.101.102.103"]}}}}"#
    )
}

fn serve_443_only() -> String {
    format!(
        r#"{{"TCP":{{"443":{{"HTTPS":true}}}},"Web":{{"{DNS}:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:3773"}}}}}}}}}}"#
    )
}

fn serve_with_8443(target: &str) -> String {
    format!(
        r#"{{"TCP":{{"443":{{"HTTPS":true}},"8443":{{"HTTPS":true}}}},"Web":{{"{DNS}:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:3773"}}}}}},"{DNS}:8443":{{"Handlers":{{"/":{{"Proxy":"{target}"}}}}}}}},"AllowFunnel":{{"{DNS}:8443":true}}}}"#
    )
}

/// The Tailscale command line in memory: connected, and the funnel commands change the
/// serve state.
struct FakeTailscale {
    serve: Mutex<String>,
    calls: Mutex<Vec<String>>,
}

impl FakeTailscale {
    fn calls(&self) -> Vec<String> {
        lock(&self.calls).clone()
    }
}

impl TailscaleCli for FakeTailscale {
    fn run(&self, args: &[&str]) -> Option<CliOutput> {
        lock(&self.calls).push(args.join(" "));
        let ok = |stdout: String| CliOutput {
            success: true,
            stdout,
            stderr: String::new(),
        };
        Some(match args {
            ["status", "--json"] => ok(status_json()),
            ["serve", "status", "--json"] => ok(lock(&self.serve).clone()),
            ["funnel", "--bg", "--https=8443", target] => {
                *lock(&self.serve) = serve_with_8443(target);
                ok(String::new())
            }
            ["funnel", "--https=8443", "off"] => {
                *lock(&self.serve) = serve_443_only();
                ok(String::new())
            }
            _ => CliOutput {
                success: false,
                stdout: String::new(),
                stderr: "an unexpected command".to_owned(),
            },
        })
    }
}

/// The Keychain in memory.
#[derive(Default)]
struct MemoryKeys(Mutex<Option<Vec<u8>>>);

impl KeyStore for MemoryKeys {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        Ok(lock(&self.0).clone().map(Zeroizing::new))
    }

    fn store(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        *lock(&self.0) = Some(key.to_vec());
        Ok(())
    }
}

/// The running embedded node, shared between the node service and the test, so the
/// test can read the whole audit of the team.
type Slot = Arc<RwLock<Option<Box<dyn RunningNode>>>>;

/// The embedded relay of the app, with a slot that the test can read.
#[derive(Clone)]
struct SpyBackend {
    relay: EmbeddedRelay,
    slot: Slot,
}

impl NodeBackend for SpyBackend {
    fn start(&self, config: NodeConfig) -> Result<Box<dyn RunningNode>, NodeError> {
        let node = self.relay.start(config)?;
        let node_addr = node.node_addr();
        let public_addr = node.public_addr();
        *self.slot.write().unwrap_or_else(PoisonError::into_inner) = Some(node);
        Ok(Box::new(SpyNode {
            slot: Arc::clone(&self.slot),
            node_addr,
            public_addr,
        }))
    }
}

/// The node that the node service gets: every call goes to the embedded node.
struct SpyNode {
    slot: Slot,
    node_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
}

impl SpyNode {
    fn with<T>(
        &self,
        f: impl FnOnce(&dyn RunningNode) -> Result<T, NodeError>,
    ) -> Result<T, NodeError> {
        let guard = self.slot.read().unwrap_or_else(PoisonError::into_inner);
        match guard.as_deref() {
            Some(node) => f(node),
            None => Err(NodeError::new("node_stopped", "The node stopped.")),
        }
    }
}

impl RunningNode for SpyNode {
    fn node_addr(&self) -> SocketAddr {
        self.node_addr
    }

    fn public_addr(&self) -> Option<SocketAddr> {
        self.public_addr
    }

    fn create_team(&self, name: &str) -> Result<NodeTeamId, NodeError> {
        self.with(|node| node.create_team(name))
    }

    fn has_team(&self, team: &NodeTeamId) -> bool {
        self.with(|node| Ok(node.has_team(team))).unwrap_or(false)
    }

    fn check_value(&self, value: &NodeSecret) -> Result<(), NodeError> {
        self.with(|node| node.check_value(value))
    }

    fn sync_items(
        &self,
        team: &NodeTeamId,
        items: &[CatalogItem],
    ) -> Result<SyncReport, NodeError> {
        self.with(|node| node.sync_items(team, items))
    }

    fn create_agent(
        &self,
        team: &NodeTeamId,
        agent: &NewCloudAgent,
    ) -> Result<CreatedAgent, NodeError> {
        self.with(|node| node.create_agent(team, agent))
    }

    fn set_agent_items(
        &self,
        team: &NodeTeamId,
        agent: NodeAgentId,
        items: &[String],
    ) -> Result<(), NodeError> {
        self.with(|node| node.set_agent_items(team, agent, items))
    }

    fn revoke_agent(&self, team: &NodeTeamId, agent: NodeAgentId) -> Result<(), NodeError> {
        self.with(|node| node.revoke_agent(team, agent))
    }

    fn pending_connects(&self) -> Result<Vec<PendingConnect>, NodeError> {
        self.with(|node| node.pending_connects())
    }

    fn decide_connect(&self, id: &str, decision: ConnectDecision) -> Result<(), NodeError> {
        self.with(|node| node.decide_connect(id, decision))
    }

    fn agent_access(
        &self,
        team: &NodeTeamId,
        agent: NodeAgentId,
    ) -> Result<AgentAccess, NodeError> {
        self.with(|node| node.agent_access(team, agent))
    }

    fn wait_pending(
        &self,
        team: &NodeTeamId,
        timeout: Duration,
    ) -> Result<Vec<PendingRun>, NodeError> {
        self.with(|node| node.wait_pending(team, timeout))
    }

    fn release(
        &self,
        team: &NodeTeamId,
        run: NodeRunId,
        values: Vec<NodeSecret>,
        reason: Option<&str>,
    ) -> Result<RunState, NodeError> {
        self.with(|node| node.release(team, run, values, reason))
    }

    fn deny(&self, team: &NodeTeamId, run: NodeRunId, reason: &str) -> Result<RunState, NodeError> {
        self.with(|node| node.deny(team, run, reason))
    }

    fn run_state(&self, team: &NodeTeamId, run: NodeRunId) -> Result<RunState, NodeError> {
        self.with(|node| node.run_state(team, run))
    }

    fn recent_audit(
        &self,
        team: &NodeTeamId,
        run: Option<NodeRunId>,
        limit: u32,
    ) -> Result<Vec<AuditRow>, NodeError> {
        self.with(|node| node.recent_audit(team, run, limit))
    }

    fn stop(self: Box<Self>) {
        let taken = self
            .slot
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(node) = taken {
            node.stop();
        }
    }
}

// ---- The upstream host. ----

/// One request that the upstream got.
#[derive(Debug, Clone)]
struct Seen {
    target: String,
    authorization: Option<String>,
}

/// An HTTPS server on 127.0.0.1 for [`HOST`] and [`DECOY_HOST`], with its own root.
struct Upstream {
    addr: SocketAddr,
    root_der: Vec<u8>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn this_year() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    1970 + i32::try_from(secs / 31_556_952).unwrap_or(56)
}

fn validity(params: &mut CertificateParams) {
    let year = this_year();
    params.not_before = rcgen::date_time_ymd(year - 1, 12, 1);
    params.not_after = rcgen::date_time_ymd(year + 1, 1, 5);
}

impl Upstream {
    fn start() -> Self {
        let mut root = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Apassy cloud e2e test root");
        root.distinguished_name = name;
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        validity(&mut root);
        let root_key = KeyPair::generate().expect("root key");
        let root_cert = root.self_signed(&root_key).expect("root");
        let issuer = Issuer::new(root, root_key);
        let mut leaf =
            CertificateParams::new(vec![HOST.to_owned(), DECOY_HOST.to_owned()]).expect("leaf");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.use_authority_key_identifier_extension = true;
        validity(&mut leaf);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf_cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
                )
                .expect("server config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let thread_seen = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let config = Arc::clone(&config);
                let seen = Arc::clone(&thread_seen);
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                    let Ok(tls) = ServerConnection::new(config) else {
                        return;
                    };
                    let _ = serve(StreamOwned::new(tls, stream), &seen);
                });
            }
        });
        Self {
            addr,
            root_der: root_cert.der().to_vec(),
            seen,
        }
    }

    /// The relay trusts the test root and resolves both hosts to this server.
    fn options(&self) -> UpstreamOptions {
        UpstreamOptions {
            extra_roots_der: vec![self.root_der.clone()],
            resolve: vec![
                (HOST.to_owned(), 443, self.addr),
                (DECOY_HOST.to_owned(), 443, self.addr),
            ],
            blocked: Vec::new(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(20),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

/// Read one request and echo its `Authorization` in a header and in the body: raw,
/// JSON-escaped, and HTML-escaped.
fn serve(stream: Tls, seen: &Mutex<Vec<Seen>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let target = line.split(' ').nth(1).unwrap_or_default().to_owned();
    let mut authorization = None;
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Ok(());
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    lock(seen).push(Seen {
        target,
        authorization: authorization.clone(),
    });
    let auth = authorization.unwrap_or_default();
    let body = format!(
        r#"{{"authorization":"{auth}","json":"{}","html":"{}"}}"#,
        json_escaped(&auth),
        html_escaped(&auth)
    );
    let stream = reader.get_mut();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Echo-Authorization: {auth}\r\nX-Echo-Html: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        html_escaped(&auth),
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    stream.conn.send_close_notify();
    stream.flush()
}

// ---- The Mac with its vault and node. ----

fn api_key(title: &str, value: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret: true,
        }],
    }
}

struct Mac {
    vault: SharedVault,
    httpbin: u64,
    broker: BrokerContext,
    tailscale: Arc<FakeTailscale>,
    slot: Slot,
    upstream: Upstream,
    node: Node,
    /// The Funnel origin, `https://<DNS>:8443`.
    public: String,
    /// The loopback redirect of the remote agent's client (RFC 8252). It is never
    /// called: the test reads the `Location`.
    _callback: TcpListener,
    callback: String,
    /// Every token and code the agent got, for the leak checks.
    secrets: Mutex<Vec<String>>,
    /// The connect requests that the test already answered.
    answered: Mutex<Vec<String>>,
    dir: tempfile::TempDir,
}

impl Mac {
    fn start() -> Self {
        let _ = tracing::subscriber::set_global_default(Capture);
        let dir = tempfile::tempdir().expect("temp dir");
        // The decision log file of the bouncer, in the temporary directory.
        apassy::decision_log::enable(dir.path().join("bouncer-decisions.log"));
        let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("vault");
        vault.unlock(PASS).expect("unlock");
        // Plan step 2: a synthetic item for httpbingo.org, delivered as a placeholder.
        let httpbin = vault.add(api_key("httpbin", VALUE)).expect("item").id;
        vault
            .set_env_binding_with(
                httpbin,
                ENV,
                "token",
                &EnvDelivery::Placeholder(vec![HOST.to_owned()]),
            )
            .expect("binding");
        let decoy = vault
            .add(api_key("Stripe test", DECOY_VALUE))
            .expect("item")
            .id;
        vault
            .set_env_binding_with(
                decoy,
                DECOY_ENV,
                "token",
                &EnvDelivery::Placeholder(vec![DECOY_HOST.to_owned()]),
            )
            .expect("binding");
        let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
        let upstream = Upstream::start();
        let slot: Slot = Arc::new(RwLock::new(None));
        let backend = SpyBackend {
            relay: EmbeddedRelay {
                upstream: upstream.options(),
            },
            slot: Arc::clone(&slot),
        };
        let tailscale = Arc::new(FakeTailscale {
            serve: Mutex::new(serve_443_only()),
            calls: Mutex::new(Vec::new()),
        });
        let node = Node::new(NodeOptions {
            backend: Arc::new(backend),
            keys: Arc::new(MemoryKeys::default()),
            cli: tailscale.clone(),
            data_dir: dir.path().join("node"),
        });
        let broker = BrokerContext {
            vault: Arc::clone(&vault),
            tls: TlsClient::platform().expect("tls"),
            approvals: Arc::new(ApprovalQueue::new()),
            approval_timeout: Duration::from_secs(60),
            run_timeout: Duration::from_secs(60),
            bouncer: None,
            model_gate: None,
            prompts: Arc::new(PromptStore::new(Vec::new())),
        };
        let callback = TcpListener::bind("127.0.0.1:0").expect("bind the callback");
        let callback_url = format!(
            "http://127.0.0.1:{}/callback",
            callback.local_addr().expect("addr").port()
        );
        Self {
            vault,
            httpbin,
            broker,
            tailscale,
            slot,
            upstream,
            node,
            public: public_origin(DNS),
            _callback: callback,
            callback: callback_url,
            secrets: Mutex::new(Vec::new()),
            answered: Mutex::new(Vec::new()),
            dir,
        }
    }

    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(lock(&self.vault).as_mut().expect("a vault"))
    }

    fn gate(&self) -> OwnerGate {
        OwnerGate::new(Arc::clone(&self.vault), None)
    }

    /// The owner check, as Touch ID would give it.
    fn owner_allows(&self, action: OwnerAction) {
        self.gate()
            .authorize(action, OwnerCheck::passphrase(PASS))
            .expect("the owner check");
    }

    fn keep_secret(&self, secret: &str) {
        lock(&self.secrets).push(secret.to_owned());
    }

    fn team(&self) -> NodeTeamId {
        NodeTeamId(
            self.with_vault(|vault| vault.cloud_node_setting().expect("setting"))
                .team_id
                .expect("a team"),
        )
    }

    /// Every audit row of the team, newest first.
    fn audit(&self, run: Option<u64>) -> Vec<AuditRow> {
        let team = self.team();
        let guard = self.slot.read().unwrap_or_else(PoisonError::into_inner);
        guard
            .as_deref()
            .expect("the node runs")
            .recent_audit(&team, run.map(NodeRunId), 500)
            .expect("audit")
    }

    /// `http://` of the public listener: what Funnel forwards to.
    fn listener(&self) -> String {
        let port = self
            .with_vault(|vault| vault.cloud_node_setting().expect("setting"))
            .port
            .expect("a port");
        format!("http://127.0.0.1:{port}")
    }

    /// Funnel: a URL of the Funnel origin, sent to the loopback listener.
    fn funnel(&self, url: &str) -> String {
        let rest = url
            .strip_prefix(&self.public)
            .unwrap_or_else(|| panic!("{url} is not on the Funnel origin"));
        format!("{}{rest}", self.listener())
    }

    fn activity(&self) -> Vec<(String, ActivityDecision, String)> {
        self.with_vault(|vault| {
            vault
                .recent_activity(200)
                .expect("activity")
                .into_iter()
                .map(|row| (row.operation, row.decision, row.reason))
                .collect()
        })
    }

    /// The remote agent knows only the MCP address (plan step 3). An unauthenticated
    /// call gives the 401 that points at the metadata.
    fn discover(&self) -> Discovered {
        let mcp = format!("{}/mcp", self.public);
        let initialize = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "Grok Bot", "version": "e2e"}}});
        let answer = call(
            "POST",
            &self.funnel(&mcp),
            &[],
            Some(("application/json", serde_json::to_vec(&initialize).unwrap())),
        );
        assert_eq!(answer.status, 401, "{}", answer.text);
        let challenge = answer.header("www-authenticate").expect("a challenge");
        assert!(challenge.starts_with("Bearer "), "{challenge}");
        let metadata = quoted(challenge, "resource_metadata").expect("resource_metadata");
        assert_eq!(
            metadata,
            format!("{}/.well-known/oauth-protected-resource/mcp", self.public)
        );
        // RFC 9728.
        let resource = call("GET", &self.funnel(&metadata), &[], None);
        assert_eq!(resource.status, 200, "{}", resource.text);
        let resource = resource.json();
        assert_eq!(resource["resource"], json!(mcp));
        let issuer = resource["authorization_servers"][0]
            .as_str()
            .expect("an authorization server")
            .to_owned();
        assert_eq!(issuer, self.public);
        // RFC 8414.
        let server = call(
            "GET",
            &self.funnel(&format!("{issuer}/.well-known/oauth-authorization-server")),
            &[],
            None,
        );
        assert_eq!(server.status, 200, "{}", server.text);
        let server = server.json();
        assert_eq!(server["issuer"], json!(issuer));
        assert!(
            server["code_challenge_methods_supported"]
                .as_array()
                .expect("methods")
                .contains(&json!("S256")),
            "{server}"
        );
        let endpoint = |name: &str| server[name].as_str().expect(name).to_owned();
        Discovered {
            mcp,
            authorize: endpoint("authorization_endpoint"),
            token: endpoint("token_endpoint"),
            register: endpoint("registration_endpoint"),
        }
    }

    /// RFC 7591: a public client with the loopback redirect. Returns the client id.
    fn register(&self, found: &Discovered, name: &str) -> String {
        let body = json!({
            "client_name": name,
            "redirect_uris": [self.callback],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        });
        let answer = call(
            "POST",
            &self.funnel(&found.register),
            &[],
            Some(("application/json", serde_json::to_vec(&body).unwrap())),
        );
        assert_eq!(answer.status, 201, "{}", answer.text);
        let reply = answer.json();
        assert!(reply.get("client_secret").is_none(), "{reply}");
        assert_eq!(reply["token_endpoint_auth_method"], "none");
        reply["client_id"].as_str().expect("client id").to_owned()
    }

    /// "Authorize": the browser opens the authorize URL and lands on the wait page.
    /// Returns the page URL, the PKCE verifier, and the state.
    fn authorize(&self, found: &Discovered, client_id: &str) -> (String, String, String) {
        let verifier = random_b64url(32);
        let state = random_b64url(12);
        let query = form(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", self.callback.as_str()),
            ("code_challenge", challenge(&verifier).as_str()),
            ("code_challenge_method", "S256"),
            ("state", state.as_str()),
            ("scope", "apassy"),
            ("resource", found.mcp.as_str()),
        ]);
        let answer = call(
            "GET",
            &format!("{}?{query}", self.funnel(&found.authorize)),
            &[],
            None,
        );
        assert_eq!(answer.status, 303, "{}", answer.text);
        let location = answer.header("location").expect("location");
        assert!(location.starts_with("/oauth/wait/"), "{location}");
        (format!("{}{location}", self.listener()), verifier, state)
    }

    /// The connect request of `client_id` as Decisions shows it, once the host read it,
    /// and the browser page with the same match code (frame 7).
    fn waiting_connect(&self, client_id: &str, page: &str) -> PendingConnect {
        // The host may still list a request of the same client that was just answered.
        let connect = until("Decisions shows the connect request", || {
            let answered = lock(&self.answered).clone();
            self.node
                .pending_connects()
                .into_iter()
                .find(|connect| connect.client_id == client_id && !answered.contains(&connect.id))
        });
        lock(&self.answered).push(connect.id.clone());
        let answer = call("GET", page, &[], None);
        assert_eq!(answer.status, 200, "{}", answer.text);
        assert_eq!(answer.header("refresh"), Some("3"));
        assert_eq!(
            answer.header("content-security-policy"),
            Some("default-src 'none'; style-src 'unsafe-inline'")
        );
        assert_eq!(answer.header("x-frame-options"), Some("DENY"));
        assert_eq!(answer.header("cache-control"), Some("no-store"));
        assert!(answer.header("set-cookie").is_none());
        assert!(
            answer.text.contains(&connect.code),
            "the page shows the code of Decisions"
        );
        let lower = answer.text.to_ascii_lowercase();
        for active in ["<script", "<form", "<button", "<input"] {
            assert!(!lower.contains(active), "{active} on the page");
        }
        connect
    }

    /// Allow on the Mac with the owner check "Connect <name> to this Mac".
    fn allow(&self, connect: &PendingConnect) -> apassy::node::ConnectedAgent {
        self.owner_allows(OwnerAction::AllowConnect {
            id: connect.id.clone(),
            client_name: apassy::node::connect_name(connect),
            code: connect.code.clone(),
            redirect_host: connect.redirect_host.clone(),
        });
        self.node
            .allow_connect(&self.vault, &connect.id)
            .expect("allow the connect")
    }

    /// The page after the answer sends the browser to the client with the code; the
    /// client trades it with its verifier.
    fn trade_code(
        &self,
        found: &Discovered,
        client_id: &str,
        page: &str,
        verifier: &str,
        state: &str,
    ) -> Tokens {
        let answer = call("GET", page, &[], None);
        assert_eq!(answer.status, 303, "{}", answer.text);
        let location = answer.header("location").expect("location").to_owned();
        assert!(
            location.starts_with(&format!("{}?", self.callback)),
            "{location}"
        );
        assert_eq!(query_param(&location, "state").as_deref(), Some(state));
        assert_eq!(
            query_param(&location, "iss").as_deref(),
            Some(self.public.as_str())
        );
        let code = query_param(&location, "code").expect("a code");
        self.keep_secret(&code);
        let again = call("GET", page, &[], None);
        assert_eq!(again.status, 200);
        assert!(again.text.contains("Connected"), "{}", again.text);
        let answer = call(
            "POST",
            &self.funnel(&found.token),
            &[],
            Some((
                "application/x-www-form-urlencoded",
                form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", self.callback.as_str()),
                    ("client_id", client_id),
                    ("code_verifier", verifier),
                    ("resource", found.mcp.as_str()),
                ])
                .into_bytes(),
            )),
        );
        self.tokens_of(&answer)
    }

    fn tokens_of(&self, answer: &Answer) -> Tokens {
        assert_eq!(answer.status, 200, "{}", answer.text);
        assert_eq!(answer.header("cache-control"), Some("no-store"));
        let reply = answer.json();
        assert_eq!(reply["token_type"], "Bearer");
        assert!(reply["expires_in"].as_u64().is_some_and(|secs| secs > 0));
        let tokens = Tokens {
            access: reply["access_token"].as_str().expect("access").to_owned(),
            refresh: reply["refresh_token"].as_str().expect("refresh").to_owned(),
        };
        self.keep_secret(&tokens.access);
        self.keep_secret(&tokens.refresh);
        tokens
    }

    fn refresh(&self, found: &Discovered, client_id: &str, refresh: &str) -> Answer {
        call(
            "POST",
            &self.funnel(&found.token),
            &[],
            Some((
                "application/x-www-form-urlencoded",
                form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh),
                    ("client_id", client_id),
                ])
                .into_bytes(),
            )),
        )
    }

    /// One JSON-RPC message on `POST /mcp` with the bearer token.
    fn mcp(&self, found: &Discovered, token: &str, message: &Value) -> Answer {
        let bearer = format!("Bearer {token}");
        call(
            "POST",
            &self.funnel(&found.mcp),
            &[("Authorization", bearer.as_str())],
            Some(("application/json", serde_json::to_vec(message).unwrap())),
        )
    }

    /// A tool call that must succeed. Returns its structured result.
    fn tool(&self, found: &Discovered, token: &str, name: &str, arguments: Value) -> Value {
        let message = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}});
        let answer = self.mcp(found, token, &message);
        assert_eq!(answer.status, 200, "{name}: {}", answer.text);
        let reply = answer.json();
        assert_eq!(reply["result"]["isError"], false, "{name}: {reply}");
        reply["result"]["structuredContent"].clone()
    }

    /// `apassy_list_access`: (env name, item id) of each item.
    fn access(&self, found: &Discovered, token: &str) -> Vec<(String, u64)> {
        let access = self.tool(found, token, "apassy_list_access", json!({}));
        assert!(
            !access.to_string().contains(DECOY_ENV),
            "the agent sees an item it was not given"
        );
        access["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| {
                (
                    item["env_name"].as_str().expect("env").to_owned(),
                    item["item_id"].as_u64().expect("id"),
                )
            })
            .collect()
    }

    /// `apassy_request_run` for the item (plan step 4). Returns the run id.
    fn request_run(&self, found: &Discovered, token: &str, item: u64) -> u64 {
        let view = self.tool(
            found,
            token,
            "apassy_request_run",
            json!({
                "items": [item],
                "command": ["curl", "-H", format!("Authorization: Bearer ${ENV}"),
                    format!("https://{HOST}/bearer")],
                "purpose": "Check the token with httpbin.",
                "user_request": USER_REQUEST,
            }),
        );
        assert_eq!(view["status"], "pending", "{view}");
        view["run_id"].as_u64().expect("run id")
    }

    /// The question of the run on this Mac: a cloud run, Allow Once only, "Not verified".
    fn question(&self) -> Question {
        let question = until("the run asks the owner", || {
            self.broker.approvals.pending().into_iter().next()
        });
        assert_eq!(question.question.reason, ReasonKind::CloudAgent);
        assert_eq!(question.question.valid_answers, [AnswerKind::Once]);
        assert_eq!(question.request_source, CLOUD_REQUEST_SOURCE);
        assert_eq!(question.user_request, USER_REQUEST);
        assert_eq!(question.env_names, [ENV]);
        assert_eq!(question.remember, None);
        assert_clean("the question", &format!("{question:?}"), &value_forms());
        question
    }

    /// Allow Once, with the owner check.
    fn allow_once(&self, question: Question) {
        let proof = self
            .gate()
            .authorize(
                OwnerAction::ApproveRun(question),
                OwnerCheck::passphrase(PASS),
            )
            .expect("the owner check");
        self.broker.approvals.approve(proof).expect("approve");
    }

    /// `apassy_run_status` until the run is no longer pending.
    fn settled(&self, found: &Discovered, token: &str, run: u64) -> Value {
        for _ in 0..6 {
            let view = self.tool(
                found,
                token,
                "apassy_run_status",
                json!({"run_id": run, "wait_secs": 10}),
            );
            if view["status"] != "pending" {
                return view;
            }
        }
        panic!("run {run} stayed pending");
    }

    /// A released run: its base URL for the host and the placeholder of the value.
    fn session(&self, view: &Value) -> (String, String) {
        assert_eq!(view["status"], "ready", "{view}");
        let session = &view["session"];
        let base = session["base_urls"][HOST]
            .as_str()
            .expect("a base URL")
            .to_owned();
        assert!(
            base.starts_with(&format!("{}/p/", self.public)),
            "the base URL is on the Funnel origin: {base}"
        );
        let placeholder = session["env"][ENV]
            .as_str()
            .expect("a placeholder")
            .to_owned();
        assert_ne!(placeholder, VALUE);
        assert_eq!(placeholder.len(), VALUE.len());
        (base, placeholder)
    }

    /// The agent's HTTP request through `/p/` with the placeholder in its header.
    fn through_proxy(&self, base: &str, placeholder: &str) -> Result<Answer, String> {
        let bearer = format!("Bearer {placeholder}");
        send(
            "GET",
            &format!("{}/bearer", self.funnel(base)),
            &[("Authorization", bearer.as_str())],
            None,
        )
    }

    /// Every file under the temporary directory, as bytes.
    fn files(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::files(&path, out);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.push((path.display().to_string(), bytes));
            }
        }
    }
}

#[test]
fn the_test_client_makes_rfc_7636_challenges() {
    assert_eq!(challenge(RFC_VERIFIER), RFC_CHALLENGE);
    assert_eq!(b64url(b"f"), "Zg");
    assert_eq!(b64url(b"fo"), "Zm8");
    assert_eq!(b64url(b"foo"), "Zm9v");
    assert_eq!(random_b64url(32).len(), 43);
    assert_eq!(decode("a%2Fb+c"), "a/b c");
    assert_eq!(
        query_param("http://x/cb?code=A%2DB&state=s", "code").as_deref(),
        Some("A-B")
    );
}

/// Plan "End-to-end acceptance with Grok Bot", steps 2 to 10 as far as they run on the
/// loopback; the physical steps are in the report of unit U4.
#[test]
fn a_remote_agent_connects_by_itself_runs_through_the_proxy_and_is_disconnected() {
    let mac = Mac::start();

    // Step 2: Remote access on (owner check), the node starts, Funnel routes 8443.
    mac.owner_allows(OwnerAction::TurnOnRemoteAccess);
    mac.node.set_route(&mac.vault, true).expect("route on");
    mac.node
        .start(&mac.vault, mac.broker.clone())
        .expect("the node starts");
    assert!(mac.node.is_running());
    let port = mac
        .with_vault(|vault| vault.cloud_node_setting().expect("setting"))
        .port
        .expect("a port");
    assert!(
        mac.tailscale
            .calls()
            .contains(&format!("funnel --bg --https=8443 http://127.0.0.1:{port}")),
        "{:?}",
        mac.tailscale.calls()
    );
    let status = mac.node.status(&mac.vault);
    assert!(status.running && status.route_on);
    assert_eq!(status.url, Some(format!("{}/mcp", mac.public)));

    // Step 3: the agent gets only the MCP address; discovery, registration, PKCE.
    let found = mac.discover();
    let client = mac.register(&found, "Grok Bot");
    let (page, verifier, state) = mac.authorize(&found, &client);
    let connect = mac.waiting_connect(&client, &page);
    assert_eq!(connect.client_name.as_deref(), Some("Grok Bot"));
    let connected = mac.allow(&connect);
    assert_eq!(connected.name, "Grok Bot");
    let agent = connected.agent_id;
    let mut tokens = mac.trade_code(&found, &client, &page, &verifier, &state);
    // The MCP session: initialize, the notification, and the three tools.
    let init = mac.mcp(
        &found,
        &tokens.access,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "Grok Bot", "version": "e2e"}}}),
    );
    assert_eq!(init.status, 200, "{}", init.text);
    assert!(init.json()["result"]["protocolVersion"].is_string());
    let note = mac.mcp(
        &found,
        &tokens.access,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    assert!(note.status == 202 || note.status == 200, "{}", note.status);
    let list = mac.mcp(
        &found,
        &tokens.access,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(list.status, 200, "{}", list.text);
    let names: Vec<String> = list.json()["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("name").to_owned())
        .collect();
    assert_eq!(
        names,
        [
            "apassy_list_access",
            "apassy_request_run",
            "apassy_run_status"
        ]
    );
    // It sees nothing until the owner chooses.
    assert!(mac.access(&found, &tokens.access).is_empty());

    // Step 4: Agents shows "Grok Bot · Remote"; Choose Credentials… gives it the item.
    let views = mac.node.agents(&mac.vault).expect("agents");
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].agent_id, agent);
    assert_eq!(views[0].connected_with, ConnectedWith::OAuth);
    assert!(views[0].items.is_empty());
    assert_eq!(
        views[0]
            .access
            .as_ref()
            .and_then(|access| access.client_id.clone()),
        Some(client.clone())
    );
    mac.with_vault(|vault| {
        vault
            .add_agent_exception(agent, mac.httpbin, ExceptionKind::Only)
            .expect("Choose Credentials…");
    });
    mac.node.sync_catalog().expect("sync");
    let access = mac.access(&found, &tokens.access);
    assert_eq!(access.len(), 1, "one chosen item: {access:?}");
    assert_eq!(access[0].0, ENV);
    let item = access[0].1;

    // Step 5: the run asks, "Not verified"; Allow Once; the value goes upstream, the
    // agent gets the placeholder only.
    let run1 = mac.request_run(&found, &tokens.access, item);
    let question = mac.question();
    mac.allow_once(question);
    let view = mac.settled(&found, &tokens.access, run1);
    let (base1, placeholder) = mac.session(&view);
    let answer = mac
        .through_proxy(&base1, &placeholder)
        .expect("the proxy answers");
    assert_eq!(answer.status, 200, "{}", answer.text);
    let seen = mac.upstream.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].target, "/bearer");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {VALUE}").as_str()),
        "the upstream gets the real value"
    );
    assert_eq!(
        answer.header("x-echo-authorization"),
        Some(format!("Bearer {placeholder}").as_str())
    );
    assert!(
        answer
            .text
            .contains(&format!(r#""authorization":"Bearer {placeholder}""#)),
        "{}",
        answer.text
    );
    assert_clean("the proxied answer", &answer.text, &value_forms());
    assert_clean(
        "the proxied headers",
        &format!("{:?}", answer.headers),
        &value_forms(),
    );
    // Logs: the run with one proxied request; the agent page counts it.
    let rows = mac.audit(Some(run1));
    let proxied: Vec<Value> = rows
        .iter()
        .filter(|row| row.action == "proxy_request")
        .map(|row| serde_json::from_str(&row.detail).expect("detail"))
        .collect();
    assert_eq!(proxied.len(), 1, "{rows:?}");
    assert_eq!(proxied[0]["host"], HOST);
    assert_eq!(proxied[0]["status"], 200);
    assert_eq!(proxied[0]["outcome"], "forwarded");
    let row1 = until("the cloud_run row of the first run", || {
        mac.with_vault(|vault| vault.cloud_run(run1).expect("cloud_run"))
    });
    assert_eq!(row1.agent_id, agent);
    assert!(row1.decision_log_id.is_some(), "linked to the decision log");
    assert!(
        mac.node.agents(&mac.vault).expect("agents")[0]
            .last_used_at
            .is_some()
    );

    // Step 6: a second run is denied (on this Mac; the iPhone is physical).
    let run2 = mac.request_run(&found, &tokens.access, item);
    let question = mac.question();
    assert!(
        mac.broker
            .approvals
            .deny_with_comment(question.id, "not now")
    );
    let view = mac.settled(&found, &tokens.access, run2);
    assert_eq!(view["status"], "denied", "{view}");
    assert!(view.get("session").is_none_or(Value::is_null), "{view}");
    let row2 = until("the cloud_run row of the denied run", || {
        mac.with_vault(|vault| vault.cloud_run(run2).expect("cloud_run"))
    });
    assert_eq!(row2.ended_at, None);
    assert_eq!(mac.upstream.seen().len(), 1, "nothing went upstream");

    // Step 7: another client, denied: "You denied the connection." Nothing is made.
    let other = mac.register(&found, "Other Bot");
    let (other_page, _, _) = mac.authorize(&found, &other);
    let other_connect = mac.waiting_connect(&other, &other_page);
    mac.node
        .deny_connect(&other_connect.id)
        .expect("deny the connect");
    let denied_page = call("GET", &other_page, &[], None);
    assert_eq!(denied_page.status, 200);
    assert!(
        denied_page.text.contains("You denied the connection."),
        "{}",
        denied_page.text
    );
    assert_eq!(mac.node.agents(&mac.vault).expect("agents").len(), 1);

    // Step 8: the refresh token rotates; one live access token per agent.
    let rotated = mac.refresh(&found, &client, &tokens.refresh);
    let rotated = mac.tokens_of(&rotated);
    assert_ne!(rotated.access, tokens.access);
    assert_ne!(rotated.refresh, tokens.refresh);
    assert_eq!(
        mac.mcp(
            &found,
            &tokens.access,
            &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        )
        .status,
        401,
        "the old access token ends at the refresh"
    );
    assert_eq!(mac.access(&found, &rotated.access).len(), 1);
    // A reused refresh token revokes the family.
    let reused = mac.refresh(&found, &client, &tokens.refresh);
    assert_eq!(reused.status, 400, "{}", reused.text);
    assert_eq!(reused.json()["error"], "invalid_grant");
    let after = mac.mcp(
        &found,
        &rotated.access,
        &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}),
    );
    assert_eq!(after.status, 401, "the family is revoked");
    assert!(after.header("www-authenticate").is_some());
    assert_eq!(
        mac.refresh(&found, &client, &rotated.refresh).json()["error"],
        "invalid_grant"
    );
    // The same client authorizes again: a second agent with no credential, never the
    // first one (a client id is public, so a connect never takes over an agent). The
    // first stays until the owner disconnects it; the owner chooses the item again.
    let (page, verifier, state) = mac.authorize(&found, &client);
    let connect = mac.waiting_connect(&client, &page);
    let again = mac.allow(&connect);
    assert_ne!(again.agent_id, agent);
    assert_eq!(again.name, "Grok Bot 2");
    tokens = mac.trade_code(&found, &client, &page, &verifier, &state);
    assert!(
        mac.access(&found, &tokens.access).is_empty(),
        "a new agent sees nothing"
    );
    assert_eq!(
        mac.node.agents(&mac.vault).expect("agents").len(),
        2,
        "the first agent stays"
    );
    mac.node
        .revoke_agent(&mac.vault, agent)
        .expect("disconnect the first agent");
    let agent = again.agent_id;
    mac.with_vault(|vault| {
        vault
            .add_agent_exception(agent, mac.httpbin, ExceptionKind::Only)
            .expect("Choose Credentials…");
    });
    mac.node.sync_catalog().expect("sync");
    assert_eq!(mac.access(&found, &tokens.access), [(ENV.to_owned(), item)]);

    // Step 9: a lock stops the node and Funnel; `/mcp` and `/p/` do not answer. The
    // loopback addresses come first: their port is in the vault, which then is locked.
    let locked_mcp = mac.funnel(&found.mcp);
    let locked_proxy = format!("{}/bearer", mac.funnel(&base1));
    mac.with_vault(|vault| vault.lock().expect("lock"));
    mac.node.stop();
    assert!(!mac.node.is_running());
    assert!(
        mac.slot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none(),
        "the embedded node stopped"
    );
    assert_eq!(
        mac.tailscale.calls().last().map(String::as_str),
        Some("funnel --https=8443 off")
    );
    assert!(
        send(
            "POST",
            &locked_mcp,
            &[],
            Some(("application/json", b"{}".to_vec()))
        )
        .is_err(),
        "nothing listens while the vault is locked"
    );
    let bearer = format!("Bearer {placeholder}");
    assert!(
        send(
            "GET",
            &locked_proxy,
            &[("Authorization", bearer.as_str())],
            None
        )
        .is_err(),
        "the proxy does not answer while the vault is locked"
    );
    let refused = mac
        .node
        .start(&mac.vault, mac.broker.clone())
        .expect_err("a locked vault starts no node");
    assert_eq!(refused.code, "vault_locked");
    // Unlock restores it: the same port and the same connection.
    mac.with_vault(|vault| vault.unlock(PASS).expect("unlock"));
    mac.node
        .start(&mac.vault, mac.broker.clone())
        .expect("the node starts again");
    assert_eq!(
        mac.with_vault(|vault| vault.cloud_node_setting().expect("setting"))
            .port,
        Some(port)
    );
    assert_eq!(mac.access(&found, &tokens.access), [(ENV.to_owned(), item)]);
    let ended = mac
        .through_proxy(&base1, &placeholder)
        .expect("the proxy answers");
    assert_ne!(ended.status, 200, "the session ended with the lock");
    assert_eq!(mac.upstream.seen().len(), 1);
    // A new run works after the unlock.
    let run3 = mac.request_run(&found, &tokens.access, item);
    let question = mac.question();
    mac.allow_once(question);
    let view = mac.settled(&found, &tokens.access, run3);
    let (base3, placeholder3) = mac.session(&view);
    let answer = mac
        .through_proxy(&base3, &placeholder3)
        .expect("the proxy answers");
    assert_eq!(answer.status, 200, "{}", answer.text);
    assert_clean("the proxied answer", &answer.text, &value_forms());
    assert_eq!(mac.upstream.seen().len(), 2);

    // Disconnect…: the next call is 401 with `WWW-Authenticate`; the session ends.
    mac.node
        .revoke_agent(&mac.vault, agent)
        .expect("disconnect");
    let gone = mac.mcp(
        &found,
        &tokens.access,
        &json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
    );
    assert_eq!(gone.status, 401, "{}", gone.text);
    let challenge = gone.header("www-authenticate").expect("a challenge");
    assert!(
        challenge.starts_with(&format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\"",
            mac.public
        )),
        "{challenge}"
    );
    assert_eq!(
        mac.refresh(&found, &client, &tokens.refresh).json()["error"],
        "invalid_grant"
    );
    let after = mac
        .through_proxy(&base3, &placeholder3)
        .expect("the proxy answers");
    assert_ne!(after.status, 200, "the session ended at the disconnect");
    assert_eq!(mac.upstream.seen().len(), 2);
    assert!(mac.node.agents(&mac.vault).expect("agents").is_empty());
    let row3 = until("the end of the third session", || {
        mac.with_vault(|vault| vault.cloud_run(run3).expect("cloud_run"))
            .filter(|row| row.ended_at.is_some())
    });
    // The request after the disconnect has no session, so it is not counted.
    assert_eq!((row3.forwarded, row3.failed), (1, 0));

    // Activity rows of this Mac (the Logs page).
    let rows = mac.activity();
    let count = |operation: &str| rows.iter().filter(|row| row.0 == operation).count();
    assert_eq!(count(ACTIVITY_ROUTE_ON), 1, "{rows:?}");
    assert_eq!(count(ACTIVITY_CONNECTED), 2, "{rows:?}");
    assert_eq!(count(ACTIVITY_CONNECT_DENIED), 1, "{rows:?}");
    // The first agent at the second connect, and the second at the end.
    assert_eq!(count(ACTIVITY_DISCONNECTED), 2, "{rows:?}");
    assert!(
        rows.iter()
            .any(|row| row.0.starts_with("cloud run") && row.1 == ActivityDecision::Allow),
        "{rows:?}"
    );
    assert!(
        rows.iter()
            .any(|row| row.0.starts_with("cloud run") && row.1 == ActivityDecision::Deny),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.0 == "cloud session end"),
        "{rows:?}"
    );

    // Nothing of the value, and no token or code, in what the test can read.
    let mut secrets = value_forms();
    secrets.extend(lock(&mac.secrets).iter().cloned());
    for row in &rows {
        assert_clean("an activity row", &format!("{row:?}"), &secrets);
    }
    let mut audit_secrets = secrets.clone();
    audit_secrets.push(placeholder.clone());
    audit_secrets.push(placeholder3.clone());
    let audit = mac.audit(None);
    assert!(audit.iter().any(|row| row.action == "proxy_request"));
    for row in &audit {
        assert_clean(
            &format!("audit row {}", row.action),
            &format!("{row:?}"),
            &audit_secrets,
        );
    }
    for line in lock(&LOG_LINES).iter() {
        assert_clean("a log line", line, &secrets);
    }
    for answer in lock(&ANSWERS).iter() {
        assert_clean("an answer to the agent", answer, &value_forms());
        // Step 10 on the loopback: the agent hears only of the Funnel origin.
        assert!(
            !answer.contains(HOSTED_RELAY),
            "an answer names the hosted relay"
        );
    }
    let mut files = Vec::new();
    Mac::files(mac.dir.path(), &mut files);
    for (name, bytes) in &files {
        let text = String::from_utf8_lossy(bytes);
        assert_clean(name, &text, &secrets);
    }
}
