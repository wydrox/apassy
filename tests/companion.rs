#![cfg(feature = "vault")]

//! The HTTPS listener of the iPhone companion (ADR 0020, contract companion-v1). A real
//! listener runs on a temporary vault. The client is rustls with a verifier that accepts
//! only the pinned certificate, as the phone does, and a phone that signs with ring keys.
//! All data is synthetic.

#[path = "support/companion.rs"]
mod companion_support;

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::broker::approvals::{
    ApprovalOutcome, ApprovalQueue, OwnerAction, OwnerCheck, PendingRun,
};
use apassy::companion::crypto::{
    ApproveAction, approve_string, certificate_pin, display_code, pair_string, pairing_code,
    pairing_code_hash, request_string,
};
use apassy::companion::digest::run_digest_hex;
use apassy::companion::pairing::{CodeError, ManualClock, pair_proof};
use apassy::companion::wire::decode_fixed;
use apassy::companion::{CompanionHandle, CompanionOptions, ConfirmError, OpenPairingError, start};
use apassy::contracts::CredentialKind;
use apassy::vault::{ActivityDecision, Field, ItemDraft, NewActivity, SecretValue};
use companion_support::{DEVICE, Fixture, PASS, PhoneKey, fixture, run};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::{Value, json};

const CANARY: &str = "FAKE-companion-secret-8842-canary";
const NOTE_CANARY: &str = "FAKE-note-canary-only-the-owner-reads-this";
const OTHER_DEVICE: &str = "fedcba9876543210fedcba9876543210";

// ----- the client: pinned TLS, as the phone does it -----

/// Accepts a server whose certificate has the pin, and nothing else. It ignores the host
/// name and the system trust store.
#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if certificate_pin(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".to_owned()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(
    pin: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    client_config_with_alpn(pin, versions, &[b"http/1.1"])
}

fn client_config_with_alpn(
    pin: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            pin: pin.to_owned(),
            provider,
        }))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

/// One answer of the listener.
#[derive(Debug)]
struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("JSON body: {}", self.body))
    }

    /// The `error.code` of an error body.
    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("an error body: {}", self.body))
            .to_owned()
    }

    fn message(&self) -> String {
        self.json()["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

fn parse_reply(bytes: &[u8]) -> std::io::Result<Reply> {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "no answer"));
    };
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "no status"))?;
    Ok(Reply {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    })
}

fn tcp(port: u16) -> TcpStream {
    let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).expect("tcp");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream
}

type ClientTls = StreamOwned<ClientConnection, TcpStream>;

fn tls_stream(port: u16, config: &Arc<ClientConfig>) -> ClientTls {
    let name = ServerName::try_from("mac.local").expect("name");
    let connection = ClientConnection::new(Arc::clone(config), name).expect("client connection");
    StreamOwned::new(connection, tcp(port))
}

/// Read until the server closes. An end without close_notify counts as an end when some
/// bytes came.
fn read_answer(tls: &mut ClientTls) -> std::io::Result<Reply> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
            Err(err) if bytes.is_empty() => return Err(err),
            Err(_) => break,
        }
    }
    parse_reply(&bytes)
}

fn try_exchange(port: u16, config: &Arc<ClientConfig>, raw: &[u8]) -> std::io::Result<Reply> {
    let mut tls = tls_stream(port, config);
    tls.write_all(raw)?;
    tls.flush()?;
    read_answer(&mut tls)
}

// ----- the phone -----

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn b64u(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, byte)| n | (u32::from(*byte) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn fresh_nonce() -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&COUNTER.fetch_add(1, Ordering::SeqCst).to_le_bytes());
    nonce[8..].copy_from_slice(&now().to_le_bytes());
    nonce
}

/// A phone: a device ID and its two keys.
struct Phone {
    id: String,
    request: PhoneKey,
    approval: PhoneKey,
}

impl Phone {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            request: PhoneKey::generate(),
            approval: PhoneKey::generate(),
        }
    }

    /// A phone that the vault has paired, with no network step.
    fn paired(env: &Env, id: &str) -> Self {
        let phone = Self::new(id);
        env.fx
            .pair(
                id,
                "Test iPhone",
                &phone.request.public(),
                &phone.approval.public(),
            )
            .expect("pair");
        phone
    }

    fn code(&self, secret: &[u8; 32]) -> String {
        let hash = pairing_code_hash(secret, &self.request.public(), &self.approval.public());
        display_code(&pairing_code(&hash))
    }

    /// The body of `POST /v1/pair`.
    fn pair_body(&self, name: &str, secret: &[u8; 32]) -> Value {
        let (request_key, approval_key) = (self.request.public(), self.approval.public());
        let text = pair_string(&self.id, name, &request_key, &approval_key).expect("pair string");
        json!({
            "v": 1,
            "device_id": self.id,
            "device_name": name,
            "request_key": b64u(&request_key),
            "approval_key": b64u(&approval_key),
            "request_key_signature": b64u(&self.request.sign(&text)),
            "approval_key_signature": b64u(&self.approval.sign(&text)),
            "proof": b64u(&pair_proof(secret, &text)),
        })
    }

    fn proof(&self, name: &str, secret: &[u8; 32]) -> String {
        let text = pair_string(
            &self.id,
            name,
            &self.request.public(),
            &self.approval.public(),
        )
        .expect("pair string");
        b64u(&pair_proof(secret, &text))
    }
}

/// How a test bends a signed request.
#[derive(Default)]
struct Bend {
    time: Option<u64>,
    nonce: Option<[u8; 16]>,
    /// A header to leave out, lowercase.
    omit: Option<&'static str>,
    /// A header value to send instead, lowercase name.
    replace: Option<(&'static str, String)>,
    /// Sign with the approval key.
    approval_key: bool,
    /// Sign this path instead of the path that is sent.
    signed_path: Option<String>,
}

fn http_request(method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: mac.local\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    raw.push_str("\r\n");
    let mut bytes = raw.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// A signed request, as bytes.
fn signed_bytes(phone: &Phone, method: &str, path: &str, body: &[u8], bend: &Bend) -> Vec<u8> {
    let time = bend.time.unwrap_or_else(now);
    let nonce = bend.nonce.unwrap_or_else(fresh_nonce);
    let text = request_string(
        method,
        bend.signed_path.as_deref().unwrap_or(path),
        &phone.id,
        time,
        &nonce,
        body,
    )
    .expect("request string");
    let key = if bend.approval_key {
        &phone.approval
    } else {
        &phone.request
    };
    let mut headers = vec![
        ("x-apassy-device".to_owned(), phone.id.clone()),
        ("x-apassy-time".to_owned(), time.to_string()),
        ("x-apassy-nonce".to_owned(), b64u(&nonce)),
        ("x-apassy-signature".to_owned(), b64u(&key.sign(&text))),
    ];
    headers.retain(|(name, _)| bend.omit != Some(name.as_str()));
    if let Some((name, value)) = &bend.replace {
        for header in &mut headers {
            if header.0 == *name {
                header.1.clone_from(value);
            }
        }
    }
    http_request(method, path, &headers, body)
}

fn json_post(path: &str, body: &Value) -> Vec<u8> {
    http_request(
        "POST",
        path,
        &[("content-type".to_owned(), "application/json".to_owned())],
        body.to_string().as_bytes(),
    )
}

// ----- the environment -----

struct Env {
    handle: CompanionHandle,
    queue: Arc<ApprovalQueue>,
    client: Arc<ClientConfig>,
    fx: Fixture,
}

fn env() -> Env {
    env_with(|_| {})
}

/// A vault with the companion on, and a listener on a free port of the loopback address.
fn env_with(tweak: impl FnOnce(&mut CompanionOptions)) -> Env {
    let fx = fixture();
    fx.with(|vault| vault.set_companion_enabled(true))
        .expect("enable");
    let queue = Arc::new(ApprovalQueue::new());
    let mut options = CompanionOptions::new(
        Arc::clone(&fx.shared),
        Arc::clone(&queue),
        fx.gate.clone(),
        "Test Mac",
        "0.0.0-test",
        Duration::from_secs(120),
    );
    options.allow_local_peers = true;
    options.bind = Ipv4Addr::LOCALHOST;
    options.port = Some(0);
    options.link_hosts = Some(vec!["127.0.0.1".to_owned()]);
    tweak(&mut options);
    let handle = start(options).expect("start");
    let client = client_config(handle.certificate_pin(), &[&rustls::version::TLS13]);
    Env {
        handle,
        queue,
        client,
        fx,
    }
}

impl Env {
    fn send(&self, raw: &[u8]) -> Reply {
        try_exchange(self.handle.port(), &self.client, raw).expect("an answer")
    }

    fn signed(&self, phone: &Phone, method: &str, path: &str, body: &[u8], bend: &Bend) -> Reply {
        self.send(&signed_bytes(phone, method, path, body, bend))
    }

    fn get(&self, phone: &Phone, path: &str) -> Reply {
        self.signed(phone, "GET", path, b"", &Bend::default())
    }

    fn post(&self, phone: &Phone, path: &str, body: &Value) -> Reply {
        self.signed(
            phone,
            "POST",
            path,
            body.to_string().as_bytes(),
            &Bend::default(),
        )
    }

    /// Open a window and give the secret of its link.
    fn open_window(&self) -> [u8; 32] {
        let invite = self.handle.pairing().open().expect("open a window");
        let link = invite.link.clone();
        link_secret(&link)
    }

    fn pair_status(&self, phone: &Phone, proof: &str) -> Reply {
        self.send(&http_request(
            "GET",
            &format!("/v1/pair/{}", phone.id),
            &[("x-apassy-pair-proof".to_owned(), proof.to_owned())],
            b"",
        ))
    }

    /// Put a run in the queue on a thread, as the broker does: the wait ends with the
    /// vault session. Returns the run as it waits and the thread.
    fn wait(&self, run: PendingRun) -> (PendingRun, JoinHandle<ApprovalOutcome>) {
        let known: Vec<u64> = self.queue.pending().iter().map(|run| run.id).collect();
        let queue = Arc::clone(&self.queue);
        let shared = Arc::clone(&self.fx.shared);
        let epoch = self.fx.with(|vault| vault.epoch());
        let waiter = thread::spawn(move || {
            queue.wait_for(run, Duration::from_secs(30), || {
                shared.lock().is_ok_and(|guard| {
                    guard
                        .as_ref()
                        .is_some_and(|v| !v.is_locked() && v.epoch() == epoch)
                })
            })
        });
        let start = Instant::now();
        loop {
            if let Some(run) = self
                .queue
                .pending()
                .into_iter()
                .find(|run| !known.contains(&run.id))
            {
                return (run, waiter);
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the run never waited"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The value of a parameter of a pairing link, and the secret in it.
fn link_param(link: &str, key: &str) -> String {
    let query = link.split_once('?').expect("a query").1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("parameter {key} in the link"))
        .to_owned()
}

fn link_secret(link: &str) -> [u8; 32] {
    decode_fixed::<32>(&link_param(link, "s")).expect("a 32-byte secret")
}

/// An approval request of a phone. The signature is by `key` over the approval string for
/// `signed_as`. A test changes a field to bend the request.
struct Approval<'a> {
    run_id: u64,
    digest: String,
    remember: bool,
    time: u64,
    key: &'a PhoneKey,
    signed_as: ApproveAction,
}

impl<'a> Approval<'a> {
    /// The approval that a phone makes for `waiting`.
    fn new(phone: &'a Phone, waiting: &PendingRun, remember: bool) -> Self {
        Self {
            run_id: waiting.id,
            digest: run_digest_hex(waiting),
            remember,
            time: now(),
            key: &phone.approval,
            signed_as: if remember {
                ApproveAction::ApproveAndRemember
            } else {
                ApproveAction::Approve
            },
        }
    }
}

fn send_approval(env: &Env, phone: &Phone, approval: &Approval<'_>) -> Reply {
    let text = approve_string(
        &phone.id,
        approval.signed_as,
        approval.run_id,
        &approval.digest,
        approval.time,
    )
    .expect("string");
    let body = json!({
        "digest": approval.digest,
        "remember": approval.remember,
        "time": approval.time,
        "approval_signature": b64u(&approval.key.sign(&text)),
    });
    env.post(
        phone,
        &format!("/v1/runs/{}/approve", approval.run_id),
        &body,
    )
}

fn approve(env: &Env, phone: &Phone, waiting: &PendingRun, remember: bool) -> Reply {
    send_approval(env, phone, &Approval::new(phone, waiting, remember))
}

fn join(waiter: JoinHandle<ApprovalOutcome>) -> ApprovalOutcome {
    waiter.join().expect("waiter")
}

// ----- pairing -----

#[test]
fn pairing_from_the_link_to_a_paired_phone() {
    let env = env();
    let controller = env.handle.pairing().clone();
    let invite = controller.open().expect("open");
    let link = invite.link.as_str().to_owned();
    assert!(
        link.starts_with("apassy://pair?v=1&h=127.0.0.1&p="),
        "{link}"
    );
    assert_eq!(link_param(&link, "p"), env.handle.port().to_string());
    assert_eq!(link_param(&link, "c"), env.handle.certificate_pin());
    assert_eq!(link_param(&link, "n"), "Test%20Mac");
    assert_eq!(link_param(&link, "e"), invite.expires_at.to_string());
    let secret = link_secret(&link);
    let phone = Phone::new(DEVICE);
    let proof = phone.proof("Test iPhone", &secret);

    // No request yet: the poll has no answer to give.
    assert_eq!(env.pair_status(&phone, &proof).status, 404);

    // A bad proof gets the same answer as no window.
    let mut bad = phone.pair_body("Test iPhone", &secret);
    bad["proof"] = json!(b64u(&pair_proof(&[9u8; 32], "other")));
    let reply = env.send(&json_post("/v1/pair", &bad));
    assert_eq!((reply.status, reply.code().as_str()), (401, "unauthorized"));
    // A bad signature too.
    let mut bad = phone.pair_body("Test iPhone", &secret);
    bad["request_key_signature"] =
        json!(phone.pair_body("Other name", &secret)["request_key_signature"]);
    assert_eq!(env.send(&json_post("/v1/pair", &bad)).status, 401);
    // A bad format is a 400, before anything is computed.
    let mut bad = phone.pair_body("Test iPhone", &secret);
    bad["device_id"] = json!("NOT-A-DEVICE-ID");
    let reply = env.send(&json_post("/v1/pair", &bad));
    assert_eq!((reply.status, reply.code().as_str()), (400, "bad_request"));
    let mut bad = phone.pair_body("Test iPhone", &secret);
    bad["unexpected"] = json!(true);
    assert_eq!(env.send(&json_post("/v1/pair", &bad)).status, 400);
    assert_eq!(
        controller.view(),
        apassy::companion::pairing::PairingView::Open {
            expires_at: invite.expires_at
        }
    );

    // The right request moves the window to "waiting".
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"expires_at": invite.expires_at}));
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "waiting"})
    );
    // The Mac shows the name and never the code.
    match controller.view() {
        apassy::companion::pairing::PairingView::Waiting {
            device_id,
            device_name,
            ..
        } => {
            assert_eq!(device_id, DEVICE);
            assert_eq!(device_name, "Test iPhone");
        }
        other => panic!("expected a waiting request, got {other:?}"),
    }

    // A second request, with a good proof of its own, finds a used window.
    let other = Phone::new(OTHER_DEVICE);
    let reply = env.send(&json_post("/v1/pair", &other.pair_body("Other", &secret)));
    assert_eq!((reply.status, reply.code().as_str()), (401, "unauthorized"));

    // A poll with a wrong proof or another device is a 404. A bad format is a 400.
    assert_eq!(env.pair_status(&phone, &b64u(&[1u8; 32])).status, 404);
    assert_eq!(env.pair_status(&other, &proof).status, 404);
    assert_eq!(env.pair_status(&phone, "short").status, 400);
    let missing = env.send(&http_request(
        "GET",
        &format!("/v1/pair/{DEVICE}"),
        &[],
        b"",
    ));
    assert_eq!(missing.status, 400);
    let bad_id = env.send(&http_request(
        "GET",
        "/v1/pair/NOT-AN-ID",
        &[("x-apassy-pair-proof".to_owned(), proof.clone())],
        b"",
    ));
    assert_eq!(bad_id.status, 400);

    // The right code starts the owner check. Nothing is stored before it.
    let code = phone.code(&secret);
    let action = controller.submit_code(&code).expect("the right code");
    assert!(matches!(&action, OwnerAction::PairCompanion { device_id, .. } if device_id == DEVICE));
    env.fx.with(|vault| {
        assert!(vault.companion_devices().expect("devices").is_empty());
    });
    let proof_of_owner = env
        .fx
        .gate
        .authorize(action, OwnerCheck::passphrase(PASS))
        .expect("the passphrase confirms");
    let device = controller.confirm(proof_of_owner).expect("paired");
    assert_eq!(
        (device.device_id.as_str(), device.name.as_str()),
        (DEVICE, "Test iPhone")
    );
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "paired", "mac_name": "Test Mac"})
    );
    assert_eq!(
        controller.view(),
        apassy::companion::pairing::PairingView::Closed
    );

    // The phone is paired: a signed request works.
    let status = env.get(&phone, "/v1/status");
    assert_eq!(status.status, 200, "{}", status.body);
    assert_eq!(
        status.json(),
        json!({
            "v": 1,
            "mac_name": "Test Mac",
            "app_version": "0.0.0-test",
            "approval_timeout_seconds": 120,
            "device": {"id": DEVICE, "name": "Test iPhone", "paired_at": device.paired_at},
        })
    );

    // The same device ID pairs once: a new window and the same ID give 409.
    let secret = env.open_window();
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (409, "already_paired")
    );
    controller.cancel();
}

#[test]
fn a_pair_request_without_an_open_window_is_unauthorized() {
    let env = env();
    let phone = Phone::new(DEVICE);
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &[3u8; 32]),
    ));
    assert_eq!((reply.status, reply.code().as_str()), (401, "unauthorized"));
    // A closed window looks the same as one that never opened.
    let secret = env.open_window();
    env.handle.pairing().cancel();
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    assert_eq!((reply.status, reply.code().as_str()), (401, "unauthorized"));
}

#[test]
fn three_wrong_codes_close_the_window_and_the_phone_hears_denied() {
    let env = env();
    let controller = env.handle.pairing().clone();
    let secret = env.open_window();
    let phone = Phone::new(DEVICE);
    let proof = phone.proof("Test iPhone", &secret);
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    assert_eq!(reply.status, 200);

    let right: u32 = phone
        .code(&secret)
        .replace(' ', "")
        .parse()
        .expect("digits");
    let wrong = format!("{:06}", (right + 1) % 1_000_000);
    assert_eq!(
        controller.submit_code(&wrong).unwrap_err(),
        CodeError::Wrong { remaining: 2 }
    );
    assert_eq!(
        controller.submit_code(&wrong).unwrap_err(),
        CodeError::Wrong { remaining: 1 }
    );
    assert_eq!(
        controller.submit_code(&wrong).unwrap_err(),
        CodeError::Closed
    );
    // The right code is too late.
    assert_eq!(
        controller.submit_code(&phone.code(&secret)).unwrap_err(),
        CodeError::NoRequest
    );
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "denied"})
    );
    env.fx.with(|vault| {
        assert!(vault.companion_devices().expect("devices").is_empty());
    });
    // The window is closed: another request finds nothing.
    let other = Phone::new(OTHER_DEVICE);
    let reply = env.send(&json_post("/v1/pair", &other.pair_body("Other", &secret)));
    assert_eq!(reply.status, 401);
}

#[test]
fn cancel_gives_denied_and_an_owner_check_for_another_device_pairs_nothing() {
    let env = env();
    let controller = env.handle.pairing().clone();
    let secret = env.open_window();
    let phone = Phone::new(DEVICE);
    let proof = phone.proof("Test iPhone", &secret);
    env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    let action = controller
        .submit_code(&phone.code(&secret))
        .expect("the right code");
    let owner_proof = env
        .fx
        .gate
        .authorize(action, OwnerCheck::passphrase(PASS))
        .expect("owner check");
    // The owner cancels before the proof is used: the device is not stored.
    controller.cancel();
    assert!(matches!(
        controller.confirm(owner_proof),
        Err(ConfirmError::NotWaiting)
    ));
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "denied"})
    );
    env.fx.with(|vault| {
        assert!(vault.companion_devices().expect("devices").is_empty());
    });
    // A proof for another action is refused, and uses up nothing that matters.
    let secret = env.open_window();
    let phone = Phone::new(DEVICE);
    env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    let reveal = env
        .fx
        .gate
        .authorize(
            OwnerAction::Reveal { item_id: 1 },
            OwnerCheck::passphrase(PASS),
        )
        .expect("reveal proof");
    assert!(matches!(
        controller.confirm(reveal),
        Err(ConfirmError::WrongProof)
    ));
}

#[test]
fn the_pair_status_ends_with_expired_and_then_is_forgotten() {
    let clock = Arc::new(ManualClock::new(now()));
    let env = env_with(|options| {
        options.pairing_clock = Some(clock.clone());
    });
    let secret = env.open_window();
    let phone = Phone::new(DEVICE);
    let proof = phone.proof("Test iPhone", &secret);
    assert_eq!(
        env.send(&json_post(
            "/v1/pair",
            &phone.pair_body("Test iPhone", &secret)
        ))
        .status,
        200
    );
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "waiting"})
    );
    clock.advance(Duration::from_secs(301));
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "expired"})
    );
    // The answer is kept for 5 minutes after the window ends.
    clock.advance(Duration::from_secs(290));
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "expired"})
    );
    clock.advance(Duration::from_secs(20));
    assert_eq!(env.pair_status(&phone, &proof).status, 404);
    // The window is gone: the link does not work any more.
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    assert_eq!(reply.status, 401);
}

#[test]
fn a_pair_request_on_a_locked_vault_is_locked_and_the_window_stays_open() {
    let env = env();
    let secret = env.open_window();
    let phone = Phone::new(DEVICE);
    env.fx.with(|vault| vault.lock()).expect("lock");
    let reply = env.send(&json_post(
        "/v1/pair",
        &phone.pair_body("Test iPhone", &secret),
    ));
    assert_eq!((reply.status, reply.code().as_str()), (423, "vault_locked"));
    assert!(matches!(
        env.handle.pairing().view(),
        apassy::companion::pairing::PairingView::Open { .. }
    ));
    // A window does not open on a locked vault.
    env.handle.pairing().cancel();
    assert_eq!(
        env.handle.pairing().open().unwrap_err(),
        OpenPairingError::VaultLocked
    );
}

// ----- signed requests -----

#[test]
fn a_signed_request_is_answered_and_updates_last_seen() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    env.fx.with(|vault| {
        let device = vault
            .companion_device(DEVICE)
            .expect("device")
            .expect("paired");
        assert_eq!(device.last_seen_at, None);
    });
    let reply = env.get(&phone, "/v1/status");
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.head.contains("Content-Type: application/json"));
    assert!(reply.head.contains("Connection: close"));
    env.fx.with(|vault| {
        let seen = vault
            .companion_device(DEVICE)
            .expect("device")
            .expect("paired")
            .last_seen_at
            .expect("seen");
        assert!(seen.abs_diff(now()) <= 2);
    });
}

#[test]
fn a_missing_or_malformed_header_is_unauthorized() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    for header in [
        "x-apassy-device",
        "x-apassy-time",
        "x-apassy-nonce",
        "x-apassy-signature",
    ] {
        let reply = env.signed(
            &phone,
            "GET",
            "/v1/status",
            b"",
            &Bend {
                omit: Some(header),
                ..Bend::default()
            },
        );
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (401, "unauthorized"),
            "{header}"
        );
    }
    let good_nonce = b64u(&fresh_nonce());
    for (header, value) in [
        ("x-apassy-device", DEVICE.to_uppercase()),
        ("x-apassy-device", DEVICE[..31].to_owned()),
        ("x-apassy-time", "abc".to_owned()),
        ("x-apassy-time", "1234567890123".to_owned()),
        ("x-apassy-time", String::new()),
        ("x-apassy-nonce", good_nonce[..21].to_owned()),
        ("x-apassy-nonce", format!("{good_nonce}A")),
        ("x-apassy-nonce", "!".repeat(22)),
        ("x-apassy-signature", "%%%".to_owned()),
        ("x-apassy-signature", "AAAA".to_owned()),
    ] {
        let reply = env.signed(
            &phone,
            "GET",
            "/v1/status",
            b"",
            &Bend {
                replace: Some((header, value.clone())),
                ..Bend::default()
            },
        );
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (401, "unauthorized"),
            "{header}: {value}"
        );
    }
}

#[test]
fn a_bad_signature_is_unauthorized_and_does_not_use_up_the_nonce() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let nonce = fresh_nonce();
    // Signed for another path.
    let reply = env.signed(
        &phone,
        "GET",
        "/v1/status",
        b"",
        &Bend {
            nonce: Some(nonce),
            signed_path: Some("/v1/inbox".to_owned()),
            ..Bend::default()
        },
    );
    assert_eq!((reply.status, reply.code().as_str()), (401, "unauthorized"));
    // Signed with the approval key: the request key is the one that counts.
    let reply = env.signed(
        &phone,
        "GET",
        "/v1/status",
        b"",
        &Bend {
            nonce: Some(nonce),
            approval_key: true,
            ..Bend::default()
        },
    );
    assert_eq!(reply.status, 401);
    // The body is part of the signature.
    let signed = signed_bytes(&phone, "POST", "/v1/runs/1/deny", b"{}", &Bend::default());
    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last - 1] = b' ';
    let reply = env.send(&tampered);
    assert_eq!(reply.status, 401);
    // A signature of another device is not a signature of this one.
    let stranger = Phone::new(DEVICE);
    let reply = env.get(&stranger, "/v1/status");
    assert_eq!(reply.status, 401);
    // The nonce that failed is still new.
    let reply = env.signed(
        &phone,
        "GET",
        "/v1/status",
        b"",
        &Bend {
            nonce: Some(nonce),
            ..Bend::default()
        },
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
}

#[test]
fn a_reused_nonce_is_unauthorized() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let raw = signed_bytes(&phone, "GET", "/v1/status", b"", &Bend::default());
    assert_eq!(env.send(&raw).status, 200);
    let replay = env.send(&raw);
    assert_eq!(
        (replay.status, replay.code().as_str()),
        (401, "unauthorized")
    );
    // A new nonce works.
    assert_eq!(env.get(&phone, "/v1/status").status, 200);
}

#[test]
fn a_request_time_more_than_60_seconds_off_is_clock_skew() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    for offset in [-120i64, 120, -65, 65] {
        let time = now().checked_add_signed(offset).expect("time");
        let reply = env.signed(
            &phone,
            "GET",
            "/v1/status",
            b"",
            &Bend {
                time: Some(time),
                ..Bend::default()
            },
        );
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (401, "clock_skew"),
            "{offset}"
        );
        // The clock of the test can move one second between the request and the check.
        let seconds = offset.unsigned_abs();
        let message = reply.message();
        assert!(
            message.contains(&format!(" {seconds} seconds"))
                || message.contains(&format!(" {} seconds", seconds - 1))
                || message.contains(&format!(" {} seconds", seconds + 1)),
            "{message}"
        );
    }
    for offset in [-55i64, 55, 0] {
        let time = now().checked_add_signed(offset).expect("time");
        let reply = env.signed(
            &phone,
            "GET",
            "/v1/status",
            b"",
            &Bend {
                time: Some(time),
                ..Bend::default()
            },
        );
        assert_eq!(reply.status, 200, "{offset}: {}", reply.body);
    }
}

#[test]
fn an_unpaired_or_removed_device_is_unpaired() {
    let env = env();
    let stranger = Phone::new(OTHER_DEVICE);
    let reply = env.get(&stranger, "/v1/status");
    assert_eq!((reply.status, reply.code().as_str()), (401, "unpaired"));
    let phone = Phone::paired(&env, DEVICE);
    assert_eq!(env.get(&phone, "/v1/status").status, 200);
    env.fx.with(|vault| {
        assert!(vault.remove_companion_device(DEVICE).expect("remove"));
    });
    let reply = env.get(&phone, "/v1/status");
    assert_eq!((reply.status, reply.code().as_str()), (401, "unpaired"));
    let reply = env.get(&phone, "/v1/inbox");
    assert_eq!(reply.status, 401);
}

#[test]
fn a_signature_of_one_device_does_not_work_for_another_paired_device() {
    let env = env();
    let first = Phone::paired(&env, DEVICE);
    let second = Phone::paired(&env, OTHER_DEVICE);
    // The second phone signs, but names the first device.
    let reply = env.signed(
        &second,
        "GET",
        "/v1/status",
        b"",
        &Bend {
            replace: Some(("x-apassy-device", first.id.clone())),
            ..Bend::default()
        },
    );
    assert_eq!(reply.status, 401);
    assert_eq!(env.get(&first, "/v1/status").status, 200);
    assert_eq!(env.get(&second, "/v1/status").status, 200);
}

#[test]
fn unknown_routes_and_wrong_methods_are_not_found_and_bodies_are_checked() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let reply = env.send(&http_request("GET", "/v1/nothing", &[], b""));
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_found"));
    let reply = env.send(&http_request("GET", "/", &[], b""));
    assert_eq!(reply.status, 404);
    // A known path with another method is not a route.
    let reply = env.signed(&phone, "POST", "/v1/status", b"{}", &Bend::default());
    assert_eq!(reply.status, 404);
    // A path that is a route with a bad ID is a 400, after the signature check.
    for path in [
        "/v1/runs/abc/deny",
        "/v1/runs/0/deny",
        "/v1/access-requests/-1/deny",
    ] {
        let reply = env.signed(&phone, "POST", path, b"{}", &Bend::default());
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (400, "bad_request"),
            "{path}"
        );
    }
    // The same path without a signature gets no such hint.
    let reply = env.send(&http_request("POST", "/v1/runs/abc/deny", &[], b"{}"));
    assert_eq!(reply.status, 401);
    // A body on a GET is refused.
    let reply = env.signed(&phone, "GET", "/v1/status", b"{}", &Bend::default());
    assert_eq!((reply.status, reply.code().as_str()), (400, "bad_request"));
    // The deny body must be the empty object.
    for body in [&b""[..], b"{\"x\":1}", b"[]", b"null", b"{"] {
        let reply = env.signed(&phone, "POST", "/v1/runs/5/deny", body, &Bend::default());
        assert_eq!(reply.status, 400, "{:?}", String::from_utf8_lossy(body));
    }
}

// ----- the inbox -----

fn seed_vault(env: &Env) -> (u64, String) {
    env.fx.with(|vault| {
        let item = vault
            .add(ItemDraft {
                title: "Stripe test key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: NOTE_CANARY.to_owned(),
                tags: vec!["tag-canary".to_owned()],
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(CANARY.to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
        vault
            .set_env_binding(item.id, "STRIPE_KEY", "token")
            .expect("binding");
        let (agent, token) = vault.register_agent("Codex").expect("agent");
        vault.set_agent_sees_all(agent.id, true).expect("see all");
        let (request, _) = vault
            .request_access(
                agent.id,
                item.id,
                "The user asked me to test checkout.",
                "/tmp/synthetic-shop",
            )
            .expect("request");
        (request, token.expose().to_owned())
    })
}

#[test]
fn the_inbox_has_runs_access_requests_and_activity_and_no_secret() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (request_id, token) = seed_vault(&env);
    env.fx.with(|vault| {
        for n in 0..60 {
            vault
                .record_activity(&NewActivity {
                    agent_id: None,
                    agent_name: "Codex".to_owned(),
                    item_id: None,
                    operation: if n == 59 {
                        "x".repeat(400)
                    } else {
                        format!("stripe charges list {n}")
                    },
                    decision: if n % 2 == 0 {
                        ActivityDecision::Allow
                    } else {
                        ActivityDecision::Deny
                    },
                    reason: if n == 59 {
                        "\u{142}".repeat(400)
                    } else {
                        "The command prints a secret.".to_owned()
                    },
                })
                .expect("activity");
        }
    });
    let (waiting, waiter) = env.wait(run(true));
    let reply = env.get(&phone, "/v1/inbox");
    assert_eq!(reply.status, 200, "{}", reply.body);
    for forbidden in [CANARY, NOTE_CANARY, "tag-canary", token.as_str()] {
        assert!(!reply.body.contains(forbidden), "the inbox has {forbidden}");
    }
    let inbox = reply.json();

    let runs = inbox["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 1);
    let entry = &runs[0];
    assert_eq!(entry["id"], json!(waiting.id.to_string()));
    assert_eq!(entry["agent"], "Companion agent");
    assert_eq!(entry["command"], json!(["npm", "run", "migrate"]));
    assert_eq!(entry["cwd"], "/tmp/synthetic-shop");
    assert_eq!(entry["env_names"], json!(["DATABASE_URL"]));
    assert_eq!(entry["purpose"], "Apply the migration.");
    assert_eq!(entry["risk"], "asks the owner");
    assert_eq!(entry["user_request"], "Deploy the schema.");
    assert_eq!(entry["request_source"], "from the host hook");
    assert_eq!(entry["agent_request"], "");
    assert_eq!(
        entry["remember"],
        json!({"pattern": "npm run migrate", "approvals": 1, "needed": 3})
    );
    assert_eq!(entry["digest"], json!(run_digest_hex(&waiting)));
    assert!(entry["waiting_seconds"].as_u64().is_some());
    let mut fields: Vec<&str> = entry
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "agent",
            "agent_request",
            "command",
            "cwd",
            "digest",
            "env_names",
            "id",
            "purpose",
            "remember",
            "request_source",
            "risk",
            "user_request",
            "waiting_seconds"
        ]
    );

    let requests = inbox["access_requests"].as_array().expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], json!(request_id.to_string()));
    assert_eq!(requests[0]["agent"], "Codex");
    assert_eq!(requests[0]["item_name"], "Stripe test key");
    assert_eq!(requests[0]["reason"], "The user asked me to test checkout.");
    assert_eq!(requests[0]["cwd"], "/tmp/synthetic-shop");
    assert!(requests[0]["requested_at"].as_u64().is_some());

    let activity = inbox["activity"].as_array().expect("activity");
    assert_eq!(activity.len(), 50, "the newest 50 entries");
    let ids: Vec<u64> = activity
        .iter()
        .map(|entry| entry["id"].as_str().expect("id").parse().expect("number"))
        .collect();
    assert!(
        ids.windows(2).all(|pair| pair[0] > pair[1]),
        "newest first: {ids:?}"
    );
    // The vault keeps 64 bytes of the operation and 700 bytes of the reason. The wire cuts
    // the reason of the newest entry (350 characters) at 300 characters.
    assert_eq!(
        activity[0]["summary"].as_str().expect("summary"),
        "x".repeat(64)
    );
    assert_eq!(
        activity[0]["reason"]
            .as_str()
            .expect("reason")
            .chars()
            .count(),
        300
    );
    assert_eq!(activity[0]["decision"], "deny");
    assert_eq!(activity[1]["decision"], "allow");
    assert_eq!(activity[1]["summary"], "stripe charges list 58");

    env.queue.deny(waiting.id);
    assert_eq!(join(waiter), ApprovalOutcome::Denied);
    // With no run and no request, the lists are empty and the shape stays.
    env.fx
        .with(|vault| vault.deny_access_request(request_id))
        .expect("deny");
    let inbox = env.get(&phone, "/v1/inbox").json();
    assert_eq!(inbox["runs"], json!([]));
    assert_eq!(inbox["access_requests"], json!([]));
}

#[test]
fn the_inbox_lists_the_newest_50_open_access_requests_newest_first() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    // An agent has at most 20 open requests, so three agents ask for 60 items.
    let ids: Vec<u64> = env.fx.with(|vault| {
        let agents: Vec<u64> = (0..3)
            .map(|n| {
                let (agent, _) = vault.register_agent(&format!("Agent {n}")).expect("agent");
                vault.set_agent_sees_all(agent.id, true).expect("see all");
                agent.id
            })
            .collect();
        (0..60)
            .map(|n| {
                let item = vault
                    .add(ItemDraft {
                        title: format!("Key {n}"),
                        kind: CredentialKind::ApiKey,
                        notes: String::new(),
                        tags: Vec::new(),
                        fields: vec![Field {
                            name: "token".to_owned(),
                            value: SecretValue::new(format!("FAKE-value-{n}")),
                            secret: true,
                        }],
                    })
                    .expect("add");
                vault
                    .set_env_binding(item.id, &format!("KEY_{n}"), "token")
                    .expect("binding");
                let (request, created) = vault
                    .request_access(agents[n % 3], item.id, "Needed for a test.", "/tmp/shop")
                    .expect("request");
                assert!(created);
                request
            })
            .collect()
    });
    let inbox = env.get(&phone, "/v1/inbox").json();
    let listed: Vec<String> = inbox["access_requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|entry| entry["id"].as_str().expect("id").to_owned())
        .collect();
    // The newest 50 of the 60, the newest first: the 10 oldest are the ones cut.
    let expected: Vec<String> = ids.iter().rev().take(50).map(u64::to_string).collect();
    assert_eq!(listed, expected);
    // A request that the owner decides leaves the list, and an older one comes in.
    env.fx
        .with(|vault| vault.deny_access_request(ids[59]))
        .expect("deny");
    let inbox = env.get(&phone, "/v1/inbox").json();
    let listed: Vec<String> = inbox["access_requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|entry| entry["id"].as_str().expect("id").to_owned())
        .collect();
    let expected: Vec<String> = ids[..59]
        .iter()
        .rev()
        .take(50)
        .map(u64::to_string)
        .collect();
    assert_eq!(listed, expected);
}

// ----- approvals -----

#[test]
fn an_approval_by_the_phone_ends_a_waiting_run_as_approved() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(false));
    let reply = approve(&env, &phone, &waiting, false);
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"outcome": "approved"}));
    assert_eq!(join(waiter), ApprovalOutcome::Approved);
    assert!(env.queue.pending().is_empty());
    // A run settles once: the second approval finds no waiting run.
    let reply = approve(&env, &phone, &waiting, false);
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_waiting"));
}

#[test]
fn approve_and_remember_ends_a_run_with_an_offer() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(true));
    let reply = approve(&env, &phone, &waiting, true);
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"outcome": "approved_and_remembered"}));
    assert_eq!(join(waiter), ApprovalOutcome::ApprovedAndRemembered);
}

#[test]
fn remember_without_an_offer_is_refused_and_the_run_keeps_waiting() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(false));
    let reply = approve(&env, &phone, &waiting, true);
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (409, "nothing_to_remember")
    );
    assert_eq!(env.queue.pending().len(), 1);
    assert_eq!(approve(&env, &phone, &waiting, false).status, 200);
    assert_eq!(join(waiter), ApprovalOutcome::Approved);
}

#[test]
fn a_changed_digest_is_refused_and_nothing_runs() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(false));
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            digest: "ab".repeat(32),
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!((reply.status, reply.code().as_str()), (409, "changed"));
    assert_eq!(env.queue.pending().len(), 1, "the run still waits");
    // The digest of a run with other text is another digest.
    let mut other = waiting.clone();
    other.command.push("--force".to_owned());
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            digest: run_digest_hex(&other),
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!(reply.code(), "changed");
    // A digest with a bad format is a 400.
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            digest: "not-a-digest".to_owned(),
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!(reply.code(), "bad_request");
    env.queue.deny(waiting.id);
    assert_eq!(join(waiter), ApprovalOutcome::Denied);
}

#[test]
fn a_stale_or_future_approval_time_is_stale() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(false));
    for time in [now() - 120, now() + 120] {
        let reply = send_approval(
            &env,
            &phone,
            &Approval {
                time,
                ..Approval::new(&phone, &waiting, false)
            },
        );
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (403, "stale"),
            "{time}"
        );
    }
    assert_eq!(env.queue.pending().len(), 1);
    env.queue.deny(waiting.id);
    assert_eq!(join(waiter), ApprovalOutcome::Denied);
}

#[test]
fn an_approval_by_the_wrong_key_or_for_another_action_fails_the_owner_check() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(true));
    // Signed with the request key: the phone has not shown Face ID.
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            key: &phone.request,
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (403, "owner_check_failed")
    );
    // Signed with a key that is not the phone's.
    let stranger = PhoneKey::generate();
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            key: &stranger,
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!(reply.code(), "owner_check_failed");
    // A signature for "approve once" does not approve and remember.
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            signed_as: ApproveAction::Approve,
            ..Approval::new(&phone, &waiting, true)
        },
    );
    assert_eq!(reply.code(), "owner_check_failed");
    // A signature for "approve and remember" does not approve once.
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            signed_as: ApproveAction::ApproveAndRemember,
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!(reply.code(), "owner_check_failed");
    // A signature for another run does not approve this one.
    let mut other = waiting.clone();
    other.id += 1;
    let reply = send_approval(
        &env,
        &phone,
        &Approval {
            key: &phone.approval,
            digest: run_digest_hex(&other),
            ..Approval::new(&phone, &waiting, false)
        },
    );
    assert_eq!(
        reply.code(),
        "changed",
        "the digest of another run is a changed run"
    );
    assert_eq!(env.queue.pending().len(), 1, "no refusal approved the run");
    // The good signature still works.
    assert_eq!(approve(&env, &phone, &waiting, false).status, 200);
    assert_eq!(join(waiter), ApprovalOutcome::Approved);
}

#[test]
fn an_approval_of_an_unknown_run_or_with_a_bad_body_is_refused() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let unknown = PendingRun {
        id: 424_242,
        ..run(false)
    };
    let reply = approve(&env, &phone, &unknown, false);
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_waiting"));
    for body in [
        json!({"digest": "cd".repeat(32), "remember": false, "time": now()}),
        json!({"digest": "cd".repeat(32), "remember": false, "time": now(), "approval_signature": "AAAA", "extra": 1}),
        json!({"digest": "cd".repeat(32), "remember": "no", "time": now(), "approval_signature": "AAAAAAAAAAAA"}),
        json!({"digest": "CD".repeat(32), "remember": false, "time": now(), "approval_signature": "AAAAAAAAAAAA"}),
        json!({"digest": "cd".repeat(32), "remember": false, "time": now(), "approval_signature": "!!!!"}),
    ] {
        let reply = env.post(&phone, "/v1/runs/77/approve", &body);
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (400, "bad_request"),
            "{body}"
        );
    }
}

#[test]
fn a_denial_by_the_phone_ends_the_run_as_denied() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(false));
    let path = format!("/v1/runs/{}/deny", waiting.id);
    let reply = env.post(&phone, &path, &json!({}));
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"outcome": "denied"}));
    assert_eq!(join(waiter), ApprovalOutcome::Denied);
    let reply = env.post(&phone, &path, &json!({}));
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_waiting"));
}

#[test]
fn the_phone_can_deny_an_access_request_and_not_grant_it() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (request_id, _) = seed_vault(&env);
    let path = format!("/v1/access-requests/{request_id}/deny");
    let reply = env.post(&phone, &path, &json!({}));
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"outcome": "denied"}));
    env.fx.with(|vault| {
        assert!(
            vault
                .access_requests(true, 10)
                .expect("requests")
                .is_empty()
        );
    });
    let reply = env.post(&phone, &path, &json!({}));
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_waiting"));
    // There is no route that grants access.
    let reply = env.post(
        &phone,
        &format!("/v1/access-requests/{request_id}/approve"),
        &json!({}),
    );
    assert_eq!(reply.status, 404);
}

#[test]
fn a_get_or_a_delete_with_a_body_is_a_bad_request() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let pair_path = format!("/v1/pair/{DEVICE}");
    let proof = ("x-apassy-pair-proof".to_owned(), b64u(&[5u8; 32]));
    for (method, path) in [
        ("GET", "/v1/status"),
        ("GET", "/v1/inbox"),
        ("DELETE", "/v1/device"),
        ("GET", pair_path.as_str()),
        // An unknown path is a 404 without a body; a body makes it a framing error first.
        ("GET", "/v1/nothing"),
        ("DELETE", "/v1/nothing"),
    ] {
        let unsigned = env.send(&http_request(
            method,
            path,
            std::slice::from_ref(&proof),
            b"{}",
        ));
        assert_eq!(
            (unsigned.status, unsigned.code().as_str()),
            (400, "bad_request"),
            "unsigned {method} {path}"
        );
        let signed = env.signed(&phone, method, path, b"{}", &Bend::default());
        assert_eq!(
            (signed.status, signed.code().as_str()),
            (400, "bad_request"),
            "signed {method} {path}"
        );
    }
    // The body did not unpair the device.
    assert_eq!(env.get(&phone, "/v1/status").status, 200);
    // A length of zero is no body.
    let empty = env.send(b"GET /v1/status HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert_eq!((empty.status, empty.code().as_str()), (401, "unauthorized"));
    // A POST keeps its body.
    let reply = env.post(&phone, "/v1/runs/5/deny", &json!({}));
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_waiting"));
}

#[test]
fn a_pair_status_has_no_answer_without_a_request_and_a_bad_format_is_a_bad_request() {
    let env = env();
    let phone = Phone::new(DEVICE);
    let proof = phone.proof("Test iPhone", &[3u8; 32]);
    // No window at all.
    assert_eq!(env.pair_status(&phone, &proof).status, 404);
    // A window with no request yet, with a proof that would be right.
    let secret = env.open_window();
    let proof = phone.proof("Test iPhone", &secret);
    let reply = env.pair_status(&phone, &proof);
    assert_eq!((reply.status, reply.code().as_str()), (404, "not_found"));
    // A malformed proof or device ID is a 400 in the same state.
    assert_eq!(env.pair_status(&phone, "short").status, 400);
    assert_eq!(env.pair_status(&phone, &format!("{proof}A")).status, 400);
    let upper = env.send(&http_request(
        "GET",
        &format!("/v1/pair/{}", DEVICE.to_uppercase()),
        &[("x-apassy-pair-proof".to_owned(), proof.clone())],
        b"",
    ));
    assert_eq!(upper.status, 400);
    // The request moves the window to "waiting", and the poll answers.
    assert_eq!(
        env.send(&json_post(
            "/v1/pair",
            &phone.pair_body("Test iPhone", &secret)
        ))
        .status,
        200
    );
    assert_eq!(
        env.pair_status(&phone, &proof).json(),
        json!({"state": "waiting"})
    );
}

#[test]
fn a_device_name_follows_the_character_rules_of_the_contract() {
    let env = env();
    let secret = env.open_window();
    let refused = [
        // Unicode White_Space at the start or the end, not only the ASCII space.
        "\u{a0}phone".to_owned(),
        "phone\u{2003}".to_owned(),
        "\u{3000}".to_owned(),
        "\u{2028}phone".to_owned(),
        // 41 Unicode scalar values, though 41 characters may be fewer bytes or more.
        "\u{142}".repeat(41),
        "\u{1f600}".repeat(41),
        "e\u{301}".repeat(21),
        String::new(),
    ];
    for (n, name) in refused.iter().enumerate() {
        let phone = Phone::new(DEVICE);
        let reply = env.send(&json_post("/v1/pair", &phone.pair_body(name, &secret)));
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (400, "bad_request"),
            "{n}: {name:?}"
        );
    }
    // A refused name does not use the window.
    let phone = Phone::new(DEVICE);
    // 40 scalars: emoji, a no-break space inside, a combining sequence, a zero width
    // space at the end (not White_Space).
    let name = format!("{}\u{a0}e\u{301}\u{200b}", "\u{1f600}".repeat(36));
    assert_eq!(name.chars().count(), 40);
    let reply = env.send(&json_post("/v1/pair", &phone.pair_body(&name, &secret)));
    assert_eq!(reply.status, 200, "{}", reply.body);
    env.handle.pairing().cancel();
}

#[test]
fn the_phone_removes_its_own_pairing() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let other = Phone::paired(&env, OTHER_DEVICE);
    let reply = env.signed(&phone, "DELETE", "/v1/device", b"{}", &Bend::default());
    assert_eq!(reply.status, 400, "a DELETE has no body");
    let reply = env.signed(&phone, "DELETE", "/v1/device", b"", &Bend::default());
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"outcome": "unpaired"}));
    env.fx.with(|vault| {
        assert!(vault.companion_device(DEVICE).expect("device").is_none());
        assert!(
            vault
                .companion_device(OTHER_DEVICE)
                .expect("device")
                .is_some()
        );
    });
    let reply = env.get(&phone, "/v1/status");
    assert_eq!((reply.status, reply.code().as_str()), (401, "unpaired"));
    assert_eq!(
        env.get(&other, "/v1/status").status,
        200,
        "another device stays"
    );
}

// ----- the vault -----

#[test]
fn a_locked_vault_answers_locked_and_a_new_session_too() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let (waiting, waiter) = env.wait(run(false));
    env.fx.with(|vault| vault.lock()).expect("lock");
    for path in ["/v1/status", "/v1/inbox"] {
        let reply = env.get(&phone, path);
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (423, "vault_locked"),
            "{path}"
        );
    }
    let reply = approve(&env, &phone, &waiting, false);
    assert_eq!((reply.status, reply.code().as_str()), (423, "vault_locked"));
    assert_eq!(env.post(&phone, "/v1/runs/5/deny", &json!({})).status, 423);
    assert_eq!(
        env.post(&phone, "/v1/access-requests/5/deny", &json!({}))
            .status,
        423
    );
    assert_eq!(
        env.signed(&phone, "DELETE", "/v1/device", b"", &Bend::default())
            .status,
        423
    );
    // The run that waited is over with the session, as for the owner.
    assert_eq!(join(waiter), ApprovalOutcome::Invalidated);
    // The owner unlocks again. The listener serves the session it started in, so it
    // still answers 423 until the app starts a new listener.
    env.fx.with(|vault| vault.unlock(PASS)).expect("unlock");
    let reply = env.get(&phone, "/v1/status");
    assert_eq!((reply.status, reply.code().as_str()), (423, "vault_locked"));
}

#[test]
fn the_listener_does_not_start_on_a_locked_vault_or_with_the_setting_off() {
    let fx = fixture();
    let queue = Arc::new(ApprovalQueue::new());
    let options = |fx: &Fixture| {
        let mut options = CompanionOptions::new(
            Arc::clone(&fx.shared),
            Arc::clone(&queue),
            fx.gate.clone(),
            "Test Mac",
            "0.0.0-test",
            Duration::from_secs(120),
        );
        options.allow_local_peers = true;
        options.bind = Ipv4Addr::LOCALHOST;
        options.port = Some(0);
        options
    };
    // The setting starts off.
    let error = start(options(&fx)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("off"), "{error}");
    fx.with(|vault| vault.set_companion_enabled(true))
        .expect("enable");
    fx.with(|vault| vault.lock()).expect("lock");
    let error = start(options(&fx)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("locked"), "{error}");
    fx.with(|vault| vault.unlock(PASS)).expect("unlock");
    assert!(start(options(&fx)).is_ok());
}

#[test]
fn a_port_in_use_is_an_error() {
    let env = env();
    let port = env.handle.port();
    let mut options = CompanionOptions::new(
        Arc::clone(&env.fx.shared),
        Arc::clone(&env.queue),
        env.fx.gate.clone(),
        "Test Mac",
        "0.0.0-test",
        Duration::from_secs(120),
    );
    options.bind = Ipv4Addr::LOCALHOST;
    options.port = Some(port);
    let error = start(options).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AddrInUse);
}

#[test]
fn stopping_ends_the_listener_the_connections_and_the_window() {
    let mut env = env();
    let port = env.handle.port();
    let controller = env.handle.pairing().clone();
    let _secret = env.open_window();
    // An idle connection that has not sent a request.
    let idle = tcp(port);
    let begin = Instant::now();
    while env.handle.open_connections() == 0 {
        assert!(begin.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(5));
    }
    let begin = Instant::now();
    env.handle.stop();
    assert!(begin.elapsed() < Duration::from_secs(3), "stop is prompt");
    assert_eq!(env.handle.open_connections(), 0);
    let mut idle = idle;
    let mut byte = [0u8; 1];
    assert!(
        idle.read(&mut byte).map_or(true, |read| read == 0),
        "the connection is closed"
    );
    assert!(
        TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_err(),
        "the port is closed"
    );
    assert_eq!(controller.open().unwrap_err(), OpenPairingError::Stopped);
    assert_eq!(
        controller.view(),
        apassy::companion::pairing::PairingView::Closed
    );
}

// ----- the transport -----

#[test]
fn a_client_with_another_pin_cannot_connect() {
    let env = env();
    let wrong = client_config(
        &certificate_pin(b"another certificate"),
        &[&rustls::version::TLS13],
    );
    let result = try_exchange(
        env.handle.port(),
        &wrong,
        &http_request("GET", "/v1/status", &[], b""),
    );
    assert!(result.is_err(), "a pin mismatch ends the handshake");
}

#[test]
fn the_certificate_is_the_certificate_of_the_vault() {
    let env = env();
    let der = env
        .fx
        .with(|vault| vault.companion_certificate())
        .expect("certificate")
        .expect("made at the start")
        .der;
    assert_eq!(env.handle.certificate_pin(), certificate_pin(&der));
}

#[test]
fn a_client_that_speaks_only_tls_12_is_refused() {
    let env = env();
    let config = client_config(env.handle.certificate_pin(), &[&rustls::version::TLS12]);
    let result = try_exchange(
        env.handle.port(),
        &config,
        &http_request("GET", "/v1/status", &[], b""),
    );
    assert!(result.is_err(), "TLS 1.2 is refused: {result:?}");
    // The listener still serves TLS 1.3.
    assert_eq!(
        env.send(&http_request("GET", "/v1/nothing", &[], b""))
            .status,
        404
    );
}

#[test]
fn the_listener_offers_http_1_1_and_nothing_else_in_alpn() {
    let env = env();
    let port = env.handle.port();
    let request = http_request("GET", "/v1/nothing", &[], b"");
    // A client that offers http/1.1, alone or after h2, gets http/1.1.
    for offered in [&[&b"http/1.1"[..]][..], &[&b"h2"[..], &b"http/1.1"[..]][..]] {
        let config = client_config_with_alpn(
            env.handle.certificate_pin(),
            &[&rustls::version::TLS13],
            offered,
        );
        let mut tls = tls_stream(port, &config);
        tls.write_all(&request).expect("write");
        tls.flush().expect("flush");
        let reply = read_answer(&mut tls).expect("an answer");
        assert_eq!(reply.status, 404);
        assert_eq!(
            tls.conn.alpn_protocol(),
            Some(&b"http/1.1"[..]),
            "{offered:?}"
        );
    }
    // A client that offers only h2 (or only h3) finds no common protocol and is refused.
    for offered in [&[&b"h2"[..]][..], &[&b"h3"[..], &b"h2"[..]][..]] {
        let config = client_config_with_alpn(
            env.handle.certificate_pin(),
            &[&rustls::version::TLS13],
            offered,
        );
        let result = try_exchange(port, &config, &request);
        assert!(result.is_err(), "no HTTP/2: {result:?}");
    }
    // The listener still serves after the refusals.
    assert_eq!(env.send(&request).status, 404);
}

#[test]
fn a_connection_from_the_mac_itself_is_closed_at_once() {
    let env = env_with(|options| options.allow_local_peers = false);
    let port = env.handle.port();
    // The peer is a loopback address. The listener closes before the TLS handshake.
    let mut raw = tcp(port);
    let begin = Instant::now();
    require_closed(&mut raw).expect("network EOF or reset before the TLS handshake");
    assert!(begin.elapsed() < Duration::from_secs(2));
    let result = try_exchange(
        port,
        &env.client,
        &http_request("GET", "/v1/nothing", &[], b""),
    );
    assert!(
        result.is_err(),
        "no answer for a peer on the Mac: {result:?}"
    );
    assert_eq!(env.handle.open_connections(), 0);
}

/// The IPv4 addresses that this host has, loopback excluded, from `ifconfig -a`.
fn own_ipv4_addresses() -> Vec<Ipv4Addr> {
    let Ok(output) = std::process::Command::new("/sbin/ifconfig")
        .arg("-a")
        .output()
    else {
        return Vec::new();
    };
    let mut addresses: Vec<Ipv4Addr> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with([' ', '\t']))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("inet")).then_some(words.next()?.parse().ok()?)
        })
        .filter(|address: &Ipv4Addr| !address.is_loopback())
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// Use a native socket so connection completion and network EOF are independent of
/// a netcat process's stdin lifetime. A timeout is a test failure, not closure.
fn connect_from(from: Ipv4Addr, to: Ipv4Addr, port: u16) -> io::Result<TcpStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.bind(&SocketAddr::from((from, 0)).into())?;
    socket.connect_timeout(&SocketAddr::from((to, port)).into(), Duration::from_secs(2))?;
    Ok(socket.into())
}

fn require_closed(stream: &mut TcpStream) -> io::Result<()> {
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            ErrorKind::InvalidData,
            "a closed connection must send no byte",
        )),
    }
}

#[test]
fn a_read_timeout_does_not_count_as_a_closed_connection() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let mut client = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
    let (held, _) = listener.accept().expect("accept");
    client
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let error = require_closed(&mut client).expect_err("an open, silent socket is not closed");
    assert!(
        matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock),
        "{error}"
    );
    drop(held);
    require_closed(&mut client).expect("actual network EOF is closure");
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let begin = Instant::now();
    while !condition() {
        assert!(
            begin.elapsed() < Duration::from_secs(3),
            "gave up waiting: {what}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_connection_from_any_address_of_the_mac_is_closed_at_once() {
    // A listener on all addresses, as in the app, and the same listener that serves
    // local peers, to show that the connection works when nothing refuses it.
    let closed = env_with(|options| {
        options.allow_local_peers = false;
        options.bind = Ipv4Addr::UNSPECIFIED;
    });
    let open = env_with(|options| {
        options.allow_local_peers = true;
        options.bind = Ipv4Addr::UNSPECIFIED;
    });
    let addresses = own_ipv4_addresses();
    if addresses.is_empty() {
        // A host with only loopback is covered by the real loopback rejection test.
        // The server unit tests also cover two distinct addresses of one host.
        return;
    }
    for (index, to) in addresses.iter().enumerate() {
        // Prefer a distinct local source on a host with multiple interfaces. Check the
        // same route with the permitted listener before attributing a failure to the
        // guard: a Docker or VPN route can block even a connection to a local address.
        let from = addresses[(index + 1) % addresses.len()];
        let mut held = match connect_from(from, *to, open.handle.port()) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!(
                    "local route {from} -> {to} is unavailable: {error}; checking the same-interface route"
                );
                connect_from(*to, *to, open.handle.port())
                    .expect("same-interface control connection")
            }
        };
        let from = match held.local_addr().expect("bound source").ip() {
            std::net::IpAddr::V4(address) => address,
            other => panic!("expected an IPv4 source: {other}"),
        };
        wait_until("the bound control connection is served", || {
            open.handle.open_connections() == 1
        });
        held.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("control timeout");
        let error = require_closed(&mut held)
            .expect_err("the permitted listener keeps this connection open");
        assert!(
            matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock),
            "{from} -> {to}: {error}"
        );
        drop(held);
        wait_until("the control connection ended", || {
            open.handle.open_connections() == 0
        });

        let mut rejected = connect_from(from, *to, closed.handle.port())
            .expect("the control proved this route connects");
        rejected
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("rejection timeout");
        let begin = Instant::now();
        require_closed(&mut rejected).unwrap_or_else(|error| {
            panic!("the connection from {from} to {to} must close at once: {error}")
        });
        assert!(begin.elapsed() < Duration::from_secs(2));
        assert_eq!(closed.handle.open_connections(), 0);
        eprintln!("local TCP route {from} -> {to}: control stays open, guarded listener closes");

        // Also verify the OS-selected source for each local destination.
        let mut plain = TcpStream::connect_timeout(
            &SocketAddr::from((*to, closed.handle.port())),
            Duration::from_secs(2),
        )
        .expect("plain connect");
        plain
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("plain timeout");
        require_closed(&mut plain).expect("the connection with the OS-selected source closes");
        assert_eq!(closed.handle.open_connections(), 0);
    }
}

#[test]
fn a_large_head_or_body_is_too_large() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let big_header = ("x-pad".to_owned(), "a".repeat(9 * 1024));
    let reply = env.send(&http_request("GET", "/v1/status", &[big_header], b""));
    assert_eq!((reply.status, reply.code().as_str()), (413, "too_large"));
    // A head of 9 KiB from a paired phone is refused as well.
    let mut head = signed_bytes(&phone, "GET", "/v1/status", b"", &Bend::default());
    head.truncate(head.len() - 2);
    head.extend_from_slice(format!("X-Pad: {}\r\n\r\n", "a".repeat(9 * 1024)).as_bytes());
    assert_eq!(env.send(&head).status, 413);
    // A body over 16 KiB: the answer comes from the header, before the body.
    let body = vec![b'a'; 20 * 1024];
    let reply = env.send(&http_request("POST", "/v1/pair", &[], &body));
    assert_eq!((reply.status, reply.code().as_str()), (413, "too_large"));
    let reply = env.send(&http_request(
        "POST",
        "/v1/pair",
        &[],
        &vec![b'a'; 16 * 1024 + 1],
    ));
    assert_eq!(reply.status, 413);
    // A body of exactly 16 KiB is read. It is not a pair request, so it is a 400.
    let reply = env.send(&http_request(
        "POST",
        "/v1/pair",
        &[],
        &vec![b'a'; 16 * 1024],
    ));
    assert_eq!((reply.status, reply.code().as_str()), (400, "bad_request"));
}

#[test]
fn transfer_encoding_and_http_10_are_refused() {
    let env = env();
    for raw in [
        &b"POST /v1/pair HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"[..],
        b"POST /v1/pair HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        b"GET /v1/status HTTP/1.0\r\n\r\n",
        b"GET /v1/status HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
        b"GET /v1/status\r\n\r\n",
        b"GET /v1/status HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
    ] {
        let reply = env.send(raw);
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (400, "bad_request"),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[test]
fn a_slow_head_and_a_slow_body_run_out_of_total_time() {
    let env = env_with(|options| {
        options.timeouts.head = Duration::from_millis(400);
        options.timeouts.body = Duration::from_millis(400);
    });
    // Nothing is sent: the connection ends at the head deadline.
    let mut idle = tls_stream(env.handle.port(), &env.client);
    idle.write_all(b"GET /v1/status HTTP/1.1\r\n")
        .expect("partial head");
    idle.flush().expect("flush");
    let begin = Instant::now();
    assert!(
        read_answer(&mut idle).is_err(),
        "no answer for a head that never ends"
    );
    assert!(
        begin.elapsed() < Duration::from_secs(3),
        "{:?}",
        begin.elapsed()
    );

    // One byte every 100 ms keeps every single read alive. The total deadline ends it.
    for body_case in [false, true] {
        let mut tls = tls_stream(env.handle.port(), &env.client);
        let begin = Instant::now();
        let script: Vec<u8> = if body_case {
            b"POST /v1/pair HTTP/1.1\r\nContent-Length: 200\r\n\r\n{".to_vec()
        } else {
            b"GET /v1/status HTTP/1.1\r\nX-Slow: ".to_vec()
        };
        tls.write_all(&script).expect("start");
        tls.flush().expect("flush");
        let mut stopped_early = false;
        for _ in 0..100 {
            thread::sleep(Duration::from_millis(100));
            if tls.write_all(b"a").and_then(|()| tls.flush()).is_err() {
                stopped_early = true;
                break;
            }
        }
        let answered = read_answer(&mut tls).is_ok();
        assert!(!answered, "no answer for a slow request");
        assert!(
            stopped_early || begin.elapsed() < Duration::from_secs(20),
            "the connection ended"
        );
        assert!(
            begin.elapsed() < Duration::from_secs(12),
            "the total deadline ended the dribble (body case: {body_case})"
        );
        // The deadline ended it long before 100 bytes could have been sent.
        assert!(
            stopped_early,
            "the writes failed after the deadline (body case: {body_case})"
        );
    }
    assert_eq!(
        env.send(&http_request("GET", "/v1/nothing", &[], b""))
            .status,
        404
    );
}

#[test]
fn at_most_four_connections_from_one_address() {
    let env = env();
    let port = env.handle.port();
    let held: Vec<TcpStream> = (0..4).map(|_| tcp(port)).collect();
    let begin = Instant::now();
    while env.handle.open_connections() < 4 {
        assert!(begin.elapsed() < Duration::from_secs(5), "the slots fill");
        thread::sleep(Duration::from_millis(5));
    }
    // The fifth is closed at once, before a handshake.
    let mut fifth = tcp(port);
    let mut byte = [0u8; 1];
    assert!(fifth.read(&mut byte).map_or(true, |read| read == 0));
    assert_eq!(env.handle.open_connections(), 4);
    // A slot frees when a connection closes.
    drop(held);
    let begin = Instant::now();
    loop {
        if let Ok(reply) = try_exchange(
            port,
            &env.client,
            &http_request("GET", "/v1/nothing", &[], b""),
        ) {
            assert_eq!(reply.status, 404);
            break;
        }
        assert!(begin.elapsed() < Duration::from_secs(10), "a slot frees");
        thread::sleep(Duration::from_millis(50));
    }
}

// ----- rates -----

#[test]
fn unsigned_requests_are_limited_per_address_and_a_correct_poll_and_a_paired_phone_are_not() {
    let env = env();
    let phone = Phone::paired(&env, OTHER_DEVICE);
    let controller = env.handle.pairing().clone();
    let secret = env.open_window();
    let pairing_phone = Phone::new(DEVICE);
    let proof = pairing_phone.proof("Test iPhone", &secret);
    // A paired phone with valid signatures does not use the budget of the address.
    for n in 0..40 {
        let reply = env.get(&phone, "/v1/status");
        assert_eq!(reply.status, 200, "request {n}: {}", reply.body);
    }
    // The pair request has no signature: it is the first of 30.
    assert_eq!(
        env.send(&json_post(
            "/v1/pair",
            &pairing_phone.pair_body("Test iPhone", &secret)
        ))
        .status,
        200
    );
    // Polls with the right proof are not counted.
    for _ in 0..40 {
        assert_eq!(env.pair_status(&pairing_phone, &proof).status, 200);
    }
    // Wrong polls are counted: 29 more answers, then 429.
    let wrong = b64u(&[5u8; 32]);
    for n in 0..29 {
        assert_eq!(
            env.pair_status(&pairing_phone, &wrong).status,
            404,
            "answer {n}"
        );
    }
    let reply = env.pair_status(&pairing_phone, &wrong);
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (429, "too_many_requests")
    );
    let reply = env.send(&http_request("GET", "/v1/nothing", &[], b""));
    assert_eq!(reply.status, 429);
    // The right poll still gets through: it is not counted, and it needs no vault.
    assert_eq!(env.pair_status(&pairing_phone, &proof).status, 200);
    // Every other route is decided before the signature: an address past its budget
    // gets 429 also for a request that is signed right (contract section 3).
    let reply = env.get(&phone, "/v1/status");
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (429, "too_many_requests")
    );
    let bad = env.signed(
        &phone,
        "GET",
        "/v1/status",
        b"",
        &Bend {
            approval_key: true,
            ..Bend::default()
        },
    );
    assert_eq!(bad.status, 429);
    controller.cancel();
}

#[test]
fn an_address_past_its_unsigned_budget_costs_no_vault_work() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    // A bad signature is an unsigned answer: 30 of them use the budget.
    for n in 0..30 {
        let bad = env.signed(
            &phone,
            "GET",
            "/v1/status",
            b"",
            &Bend {
                approval_key: true,
                ..Bend::default()
            },
        );
        assert_eq!(bad.status, 401, "answer {n}");
    }
    // Hold the vault mutex, as the UI thread can. Any vault query now waits for it.
    // The answer must come without one, so it comes while the mutex is held.
    let guard = env.fx.shared.lock().expect("vault mutex");
    let begin = Instant::now();
    let signed = env.get(&phone, "/v1/status");
    let unknown_device = env.signed(
        &Phone::new(OTHER_DEVICE),
        "GET",
        "/v1/inbox",
        b"",
        &Bend::default(),
    );
    let malformed = env.send(&http_request("GET", "/v1/inbox", &[], b""));
    let elapsed = begin.elapsed();
    drop(guard);
    for reply in [&signed, &unknown_device, &malformed] {
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (429, "too_many_requests")
        );
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "the answers waited for the vault: {elapsed:?}"
    );
    // The refused request did not touch the device.
    env.fx.with(|vault| {
        let device = vault
            .companion_device(DEVICE)
            .expect("device")
            .expect("paired");
        assert_eq!(device.last_seen_at, None);
    });
}

#[test]
fn a_paired_device_gets_120_requests_per_minute() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let other = Phone::paired(&env, OTHER_DEVICE);
    for n in 0..120 {
        let reply = env.get(&phone, "/v1/status");
        assert_eq!(reply.status, 200, "request {n}: {}", reply.body);
    }
    let reply = env.get(&phone, "/v1/status");
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (429, "too_many_requests")
    );
    // Another device has its own count.
    assert_eq!(env.get(&other, "/v1/status").status, 200);
    // An unsigned answer is not counted against a device: the address still has its 30.
    assert_eq!(
        env.send(&http_request("GET", "/v1/nothing", &[], b""))
            .status,
        404
    );
}

#[test]
fn a_request_refused_for_the_device_rate_records_no_nonce_and_no_last_seen() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    for n in 0..120 {
        let reply = env.get(&phone, "/v1/status");
        assert_eq!(reply.status, 200, "request {n}: {}", reply.body);
    }
    let seen = env.fx.with(|vault| {
        vault
            .companion_device(DEVICE)
            .expect("device")
            .expect("paired")
            .last_seen_at
            .expect("seen")
    });
    // "Last seen" has a resolution of one second: wait until a write would show.
    while now() <= seen {
        thread::sleep(Duration::from_millis(50));
    }
    let raw = signed_bytes(&phone, "GET", "/v1/status", b"", &Bend::default());
    let first = env.send(&raw);
    assert_eq!(
        (first.status, first.code().as_str()),
        (429, "too_many_requests")
    );
    // The same bytes again, with the same nonce. Had the first one recorded its nonce,
    // this would be a reused nonce (401). It is the same 429.
    let again = env.send(&raw);
    assert_eq!(
        (again.status, again.code().as_str()),
        (429, "too_many_requests")
    );
    env.fx.with(|vault| {
        let device = vault
            .companion_device(DEVICE)
            .expect("device")
            .expect("paired");
        assert_eq!(device.last_seen_at, Some(seen), "a 429 changes nothing");
    });
}

#[test]
fn concurrent_requests_with_one_nonce_pass_only_once() {
    let env = env();
    let phone = Phone::paired(&env, DEVICE);
    let raw = signed_bytes(&phone, "GET", "/v1/status", b"", &Bend::default());
    let port = env.handle.port();
    let client = Arc::clone(&env.client);
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let threads: Vec<_> = (0..3)
        .map(|_| {
            let (raw, client, statuses) = (raw.clone(), Arc::clone(&client), Arc::clone(&statuses));
            thread::spawn(move || {
                let reply = try_exchange(port, &client, &raw).expect("answer");
                statuses.lock().expect("statuses").push(reply.status);
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("thread");
    }
    let mut statuses = statuses.lock().expect("statuses").clone();
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 401, 401]);
}
