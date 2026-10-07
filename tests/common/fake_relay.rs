//! An in-process fake of the Apassy relay for the sync tests (contract relay-sync-v1).
//!
//! It speaks plain HTTP/1.1 on 127.0.0.1, one thread per connection, and keeps
//! everything in memory: teams, devices, link codes, tokens, heads, and snapshots. It
//! checks what the real relay checks on a push (section 9) with `ring` directly, not
//! with the app's code, and it answers every call in the JSON envelope. It is not the
//! relay crate: the app must not depend on it (another license).
//!
//! Test hooks change its state the way a broken or hostile relay would: roll back to an
//! older version, replace the newest heads with a forged chain, damage a snapshot, run a
//! push of another Mac in the middle of a push, lower the size limit, answer slowly,
//! fail the next requests, or answer every long poll at once.
//!
//! The chain answer follows the relay's rule: the oldest 1000 heads after `since`, with
//! the signers of the page (a removed device with the newest version it pushed).
//!
//! The engine tests (`tests/relay_sync.rs`) and the headless app tests
//! (`src/desktop/ui/sync_tests.rs`) both include this file with `#[path]`. Each names the
//! sync module of the app `relay_api` in the parent module: `apassy::sync` in an
//! integration test, `crate::sync` in the library.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::relay_api::{
    HeadFields, NO_PREVIOUS, decode_b64u, encode_b64u, safety_words, sha256_hex,
};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde_json::{Value, json};

/// The size limit of the real relay: 64 MiB.
pub const SYNC_BYTES: u64 = 67_108_864;

type Hook = Box<dyn FnOnce() + Send>;

#[derive(Clone)]
struct Device {
    id: u64,
    name: String,
    public_key: Vec<u8>,
    live: bool,
}

#[derive(Clone, PartialEq, Eq)]
enum LinkState {
    Pending,
    Confirmed,
    Refused,
}

#[derive(Clone)]
struct Link {
    id: u64,
    code: String,
    device_name: String,
    public_key: Vec<u8>,
    safety: String,
    state: LinkState,
}

/// One head on the relay: its b64u text and signature, and the device that pushed it.
#[derive(Clone)]
pub struct StoredHead {
    pub version: u64,
    pub text: String,
    pub signature: Vec<u8>,
    pub device_id: u64,
}

impl StoredHead {
    pub fn hash(&self) -> String {
        sha256_hex(self.text.as_bytes())
    }
}

#[derive(Default)]
struct Team {
    name: String,
    devices: Vec<Device>,
    codes: Vec<String>,
    links: Vec<Link>,
    heads: Vec<StoredHead>,
    snapshots: BTreeMap<u64, Vec<u8>>,
    receipts: BTreeMap<u64, u64>,
}

impl Team {
    fn version(&self) -> u64 {
        self.heads.last().map_or(0, |head| head.version)
    }

    fn device(&self, id: u64) -> Option<&Device> {
        self.devices
            .iter()
            .find(|device| device.id == id && device.live)
    }
}

#[derive(Default)]
struct Relay {
    origin: String,
    team_codes: Vec<String>,
    teams: BTreeMap<String, Team>,
    tokens: BTreeMap<String, (String, u64)>,
    nonces: BTreeMap<String, (String, Vec<u8>)>,
    next_team: u64,
    next_device: u64,
    next_link: u64,
    next_secret: u64,
    max_bytes: u64,
    log: Vec<String>,
    before_put: Option<Hook>,
    stopped: bool,
    /// Requests that start with the prefix wait this long before the answer.
    delays: Vec<(String, Duration)>,
    /// The next requests that start with the prefix fail with this status.
    failures: Vec<(String, usize, u16)>,
    /// A long poll answers at once, as a second poll of one device does.
    polls_at_once: bool,
    /// The `since` of the last head request.
    last_since: Option<u64>,
    /// The next requests that start with the prefix get no answer after the relay did
    /// them: the answer is lost on the network.
    lost_answers: Vec<(String, usize)>,
    /// The seconds that a new access token lasts; 0 is the relay's 900.
    token_seconds: u64,
}

/// A running fake relay. It stops when dropped.
pub struct FakeRelay {
    /// The origin, `http://127.0.0.1:<port>`.
    pub url: String,
    shared: Arc<(Mutex<Relay>, Condvar)>,
}

fn lock(relay: &Mutex<Relay>) -> MutexGuard<'_, Relay> {
    relay.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .is_ok()
}

/// 64 lowercase hex characters that differ for each call.
fn secret_hex(counter: u64) -> String {
    sha256_hex(format!("fake-relay-secret-{counter}-{}", now()).as_bytes())
}

impl FakeRelay {
    /// Start a fake relay on a free port of 127.0.0.1.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake relay");
        let url = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        );
        let shared = Arc::new((
            Mutex::new(Relay {
                origin: url.clone(),
                next_device: 1,
                next_link: 1,
                max_bytes: SYNC_BYTES,
                ..Relay::default()
            }),
            Condvar::new(),
        ));
        let server = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                if lock(&server.0).stopped {
                    return;
                }
                let server = Arc::clone(&server);
                std::thread::spawn(move || handle(&server, stream));
            }
        });
        Self { url, shared }
    }

    /// Add an operator team code: `apassy_tcd_<64 hex>`.
    pub fn team_code(&self) -> String {
        let mut relay = lock(&self.shared.0);
        relay.next_secret += 1;
        let code = format!("apassy_tcd_{}", secret_hex(relay.next_secret));
        relay.team_codes.push(code.clone());
        code
    }

    /// The origin that the challenge reports (a relay behind another address).
    pub fn set_origin(&self, origin: &str) {
        lock(&self.shared.0).origin = origin.to_owned();
    }

    /// The seconds that each new access token lasts (the relay's: 900).
    pub fn set_token_lifetime(&self, seconds: u64) {
        lock(&self.shared.0).token_seconds = seconds;
    }

    /// The size limit of a push (`sync_bytes`).
    pub fn set_max_bytes(&self, bytes: u64) {
        lock(&self.shared.0).max_bytes = bytes;
    }

    /// Run `hook` when the next push arrives, before the relay looks at it: another Mac
    /// pushes in the middle.
    pub fn on_next_put(&self, hook: impl FnOnce() + Send + 'static) {
        lock(&self.shared.0).before_put = Some(Box::new(hook));
    }

    /// Answer each request that starts with `prefix` (`"GET /v1/sync/snapshot"`) after
    /// `delay`: a slow transfer.
    pub fn delay(&self, prefix: &str, delay: Duration) {
        lock(&self.shared.0).delays.push((prefix.to_owned(), delay));
    }

    /// Fail the next `count` requests that start with `prefix` with `status`: 502 is a
    /// text body (a Worker without a relay), 429 has `Retry-After: 2`, others a JSON
    /// error.
    pub fn fail_next(&self, prefix: &str, count: usize, status: u16) {
        lock(&self.shared.0)
            .failures
            .push((prefix.to_owned(), count, status));
    }

    /// Do the next `count` requests that start with `prefix`, then close the connection
    /// without an answer: the answer is lost on the network.
    pub fn lose_next_answers(&self, prefix: &str, count: usize) {
        lock(&self.shared.0)
            .lost_answers
            .push((prefix.to_owned(), count));
    }

    /// Answer every long poll at once, as the relay does for a second poll of one
    /// device or while it stops.
    pub fn answer_polls_at_once(&self, at_once: bool) {
        lock(&self.shared.0).polls_at_once = at_once;
    }

    /// Damage the stored bytes of `version`: its head no longer matches them.
    pub fn corrupt_snapshot(&self, version: u64) {
        let id = self.team_id();
        let mut relay = lock(&self.shared.0);
        let team = relay.teams.get_mut(&id).expect("team");
        let bytes = team.snapshots.get_mut(&version).expect("snapshot");
        bytes[0] ^= 0xff;
    }

    /// The receipts of the only team: device id and the version it merged.
    pub fn receipts(&self) -> BTreeMap<u64, u64> {
        let id = self.team_id();
        lock(&self.shared.0).teams[&id].receipts.clone()
    }

    /// The pending links of the only team.
    pub fn pending_links(&self) -> usize {
        let id = self.team_id();
        lock(&self.shared.0).teams[&id]
            .links
            .iter()
            .filter(|link| link.state == LinkState::Pending)
            .count()
    }

    /// Each request so far: `METHOD path`.
    pub fn log(&self) -> Vec<String> {
        lock(&self.shared.0).log.clone()
    }

    /// The `since` of the last head request (`GET /v1/sync/head?since=N`).
    pub fn last_since(&self) -> Option<u64> {
        lock(&self.shared.0).last_since
    }

    /// The number of requests that start with `prefix` (`"PUT /v1/sync/snapshot"`).
    pub fn count(&self, prefix: &str) -> usize {
        self.log()
            .iter()
            .filter(|line| line.starts_with(prefix))
            .count()
    }

    /// The only team.
    fn team_id(&self) -> String {
        lock(&self.shared.0)
            .teams
            .keys()
            .next()
            .cloned()
            .expect("a team")
    }

    /// The current version of the only team.
    pub fn version(&self) -> u64 {
        let id = self.team_id();
        lock(&self.shared.0).teams[&id].version()
    }

    /// The heads of the only team, oldest first.
    pub fn heads(&self) -> Vec<StoredHead> {
        let id = self.team_id();
        lock(&self.shared.0).teams[&id].heads.clone()
    }

    /// A relay restored from an older backup: every head after `version` goes.
    pub fn roll_back_to(&self, version: u64) {
        let id = self.team_id();
        let mut relay = lock(&self.shared.0);
        let team = relay.teams.get_mut(&id).expect("team");
        team.heads.retain(|head| head.version <= version);
        team.snapshots.retain(|stored, _| *stored <= version);
    }

    /// A forged history: the heads from `heads[0].version` on are replaced, with their
    /// snapshots. The heads are trusted as they are.
    pub fn replace_from(&self, heads: Vec<(StoredHead, Vec<u8>)>) {
        let id = self.team_id();
        let first = heads.first().expect("a head").0.version;
        let mut relay = lock(&self.shared.0);
        let team = relay.teams.get_mut(&id).expect("team");
        team.heads.retain(|head| head.version < first);
        team.snapshots.retain(|stored, _| *stored < first);
        for (head, bytes) in heads {
            team.snapshots.insert(head.version, bytes);
            team.heads.push(head);
        }
        self.shared.1.notify_all();
    }

    /// The live device ids of the only team.
    pub fn devices(&self) -> Vec<u64> {
        let id = self.team_id();
        lock(&self.shared.0).teams[&id]
            .devices
            .iter()
            .filter(|device| device.live)
            .map(|device| device.id)
            .collect()
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        lock(&self.shared.0).stopped = true;
        self.shared.1.notify_all();
        // Wake the accept loop so that it sees the stop.
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
    }
}

/// One request.
struct Incoming {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Incoming {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// An answer: a status, headers, and a body.
struct Outgoing {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn ok(result: Value) -> Outgoing {
    Outgoing {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(&json!({"ok": true, "result": result})).unwrap(),
    }
}

fn fail(status: u16, code: &str) -> Outgoing {
    Outgoing {
        status,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(
            &json!({"ok": false, "error": {"code": code, "message": format!("synthetic {code}")}}),
        )
        .unwrap(),
    }
}

fn read_request(stream: &TcpStream) -> Option<Incoming> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.trim_end().split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" {
            break;
        }
        let (name, value) = line.trim_end().split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query),
        None => (target.clone(), ""),
    };
    let query = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    Some(Incoming {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn handle(shared: &Arc<(Mutex<Relay>, Condvar)>, mut stream: TcpStream) {
    let Some(request) = read_request(&stream) else {
        return;
    };
    let line = format!("{} {}", request.method, request.path);
    let (delay, failure, lost) = {
        let mut relay = lock(&shared.0);
        relay.log.push(line.clone());
        let lost = relay
            .lost_answers
            .iter_mut()
            .find(|(prefix, left)| *left > 0 && line.starts_with(prefix.as_str()))
            .map(|(_, left)| *left -= 1)
            .is_some();
        let delay = relay
            .delays
            .iter()
            .find(|(prefix, _)| line.starts_with(prefix.as_str()))
            .map(|(_, delay)| *delay);
        let failure = relay
            .failures
            .iter_mut()
            .find(|(prefix, left, _)| *left > 0 && line.starts_with(prefix.as_str()))
            .map(|(_, left, status)| {
                *left -= 1;
                *status
            });
        (delay, failure, lost)
    };
    if let Some(delay) = delay {
        std::thread::sleep(delay);
    }
    let answer = match failure {
        Some(502) => Outgoing {
            status: 502,
            headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
            body: b"relay unreachable".to_vec(),
        },
        Some(429) => {
            let mut answer = fail(429, "rate_limited");
            answer
                .headers
                .push(("Retry-After".to_owned(), "2".to_owned()));
            answer
        }
        Some(503) => fail(503, "busy"),
        Some(status) => fail(status, "relay_error"),
        None => route(shared, &request),
    };
    if lost {
        return;
    }
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        answer.status,
        answer.body.len()
    );
    for (name, value) in &answer.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&answer.body);
    let _ = stream.flush();
}

/// The team and the device of the bearer token, when the device is live.
fn caller(relay: &Relay, request: &Incoming) -> Option<(String, u64)> {
    let token = request.header("authorization")?.strip_prefix("Bearer ")?;
    let (team, device) = relay.tokens.get(token)?.clone();
    relay.teams.get(&team)?.device(device)?;
    Some((team, device))
}

/// The signers of `devices`: the key, and for a removed device the newest version it
/// pushed.
fn signers(team: &Team, devices: &[u64]) -> Vec<Value> {
    let mut ids = devices.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids.iter()
        .filter_map(|id| team.devices.iter().find(|device| device.id == *id))
        .map(|device| {
            let mut signer = json!({"device_id": device.id,
                                    "public_key": encode_b64u(&device.public_key)});
            if !device.live {
                signer["removed"] = json!(true);
                if let Some(last) = team
                    .heads
                    .iter()
                    .filter(|head| head.device_id == device.id)
                    .map(|head| head.version)
                    .max()
                {
                    signer["last_version"] = json!(last);
                }
            }
            signer
        })
        .collect()
}

fn head_view(team: &Team, since: u64) -> Value {
    let version = team.version();
    let receipts: Vec<Value> = team
        .receipts
        .iter()
        .map(|(device, merged)| json!({"device_id": device, "device_name": "", "version": merged, "at": now()}))
        .collect();
    let Some(current) = team.heads.last() else {
        return json!({"version": 0, "chain": [], "receipts": receipts});
    };
    let page: Vec<&StoredHead> = team
        .heads
        .iter()
        .filter(|head| head.version > since)
        .take(1000)
        .collect();
    let mut signed: Vec<u64> = page.iter().map(|head| head.device_id).collect();
    signed.push(current.device_id);
    let chain: Vec<Value> = page
        .iter()
        .map(|head| {
            json!({"version": head.version, "head": encode_b64u(head.text.as_bytes()),
                   "signature": encode_b64u(&head.signature), "device_id": head.device_id,
                   "pushed_at": now()})
        })
        .collect();
    let mut view = json!({
        "version": version,
        "head": encode_b64u(current.text.as_bytes()),
        "signature": encode_b64u(&current.signature),
        "device_id": current.device_id,
        "device_name": "",
        "pushed_at": now(),
        "chain": chain,
        "receipts": receipts,
        "signers": signers(team, &signed),
    });
    if let Some(first) = team.heads.iter().find(|head| head.version > since) {
        view["chain_from"] = json!(first.version);
    }
    view
}

fn device_view(device: &Device, current: u64) -> Value {
    json!({"id": device.id, "member_id": 1, "member_name": "owner", "name": device.name,
           "public_key": encode_b64u(&device.public_key), "key_holder": device.id == 1,
           "created_at": now(), "last_seen_at": now(), "current": device.id == current})
}

fn route(shared: &Arc<(Mutex<Relay>, Condvar)>, request: &Incoming) -> Outgoing {
    let (mutex, changed) = &**shared;
    let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
    match (request.method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "teams"]) => {
            let body = request.json();
            let mut relay = lock(mutex);
            let code = body["code"].as_str().unwrap_or_default().to_owned();
            let Some(at) = relay.team_codes.iter().position(|known| *known == code) else {
                return fail(403, "invite_invalid");
            };
            relay.team_codes.remove(at);
            let Some(public_key) = body["public_key"].as_str().and_then(decode_b64u) else {
                return fail(400, "invalid_request");
            };
            relay.next_team += 1;
            // A relay team id: `t_` and 10 characters of `a-z2-7`.
            let team_id: String = format!("t_fake{:06}", relay.next_team)
                .chars()
                .map(|ch| match ch.to_digit(10) {
                    Some(digit) => char::from(b'a' + digit as u8),
                    None => ch,
                })
                .collect();
            let device_id = relay.next_device;
            relay.next_device += 1;
            relay.teams.insert(
                team_id.clone(),
                Team {
                    name: body["team"].as_str().unwrap_or_default().to_owned(),
                    devices: vec![Device {
                        id: device_id,
                        name: body["device_name"].as_str().unwrap_or_default().to_owned(),
                        public_key,
                        live: true,
                    }],
                    ..Team::default()
                },
            );
            ok(json!({"team_id": team_id, "member_id": 1, "device_id": device_id}))
        }
        ("POST", ["v1", "auth", "challenge"]) => {
            if request.header("authorization").is_some() {
                return fail(401, "unauthenticated");
            }
            let body = request.json();
            let mut relay = lock(mutex);
            let team_id = body["team_id"].as_str().unwrap_or_default().to_owned();
            let Some(public_key) = body["public_key"].as_str().and_then(decode_b64u) else {
                return fail(400, "invalid_request");
            };
            let Some(team) = relay.teams.get(&team_id) else {
                return fail(401, "unauthenticated");
            };
            let live = team
                .devices
                .iter()
                .any(|device| device.live && device.public_key == public_key);
            if !live {
                return match team.links.iter().find(|link| link.public_key == public_key) {
                    Some(link) if link.state == LinkState::Pending => fail(403, "join_pending"),
                    Some(link) if link.state == LinkState::Refused => fail(403, "join_refused"),
                    _ => fail(401, "unauthenticated"),
                };
            }
            relay.next_secret += 1;
            let nonce: Vec<u8> = decode_hex(&secret_hex(relay.next_secret));
            let nonce = encode_b64u(&nonce);
            relay.nonces.insert(nonce.clone(), (team_id, public_key));
            let origin = relay.origin.clone();
            ok(json!({"nonce": nonce, "expires_at": now() + 60, "origin": origin}))
        }
        ("POST", ["v1", "auth", "token"]) => {
            let body = request.json();
            let mut relay = lock(mutex);
            let nonce = body["nonce"].as_str().unwrap_or_default().to_owned();
            let Some((team_id, public_key)) = relay.nonces.remove(&nonce) else {
                return fail(401, "unauthenticated");
            };
            let public_b64u = encode_b64u(&public_key);
            let message = format!(
                "apassy-relay sign-in v1\0{}\0{team_id}\0{public_b64u}\0{nonce}",
                relay.origin
            );
            let signature = body["signature"]
                .as_str()
                .and_then(decode_b64u)
                .unwrap_or_default();
            if body["team_id"] != json!(team_id)
                || body["public_key"] != json!(public_b64u)
                || !verify(&public_key, message.as_bytes(), &signature)
            {
                return fail(401, "unauthenticated");
            }
            let device_id = relay.teams[&team_id]
                .devices
                .iter()
                .find(|device| device.live && device.public_key == public_key)
                .map(|device| device.id)
                .expect("live device");
            relay.next_secret += 1;
            let token = format!("apassy_acc_{team_id}_{}", secret_hex(relay.next_secret));
            relay
                .tokens
                .insert(token.clone(), (team_id.clone(), device_id));
            let team = relay.teams[&team_id].name.clone();
            let lifetime = match relay.token_seconds {
                0 => 900,
                seconds => seconds,
            };
            ok(
                json!({"token": token, "expires_at": now() + lifetime, "team_id": team_id,
                      "team": team, "member_id": 1, "member_name": "owner", "role": "owner",
                      "device_id": device_id, "key_holder": device_id == 1}),
            )
        }
        ("POST", ["v1", "devices", "link"]) => {
            if request.header("authorization").is_some() {
                return fail(401, "unauthenticated");
            }
            let body = request.json();
            let mut relay = lock(mutex);
            let code = body["code"].as_str().unwrap_or_default().to_owned();
            let Some(team_id) = code
                .strip_prefix("apassy_lnk_")
                .and_then(|rest| rest.get(..12))
                .map(str::to_owned)
            else {
                return fail(403, "forbidden");
            };
            let Some(public_key) = body["public_key"].as_str().and_then(decode_b64u) else {
                return fail(400, "invalid_request");
            };
            relay.next_link += 1;
            let id = relay.next_link;
            let Some(team) = relay.teams.get_mut(&team_id) else {
                return fail(403, "forbidden");
            };
            let Some(at) = team.codes.iter().position(|known| *known == code) else {
                // The same code with the same key again (a retry after a network
                // error) gets the same answer.
                let Some(link) = team.links.iter().find(|link| {
                    link.code == code
                        && link.public_key == public_key
                        && link.state == LinkState::Pending
                }) else {
                    return fail(403, "forbidden");
                };
                let name = team.name.clone();
                return ok(json!({"id": link.id, "team_id": team_id, "team": name,
                          "safety": link.safety, "expires_at": now() + 600, "by": "owner"}));
            };
            team.codes.remove(at);
            let safety = safety_words(&team_id, &code, &public_key);
            team.links.push(Link {
                id,
                code: code.clone(),
                device_name: body["device_name"].as_str().unwrap_or_default().to_owned(),
                public_key,
                safety: safety.clone(),
                state: LinkState::Pending,
            });
            let name = team.name.clone();
            ok(
                json!({"id": id, "team_id": team_id, "team": name, "safety": safety,
                      "expires_at": now() + 600, "by": "owner"}),
            )
        }
        ("POST", ["v1", "devices", "link", "cancel"]) => {
            if request.header("authorization").is_some() {
                return fail(401, "unauthenticated");
            }
            let body = request.json();
            let mut relay = lock(mutex);
            let code = body["code"].as_str().unwrap_or_default().to_owned();
            let public_key = body["public_key"]
                .as_str()
                .and_then(decode_b64u)
                .unwrap_or_default();
            let found = relay.teams.values_mut().find_map(|team| {
                team.links
                    .iter_mut()
                    .find(|link| link.code == code && link.public_key == public_key)
            });
            match found {
                Some(link) if link.state == LinkState::Confirmed => fail(409, "conflict"),
                Some(link) => {
                    link.state = LinkState::Refused;
                    ok(json!({"id": link.id}))
                }
                None => fail(403, "forbidden"),
            }
        }
        (method, ["v1", ..]) => {
            let mut relay = lock(mutex);
            let Some((team_id, device_id)) = caller(&relay, request) else {
                return fail(401, "unauthenticated");
            };
            match (method, &segments[1..]) {
                ("GET", ["devices"]) => {
                    let team = &relay.teams[&team_id];
                    let devices: Vec<Value> = team
                        .devices
                        .iter()
                        .filter(|device| device.live)
                        .map(|device| device_view(device, device_id))
                        .collect();
                    ok(json!(devices))
                }
                ("DELETE", ["devices", id]) => {
                    let id: u64 = id.parse().unwrap_or(0);
                    let team = relay.teams.get_mut(&team_id).expect("team");
                    // As the relay: the last device of the (one) owner stays.
                    let others = team
                        .devices
                        .iter()
                        .filter(|device| device.live && device.id != id)
                        .count();
                    if others == 0 {
                        return fail(409, "conflict");
                    }
                    match team
                        .devices
                        .iter_mut()
                        .find(|device| device.id == id && device.live)
                    {
                        Some(device) => {
                            device.live = false;
                            relay.tokens.retain(|_, (_, device)| *device != id);
                            ok(json!({}))
                        }
                        None => fail(404, "not_found"),
                    }
                }
                ("POST", ["devices", "links"]) => {
                    relay.next_secret += 1;
                    let code = format!("apassy_lnk_{team_id}_{}", secret_hex(relay.next_secret));
                    relay
                        .teams
                        .get_mut(&team_id)
                        .expect("team")
                        .codes
                        .push(code.clone());
                    ok(json!({"secret": code, "expires_at": now() + 600}))
                }
                ("GET", ["devices", "links"]) => {
                    let links: Vec<Value> = relay.teams[&team_id]
                        .links
                        .iter()
                        .filter(|link| link.state == LinkState::Pending)
                        .map(|link| {
                            json!({"id": link.id, "device_name": link.device_name,
                                   "public_key": encode_b64u(&link.public_key),
                                   "created_at": now(), "expires_at": now() + 600})
                        })
                        .collect();
                    ok(json!(links))
                }
                ("POST", ["devices", "links", id, action]) => {
                    let id: u64 = id.parse().unwrap_or(0);
                    let words = request.json()["safety"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    let next = relay.next_device;
                    let team = relay.teams.get_mut(&team_id).expect("team");
                    let Some(link) = team
                        .links
                        .iter_mut()
                        .find(|link| link.id == id && link.state == LinkState::Pending)
                    else {
                        return fail(409, "conflict");
                    };
                    if *action == "refuse" {
                        link.state = LinkState::Refused;
                        return ok(json!({}));
                    }
                    if words != link.safety {
                        return fail(409, "conflict");
                    }
                    link.state = LinkState::Confirmed;
                    let device = Device {
                        id: next,
                        name: link.device_name.clone(),
                        public_key: link.public_key.clone(),
                        live: true,
                    };
                    let view = device_view(&device, 0);
                    team.devices.push(device);
                    relay.next_device += 1;
                    ok(view)
                }
                ("GET", ["sync", "head"]) => {
                    let since: u64 = request
                        .query
                        .get("since")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    let wait: u64 = request
                        .query
                        .get("wait")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    if wait > 25 {
                        return fail(400, "invalid_request");
                    }
                    relay.last_since = Some(since);
                    if wait > 0 && !relay.polls_at_once {
                        let (guard, _) = changed
                            .wait_timeout_while(relay, Duration::from_secs(wait), |relay| {
                                !relay.stopped && relay.teams[&team_id].version() == since
                            })
                            .unwrap_or_else(PoisonError::into_inner);
                        relay = guard;
                    }
                    ok(head_view(&relay.teams[&team_id], since))
                }
                ("GET", ["sync", "snapshot"]) => {
                    let version: u64 = request
                        .query
                        .get("version")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    let team = &relay.teams[&team_id];
                    let (Some(bytes), Some(head)) = (
                        team.snapshots.get(&version),
                        team.heads.iter().find(|head| head.version == version),
                    ) else {
                        return fail(404, "not_found");
                    };
                    Outgoing {
                        status: 200,
                        headers: vec![
                            (
                                "Content-Type".to_owned(),
                                "application/octet-stream".to_owned(),
                            ),
                            ("ETag".to_owned(), format!("\"{version}\"")),
                            (
                                "X-Apassy-Sync-Head".to_owned(),
                                encode_b64u(head.text.as_bytes()),
                            ),
                            (
                                "X-Apassy-Sync-Signature".to_owned(),
                                encode_b64u(&head.signature),
                            ),
                        ],
                        body: bytes.clone(),
                    }
                }
                ("PUT", ["sync", "snapshot"]) => {
                    if let Some(hook) = relay.before_put.take() {
                        drop(relay);
                        hook();
                        relay = lock(mutex);
                    }
                    put(&mut relay, &team_id, device_id, request, changed)
                }
                ("POST", ["sync", "receipt"]) => {
                    let version = request.json()["version"].as_u64().unwrap_or(0);
                    let team = relay.teams.get_mut(&team_id).expect("team");
                    if version > team.version() {
                        return fail(409, "conflict");
                    }
                    team.receipts.insert(device_id, version);
                    ok(json!({"version": version, "at": now()}))
                }
                ("DELETE", ["sync"]) => {
                    let team = relay.teams.get_mut(&team_id).expect("team");
                    let current = team.version();
                    if request.header("if-match") != Some(&format!("\"{current}\"")) {
                        return fail(412, "precondition_failed");
                    }
                    team.heads.clear();
                    team.snapshots.clear();
                    team.receipts.clear();
                    changed.notify_all();
                    ok(json!({"last_version": current}))
                }
                _ => fail(404, "not_found"),
            }
        }
        _ => fail(404, "not_found"),
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap_or(0))
        .collect()
}

/// `PUT /v1/sync/snapshot` with the checks of the contract, in their order.
fn put(
    relay: &mut Relay,
    team_id: &str,
    device_id: u64,
    request: &Incoming,
    changed: &Condvar,
) -> Outgoing {
    let length = request.body.len() as u64;
    if length > relay.max_bytes {
        return fail(413, "payload_too_large");
    }
    let team = relay.teams.get_mut(team_id).expect("team");
    let current = team.version();
    let Some(text) = request
        .header("x-apassy-sync-head")
        .and_then(decode_b64u)
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return fail(400, "invalid_request");
    };
    let Some(signature) = request
        .header("x-apassy-sync-signature")
        .and_then(decode_b64u)
    else {
        return fail(400, "invalid_request");
    };
    let Some(fields) = HeadFields::parse(&text) else {
        return fail(400, "invalid_request");
    };
    if request.header("if-match") != Some(&format!("\"{current}\"")) {
        let mut answer = fail(412, "precondition_failed");
        answer
            .headers
            .push(("ETag".to_owned(), format!("\"{current}\"")));
        return answer;
    }
    let device = team.device(device_id).cloned().expect("live device");
    let previous = team
        .heads
        .last()
        .map_or(NO_PREVIOUS.to_owned(), StoredHead::hash);
    let same_vault = team.heads.last().is_none_or(|head| {
        HeadFields::parse(&head.text).is_some_and(|last| last.vault_id == fields.vault_id)
    });
    if fields.team_id != team_id
        || fields.device_id != device_id
        || !verify(&device.public_key, text.as_bytes(), &signature)
        || fields.version != current + 1
        || fields.previous != previous
        || !same_vault
        || fields.size != length
        || fields.snapshot_sha256 != sha256_hex(&request.body)
    {
        return fail(403, "sync_head_invalid");
    }
    team.snapshots.insert(fields.version, request.body.clone());
    team.snapshots
        .retain(|version, _| *version + 1 >= fields.version);
    team.heads.push(StoredHead {
        version: fields.version,
        text,
        signature,
        device_id,
    });
    changed.notify_all();
    let mut view = head_view(team, fields.version);
    view["chain"] = json!([]);
    ok(view)
}
