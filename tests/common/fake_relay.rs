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
//! It also speaks the question endpoints (relay-questions-v1, section 10) and does not
//! read the envelopes: it checks their shape and size, stores them as they came, and
//! gives the hooks to expire a question and to read what the app sent.
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
    questions: Vec<FakeQuestion>,
    question_seq: u64,
    /// A team made by `POST /v1/connect` (a Connect team), not by a team code.
    connect: bool,
    /// The limits of a Connect team are lifted: its first snapshot push is allowed.
    plan_lifted: bool,
}

/// One answer to a question: the envelope as the text that came.
#[derive(Clone)]
struct FakeAnswer {
    id: u64,
    device_id: u64,
    key_id: String,
    nonce: String,
    ciphertext: String,
    at: u64,
}

/// One question of a team. The nonce and the ciphertext are the b64u text that came.
#[derive(Clone)]
struct FakeQuestion {
    qid: String,
    device_id: u64,
    to: String,
    key_id: String,
    nonce: String,
    ciphertext: String,
    created_at: u64,
    expires_at: u64,
    seq: u64,
    /// `open`, `settled`, or `expired`.
    state: String,
    settled_at: Option<u64>,
    /// The settle envelope: key id, nonce, ciphertext.
    settle: Option<(String, String, String)>,
    answers: Vec<FakeAnswer>,
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
    /// The `wait` of each `GET /v1/questions`, in order.
    list_waits: Vec<u64>,
    /// The `since` of the last head request.
    last_since: Option<u64>,
    /// The next requests that start with the prefix get no answer after the relay did
    /// them: the answer is lost on the network.
    lost_answers: Vec<(String, usize)>,
    /// The seconds that a new access token lasts; 0 is the relay's 900.
    token_seconds: u64,
    /// The id of the last answer to a question (one count for the relay).
    next_answer: u64,
    /// The body of each request that had one, as text.
    bodies: Vec<String>,
    /// The public keys (their bytes) that made a Connect team: one team for each key, ever.
    connect_keys: Vec<Vec<u8>>,
    /// `POST /v1/connect` is missing: an old relay answers 404.
    connect_missing: bool,
    /// The daily cap of Connect teams is reached: 503 `busy`, `Retry-After: 3600`.
    connect_busy: bool,
    /// The next Connect calls that answer 409 `connect_key_used` (the key counts as used).
    refuse_connect_keys: usize,
    /// The link code that `POST /v1/devices/links` made last.
    last_code: Option<String>,
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

    /// Whether `POST /v1/connect` exists (default); `false` is an old relay that answers 404.
    pub fn set_connect_available(&self, available: bool) {
        lock(&self.shared.0).connect_missing = !available;
    }

    /// The daily cap of Connect teams is reached (or not): `POST /v1/connect` answers 503
    /// `busy` with `Retry-After: 3600`.
    pub fn set_connect_busy(&self, busy: bool) {
        lock(&self.shared.0).connect_busy = busy;
    }

    /// Answer the next `count` Connect calls with 409 `connect_key_used`, as if their keys
    /// had made a Connect team before.
    pub fn refuse_next_connect_keys(&self, count: usize) {
        lock(&self.shared.0).refuse_connect_keys = count;
    }

    /// Lift the limits of the Connect team `team_id`: its first snapshot push is allowed.
    pub fn lift_plan(&self, team_id: &str) {
        lock(&self.shared.0)
            .teams
            .get_mut(team_id)
            .expect("team")
            .plan_lifted = true;
    }

    /// The kind of the team `team_id`: `connect` or `operator` (`None` for an unknown team).
    pub fn team_kind(&self, team_id: &str) -> Option<String> {
        lock(&self.shared.0)
            .teams
            .get(team_id)
            .map(|team| if team.connect { "connect" } else { "operator" }.to_owned())
    }

    /// The link code that `POST /v1/devices/links` made last, as a device would scan it.
    pub fn last_link_code(&self) -> Option<String> {
        lock(&self.shared.0).last_code.clone()
    }

    /// The relay forgets the team `team_id`, as after 30 days without use: each sign-in
    /// of its devices answers `401`.
    pub fn delete_team(&self, team_id: &str) {
        lock(&self.shared.0).teams.remove(team_id);
    }

    /// The ids of all teams, in order.
    pub fn team_ids(&self) -> Vec<String> {
        lock(&self.shared.0).teams.keys().cloned().collect()
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

    /// The `wait` of each `GET /v1/questions` so far, in order.
    pub fn list_waits(&self) -> Vec<u64> {
        lock(&self.shared.0).list_waits.clone()
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

    /// The body of each request that had one, in the order they came (a snapshot push
    /// is read as lossy text).
    pub fn request_bodies(&self) -> Vec<String> {
        lock(&self.shared.0).bodies.clone()
    }

    /// Expire every open question of every team now: its `expires_at` is the present, its
    /// state `expired`, and it gets a new `seq`. The long polls wake.
    pub fn expire_questions(&self) {
        let mut relay = lock(&self.shared.0);
        for team in relay.teams.values_mut() {
            let at = now();
            for index in 0..team.questions.len() {
                if team.questions[index].state == "open" {
                    team.question_seq += 1;
                    let question = &mut team.questions[index];
                    question.expires_at = at;
                    question.state = "expired".to_owned();
                    question.seq = team.question_seq;
                }
            }
        }
        drop(relay);
        self.shared.1.notify_all();
    }

    /// The state (`open`, `settled`, `expired`) of the question `qid` in any team.
    pub fn question_state(&self, qid: &str) -> Option<String> {
        lock(&self.shared.0)
            .teams
            .values()
            .flat_map(|team| team.questions.iter())
            .find(|question| question.qid == qid)
            .map(|question| question.state.clone())
    }

    /// The number of answers stored for the question `qid` (0 when it is unknown).
    pub fn answer_count(&self, qid: &str) -> usize {
        lock(&self.shared.0)
            .teams
            .values()
            .flat_map(|team| team.questions.iter())
            .find(|question| question.qid == qid)
            .map_or(0, |question| question.answers.len())
    }

    /// The number of questions posted in all teams.
    pub fn questions_posted(&self) -> usize {
        lock(&self.shared.0)
            .teams
            .values()
            .map(|team| team.questions.len())
            .sum()
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
        if !request.body.is_empty() {
            relay
                .bodies
                .push(String::from_utf8_lossy(&request.body).into_owned());
        }
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
        ("POST", ["v1", "connect"]) => {
            if request.header("authorization").is_some() {
                return fail(401, "unauthenticated");
            }
            let mut relay = lock(mutex);
            if relay.connect_missing {
                return fail(404, "not_found");
            }
            let Some(map) = exact_object(
                request,
                &["v", "team", "device_name", "public_key", "signature"],
            ) else {
                return fail(400, "invalid_request");
            };
            let Some(public_key) = map["public_key"]
                .as_str()
                .and_then(decode_b64u)
                .filter(|key| key.len() == 65 && key[0] == 0x04)
            else {
                return fail(400, "invalid_request");
            };
            if map["v"].as_u64() != Some(1)
                || !map["team"].is_string()
                || !map["device_name"].is_string()
            {
                return fail(400, "invalid_request");
            }
            // The proof of key: the key signs the tag, the origin, and its own text.
            let message = format!(
                "apassy-relay connect v1\0{}\0{}",
                relay.origin,
                map["public_key"].as_str().unwrap_or_default()
            );
            let signature = map["signature"]
                .as_str()
                .and_then(decode_b64u)
                .unwrap_or_default();
            if !verify(&public_key, message.as_bytes(), &signature) {
                return fail(400, "invalid_request");
            }
            if relay.refuse_connect_keys > 0 {
                relay.refuse_connect_keys -= 1;
                relay.connect_keys.push(public_key);
                return fail(409, "connect_key_used");
            }
            if relay.connect_keys.contains(&public_key) {
                return fail(409, "connect_key_used");
            }
            if relay.connect_busy {
                let mut answer = fail(503, "busy");
                answer
                    .headers
                    .push(("Retry-After".to_owned(), "3600".to_owned()));
                return answer;
            }
            relay.connect_keys.push(public_key.clone());
            relay.next_team += 1;
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
                    name: map["team"].as_str().unwrap_or_default().to_owned(),
                    devices: vec![Device {
                        id: device_id,
                        name: map["device_name"].as_str().unwrap_or_default().to_owned(),
                        public_key,
                        live: true,
                    }],
                    connect: true,
                    ..Team::default()
                },
            );
            ok(
                json!({"team_id": team_id, "member_id": 1, "device_id": device_id,
                      "kind": "connect"}),
            )
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
            let team_kind = if relay.teams[&team_id].connect {
                "connect"
            } else {
                "operator"
            };
            let lifetime = match relay.token_seconds {
                0 => 900,
                seconds => seconds,
            };
            ok(
                json!({"token": token, "expires_at": now() + lifetime, "team_id": team_id,
                      "team": team, "member_id": 1, "member_name": "owner", "role": "owner",
                      "device_id": device_id, "key_holder": device_id == 1,
                      "team_kind": team_kind}),
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
                    relay.last_code = Some(code.clone());
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
                ("POST", ["questions"]) => {
                    post_question(&mut relay, &team_id, device_id, request, changed)
                }
                ("GET", ["questions"]) => {
                    list_questions(relay, &team_id, device_id, request, changed)
                }
                ("POST", ["questions", qid, "answers"]) => {
                    post_answer(&mut relay, &team_id, device_id, qid, request, changed)
                }
                ("GET", ["questions", qid, "answers"]) => {
                    list_answers(relay, &team_id, device_id, qid, request, changed)
                }
                ("POST", ["questions", qid, "settle"]) => {
                    settle_question(&mut relay, &team_id, device_id, qid, request, changed)
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
    let team = &relay.teams[team_id];
    if team.connect && !team.plan_lifted {
        return fail(403, "plan_required");
    }
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

/// The ciphertext limits of the contract (section 15): card, answer, settle.
const CARD_BYTES: usize = 32_784;
const ANSWER_BYTES: usize = 8_208;
const SETTLE_BYTES: usize = 1_040;
/// Open questions of a team (`open_questions`) and answers of a device to a question.
const OPEN_QUESTIONS: usize = 20;
/// The open questions of one device and of one member (relay feat/questions 9851d33).
const OPEN_PER_DEVICE: usize = 10;
const OPEN_PER_MEMBER: usize = 15;
const ANSWERS_PER_DEVICE: usize = 3;
/// The answers of one question, of all devices.
const ANSWERS_PER_QUESTION: usize = 20;

type Fields = serde_json::Map<String, Value>;

/// The envelope of a body whose shape is right: texts as they came, and the size of the
/// decoded ciphertext.
struct Envelope {
    key_id: String,
    nonce: String,
    ciphertext: String,
    size: usize,
}

/// Every open question whose time has come becomes `expired`, with a new `seq`.
fn expire_due(team: &mut Team) {
    let at = now();
    for index in 0..team.questions.len() {
        if team.questions[index].state == "open" && at >= team.questions[index].expires_at {
            team.question_seq += 1;
            let question = &mut team.questions[index];
            question.state = "expired".to_owned();
            question.seq = team.question_seq;
        }
    }
}

/// The body as a JSON object with exactly `keys`.
fn exact_object(request: &Incoming, keys: &[&str]) -> Option<Fields> {
    let Value::Object(map) = serde_json::from_slice::<Value>(&request.body).ok()? else {
        return None;
    };
    (map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))).then_some(map)
}

/// `v`, `key_id`, `nonce`, and `ciphertext` of a body, in their forms.
fn envelope(map: &Fields) -> Option<Envelope> {
    if map["v"].as_u64() != Some(1) {
        return None;
    }
    let key_id = map["key_id"].as_str()?;
    if key_id.len() != 16
        || !key_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let nonce = map["nonce"].as_str()?;
    if decode_b64u(nonce)?.len() != 12 {
        return None;
    }
    let ciphertext = map["ciphertext"].as_str()?;
    let size = decode_b64u(ciphertext)?.len();
    if size == 0 {
        return None;
    }
    Some(Envelope {
        key_id: key_id.to_owned(),
        nonce: nonce.to_owned(),
        ciphertext: ciphertext.to_owned(),
        size,
    })
}

/// A question id: 22 characters of `A-Za-z0-9-_`.
fn valid_qid(qid: &str) -> bool {
    qid.len() == 22
        && qid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A number of the query: 0 when absent, `None` when it is not a number.
fn query_number(request: &Incoming, name: &str) -> Option<u64> {
    match request.query.get(name) {
        None => Some(0),
        Some(value) => value.parse().ok(),
    }
}

fn question_view(team: &Team, question: &FakeQuestion) -> Value {
    let name = team
        .devices
        .iter()
        .find(|device| device.id == question.device_id)
        .map_or("", |device| device.name.as_str());
    let mut view = json!({
        "qid": question.qid, "seq": question.seq, "to": question.to,
        "from_device_id": question.device_id, "from_device_name": name,
        "key_id": question.key_id, "nonce": question.nonce,
        "ciphertext": question.ciphertext, "created_at": question.created_at,
        "expires_at": question.expires_at, "state": question.state,
    });
    if let (Some(at), Some((key_id, nonce, ciphertext))) = (question.settled_at, &question.settle) {
        view["settled_at"] = json!(at);
        view["settle"] = json!({"key_id": key_id, "nonce": nonce, "ciphertext": ciphertext});
    }
    view
}

/// `POST /v1/questions`.
fn post_question(
    relay: &mut Relay,
    team_id: &str,
    device_id: u64,
    request: &Incoming,
    changed: &Condvar,
) -> Outgoing {
    let keys = [
        "v",
        "qid",
        "to",
        "expires_at",
        "key_id",
        "nonce",
        "ciphertext",
    ];
    let Some(map) = exact_object(request, &keys) else {
        return fail(400, "invalid_request");
    };
    let Some(card) = envelope(&map) else {
        return fail(400, "invalid_request");
    };
    let at = now();
    let (Some(qid), Some(to), Some(expires_at)) = (
        map["qid"].as_str().filter(|qid| valid_qid(qid)),
        map["to"]
            .as_str()
            .filter(|to| matches!(*to, "member" | "approvers")),
        map["expires_at"]
            .as_u64()
            .filter(|expires| *expires > at + 10 && *expires <= at + 600),
    ) else {
        return fail(400, "invalid_request");
    };
    if card.size > CARD_BYTES {
        return fail(413, "payload_too_large");
    }
    // Questions to the approvers wait for shared vaults: the relay refuses them.
    if to == "approvers" {
        return fail(403, "not_routed");
    }
    let team = relay.teams.get_mut(team_id).expect("team");
    expire_due(team);
    if team.questions.iter().any(|question| question.qid == qid) {
        return fail(409, "conflict");
    }
    let open = team
        .questions
        .iter()
        .filter(|question| question.state == "open")
        .count();
    let of_device = team
        .questions
        .iter()
        .filter(|question| question.state == "open" && question.device_id == device_id)
        .count();
    // One member (the owner) holds every device of the fake.
    if open >= OPEN_QUESTIONS || open >= OPEN_PER_MEMBER || of_device >= OPEN_PER_DEVICE {
        return fail(403, "too_many_questions");
    }
    team.question_seq += 1;
    let seq = team.question_seq;
    team.questions.push(FakeQuestion {
        qid: qid.to_owned(),
        device_id,
        to: to.to_owned(),
        key_id: card.key_id,
        nonce: card.nonce,
        ciphertext: card.ciphertext,
        created_at: at,
        expires_at,
        seq,
        state: "open".to_owned(),
        settled_at: None,
        settle: None,
        answers: Vec::new(),
    });
    changed.notify_all();
    ok(json!({"qid": qid, "seq": seq, "created_at": at, "expires_at": expires_at}))
}

/// Nothing in the list of `device_id` after `since`: the long poll goes on.
fn no_new_question(relay: &mut Relay, team_id: &str, device_id: u64, since: u64) -> bool {
    let Some(team) = relay.teams.get_mut(team_id) else {
        return false;
    };
    expire_due(team);
    !team
        .questions
        .iter()
        .any(|question| question.device_id != device_id && question.seq > since)
}

/// `GET /v1/questions?since=N&wait=S`.
fn list_questions<'a>(
    mut relay: MutexGuard<'a, Relay>,
    team_id: &str,
    device_id: u64,
    request: &Incoming,
    changed: &Condvar,
) -> Outgoing {
    let (Some(since), Some(wait)) = (
        query_number(request, "since"),
        query_number(request, "wait"),
    ) else {
        return fail(400, "invalid_request");
    };
    if wait > 25 {
        return fail(400, "invalid_request");
    }
    relay.list_waits.push(wait);
    if let Some(team) = relay.teams.get_mut(team_id) {
        expire_due(team);
    }
    if wait > 0 && !relay.polls_at_once {
        let (guard, _) = changed
            .wait_timeout_while(relay, Duration::from_secs(wait), |relay| {
                !relay.stopped && no_new_question(relay, team_id, device_id, since)
            })
            .unwrap_or_else(PoisonError::into_inner);
        relay = guard;
    }
    let team = relay.teams.get_mut(team_id).expect("team");
    expire_due(team);
    let mut list: Vec<&FakeQuestion> = team
        .questions
        .iter()
        .filter(|question| question.device_id != device_id && question.seq > since)
        .collect();
    list.sort_by_key(|question| question.seq);
    let questions: Vec<Value> = list
        .iter()
        .take(100)
        .map(|question| question_view(team, question))
        .collect();
    ok(json!({"seq": team.question_seq, "questions": questions}))
}

/// `POST /v1/questions/{qid}/answers`, with the codes in the order of section 10.2.
fn post_answer(
    relay: &mut Relay,
    team_id: &str,
    device_id: u64,
    qid: &str,
    request: &Incoming,
    changed: &Condvar,
) -> Outgoing {
    let Some(map) = exact_object(request, &["v", "key_id", "nonce", "ciphertext"]) else {
        return fail(400, "invalid_request");
    };
    let Some(answer) = envelope(&map) else {
        return fail(400, "invalid_request");
    };
    if answer.size > ANSWER_BYTES {
        return fail(413, "payload_too_large");
    }
    let id = relay.next_answer + 1;
    let team = relay.teams.get_mut(team_id).expect("team");
    expire_due(team);
    let Some(question) = team
        .questions
        .iter_mut()
        .find(|question| question.qid == qid)
    else {
        return fail(404, "not_found");
    };
    if question.device_id == device_id {
        return fail(403, "not_routed");
    }
    match question.state.as_str() {
        "settled" => return fail(409, "question_settled"),
        "expired" => return fail(409, "question_expired"),
        _ => {}
    }
    if answer.key_id != question.key_id {
        return fail(400, "invalid_request");
    }
    let given = question
        .answers
        .iter()
        .filter(|stored| stored.device_id == device_id)
        .count();
    if given >= ANSWERS_PER_DEVICE || question.answers.len() >= ANSWERS_PER_QUESTION {
        return fail(403, "too_many_answers");
    }
    let at = now();
    question.answers.push(FakeAnswer {
        id,
        device_id,
        key_id: answer.key_id,
        nonce: answer.nonce,
        ciphertext: answer.ciphertext,
        at,
    });
    relay.next_answer = id;
    changed.notify_all();
    ok(json!({"id": id, "at": at}))
}

/// No answer after `after` and the question still open: the long poll goes on.
fn no_new_answer(relay: &mut Relay, team_id: &str, qid: &str, after: u64) -> bool {
    let Some(team) = relay.teams.get_mut(team_id) else {
        return false;
    };
    expire_due(team);
    team.questions
        .iter()
        .find(|question| question.qid == qid)
        .is_some_and(|question| {
            question.state == "open" && !question.answers.iter().any(|answer| answer.id > after)
        })
}

/// `GET /v1/questions/{qid}/answers?after=N&wait=S`.
fn list_answers<'a>(
    mut relay: MutexGuard<'a, Relay>,
    team_id: &str,
    device_id: u64,
    qid: &str,
    request: &Incoming,
    changed: &Condvar,
) -> Outgoing {
    let (Some(after), Some(wait)) = (
        query_number(request, "after"),
        query_number(request, "wait"),
    ) else {
        return fail(400, "invalid_request");
    };
    if wait > 25 {
        return fail(400, "invalid_request");
    }
    let team = relay.teams.get_mut(team_id).expect("team");
    expire_due(team);
    let asked = team
        .questions
        .iter()
        .any(|question| question.qid == qid && question.device_id == device_id);
    if !asked {
        return fail(404, "not_found");
    }
    if wait > 0 && !relay.polls_at_once {
        let (guard, _) = changed
            .wait_timeout_while(relay, Duration::from_secs(wait), |relay| {
                !relay.stopped && no_new_answer(relay, team_id, qid, after)
            })
            .unwrap_or_else(PoisonError::into_inner);
        relay = guard;
    }
    let team = relay.teams.get_mut(team_id).expect("team");
    expire_due(team);
    let Some(question) = team.questions.iter().find(|question| question.qid == qid) else {
        return fail(404, "not_found");
    };
    let answers: Vec<Value> = question
        .answers
        .iter()
        .filter(|answer| answer.id > after)
        .map(|answer| {
            json!({"id": answer.id, "device_id": answer.device_id, "member_id": 1,
                   "role": "owner", "key_id": answer.key_id, "nonce": answer.nonce,
                   "ciphertext": answer.ciphertext, "at": answer.at})
        })
        .collect();
    ok(
        json!({"state": question.state, "expires_at": question.expires_at,
              "answers": answers}),
    )
}

/// `POST /v1/questions/{qid}/settle`.
fn settle_question(
    relay: &mut Relay,
    team_id: &str,
    device_id: u64,
    qid: &str,
    request: &Incoming,
    changed: &Condvar,
) -> Outgoing {
    let Some(map) = exact_object(request, &["v", "key_id", "nonce", "ciphertext"]) else {
        return fail(400, "invalid_request");
    };
    let Some(settle) = envelope(&map) else {
        return fail(400, "invalid_request");
    };
    if settle.size > SETTLE_BYTES {
        return fail(413, "payload_too_large");
    }
    let team = relay.teams.get_mut(team_id).expect("team");
    expire_due(team);
    let Some(index) = team
        .questions
        .iter()
        .position(|question| question.qid == qid && question.device_id == device_id)
    else {
        return fail(404, "not_found");
    };
    let question = &mut team.questions[index];
    let sent = (settle.key_id, settle.nonce, settle.ciphertext);
    match question.state.as_str() {
        "settled" => {
            return if question.settle.as_ref() == Some(&sent) {
                ok(json!({"qid": qid, "state": "settled", "settled_at": question.settled_at}))
            } else {
                fail(409, "question_settled")
            };
        }
        "expired" => return fail(409, "question_expired"),
        _ => {}
    }
    if sent.0 != question.key_id {
        return fail(400, "invalid_request");
    }
    let at = now();
    team.question_seq += 1;
    let question = &mut team.questions[index];
    question.state = "settled".to_owned();
    question.settled_at = Some(at);
    question.settle = Some(sent);
    question.seq = team.question_seq;
    changed.notify_all();
    ok(json!({"qid": qid, "state": "settled", "settled_at": at}))
}
