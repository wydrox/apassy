//! An in-process fake of the relay's question routes (contract relay-questions-v1,
//! section 10) and of the sign-in and device link routes that an iPhone needs to join a
//! notifications-only team (relay-sync-v1, sections 5 and 7.2). One team, plain HTTP on
//! 127.0.0.1, one thread per connection, everything in memory. It checks what the real
//! relay checks for an answer (routing, state, `key_id`, the count), never reads an
//! envelope, and answers in the JSON envelope. Synthetic values only.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::sync::{decode_b64u, encode_b64u, safety_words, sha256_hex, sign_in_message};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde_json::{Value, json};

#[derive(Clone)]
struct Device {
    id: u64,
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
    code: String,
    device_name: String,
    public_key: Vec<u8>,
    state: LinkState,
}

/// A question as the relay stores it.
#[derive(Clone)]
pub struct StoredQuestion {
    pub qid: String,
    pub seq: u64,
    pub to: String,
    pub from_device_id: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: String,
    pub settled_at: Option<u64>,
    pub settle: Option<Value>,
}

/// An answer as the relay stamps it.
#[derive(Clone, Debug)]
pub struct StoredAnswer {
    pub id: u64,
    pub qid: String,
    pub device_id: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Default)]
struct Relay {
    origin: String,
    team_id: String,
    devices: Vec<Device>,
    links: Vec<Link>,
    codes: Vec<String>,
    tokens: BTreeMap<String, u64>,
    nonces: BTreeMap<String, Vec<u8>>,
    questions: Vec<StoredQuestion>,
    answers: Vec<StoredAnswer>,
    seq: u64,
    next_secret: u64,
    push: Option<(u64, Value)>,
    log: Vec<String>,
    /// The relay does not answer: each connection closes with no answer.
    offline: bool,
    /// The list long poll answers at once, as a Connect team over its waiting polls.
    polls_at_once: bool,
}

impl Relay {
    fn live(&self, public_key: &[u8]) -> Option<u64> {
        self.devices
            .iter()
            .find(|device| device.live && device.public_key == public_key)
            .map(|device| device.id)
    }

    fn secret(&mut self) -> String {
        self.next_secret += 1;
        sha256_hex(format!("questions-relay-{}-{}", self.next_secret, now()).as_bytes())
    }
}

/// A running fake. It stops serving when dropped (the listener thread ends at the next
/// connection).
pub struct QuestionsRelay {
    /// The origin, `http://127.0.0.1:<port>`.
    pub url: String,
    pub team_id: String,
    shared: Arc<(Mutex<Relay>, Condvar)>,
}

fn lock(relay: &Mutex<Relay>) -> MutexGuard<'_, Relay> {
    relay.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .is_ok()
}

impl QuestionsRelay {
    /// Start the fake with the team `team_id` and the asking Mac as device 1.
    pub fn start(team_id: &str, mac_public_key: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        );
        let shared = Arc::new((
            Mutex::new(Relay {
                origin: url.clone(),
                team_id: team_id.to_owned(),
                devices: vec![Device {
                    id: 1,
                    public_key: mac_public_key.to_vec(),
                    live: true,
                }],
                ..Relay::default()
            }),
            Condvar::new(),
        ));
        let server = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let server = Arc::clone(&server);
                std::thread::spawn(move || handle(&server, stream));
            }
        });
        Self {
            url,
            team_id: team_id.to_owned(),
            shared,
        }
    }

    /// A device link of "Add an iPhone" on the Mac: `<url>/link#<code>`.
    pub fn link(&self) -> (String, String) {
        let mut relay = lock(&self.shared.0);
        let secret = relay.secret();
        let code = format!("apassy_lnk_{}_{secret}", relay.team_id);
        relay.codes.push(code.clone());
        (format!("{}/link#{code}", self.url), code)
    }

    /// The Mac confirms every pending link: each gets a live device.
    pub fn confirm_links(&self) -> Vec<u64> {
        let mut relay = lock(&self.shared.0);
        let mut added = Vec::new();
        let pending: Vec<Vec<u8>> = relay
            .links
            .iter_mut()
            .filter(|link| link.state == LinkState::Pending)
            .map(|link| {
                link.state = LinkState::Confirmed;
                link.public_key.clone()
            })
            .collect();
        for public_key in pending {
            let id = relay.devices.len() as u64 + 1;
            relay.devices.push(Device {
                id,
                public_key,
                live: true,
            });
            added.push(id);
        }
        added
    }

    /// The device name and the key of each confirmed link, with the device number of the
    /// device it made, as the confirming Mac sees them.
    pub fn confirmed(&self) -> Vec<(u64, String, Vec<u8>)> {
        let relay = lock(&self.shared.0);
        relay
            .links
            .iter()
            .filter(|link| link.state == LinkState::Confirmed)
            .filter_map(|link| {
                let device = relay
                    .devices
                    .iter()
                    .find(|device| device.public_key == link.public_key)?;
                Some((device.id, link.device_name.clone(), link.public_key.clone()))
            })
            .collect()
    }

    /// Whether device `id` is in the team and not revoked.
    pub fn is_live(&self, id: u64) -> bool {
        lock(&self.shared.0)
            .devices
            .iter()
            .any(|device| device.id == id && device.live)
    }

    /// The links that wait for the Mac.
    pub fn pending_links(&self) -> usize {
        lock(&self.shared.0)
            .links
            .iter()
            .filter(|link| link.state == LinkState::Pending)
            .count()
    }

    /// The relay stops answering, or answers again.
    pub fn set_offline(&self, offline: bool) {
        lock(&self.shared.0).offline = offline;
    }

    /// Answer every list long poll at once, as the relay does for a Connect team that
    /// holds its waiting polls already (relay-connect-v1 section 5).
    pub fn answer_polls_at_once(&self, at_once: bool) {
        lock(&self.shared.0).polls_at_once = at_once;
    }

    /// The relay revokes device `id`.
    pub fn revoke(&self, id: u64) {
        let mut relay = lock(&self.shared.0);
        for device in relay.devices.iter_mut().filter(|device| device.id == id) {
            device.live = false;
        }
    }

    /// The asking Mac (device 1) posts a sealed card.
    pub fn post_question(
        &self,
        qid: &str,
        key_id: &str,
        nonce: &str,
        ciphertext: &str,
        expires_at: u64,
    ) {
        let (mutex, changed) = &*self.shared;
        let mut relay = lock(mutex);
        relay.seq += 1;
        let seq = relay.seq;
        relay.questions.push(StoredQuestion {
            qid: qid.to_owned(),
            seq,
            to: "member".to_owned(),
            from_device_id: 1,
            key_id: key_id.to_owned(),
            nonce: nonce.to_owned(),
            ciphertext: ciphertext.to_owned(),
            created_at: now(),
            expires_at,
            state: "open".to_owned(),
            settled_at: None,
            settle: None,
        });
        changed.notify_all();
    }

    /// The asker settles `qid` with a sealed settle.
    pub fn settle(&self, qid: &str, key_id: &str, nonce: &str, ciphertext: &str) {
        let (mutex, changed) = &*self.shared;
        let mut relay = lock(mutex);
        relay.seq += 1;
        let seq = relay.seq;
        let question = relay
            .questions
            .iter_mut()
            .find(|question| question.qid == qid)
            .expect("question");
        question.seq = seq;
        question.state = "settled".to_owned();
        question.settled_at = Some(now());
        question.settle = Some(json!({"key_id": key_id, "nonce": nonce, "ciphertext": ciphertext}));
        changed.notify_all();
    }

    /// The public key of device `id`.
    pub fn device_key(&self, id: u64) -> Vec<u8> {
        lock(&self.shared.0)
            .devices
            .iter()
            .find(|device| device.id == id)
            .map(|device| device.public_key.clone())
            .expect("device")
    }

    pub fn answers(&self) -> Vec<StoredAnswer> {
        lock(&self.shared.0).answers.clone()
    }

    /// The push token of a device and its body, when one is set.
    pub fn push_token(&self) -> Option<(u64, Value)> {
        lock(&self.shared.0).push.clone()
    }

    pub fn log(&self) -> Vec<String> {
        lock(&self.shared.0).log.clone()
    }
}

struct Incoming {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Incoming {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

fn ok(result: Value) -> (u16, Value) {
    (200, json!({"ok": true, "result": result}))
}

fn fail(status: u16, code: &str) -> (u16, Value) {
    (
        status,
        json!({"ok": false, "error": {"code": code, "message": format!("synthetic {code}")}}),
    )
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
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target.clone(), String::new()),
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
    if lock(&shared.0).offline {
        // No answer: the connection closes.
        return;
    }
    lock(&shared.0)
        .log
        .push(format!("{} {}", request.method, request.path));
    let (status, body) = route(shared, &request);
    let body = serde_json::to_vec(&body).unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn question_view(question: &StoredQuestion) -> Value {
    let mut view = json!({
        "qid": question.qid, "seq": question.seq, "to": question.to,
        "from_device_id": question.from_device_id, "from_device_name": "MacBook Pro",
        "key_id": question.key_id, "nonce": question.nonce, "ciphertext": question.ciphertext,
        "created_at": question.created_at, "expires_at": question.expires_at,
        "state": question.state,
    });
    if let (Some(at), Some(settle)) = (question.settled_at, &question.settle) {
        view["settled_at"] = json!(at);
        view["settle"] = settle.clone();
    }
    view
}

fn route(shared: &Arc<(Mutex<Relay>, Condvar)>, request: &Incoming) -> (u16, Value) {
    let (mutex, changed) = &**shared;
    let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
    match (request.method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "auth", "challenge"]) => {
            let body = request.json();
            let mut relay = lock(mutex);
            let Some(public_key) = body["public_key"].as_str().and_then(decode_b64u) else {
                return fail(400, "invalid_request");
            };
            if body["team_id"] != json!(relay.team_id) {
                return fail(401, "unauthenticated");
            }
            if relay.live(&public_key).is_none() {
                return match relay
                    .links
                    .iter()
                    .find(|link| link.public_key == public_key)
                {
                    Some(link) if link.state == LinkState::Pending => fail(403, "join_pending"),
                    Some(link) if link.state == LinkState::Refused => fail(403, "join_refused"),
                    _ => fail(401, "unauthenticated"),
                };
            }
            let nonce = encode_b64u(
                &ring::digest::digest(&ring::digest::SHA256, relay.secret().as_bytes()).as_ref()
                    [..32],
            );
            relay.nonces.insert(nonce.clone(), public_key);
            let origin = relay.origin.clone();
            ok(json!({"nonce": nonce, "expires_at": now() + 60, "origin": origin}))
        }
        ("POST", ["v1", "auth", "token"]) => {
            let body = request.json();
            let mut relay = lock(mutex);
            let nonce = body["nonce"].as_str().unwrap_or_default().to_owned();
            let Some(public_key) = relay.nonces.remove(&nonce) else {
                return fail(401, "unauthenticated");
            };
            let message = sign_in_message(
                &relay.origin,
                &relay.team_id,
                &encode_b64u(&public_key),
                &nonce,
            );
            let signature = body["signature"]
                .as_str()
                .and_then(decode_b64u)
                .unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(401, "unauthenticated");
            }
            let Some(device_id) = relay.live(&public_key) else {
                return fail(401, "unauthenticated");
            };
            let secret = relay.secret();
            let token = format!("apassy_acc_{}_{secret}", relay.team_id);
            relay.tokens.insert(token.clone(), device_id);
            let team_id = relay.team_id.clone();
            ok(
                json!({"token": token, "expires_at": now() + 900, "team_id": team_id,
                      "team": "Notifications", "member_id": 1, "member_name": "owner",
                      "role": "owner", "device_id": device_id, "key_holder": false}),
            )
        }
        ("POST", ["v1", "devices", "link"]) => {
            let body = request.json();
            let mut relay = lock(mutex);
            let code = body["code"].as_str().unwrap_or_default().to_owned();
            let Some(public_key) = body["public_key"].as_str().and_then(decode_b64u) else {
                return fail(400, "invalid_request");
            };
            let Some(at) = relay.codes.iter().position(|known| *known == code) else {
                return fail(403, "forbidden");
            };
            // The relay takes a device name of 1 to 64 bytes with no control character.
            let device_name = body["device_name"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_owned();
            if device_name.is_empty()
                || device_name.len() > 64
                || device_name.chars().any(char::is_control)
            {
                return fail(400, "invalid_request");
            }
            relay.codes.remove(at);
            let team_id = relay.team_id.clone();
            let safety = safety_words(&team_id, &code, &public_key);
            relay.links.push(Link {
                code,
                device_name,
                public_key,
                state: LinkState::Pending,
            });
            ok(
                json!({"id": relay.links.len(), "team_id": team_id, "team": "Notifications",
                      "safety": safety, "expires_at": now() + 600, "by": "owner"}),
            )
        }
        ("POST", ["v1", "devices", "link", "cancel"]) => {
            let body = request.json();
            let mut relay = lock(mutex);
            let code = body["code"].as_str().unwrap_or_default().to_owned();
            match relay.links.iter_mut().find(|link| link.code == code) {
                Some(link) if link.state == LinkState::Confirmed => fail(409, "conflict"),
                Some(link) => {
                    link.state = LinkState::Refused;
                    ok(json!({}))
                }
                None => fail(403, "forbidden"),
            }
        }
        (method, ["v1", ..]) => {
            let mut relay = lock(mutex);
            let device = request
                .headers
                .get("authorization")
                .and_then(|value| value.strip_prefix("Bearer "))
                .and_then(|token| relay.tokens.get(token).copied())
                .filter(|id| relay.devices.iter().any(|d| d.id == *id && d.live));
            let Some(device) = device else {
                return fail(401, "unauthenticated");
            };
            match (method, &segments[1..]) {
                ("DELETE", ["devices", id]) => {
                    let id: u64 = id.parse().unwrap_or_default();
                    for d in relay.devices.iter_mut().filter(|d| d.id == id) {
                        d.live = false;
                    }
                    ok(json!({}))
                }
                ("GET", ["questions"]) => {
                    let since: u64 = request
                        .query
                        .get("since")
                        .and_then(|text| text.parse().ok())
                        .unwrap_or(0);
                    let wait: u64 = request
                        .query
                        .get("wait")
                        .and_then(|text| text.parse().ok())
                        .unwrap_or(0);
                    if wait > 25 {
                        return fail(400, "invalid_request");
                    }
                    let wait = if relay.polls_at_once { 0 } else { wait };
                    let end = Instant::now() + Duration::from_secs(wait);
                    loop {
                        let found: Vec<Value> = relay
                            .questions
                            .iter()
                            .filter(|q| q.seq > since && q.from_device_id != device)
                            .map(question_view)
                            .collect();
                        let left = end.saturating_duration_since(Instant::now());
                        if !found.is_empty() || left.is_zero() {
                            return ok(json!({"seq": relay.seq, "questions": found}));
                        }
                        relay = changed
                            .wait_timeout(relay, left)
                            .map(|(guard, _)| guard)
                            .unwrap_or_else(|error| error.into_inner().0);
                    }
                }
                ("POST", ["questions", qid, "answers"]) => {
                    let body = request.json();
                    let Some(at) = relay.questions.iter().position(|q| q.qid == *qid) else {
                        return fail(404, "not_found");
                    };
                    let question = relay.questions[at].clone();
                    if question.from_device_id == device {
                        return fail(403, "not_routed");
                    }
                    if question.state == "settled" {
                        return fail(409, "question_settled");
                    }
                    if question.state != "open" || now() >= question.expires_at {
                        return fail(409, "question_expired");
                    }
                    if body["v"] != json!(1) || body["key_id"] != json!(question.key_id) {
                        return fail(400, "invalid_request");
                    }
                    let count = relay
                        .answers
                        .iter()
                        .filter(|a| a.qid == *qid && a.device_id == device)
                        .count();
                    if count >= 3 {
                        return fail(403, "too_many_answers");
                    }
                    let id = relay.answers.len() as u64 + 1;
                    relay.answers.push(StoredAnswer {
                        id,
                        qid: (*qid).to_owned(),
                        device_id: device,
                        key_id: question.key_id.clone(),
                        nonce: body["nonce"].as_str().unwrap_or_default().to_owned(),
                        ciphertext: body["ciphertext"].as_str().unwrap_or_default().to_owned(),
                    });
                    ok(json!({"id": id, "at": now()}))
                }
                ("PUT", ["push", "token"]) => {
                    let body = request.json();
                    relay.push = Some((device, body));
                    ok(json!({"device_id": device, "updated_at": now()}))
                }
                ("DELETE", ["push", "token"]) => {
                    relay.push = None;
                    ok(json!({"device_id": device}))
                }
                _ => fail(404, "not_found"),
            }
        }
        _ => fail(404, "not_found"),
    }
}
