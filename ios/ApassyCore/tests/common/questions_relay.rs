//! An in-process fake of the relay's question routes (contract relay-questions-v1,
//! section 10), of its feed routes (relay-feed-v1, section 10), and of the sign-in and
//! device link routes that an iPhone needs to join a notifications-only team
//! (relay-sync-v1, sections 5 and 7.2). One team with one member, plain HTTP on
//! 127.0.0.1, one thread per connection, everything in memory. It checks what the real
//! relay checks for an answer and an action (routing, state, `key_id`, the forms), never
//! reads an envelope, and answers in the JSON envelope. Synthetic values only.

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
    /// The feed of each device, by device id.
    feeds: BTreeMap<u64, StoredFeed>,
    feed_change: u64,
    actions: Vec<StoredAction>,
    action_seq: u64,
}

/// The feed of a device as the relay stores it (relay-feed-v1 section 13.1).
#[derive(Clone, Debug)]
pub struct StoredFeed {
    pub seq: u64,
    pub change: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub updated_at: u64,
}

/// An action as the relay stamps it.
#[derive(Clone, Debug)]
pub struct StoredAction {
    pub action_id: String,
    pub seq: u64,
    pub from_device: u64,
    pub to_device: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: String,
    pub outcome: Option<String>,
    pub settled_at: Option<u64>,
    pub settle: Option<Value>,
}

impl StoredAction {
    fn view(&self) -> Value {
        let mut view = json!({
            "action_id": self.action_id, "to_device": self.to_device, "state": self.state,
            "created_at": self.created_at, "expires_at": self.expires_at,
        });
        if let (Some(outcome), Some(at), Some(settle)) =
            (&self.outcome, self.settled_at, &self.settle)
        {
            view["outcome"] = json!(outcome);
            view["settled_at"] = json!(at);
            view["settle"] = settle.clone();
        }
        view
    }
}

fn valid_b64u_16(text: &str) -> bool {
    text.len() == 22 && decode_b64u(text).is_some_and(|bytes| bytes.len() == 16)
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

    /// A new live device of the member with `public_key` (another Mac): its id.
    pub fn add_device(&self, public_key: &[u8]) -> u64 {
        let mut relay = lock(&self.shared.0);
        let id = relay.devices.len() as u64 + 1;
        relay.devices.push(Device {
            id,
            public_key: public_key.to_vec(),
            live: true,
        });
        id
    }

    /// Device `device_id` publishes a feed, with no check of its `seq`: the test plays a
    /// relay that serves any record.
    pub fn put_feed(&self, device_id: u64, seq: u64, key_id: &str, nonce: &str, ciphertext: &str) {
        let (mutex, changed) = &*self.shared;
        let mut relay = lock(mutex);
        relay.feed_change += 1;
        let change = relay.feed_change;
        relay.feeds.insert(
            device_id,
            StoredFeed {
                seq,
                change,
                key_id: key_id.to_owned(),
                nonce: nonce.to_owned(),
                ciphertext: ciphertext.to_owned(),
                updated_at: now(),
            },
        );
        changed.notify_all();
    }

    /// Device `device_id` removes its feed (`DELETE /v1/feed`).
    pub fn delete_feed(&self, device_id: u64) {
        let (mutex, changed) = &*self.shared;
        let mut relay = lock(mutex);
        if relay.feeds.remove(&device_id).is_some() {
            relay.feed_change += 1;
        }
        changed.notify_all();
    }

    pub fn feeds(&self) -> BTreeMap<u64, StoredFeed> {
        lock(&self.shared.0).feeds.clone()
    }

    pub fn actions(&self) -> Vec<StoredAction> {
        lock(&self.shared.0).actions.clone()
    }

    /// The target settles `action_id` (`POST /v1/feed/actions/{id}/settle`).
    pub fn settle_action(
        &self,
        action_id: &str,
        outcome: &str,
        key_id: &str,
        nonce: &str,
        ciphertext: &str,
    ) {
        let (mutex, changed) = &*self.shared;
        let mut relay = lock(mutex);
        let action = relay
            .actions
            .iter_mut()
            .find(|action| action.action_id == action_id)
            .expect("action");
        action.state = "settled".to_owned();
        action.outcome = Some(outcome.to_owned());
        action.settled_at = Some(now());
        action.settle = Some(json!({"key_id": key_id, "nonce": nonce, "ciphertext": ciphertext}));
        changed.notify_all();
    }

    /// The relay's maintenance marks `action_id` expired.
    pub fn expire_action(&self, action_id: &str) {
        let (mutex, changed) = &*self.shared;
        let mut relay = lock(mutex);
        for action in relay
            .actions
            .iter_mut()
            .filter(|a| a.action_id == action_id)
        {
            action.state = "expired".to_owned();
        }
        changed.notify_all();
    }
}

/// Hold a long poll of `wait` seconds on `changed`: `found` answers, or holds with None
/// while its second argument (the wait is over) is false.
fn long_poll(
    mut relay: MutexGuard<'_, Relay>,
    changed: &Condvar,
    wait: u64,
    mut found: impl FnMut(&mut Relay, bool) -> Option<(u16, Value)>,
) -> (u16, Value) {
    let end = Instant::now() + Duration::from_secs(wait);
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if let Some(answer) = found(&mut relay, left.is_zero()) {
            return answer;
        }
        if left.is_zero() {
            return fail(500, "internal");
        }
        relay = changed
            .wait_timeout(relay, left)
            .map(|(guard, _)| guard)
            .unwrap_or_else(|error| error.into_inner().0);
    }
}

/// A number of the query; absent is 0.
fn number(request: &Incoming, name: &str) -> Option<u64> {
    match request.query.get(name) {
        None => Some(0),
        Some(text) => text.parse().ok(),
    }
}

/// The feed routes of relay-feed-v1 section 10 under `/v1/feed`, for the caller
/// `device`. None: no such route.
fn feed_route(
    mut relay: MutexGuard<'_, Relay>,
    changed: &Condvar,
    request: &Incoming,
    device: u64,
    rest: &[&str],
) -> Option<(u16, Value)> {
    let answer = match (request.method.as_str(), rest) {
        ("PUT", []) => {
            let body = request.json();
            let (Some(seq), Some(key_id), Some(nonce), Some(ciphertext)) = (
                body["seq"].as_u64(),
                body["key_id"].as_str(),
                body["nonce"].as_str(),
                body["ciphertext"].as_str(),
            ) else {
                return Some(fail(400, "invalid_request"));
            };
            if body["v"] != json!(1) {
                return Some(fail(400, "invalid_request"));
            }
            if relay.feeds.get(&device).is_some_and(|feed| feed.seq >= seq) {
                return Some(fail(409, "seq_not_newer"));
            }
            relay.feed_change += 1;
            let change = relay.feed_change;
            relay.feeds.insert(
                device,
                StoredFeed {
                    seq,
                    change,
                    key_id: key_id.to_owned(),
                    nonce: nonce.to_owned(),
                    ciphertext: ciphertext.to_owned(),
                    updated_at: now(),
                },
            );
            changed.notify_all();
            ok(json!({"device_id": device, "seq": seq, "change": change, "updated_at": now()}))
        }
        ("DELETE", []) => {
            if relay.feeds.remove(&device).is_some() {
                relay.feed_change += 1;
            }
            changed.notify_all();
            ok(json!({"device_id": device, "change": relay.feed_change}))
        }
        ("GET", []) => {
            let (Some(since), Some(wait)) = (number(request, "since"), number(request, "wait"))
            else {
                return Some(fail(400, "invalid_request"));
            };
            if wait > 25 {
                return Some(fail(400, "invalid_request"));
            }
            long_poll(relay, changed, wait, |relay, done| {
                let mut found: Vec<(u64, StoredFeed)> = relay
                    .feeds
                    .iter()
                    .filter(|(_, feed)| feed.change > since)
                    .map(|(id, feed)| (*id, feed.clone()))
                    .collect();
                // A removal raises `change` too: it is news.
                if found.is_empty() && since >= relay.feed_change && !done {
                    return None;
                }
                found.sort_by_key(|(_, feed)| feed.change);
                let feeds: Vec<Value> = found
                    .iter()
                    .map(|(id, feed)| {
                        json!({"device_id": id, "device_name": "MacBook Pro", "seq": feed.seq,
                               "change": feed.change, "key_id": feed.key_id, "nonce": feed.nonce,
                               "ciphertext": feed.ciphertext, "updated_at": feed.updated_at})
                    })
                    .collect();
                let present: Vec<u64> = relay.feeds.keys().copied().collect();
                Some(ok(json!({"change": relay.feed_change, "more": false,
                               "present": present, "feeds": feeds})))
            })
        }
        ("POST", ["actions"]) => {
            let body = request.json();
            let (Some(action_id), Some(to_device), Some(key_id), Some(nonce), Some(ciphertext)) = (
                body["action_id"].as_str(),
                body["to_device"].as_u64(),
                body["key_id"].as_str(),
                body["nonce"].as_str(),
                body["ciphertext"].as_str(),
            ) else {
                return Some(fail(400, "invalid_request"));
            };
            let known = [
                "v",
                "action_id",
                "to_device",
                "key_id",
                "nonce",
                "ciphertext",
            ];
            let unknown = body
                .as_object()
                .is_none_or(|map| map.keys().any(|key| !known.contains(&key.as_str())));
            if body["v"] != json!(1) || unknown || !valid_b64u_16(action_id) {
                return Some(fail(400, "invalid_request"));
            }
            if decode_b64u(ciphertext).is_none_or(|bytes| bytes.len() > 4112) {
                return Some(fail(413, "payload_too_large"));
            }
            let routed =
                to_device != device && relay.devices.iter().any(|d| d.id == to_device && d.live);
            if !routed {
                return Some(fail(403, "not_routed"));
            }
            if !relay.feeds.contains_key(&to_device) {
                return Some(fail(404, "not_found"));
            }
            if relay.actions.iter().any(|a| a.action_id == action_id) {
                return Some(fail(409, "conflict"));
            }
            relay.action_seq += 1;
            let seq = relay.action_seq;
            let created_at = now();
            relay.actions.push(StoredAction {
                action_id: action_id.to_owned(),
                seq,
                from_device: device,
                to_device,
                key_id: key_id.to_owned(),
                nonce: nonce.to_owned(),
                ciphertext: ciphertext.to_owned(),
                created_at,
                expires_at: created_at + 300,
                state: "open".to_owned(),
                outcome: None,
                settled_at: None,
                settle: None,
            });
            changed.notify_all();
            ok(
                json!({"action_id": action_id, "seq": seq, "created_at": created_at,
                      "expires_at": created_at + 300}),
            )
        }
        ("GET", ["actions"]) => {
            let (Some(after), Some(wait)) = (number(request, "after"), number(request, "wait"))
            else {
                return Some(fail(400, "invalid_request"));
            };
            long_poll(relay, changed, wait.min(25), |relay, done| {
                let found: Vec<Value> = relay
                    .actions
                    .iter()
                    .filter(|a| a.to_device == device && a.state == "open" && a.seq > after)
                    .take(20)
                    .map(|a| {
                        json!({"action_id": a.action_id, "seq": a.seq,
                               "from_device_id": a.from_device, "key_id": a.key_id,
                               "nonce": a.nonce, "ciphertext": a.ciphertext,
                               "created_at": a.created_at, "expires_at": a.expires_at})
                    })
                    .collect();
                if found.is_empty() && !done {
                    return None;
                }
                Some(ok(json!({"seq": relay.action_seq, "actions": found})))
            })
        }
        ("GET", ["actions", action_id]) => {
            let Some(wait) = number(request, "wait") else {
                return Some(fail(400, "invalid_request"));
            };
            let action_id = (*action_id).to_owned();
            long_poll(relay, changed, wait.min(25), |relay, done| {
                // The sender only.
                let Some(action) = relay
                    .actions
                    .iter_mut()
                    .find(|a| a.action_id == action_id && a.from_device == device)
                else {
                    return Some(fail(404, "not_found"));
                };
                if action.state == "open" && now() >= action.expires_at {
                    action.state = "expired".to_owned();
                }
                if action.state == "open" && !done {
                    return None;
                }
                Some(ok(action.view()))
            })
        }
        ("POST", ["actions", action_id, "settle"]) => {
            let body = request.json();
            let Some(outcome) = body["outcome"]
                .as_str()
                .filter(|o| matches!(*o, "applied" | "refused" | "stale"))
            else {
                return Some(fail(400, "invalid_request"));
            };
            // The target only.
            let Some(action) = relay
                .actions
                .iter_mut()
                .find(|a| a.action_id == *action_id && a.to_device == device)
            else {
                return Some(fail(404, "not_found"));
            };
            if action.state == "settled" {
                return Some(fail(409, "action_settled"));
            }
            action.state = "settled".to_owned();
            action.outcome = Some(outcome.to_owned());
            action.settled_at = Some(now());
            action.settle = Some(json!({"key_id": body["key_id"], "nonce": body["nonce"],
                                        "ciphertext": body["ciphertext"]}));
            changed.notify_all();
            ok(
                json!({"action_id": action_id, "state": "settled", "outcome": outcome,
                      "settled_at": now()}),
            )
        }
        _ => return None,
    };
    Some(answer)
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
            if segments.get(1) == Some(&"feed") {
                return feed_route(relay, changed, request, device, &segments[2..])
                    .unwrap_or_else(|| fail(404, "not_found"));
            }
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
