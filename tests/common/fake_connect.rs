//! An in-process fake of Apassy Connect accounts for the Mac tests (contract
//! connect-account-v1, plan s7 unit M1), in the style of `fake_relay.rs`.
//!
//! It speaks plain HTTP/1.1 on 127.0.0.1, one thread per connection, keeps everything in
//! memory, and checks what Connect checks with `ring` directly, not with the app's code:
//! the strict request bodies, the signatures of section 5 over its own origin, the
//! one-use nonces, the tokens, the links and joins of section 7, the recovery hash of
//! section 9, and the entitlement token of section 10 (signed with the Ed25519 seed of
//! the test vectors, kid `ek_test_1`). It is not the relay crate (C1), which replaces it
//! once C1 merges.
//!
//! Hooks act as a broken or hostile Connect: report another origin in the challenge,
//! shorten the token lifetime, lose the next answers after doing the step, entitle an
//! account, revoke a device behind the app's back, and read what the app sent.
//!
//! Billing and groups (contract connect-billing-v1, plan s7 unit M2): `GET /v1/plans`
//! answers `tests/fixtures/connect-billing-v1/plans.json`; the checkout, the portal, the
//! plan, and the group routes check the strict bodies and the roles of sections 4 to 6
//! and answer synthetic Stripe URLs. No Stripe is called: [`FakeConnect::complete_checkout`]
//! does what the webhook would (binds the customer, sets the plan, makes the group), and
//! [`FakeConnect::set_plan`] sets any `PlanView` of section 8. A seats change applies at
//! once here (Connect waits for `customer.subscription.updated`).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use super::relay_api::{decode_b64u, encode_b64u, sha256_hex};
use ring::signature::{ECDSA_P256_SHA256_ASN1, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};

/// The Ed25519 seed of the test vectors: bytes 32 to 63.
pub fn entitlement_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = 32 + index as u8;
    }
    seed
}

/// The kid of the entitlement key of the test vectors.
pub const KID: &str = "ek_test_1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JoinState {
    Pending,
    Confirmed,
    Refused,
    Cancelled,
}

#[derive(Clone)]
struct Device {
    id: String,
    account: String,
    name: String,
    platform: String,
    public_key: Vec<u8>,
    created_at: u64,
    live: bool,
}

#[derive(Clone)]
struct Account {
    name: String,
    created_at: u64,
    recovery_hash: String,
    entitled: bool,
    /// A `PlanView` set by [`FakeConnect::set_plan`] or a completed checkout.
    plan: Option<Value>,
    /// A Stripe customer is bound (a checkout completed): the portal works.
    customer: bool,
}

/// A checkout session that the app asked for.
struct Checkout {
    session_id: String,
    account: String,
    body: Value,
    completed: bool,
}

struct Member {
    account: String,
    role: String,
    state: String,
    joined_at: u64,
}

struct Group {
    id: String,
    kind: String,
    owner: String,
    included: u64,
    max: u64,
    quantity: u64,
    members: Vec<Member>,
}

struct Invite {
    code: String,
    group: String,
    role: String,
    used: bool,
}

struct Link {
    id: u64,
    account: String,
    device: String,
    hash: String,
    expires_at: u64,
    used: bool,
}

struct Join {
    id: u64,
    link_id: u64,
    account: String,
    name: String,
    platform: String,
    public_key: Vec<u8>,
    state: JoinState,
    body: Value,
}

struct Store {
    team_id: String,
    vault_id: String,
    name: String,
    account: String,
    created_at: u64,
    devices: Vec<(u64, String)>,
}

#[derive(Default)]
struct State {
    origin: String,
    reported_origin: Option<String>,
    accounts: BTreeMap<String, Account>,
    devices: Vec<Device>,
    links: Vec<Link>,
    joins: Vec<Join>,
    stores: Vec<Store>,
    /// nonce → (account, key).
    nonces: BTreeMap<String, (String, Vec<u8>)>,
    /// token → (account, device, expires_at).
    tokens: BTreeMap<String, (String, String, u64)>,
    token_seconds: u64,
    next: u64,
    /// The bodies of `POST /v1/account` by key, for a retry after a lost answer.
    created: BTreeMap<Vec<u8>, (Value, Value)>,
    lost_answers: Vec<(String, usize)>,
    log: Vec<String>,
    bodies: Vec<String>,
    /// Each request line with its `Authorization` header.
    authorizations: Vec<(String, Option<String>)>,
    recover_tries: u64,
    checkouts: Vec<Checkout>,
    groups: Vec<Group>,
    invites: Vec<Invite>,
}

/// A running fake Connect.
pub struct FakeConnect {
    /// The origin, `http://127.0.0.1:<port>`.
    pub url: String,
    shared: Arc<Mutex<State>>,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
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

fn joined(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

/// An id of `prefix` and 10 characters of `a-z2-7`, from a counter.
fn id(prefix: &str, counter: u64) -> String {
    let digits = format!("{counter:010}");
    let tail: String = digits
        .chars()
        .map(|ch| char::from(b'a' + ch.to_digit(10).unwrap_or(0) as u8))
        .collect();
    format!("{prefix}{tail}")
}

/// 64 lowercase hex characters that differ for each call.
fn secret_hex(counter: u64) -> String {
    sha256_hex(format!("fake-connect-secret-{counter}-{}", now()).as_bytes())
}

/// A strict body: exactly these keys, each a string.
fn strict(body: &Value, keys: &[&str]) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    map.len() == keys.len()
        && keys
            .iter()
            .all(|key| map.get(*key).is_some_and(Value::is_string))
}

fn text<'a>(body: &'a Value, key: &str) -> &'a str {
    body[key].as_str().unwrap_or_default()
}

fn point(text: &str) -> Option<Vec<u8>> {
    decode_b64u(text).filter(|key| key.len() == 65 && key[0] == 0x04)
}

impl FakeConnect {
    /// Start a fake Connect on a free port of 127.0.0.1.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake connect");
        let url = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        );
        let shared = Arc::new(Mutex::new(State {
            origin: url.clone(),
            token_seconds: 900,
            next: 1,
            ..State::default()
        }));
        let server = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let server = Arc::clone(&server);
                std::thread::spawn(move || handle(&server, stream));
            }
        });
        Self { url, shared }
    }

    /// The challenge reports `origin` (a Connect behind another address, or a hostile
    /// one).
    pub fn report_origin(&self, origin: &str) {
        lock(&self.shared).reported_origin = Some(origin.to_owned());
    }

    /// Tokens live `seconds`.
    pub fn set_token_lifetime(&self, seconds: u64) {
        lock(&self.shared).token_seconds = seconds;
    }

    /// The next `count` requests that start with `prefix` do their step and lose the
    /// answer (the connection closes).
    pub fn lose_next_answers(&self, prefix: &str, count: usize) {
        lock(&self.shared)
            .lost_answers
            .push((prefix.to_owned(), count));
    }

    /// The account gets an entitled plan (Personal).
    pub fn entitle(&self, account: &str) {
        if let Some(account) = lock(&self.shared).accounts.get_mut(account) {
            account.entitled = true;
        }
    }

    /// Revoke a device as another device of the account would.
    pub fn revoke(&self, device: &str) {
        let mut state = lock(&self.shared);
        for entry in &mut state.devices {
            if entry.id == device {
                entry.live = false;
            }
        }
        state
            .tokens
            .retain(|_, (_, owner, _)| owner.as_str() != device);
    }

    /// The live device ids of `account`.
    pub fn live_devices(&self, account: &str) -> Vec<String> {
        lock(&self.shared)
            .devices
            .iter()
            .filter(|device| device.live && device.account == account)
            .map(|device| device.id.clone())
            .collect()
    }

    /// The public keys of every device that Connect ever saw.
    pub fn known_keys(&self) -> Vec<Vec<u8>> {
        lock(&self.shared)
            .devices
            .iter()
            .map(|device| device.public_key.clone())
            .collect()
    }

    /// The accounts that exist.
    pub fn accounts(&self) -> Vec<String> {
        lock(&self.shared).accounts.keys().cloned().collect()
    }

    /// The request lines.
    pub fn log(&self) -> Vec<String> {
        lock(&self.shared).log.clone()
    }

    /// How many requests start with `prefix`.
    pub fn count(&self, prefix: &str) -> usize {
        lock(&self.shared)
            .log
            .iter()
            .filter(|line| line.starts_with(prefix))
            .count()
    }

    /// Every request body, as text.
    pub fn bodies(&self) -> Vec<String> {
        lock(&self.shared).bodies.clone()
    }

    /// Each request line with its `Authorization` header.
    pub fn authorizations(&self) -> Vec<(String, Option<String>)> {
        lock(&self.shared).authorizations.clone()
    }

    /// The ids of the vault stores of `account`.
    pub fn stores(&self, account: &str) -> Vec<String> {
        lock(&self.shared)
            .stores
            .iter()
            .filter(|store| store.account == account)
            .map(|store| store.team_id.clone())
            .collect()
    }

    /// The `PlanView` that `GET /v1/account` and `GET /v1/account/plan` answer for
    /// `account`; `entitled` follows its `entitled` field.
    pub fn set_plan(&self, account: &str, plan: Value) {
        if let Some(entry) = lock(&self.shared).accounts.get_mut(account) {
            entry.entitled = plan["entitled"].as_bool().unwrap_or(false);
            entry.plan = Some(plan);
        }
    }

    /// What the webhook does after `checkout.session.completed` and
    /// `customer.subscription.created` for the checkout `session_id`: the customer is
    /// bound, the plan is active, and a Family or Team checkout makes the group with the
    /// buyer as its owner. False for an unknown or completed session.
    pub fn complete_checkout(&self, session_id: &str) -> bool {
        let mut state = lock(&self.shared);
        let Some(index) = state
            .checkouts
            .iter()
            .position(|checkout| checkout.session_id == session_id && !checkout.completed)
        else {
            return false;
        };
        state.checkouts[index].completed = true;
        let account = state.checkouts[index].account.clone();
        let body = state.checkouts[index].body.clone();
        let plan = text(&body, "plan").to_owned();
        let quantity = body["people"]
            .as_u64()
            .or_else(|| body["seats"].as_u64())
            .unwrap_or(1);
        state.next += 1;
        let group_id = (plan != "personal").then(|| id("grp_", state.next));
        let renews = now() + 2_592_000;
        let view = json!({"plan": plan, "status": "active", "entitled": true,
                          "interval": text(&body, "interval"), "quantity": quantity,
                          "renews_at": renews, "ends_at": null, "grace_until": null,
                          "read_only_until": null, "delete_at": null, "group_id": group_id});
        if let Some(entry) = state.accounts.get_mut(&account) {
            entry.entitled = true;
            entry.customer = true;
            entry.plan = Some(view);
        }
        if let Some(group_id) = group_id {
            let offer = plan_offer(&plan);
            state.groups.push(Group {
                id: group_id,
                kind: plan.clone(),
                owner: account.clone(),
                included: offer["included"].as_u64().unwrap_or(1),
                max: offer["max"].as_u64().unwrap_or(1),
                quantity,
                members: vec![Member {
                    account,
                    role: "owner".to_owned(),
                    state: "active".to_owned(),
                    joined_at: now(),
                }],
            });
        }
        true
    }

    /// The bodies of the checkouts that the app asked for, in order, with their session
    /// ids.
    pub fn checkouts(&self) -> Vec<(String, Value)> {
        lock(&self.shared)
            .checkouts
            .iter()
            .map(|checkout| (checkout.session_id.clone(), checkout.body.clone()))
            .collect()
    }

    /// The members of the group of `account`: (account, role, state).
    pub fn members(&self, account: &str) -> Vec<(String, String, String)> {
        let state = lock(&self.shared);
        group_of(&state, account)
            .map(|index| {
                state.groups[index]
                    .members
                    .iter()
                    .map(|member| {
                        (
                            member.account.clone(),
                            member.role.clone(),
                            member.state.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The subscription quantity of the group of `account`.
    pub fn quantity(&self, account: &str) -> Option<u64> {
        let state = lock(&self.shared);
        group_of(&state, account).map(|index| state.groups[index].quantity)
    }

    /// The public key of the entitlement key, b64u.
    pub fn entitlement_public_key() -> String {
        let pair = Ed25519KeyPair::from_seed_unchecked(&entitlement_seed()).expect("seed");
        encode_b64u(pair.public_key().as_ref())
    }
}

/// One request.
struct Incoming {
    method: String,
    path: String,
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

struct Outgoing {
    status: u16,
    body: Vec<u8>,
}

fn ok(result: Value) -> Outgoing {
    Outgoing {
        status: 200,
        body: serde_json::to_vec(&json!({"ok": true, "result": result})).unwrap(),
    }
}

fn fail(status: u16, code: &str) -> Outgoing {
    Outgoing {
        status,
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
    let mut body = vec![0u8; length.min(64 * 1024)];
    reader.read_exact(&mut body).ok()?;
    let path = target.split('?').next().unwrap_or_default().to_owned();
    Some(Incoming {
        method,
        path,
        headers,
        body,
    })
}

fn handle(shared: &Arc<Mutex<State>>, mut stream: TcpStream) {
    let Some(request) = read_request(&stream) else {
        return;
    };
    let line = format!("{} {}", request.method, request.path);
    let lost = {
        let mut state = lock(shared);
        state.log.push(line.clone());
        state.authorizations.push((
            line.clone(),
            request.header("authorization").map(str::to_owned),
        ));
        if !request.body.is_empty() {
            state
                .bodies
                .push(String::from_utf8_lossy(&request.body).into_owned());
        }
        state
            .lost_answers
            .iter_mut()
            .find(|(prefix, left)| *left > 0 && line.starts_with(prefix.as_str()))
            .map(|(_, left)| *left -= 1)
            .is_some()
    };
    let answer = route(shared, &request);
    if lost {
        return;
    }
    let head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        answer.status,
        answer.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&answer.body);
    let _ = stream.flush();
}

/// The account and the device of the bearer token, when the device is live.
fn caller(state: &State, request: &Incoming) -> Option<(String, String)> {
    let token = request.header("authorization")?.strip_prefix("Bearer ")?;
    let (account, device, expires_at) = state.tokens.get(token)?.clone();
    if expires_at <= now() {
        return None;
    }
    state
        .devices
        .iter()
        .any(|entry| entry.id == device && entry.live)
        .then_some((account, device))
}

fn device_view(device: &Device) -> Value {
    json!({"device_id": device.id, "name": device.name, "platform": device.platform,
           "public_key": encode_b64u(&device.public_key), "created_at": device.created_at,
           "last_seen_at": null})
}

/// The plans of the default configuration (connect-billing-v1 section 2).
fn plans() -> Value {
    serde_json::from_str(include_str!("../fixtures/connect-billing-v1/plans.json"))
        .expect("plans.json")
}

/// One plan of [`plans`].
fn plan_offer(plan: &str) -> Value {
    plans()["plans"]
        .as_array()
        .and_then(|offers| offers.iter().find(|offer| offer["plan"] == plan).cloned())
        .unwrap_or(Value::Null)
}

/// The index of the group in which `account` is a member (pending or active).
fn group_of(state: &State, account: &str) -> Option<usize> {
    state
        .groups
        .iter()
        .position(|group| group.members.iter().any(|member| member.account == account))
}

/// The member entry of `account` in its group.
fn membership<'a>(state: &'a State, account: &str) -> Option<(&'a Group, &'a Member)> {
    let group = &state.groups[group_of(state, account)?];
    let member = group
        .members
        .iter()
        .find(|member| member.account == account)?;
    Some((group, member))
}

fn no_plan() -> Value {
    json!({"plan": null, "status": "none", "entitled": false, "interval": null,
           "quantity": null, "renews_at": null, "ends_at": null, "grace_until": null,
           "read_only_until": null, "delete_at": null, "group_id": null})
}

/// The `PlanView` of `account`: its own plan, or for an active member the plan of the
/// group's owner, and none for a pending member (section 8).
fn account_plan(state: &State, account: &str) -> Value {
    if let Some((group, member)) = membership(state, account)
        && group.owner != account
    {
        if member.state != "active" {
            return no_plan();
        }
        let mut view = state
            .accounts
            .get(&group.owner)
            .map_or_else(no_plan, plan_view);
        view["quantity"] = json!(group.quantity);
        view["group_id"] = json!(group.id);
        return view;
    }
    let Some(entry) = state.accounts.get(account) else {
        return no_plan();
    };
    let mut view = plan_view(entry);
    if let Some(index) = group_of(state, account) {
        view["quantity"] = json!(state.groups[index].quantity);
    }
    view
}

/// The short group of `GET /v1/account`.
fn account_group(state: &State, account: &str) -> Value {
    match membership(state, account) {
        Some((group, member)) => json!({"group_id": group.id, "kind": group.kind,
                                        "role": member.role, "state": member.state}),
        None => Value::Null,
    }
}

fn member_view(state: &State, member: &Member) -> Value {
    let name = state
        .accounts
        .get(&member.account)
        .map(|entry| entry.name.clone())
        .unwrap_or_default();
    json!({"account_id": member.account, "name": name, "role": member.role,
           "state": member.state, "joined_at": member.joined_at})
}

fn plan_view(account: &Account) -> Value {
    if let Some(plan) = &account.plan {
        return plan.clone();
    }
    if account.entitled {
        json!({"plan": "personal", "status": "active", "entitled": true, "interval": "month",
               "quantity": 1, "renews_at": now() + 2_592_000, "ends_at": null,
               "grace_until": null, "read_only_until": null, "delete_at": null,
               "group_id": null})
    } else {
        json!({"plan": null, "status": "none", "entitled": false, "interval": null,
               "quantity": null, "renews_at": null, "ends_at": null, "grace_until": null,
               "read_only_until": null, "delete_at": null, "group_id": null})
    }
}

fn store_view(store: &Store, state: &State) -> Value {
    let devices: Vec<Value> = store
        .devices
        .iter()
        .map(|(number, device)| {
            let account = state
                .devices
                .iter()
                .find(|entry| &entry.id == device)
                .map(|entry| entry.account.clone())
                .unwrap_or_default();
            json!({"store_device_id": number, "device_id": device, "account_id": account})
        })
        .collect();
    json!({"team_id": store.team_id, "vault_id": store.vault_id, "name": store.name,
           "created_at": store.created_at, "shared": false, "devices": devices})
}

fn new_device(
    state: &mut State,
    account: &str,
    name: &str,
    platform: &str,
    public_key: Vec<u8>,
) -> Device {
    state.next += 1;
    let device = Device {
        id: id("dev_", state.next),
        account: account.to_owned(),
        name: name.to_owned(),
        platform: platform.to_owned(),
        public_key,
        created_at: now(),
        live: true,
    };
    state.devices.push(device.clone());
    device
}

fn route(shared: &Arc<Mutex<State>>, request: &Incoming) -> Outgoing {
    let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
    let mut state = lock(shared);
    let origin = state.origin.clone();
    let edge = matches!(
        (request.method.as_str(), segments.as_slice()),
        ("POST", ["v1", "account"])
            | ("POST", ["v1", "account", "challenge" | "token" | "recover"])
            | ("POST", ["v1", "account", "devices", "join"])
            | ("POST", ["v1", "account", "devices", "join", "cancel"])
            | ("GET", [".well-known", "apassy-connect.json"])
    );
    if edge && request.header("authorization").is_some() {
        return fail(400, "invalid_request");
    }
    let body = request.json();
    match (request.method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "account"]) => {
            let keys = [
                "name",
                "device_name",
                "platform",
                "public_key",
                "recovery_hash",
                "signature",
            ];
            if !strict(&body, &keys) {
                return fail(400, "invalid_request");
            }
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            let message = joined(&[
                "apassy-connect account v1",
                &origin,
                text(&body, "public_key"),
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
            if let Some((earlier, answer)) = state.created.get(&public_key) {
                return if *earlier == body {
                    ok(answer.clone())
                } else {
                    fail(409, "conflict")
                };
            }
            if state
                .devices
                .iter()
                .any(|device| device.public_key == public_key)
            {
                return fail(409, "conflict");
            }
            state.next += 1;
            let account_id = id("acc_", state.next);
            state.accounts.insert(
                account_id.clone(),
                Account {
                    name: text(&body, "name").to_owned(),
                    created_at: now(),
                    recovery_hash: text(&body, "recovery_hash").to_owned(),
                    entitled: false,
                    plan: None,
                    customer: false,
                },
            );
            let device = new_device(
                &mut state,
                &account_id,
                text(&body, "device_name"),
                text(&body, "platform"),
                public_key.clone(),
            );
            let answer = json!({"account_id": account_id, "device_id": device.id,
                                "created_at": device.created_at});
            state.created.insert(public_key, (body, answer.clone()));
            ok(answer)
        }
        ("POST", ["v1", "account", "challenge"]) => {
            if !strict(&body, &["account_id", "public_key"]) {
                return fail(400, "invalid_request");
            }
            let account = text(&body, "account_id").to_owned();
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            let live = state.devices.iter().any(|device| {
                device.live && device.account == account && device.public_key == public_key
            });
            if !live {
                return match state
                    .joins
                    .iter()
                    .rev()
                    .find(|join| join.account == account && join.public_key == public_key)
                    .map(|join| join.state)
                {
                    Some(JoinState::Pending) => fail(403, "join_pending"),
                    Some(JoinState::Refused | JoinState::Cancelled) => fail(403, "join_refused"),
                    _ => fail(401, "unauthenticated"),
                };
            }
            state.next += 1;
            let hex = secret_hex(state.next);
            let nonce_bytes: Vec<u8> = (0..32)
                .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
                .collect();
            let nonce = encode_b64u(&nonce_bytes);
            state.nonces.insert(nonce.clone(), (account, public_key));
            let reported = state.reported_origin.clone().unwrap_or(origin);
            ok(json!({"nonce": nonce, "expires_at": now() + 60, "origin": reported}))
        }
        ("POST", ["v1", "account", "token"]) => {
            if !strict(&body, &["account_id", "public_key", "nonce", "signature"]) {
                return fail(400, "invalid_request");
            }
            let nonce = text(&body, "nonce").to_owned();
            let Some((account, public_key)) = state.nonces.remove(&nonce) else {
                return fail(401, "unauthenticated");
            };
            let message = joined(&[
                "apassy-connect sign-in v1",
                &origin,
                &account,
                &encode_b64u(&public_key),
                &nonce,
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if text(&body, "account_id") != account
                || point(text(&body, "public_key")).as_deref() != Some(public_key.as_slice())
                || !verify(&public_key, &message, &signature)
            {
                return fail(401, "unauthenticated");
            }
            let Some(device) = state
                .devices
                .iter()
                .find(|device| device.live && device.public_key == public_key)
                .map(|device| device.id.clone())
            else {
                return fail(401, "unauthenticated");
            };
            state.next += 1;
            let token = format!("apassy_act_{account}_{}", secret_hex(state.next));
            let expires_at = now() + state.token_seconds;
            state
                .tokens
                .insert(token.clone(), (account.clone(), device.clone(), expires_at));
            ok(
                json!({"token": token, "expires_at": expires_at, "account_id": account,
                      "device_id": device}),
            )
        }
        ("POST", ["v1", "account", "devices", "join"]) => {
            let keys = [
                "account_id",
                "link_hash",
                "device_name",
                "platform",
                "public_key",
                "signature",
            ];
            if !strict(&body, &keys) {
                return fail(400, "invalid_request");
            }
            let account = text(&body, "account_id").to_owned();
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            let message = joined(&[
                "apassy-connect join v1",
                &origin,
                &account,
                text(&body, "link_hash"),
                text(&body, "public_key"),
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
            // The same body again answers the same result.
            if let Some(join) = state.joins.iter().find(|join| join.body == body) {
                let link_id = join.link_id;
                let join_id = join.id;
                let link = state
                    .links
                    .iter()
                    .find(|link| link.id == link_id)
                    .expect("link");
                let confirmer = state
                    .devices
                    .iter()
                    .find(|device| device.id == link.device)
                    .expect("confirmer");
                return ok(json!({"join_id": join_id, "account_id": account,
                    "confirmer": {"device_id": confirmer.id, "name": confirmer.name,
                                  "public_key": encode_b64u(&confirmer.public_key)},
                    "expires_at": link.expires_at}));
            }
            let at = now();
            let Some(link) = state.links.iter_mut().find(|link| {
                link.account == account
                    && link.hash == text(&body, "link_hash")
                    && !link.used
                    && link.expires_at > at
            }) else {
                return fail(403, "forbidden");
            };
            link.used = true;
            let (link_id, creator, expires_at) = (link.id, link.device.clone(), link.expires_at);
            state.next += 1;
            let join_id = state.next;
            state.joins.push(Join {
                id: join_id,
                link_id,
                account: account.clone(),
                name: text(&body, "device_name").to_owned(),
                platform: text(&body, "platform").to_owned(),
                public_key,
                state: JoinState::Pending,
                body: body.clone(),
            });
            let confirmer = state
                .devices
                .iter()
                .find(|device| device.id == creator)
                .expect("confirmer");
            ok(json!({"join_id": join_id, "account_id": account,
                "confirmer": {"device_id": confirmer.id, "name": confirmer.name,
                              "public_key": encode_b64u(&confirmer.public_key)},
                "expires_at": expires_at}))
        }
        ("POST", ["v1", "account", "devices", "join", "cancel"]) => {
            if !strict(&body, &["account_id", "link_hash", "public_key"]) {
                return fail(400, "invalid_request");
            }
            let public_key = point(text(&body, "public_key")).unwrap_or_default();
            let link_ids: Vec<u64> = state
                .links
                .iter()
                .filter(|link| link.hash == text(&body, "link_hash"))
                .map(|link| link.id)
                .collect();
            match state.joins.iter_mut().find(|join| {
                join.public_key == public_key
                    && link_ids.contains(&join.link_id)
                    && join.state == JoinState::Pending
            }) {
                Some(join) => {
                    join.state = JoinState::Cancelled;
                    ok(json!({"join_id": join.id}))
                }
                None => fail(403, "forbidden"),
            }
        }
        ("POST", ["v1", "account", "recover"]) => {
            let keys = [
                "account_id",
                "recovery",
                "device_name",
                "platform",
                "public_key",
                "recovery_hash",
                "signature",
            ];
            if !strict(&body, &keys) {
                return fail(400, "invalid_request");
            }
            let account = text(&body, "account_id").to_owned();
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            state.recover_tries += 1;
            let Some(hex) = text(&body, "recovery").strip_prefix("apassy_rec_") else {
                return fail(403, "forbidden");
            };
            let Some(bytes) = (0..16)
                .map(|index| u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()
            else {
                return fail(403, "forbidden");
            };
            let mut hashed = b"apassy-connect recovery v1\0".to_vec();
            hashed.extend_from_slice(&bytes);
            let live = state
                .devices
                .iter()
                .any(|device| device.live && device.account == account);
            let matches = state
                .accounts
                .get(&account)
                .is_some_and(|entry| entry.recovery_hash == sha256_hex(&hashed));
            if live || !matches {
                return fail(403, "forbidden");
            }
            let message = joined(&[
                "apassy-connect recover v1",
                &origin,
                &account,
                text(&body, "public_key"),
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
            let deleted = state
                .stores
                .iter()
                .filter(|store| store.account == account)
                .count();
            state.stores.retain(|store| store.account != account);
            let new_hash = text(&body, "recovery_hash").to_owned();
            if let Some(entry) = state.accounts.get_mut(&account) {
                entry.recovery_hash = new_hash;
            }
            let device = new_device(
                &mut state,
                &account,
                text(&body, "device_name"),
                text(&body, "platform"),
                public_key,
            );
            ok(json!({"account_id": account, "device_id": device.id,
                      "deleted_stores": deleted}))
        }
        ("GET", ["v1", "plans"]) => ok(plans()),
        ("GET", [".well-known", "apassy-connect.json"]) => ok(json!({
            "v": 1,
            "origin": origin,
            "keys": [{"kid": KID, "alg": "Ed25519",
                      "public_key": FakeConnect::entitlement_public_key()}],
        })),
        (method, ["v1", "account", rest @ ..]) => {
            let Some((account, device)) = caller(&state, request) else {
                return fail(401, "unauthenticated");
            };
            authenticated(&mut state, method, rest, &body, &account, &device, &origin)
        }
        _ => fail(404, "not_found"),
    }
}

fn authenticated(
    state: &mut State,
    method: &str,
    rest: &[&str],
    body: &Value,
    account: &str,
    device: &str,
    origin: &str,
) -> Outgoing {
    match (method, rest) {
        ("GET", []) => {
            let entry = state.accounts.get(account).expect("account").clone();
            let devices: Vec<Value> = state
                .devices
                .iter()
                .filter(|entry| entry.live && entry.account == account)
                .map(device_view)
                .collect();
            ok(
                json!({"account_id": account, "name": entry.name, "email": null,
                      "created_at": entry.created_at,
                      "plan": account_plan(state, account),
                      "devices": devices, "group": account_group(state, account)}),
            )
        }
        ("DELETE", []) => {
            if body.as_object().is_none_or(|map| !map.is_empty()) {
                return fail(400, "invalid_request");
            }
            if let Some((group, _)) = membership(state, account)
                && group.owner == account
                && group.members.len() > 1
            {
                return fail(409, "conflict");
            }
            if let Some(index) = group_of(state, account) {
                if state.groups[index].owner == account {
                    state.groups.remove(index);
                } else {
                    state.groups[index]
                        .members
                        .retain(|member| member.account != account);
                }
            }
            let deleted = state
                .stores
                .iter()
                .filter(|store| store.account == account)
                .count();
            state.stores.retain(|store| store.account != account);
            state.accounts.remove(account);
            for entry in &mut state.devices {
                if entry.account == account {
                    entry.live = false;
                }
            }
            state
                .tokens
                .retain(|_, (owner, _, _)| owner.as_str() != account);
            ok(json!({"account_id": account, "deleted_stores": deleted,
                      "subscription_canceled": false}))
        }
        ("POST", ["devices", "link"]) => {
            if !strict(body, &["link_hash"]) || text(body, "link_hash").len() != 43 {
                return fail(400, "invalid_request");
            }
            state.next += 1;
            let link_id = state.next;
            let expires_at = now() + 600;
            state.links.push(Link {
                id: link_id,
                account: account.to_owned(),
                device: device.to_owned(),
                hash: text(body, "link_hash").to_owned(),
                expires_at,
                used: false,
            });
            ok(json!({"link_id": link_id, "expires_at": expires_at}))
        }
        ("GET", ["devices", "pending"]) => {
            let mine: Vec<u64> = state
                .links
                .iter()
                .filter(|link| link.device == device)
                .map(|link| link.id)
                .collect();
            let pending: Vec<Value> = state
                .joins
                .iter()
                .filter(|join| join.state == JoinState::Pending && mine.contains(&join.link_id))
                .map(|join| {
                    json!({"join_id": join.id, "link_id": join.link_id,
                           "device_name": join.name, "platform": join.platform,
                           "public_key": encode_b64u(&join.public_key),
                           "created_at": now(), "expires_at": now() + 600})
                })
                .collect();
            ok(Value::Array(pending))
        }
        (
            "POST",
            [
                "devices",
                "pending",
                join_id,
                action @ ("confirm" | "refuse"),
            ],
        ) => {
            let join_id: u64 = join_id.parse().unwrap_or(0);
            let Some(index) = state.joins.iter().position(|join| join.id == join_id) else {
                return fail(404, "not_found");
            };
            let link_id = state.joins[index].link_id;
            let owner = state
                .links
                .iter()
                .find(|link| link.id == link_id)
                .map(|link| link.device.clone());
            if owner.as_deref() != Some(device) {
                return fail(403, "forbidden");
            }
            if state.joins[index].state != JoinState::Pending {
                return fail(409, "conflict");
            }
            if *action == "refuse" {
                if !strict(body, &[]) {
                    return fail(400, "invalid_request");
                }
                state.joins[index].state = JoinState::Refused;
                return ok(json!({"join_id": join_id}));
            }
            if !strict(body, &["public_key"]) {
                return fail(400, "invalid_request");
            }
            if point(text(body, "public_key")).as_deref()
                != Some(state.joins[index].public_key.as_slice())
            {
                return fail(409, "conflict");
            }
            state.joins[index].state = JoinState::Confirmed;
            let join = &state.joins[index];
            let (name, platform, key) = (
                join.name.clone(),
                join.platform.clone(),
                join.public_key.clone(),
            );
            let added = new_device(state, account, &name, &platform, key);
            ok(device_view(&added))
        }
        ("DELETE", ["devices", target]) => {
            let Some(entry) = state
                .devices
                .iter_mut()
                .find(|entry| entry.id == *target && entry.account == account && entry.live)
            else {
                return fail(404, "not_found");
            };
            entry.live = false;
            let target = (*target).to_owned();
            state.tokens.retain(|_, (_, owner, _)| *owner != target);
            let mut removed = 0;
            for store in &mut state.stores {
                let before = store.devices.len();
                store.devices.retain(|(_, member)| *member != target);
                removed += before - store.devices.len();
            }
            ok(json!({"device_id": target, "removed_from_stores": removed}))
        }
        ("POST", ["vaults"]) => {
            if !strict(body, &["vault_id", "name"]) {
                return fail(400, "invalid_request");
            }
            if !state
                .accounts
                .get(account)
                .is_some_and(|entry| entry.entitled)
            {
                return fail(403, "plan_required");
            }
            let vault_id = text(body, "vault_id").to_owned();
            if let Some(store) = state
                .stores
                .iter()
                .find(|store| store.account == account && store.vault_id == vault_id)
            {
                return ok(store_view(store, state));
            }
            state.next += 1;
            let store = Store {
                team_id: id("t_", state.next),
                vault_id,
                name: text(body, "name").to_owned(),
                account: account.to_owned(),
                created_at: now(),
                devices: vec![(1, device.to_owned())],
            };
            let view = store_view(&store, state);
            state.stores.push(store);
            ok(view)
        }
        ("POST", ["vaults", team, "devices"]) => {
            if !strict(body, &["device_id"]) {
                return fail(400, "invalid_request");
            }
            let device_id = text(body, "device_id").to_owned();
            let Some(added) = state
                .devices
                .iter()
                .find(|entry| entry.id == device_id && entry.live)
                .map(|entry| entry.account.clone())
            else {
                return fail(404, "not_found");
            };
            if added != account {
                return fail(403, "not_in_group");
            }
            let Some(store) = state
                .stores
                .iter_mut()
                .find(|store| store.account == account && store.team_id == *team)
            else {
                return fail(404, "not_found");
            };
            let number = match store.devices.iter().find(|(_, id)| *id == device_id) {
                Some((number, _)) => *number,
                None => {
                    let number = store.devices.len() as u64 + 1;
                    store.devices.push((number, device_id.clone()));
                    number
                }
            };
            ok(json!({"store_device_id": number, "device_id": device_id, "account_id": added}))
        }
        ("DELETE", ["vaults", team]) => {
            let before = state.stores.len();
            state
                .stores
                .retain(|store| !(store.account == account && store.team_id == *team));
            if state.stores.len() == before {
                return fail(404, "not_found");
            }
            ok(json!({"team_id": team}))
        }
        ("GET", ["vaults"]) => {
            let views: Vec<Value> = state
                .stores
                .iter()
                .filter(|store| store.account == account)
                .map(|store| store_view(store, state))
                .collect();
            ok(Value::Array(views))
        }
        ("GET", ["entitlement"]) => {
            if !state
                .accounts
                .get(account)
                .is_some_and(|entry| entry.entitled)
            {
                return fail(403, "plan_required");
            }
            let iat = now();
            let claims = json!({"v": 1, "kid": KID, "acc": account, "plan": "personal",
                                "group": null, "feats": ["brain", "sync", "tunnel"],
                                "iat": iat, "exp": iat + 86_400});
            let payload = encode_b64u(&serde_json::to_vec(&claims).unwrap());
            let pair = Ed25519KeyPair::from_seed_unchecked(&entitlement_seed()).expect("seed");
            let mut message = b"apassy-connect entitlement v1\0".to_vec();
            message.extend_from_slice(payload.as_bytes());
            let signature = encode_b64u(pair.sign(&message).as_ref());
            let _ = origin;
            ok(json!({"token": format!("{payload}.{signature}"), "expires_at": iat + 86_400}))
        }
        _ => billing(state, method, rest, body, account),
    }
}

/// A count field of a checkout body: a JSON number.
fn count(body: &Value, key: &str) -> Option<u64> {
    body.get(key).and_then(Value::as_u64)
}

/// The routes of connect-billing-v1 sections 4 to 6 and 8.
fn billing(
    state: &mut State,
    method: &str,
    rest: &[&str],
    body: &Value,
    account: &str,
) -> Outgoing {
    match (method, rest) {
        ("GET", ["plan"]) => ok(account_plan(state, account)),
        ("POST", ["checkout"]) => {
            let Some(map) = body.as_object() else {
                return fail(400, "invalid_request");
            };
            let plan = text(body, "plan");
            let field = match plan {
                "personal" => None,
                "family" => Some("people"),
                "team" => Some("seats"),
                _ => return fail(400, "invalid_request"),
            };
            let expected = 2 + usize::from(field.is_some());
            if map.len() != expected
                || !matches!(text(body, "interval"), "month" | "year")
                || field.is_some_and(|field| count(body, field).is_none())
            {
                return fail(400, "invalid_request");
            }
            if account_plan(state, account)["entitled"] == true
                || membership(state, account).is_some()
            {
                return fail(409, "conflict");
            }
            let offer = plan_offer(plan);
            let n = field.and_then(|field| count(body, field)).unwrap_or(1);
            if n == 0 || n > offer["max"].as_u64().unwrap_or(1) {
                return fail(409, "seat_limit");
            }
            state.next += 1;
            let session_id = format!("cs_test_Fake{:04}", state.next);
            state.checkouts.push(Checkout {
                session_id: session_id.clone(),
                account: account.to_owned(),
                body: body.clone(),
                completed: false,
            });
            ok(
                json!({"url": format!("https://checkout.stripe.com/c/pay/{session_id}"),
                      "session_id": session_id, "expires_at": now() + 86_400}),
            )
        }
        ("POST", ["portal"]) => {
            if !strict(body, &[]) {
                return fail(400, "invalid_request");
            }
            if let Some((group, _)) = membership(state, account)
                && group.owner != account
            {
                return fail(403, "forbidden");
            }
            if !state
                .accounts
                .get(account)
                .is_some_and(|entry| entry.customer)
            {
                return fail(404, "not_found");
            }
            state.next += 1;
            ok(
                json!({"url": format!("https://billing.stripe.com/p/session/test_Fake{:04}", state.next)}),
            )
        }
        ("GET", ["group"]) => {
            let Some((group, member)) = membership(state, account) else {
                return fail(404, "not_found");
            };
            let members: Vec<Value> = group
                .members
                .iter()
                .map(|entry| member_view(state, entry))
                .collect();
            ok(
                json!({"group_id": group.id, "kind": group.kind, "role": member.role,
                      "owner_account": group.owner, "included": group.included,
                      "quantity": group.quantity, "members": members}),
            )
        }
        ("POST", ["group", "invites"]) => {
            if !strict(body, &["role"]) || !matches!(text(body, "role"), "member" | "admin") {
                return fail(400, "invalid_request");
            }
            let Some((group, member)) = membership(state, account) else {
                return fail(403, "not_in_group");
            };
            let role = text(body, "role");
            let allowed = match member.role.as_str() {
                "owner" => group.kind == "team" || role == "member",
                "admin" => role == "member",
                _ => false,
            };
            if member.state != "active" || !allowed {
                return fail(403, "forbidden");
            }
            let group_id = group.id.clone();
            state.next += 1;
            let code = format!("apassy_gin_{group_id}_{}", secret_hex(state.next));
            state.invites.push(Invite {
                code: code.clone(),
                group: group_id,
                role: role.to_owned(),
                used: false,
            });
            ok(json!({"invite_id": state.next,
                      "url": format!("https://apassy.wyderka.cc/connect/join#{code}"),
                      "expires_at": now() + 604_800}))
        }
        ("POST", ["group", "join"]) => {
            if !strict(body, &["code"]) {
                return fail(400, "invalid_request");
            }
            let Some(invite) = state
                .invites
                .iter()
                .position(|invite| invite.code == text(body, "code") && !invite.used)
            else {
                return fail(403, "forbidden");
            };
            if membership(state, account).is_some()
                || account_plan(state, account)["entitled"] == true
            {
                return fail(409, "conflict");
            }
            state.invites[invite].used = true;
            let (group_id, role) = (
                state.invites[invite].group.clone(),
                state.invites[invite].role.clone(),
            );
            let Some(index) = state.groups.iter().position(|group| group.id == group_id) else {
                return fail(403, "forbidden");
            };
            state.groups[index].members.push(Member {
                account: account.to_owned(),
                role,
                state: "pending".to_owned(),
                joined_at: now(),
            });
            let group = &state.groups[index];
            let owner_name = state
                .accounts
                .get(&group.owner)
                .map(|entry| entry.name.clone())
                .unwrap_or_default();
            ok(
                json!({"group_id": group.id, "kind": group.kind, "state": "pending",
                      "owner_name": owner_name}),
            )
        }
        ("POST", ["group", "members", target, "confirm"]) => {
            if !strict(body, &[]) {
                return fail(400, "invalid_request");
            }
            let Some(index) = group_of(state, account) else {
                return fail(403, "not_in_group");
            };
            let group = &state.groups[index];
            let caller = group
                .members
                .iter()
                .find(|member| member.account == account);
            if !caller.is_some_and(|member| matches!(member.role.as_str(), "owner" | "admin")) {
                return fail(403, "forbidden");
            }
            let Some(position) = group
                .members
                .iter()
                .position(|member| member.account == *target)
            else {
                return fail(403, "not_in_group");
            };
            let active = group
                .members
                .iter()
                .filter(|member| member.state == "active")
                .count() as u64;
            let wanted = active + u64::from(group.members[position].state != "active");
            if wanted > group.max {
                return fail(409, "seat_limit");
            }
            let group = &mut state.groups[index];
            group.members[position].state = "active".to_owned();
            if group.kind == "team" && wanted > group.quantity {
                group.quantity = wanted;
            }
            if group.kind == "family" && wanted > group.quantity.max(group.included) {
                group.quantity = wanted;
            }
            let group = &state.groups[index];
            ok(member_view(state, &group.members[position]))
        }
        ("DELETE", ["group", "members", target]) => {
            let Some(index) = group_of(state, account) else {
                return fail(403, "not_in_group");
            };
            let group = &state.groups[index];
            let Some(position) = group
                .members
                .iter()
                .position(|member| member.account == *target)
            else {
                return fail(403, "not_in_group");
            };
            let caller = group
                .members
                .iter()
                .find(|member| member.account == account)
                .map(|member| member.role.clone())
                .unwrap_or_default();
            let target_role = group.members[position].role.clone();
            let allowed = *target != group.owner
                && (*target == account
                    || caller == "owner"
                    || (caller == "admin" && target_role == "member"));
            if !allowed {
                return fail(403, "forbidden");
            }
            state.groups[index].members.remove(position);
            ok(json!({"account_id": target, "removed_from_stores": 0}))
        }
        ("POST", ["group", "seats"]) => {
            let Some(quantity) = (body.as_object().is_some_and(|map| map.len() == 1))
                .then(|| count(body, "quantity"))
                .flatten()
            else {
                return fail(400, "invalid_request");
            };
            let Some(index) = group_of(state, account) else {
                return fail(403, "not_in_group");
            };
            let group = &mut state.groups[index];
            if group.owner != account {
                return fail(403, "forbidden");
            }
            let active = group
                .members
                .iter()
                .filter(|member| member.state == "active")
                .count() as u64;
            if quantity == 0 || quantity < active || quantity > group.max {
                return fail(409, "seat_limit");
            }
            group.quantity = quantity;
            ok(json!({"quantity": quantity, "pending": true}))
        }
        _ => fail(404, "not_found"),
    }
}
