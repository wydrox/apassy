//! An in-process fake of Apassy Connect accounts for the Mac tests (contract
//! connect-account-v1, plan s7 unit M1), in the style of `fake_relay.rs`.
//!
//! It speaks plain HTTP/1.1 on 127.0.0.1, one thread per connection, keeps everything in
//! memory, and checks what Connect checks with `ring` directly, not with the app's code:
//! the strict request bodies, the signatures of section 5 over its own origin, the
//! one-use nonces (a challenge never ends another challenge), `403 device_removed` only
//! after a valid sign-in signature of a key that was a device of the account, the links
//! and joins of section 7 with the signed cancel, the signed device list (each `add` and
//! `remove` signed by a device of the list over the hash of the entry before, a stale
//! version `409`), the vault store devices with the key the caller verified, the
//! recovery key and the Ed25519 recovery signature of section 9 (a repeat of the same
//! body answers the same result), and the entitlement token of section 10 (signed with
//! the Ed25519 seed of the test vectors, kid `ek_test_1`). It is not the relay crate
//! (C1), which replaces it once C1 merges.
//!
//! Hooks act as a broken or hostile Connect: report another origin in the challenge,
//! shorten the token lifetime, lose the next answers after doing the step, drop every
//! open nonce (a restart), refuse the next token calls with `401` or `503`, name another
//! confirmer in a join answer, insert a device row that the list does not hold, bring a
//! revoked device back, swap the key of a device, entitle an account, hide a device
//! behind the app's back (no list entry), serve an older or another device list, and read
//! what the app sent.
//!
//! Billing and groups (contract connect-billing-v1, plan s7 unit M2): `GET /v1/plans`
//! answers `tests/fixtures/connect-billing-v1/plans.json`; the checkout, the portal, the
//! plan, and the group routes check the strict bodies and the roles of sections 4 to 6
//! and answer synthetic Stripe URLs. No Stripe is called: [`FakeConnect::complete_checkout`]
//! does what the webhook would (binds the customer, sets the plan, makes the group), and
//! [`FakeConnect::set_plan`] sets any `PlanView` of section 8. A seats change applies at
//! once here (Connect waits for `customer.subscription.updated`).

//!
//! Vault stores (connect-account-v1 section 8, plan s7 unit M3): with a backing relay
//! ([`FakeConnect::with_relay`], a [`StoreRelay`] such as the fake relay of
//! `fake_relay.rs`), a store is a relay-sync-v1 team of that relay, made with the account
//! key of the creating device, and the relay-sync-v1 routes (`/v1/auth/…`, `/v1/sync…`,
//! `/v1/devices…`) of this origin go to that relay byte for byte, so the app signs in,
//! pushes, and pulls at the Connect origin as it does at the hosted Connect. The relay
//! checks the signed heads with `ring`. A plan that does not push (`set_plan` with
//! `entitled: false`) gives the stores of the account `sync_bytes` 0: a push is
//! `403 plan_required`, a pull works. A device link of a store adds only a device of the
//! account or of an active member of its group (`403 not_in_group`).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use super::relay_api::{decode_b64u, encode_b64u, sha256_hex};
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey,
};
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

/// The check of a device link of a store: the store, the key of the device, and the
/// device id that the relay would give it. True adds it.
pub type StoreGuard = Arc<dyn Fn(&str, &[u8], u64) -> bool + Send + Sync>;

/// The relay that keeps the vault stores of [`FakeConnect::with_relay`].
pub trait StoreRelay: Send + Sync {
    /// The relay origin, `http://127.0.0.1:<port>`.
    fn url(&self) -> String;
    /// The origin that the relay's challenges report and its sign-ins sign.
    fn set_origin(&self, origin: &str);
    /// A new store team `team_id` with `public_key` as its first device: its device id.
    fn add_store_team(
        &self,
        team_id: &str,
        name: &str,
        device_name: &str,
        public_key: &[u8],
    ) -> u64;
    /// Another device in the store: its device id.
    fn add_store_device(&self, team_id: &str, device_name: &str, public_key: &[u8]) -> u64;
    /// Delete the store with its copy.
    fn remove_team(&self, team_id: &str);
    /// The size limit of the store; 0 refuses pushes with `403 plan_required`.
    fn set_team_sync_bytes(&self, team_id: &str, bytes: u64);
    /// The check of a device link of a store.
    fn set_store_guard(&self, guard: StoreGuard);
}

/// The size limit of a store of an account that pushes: 64 MiB.
const STORE_BYTES: u64 = 67_108_864;

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
    /// The device that confirmed this one. `None` for a root.
    added_by: Option<String>,
}

#[derive(Clone)]
struct Account {
    name: String,
    created_at: u64,
    /// The Ed25519 public key of the recovery code (32 bytes).
    recovery_key: Vec<u8>,
    /// The last recovery: its body, its answer, its time, and the device it made.
    recovered: Option<(Value, Value, u64, String)>,
    entitled: bool,
    /// A `PlanView` set by [`FakeConnect::set_plan`] or a completed checkout.
    plan: Option<Value>,
    /// A Stripe customer is bound (a checkout completed): the portal works.
    customer: bool,
    /// The signed device list (section 7.5): the entries as Connect answers them, and the
    /// list hash of each.
    list: Vec<Value>,
    hashes: Vec<String>,
    /// The last list before the last recovery (`reset_list` of the peer reads).
    before_reset: Vec<Value>,
}

/// The message of the entry `version` of a device list.
#[allow(clippy::too_many_arguments)]
fn list_message(
    origin: &str,
    account: &str,
    version: u64,
    previous: &str,
    op: &str,
    key: &str,
    link_hash: &str,
    name: &str,
    by: &str,
) -> Vec<u8> {
    joined(&[
        "apassy-connect device-list v1",
        origin,
        account,
        &version.to_string(),
        previous,
        op,
        key,
        link_hash,
        name,
        by,
    ])
}

/// Whether `statement` is the signature of `root` over the root entry of a new list of
/// `account` that names the device `name`.
fn root_statement_verifies(
    origin: &str,
    account: &str,
    root: &[u8],
    name: &str,
    statement: &[u8],
) -> bool {
    let key = encode_b64u(root);
    let message = list_message(origin, account, 1, "-", "root", &key, "-", name, &key);
    verify(root, &message, statement)
}

/// An account id of section 2: `acc_` and 10 characters of `a-z2-7`.
fn account_id_form(text: &str) -> bool {
    text.strip_prefix("acc_").is_some_and(|rest| {
        rest.len() == 10
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    })
}

/// The list hash of a message: b64u of its SHA-256.
fn list_hash(message: &[u8]) -> String {
    encode_b64u(ring::digest::digest(&ring::digest::SHA256, message).as_ref())
}

impl Account {
    /// A new list with `root` (named `name`, with its own signature `statement`) as
    /// version 1.
    fn start_list(
        &mut self,
        origin: &str,
        account: &str,
        root: &[u8],
        name: &str,
        statement: &[u8],
    ) {
        let key = encode_b64u(root);
        self.list = vec![
            json!({"version": 1, "op": "root", "key": key, "link_hash": null, "name": name,
                                "by": key, "signature": encode_b64u(statement)}),
        ];
        self.hashes = vec![list_hash(&list_message(
            origin, account, 1, "-", "root", &key, "-", name, &key,
        ))];
    }

    /// Append the entry `op` of `key` signed by `by` with `statement` at `version`: `409`
    /// for a version that is not the next one, `400` for a statement that does not verify.
    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        origin: &str,
        account: &str,
        version: u64,
        op: &str,
        key: &[u8],
        (link_hash, name): (Option<&str>, Option<&str>),
        by: &[u8],
        statement: &[u8],
    ) -> Result<(), Outgoing> {
        if version != self.list.len() as u64 + 1 {
            return Err(fail(409, "conflict"));
        }
        // The relay keeps room to end every live device, peer, share, and join
        // (connect-account-v1 sections 13 and 16).
        if version > 1024 || (op == "add" && version > 822) {
            return Err(fail(403, "account_limit"));
        }
        let message = list_message(
            origin,
            account,
            version,
            self.hashes.last().expect("a list"),
            op,
            &encode_b64u(key),
            link_hash.unwrap_or("-"),
            name.unwrap_or("-"),
            &encode_b64u(by),
        );
        if !verify(by, &message, statement) {
            return Err(fail(400, "invalid_request"));
        }
        self.list.push(
            json!({"version": version, "op": op, "key": encode_b64u(key),
            "link_hash": link_hash, "name": name, "by": encode_b64u(by),
            "signature": encode_b64u(statement)}),
        );
        self.hashes.push(list_hash(&message));
        Ok(())
    }
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
    /// The joining key's signature over the join message, which names `name`.
    signature: Vec<u8>,
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
    /// The accounts whose share of this store the fake counts as void (`void_share`).
    void: Vec<String>,
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
    /// nonce → (account, key, expires_at). A challenge never ends another one.
    nonces: BTreeMap<String, (String, Vec<u8>, u64)>,
    /// The next token calls: drop every nonce first (a restart between the challenge and
    /// the token), answer `401`, or answer `503 busy` (the nonce stays unused).
    token_restarts: usize,
    token_unauthenticated: usize,
    token_busy: usize,
    /// The `confirmer` of the next join answers, instead of the device of the link.
    confirmer: Option<Value>,
    /// token → (account, device, expires_at).
    tokens: BTreeMap<String, (String, String, u64)>,
    token_seconds: u64,
    next: u64,
    /// The bodies of `POST /v1/account` by key, for a retry after a lost answer.
    created: BTreeMap<Vec<u8>, (Value, Value)>,
    /// Every account id that an account ever had: an id is used once, also after its
    /// account was deleted (`409 account_id_taken`).
    used_ids: std::collections::BTreeSet<String>,
    /// The next creations answer `409 account_id_taken` whatever their id.
    taken_ids: usize,
    lost_answers: Vec<(String, usize)>,
    /// The next requests that start with the prefix wait this long before their step.
    slow_answers: Vec<(String, usize, std::time::Duration)>,
    /// Requests that start with the prefix answer this status and error code instead.
    route_errors: Vec<(String, u16, String)>,
    /// `GET /v1/account/group` answers this view instead (a Connect that shows a group
    /// without members, or without the caller).
    group_view: Option<Value>,
    log: Vec<String>,
    bodies: Vec<String>,
    /// Each request line with its `Authorization` header.
    authorizations: Vec<(String, Option<String>)>,
    recover_tries: u64,
    checkouts: Vec<Checkout>,
    groups: Vec<Group>,
    invites: Vec<Invite>,
    /// The relay of the vault stores ([`FakeConnect::with_relay`]).
    relay: Option<Arc<dyn StoreRelay>>,
    /// The recovery-key rotations: the account and the device of each.
    rotations: Vec<(String, String)>,
    /// The last rotation of each account: its time and its device (section 9.1).
    rotated: BTreeMap<String, (u64, String)>,
    /// `POST /v1/account/recovery` answers 200 and keeps the stored key (a lying Connect).
    keep_recovery_key: bool,
    /// The pending joins are answered without their `signature` field.
    pending_without_signature: bool,
    /// The share codes and the lying hooks of section 16 (`fake_connect_share.rs`).
    share: share::ShareState,
}

#[path = "fake_connect_share.rs"]
mod share;

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

fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// A body seen again within this many seconds answers the same result.
const REPEAT_SECONDS: u64 = 600;

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

/// A strict body with the text fields `keys` and the number `version`.
fn strict_versioned(body: &Value, keys: &[&str]) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    map.len() == keys.len() + 1
        && map.get("version").is_some_and(Value::is_u64)
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

/// A name in the canonical form of contract section 2: trimmed, 1 to 64 bytes, no
/// control character, not `-`.
fn canonical_name(text: &str) -> Option<&str> {
    let name = text.trim();
    (!name.is_empty() && name.len() <= 64 && name != "-" && !name.chars().any(char::is_control))
        .then_some(name)
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

    /// A fake Connect whose vault stores are teams of `relay`: see the module
    /// documentation. The relay then reports and checks the origin of this Connect.
    pub fn with_relay(relay: Arc<dyn StoreRelay>) -> Self {
        let connect = Self::start();
        relay.set_origin(&connect.url);
        let weak: Weak<Mutex<State>> = Arc::downgrade(&connect.shared);
        relay.set_store_guard(Arc::new(move |team, key, number| {
            weak.upgrade()
                .is_some_and(|shared| store_link_allowed(&mut lock(&shared), team, key, number))
        }));
        lock(&connect.shared).relay = Some(relay);
        connect
    }

    /// Make a group of `kind` (`family` or `team`) with `owner` as its owner, for a test
    /// that does not go through a checkout. The owner's plan becomes that plan, active.
    pub fn make_group(&self, owner: &str, kind: &str) -> String {
        let mut state = lock(&self.shared);
        state.next += 1;
        let group_id = id("grp_", state.next);
        if let Some(entry) = state.accounts.get_mut(owner) {
            entry.entitled = true;
            entry.plan = Some(json!({"plan": kind, "status": "active", "entitled": true,
                "interval": "month", "quantity": 4, "renews_at": now() + 2_592_000,
                "ends_at": null, "grace_until": null, "read_only_until": null,
                "delete_at": null, "group_id": group_id}));
        }
        state.groups.push(Group {
            id: group_id.clone(),
            kind: kind.to_owned(),
            owner: owner.to_owned(),
            included: 4,
            max: 12,
            quantity: 4,
            members: vec![Member {
                account: owner.to_owned(),
                role: "owner".to_owned(),
                state: "active".to_owned(),
                joined_at: now(),
            }],
        });
        group_id
    }

    /// Add `member` to the group of `owner` as an active member (the invite, the join,
    /// and the confirmation of connect-billing-v1 section 6 in one step).
    pub fn add_member(&self, owner: &str, member: &str) {
        let mut state = lock(&self.shared);
        let index = group_of(&state, owner).expect("a group");
        state.groups[index].members.push(Member {
            account: member.to_owned(),
            role: "member".to_owned(),
            state: "active".to_owned(),
            joined_at: now(),
        });
    }

    /// The store of `vault_id` of `account`, when Connect holds one.
    pub fn store_of(&self, account: &str, vault_id: &str) -> Option<String> {
        lock(&self.shared)
            .stores
            .iter()
            .find(|store| store.account == account && store.vault_id == vault_id)
            .map(|store| store.team_id.clone())
    }

    /// The account device ids in the store `team_id`.
    pub fn store_devices(&self, team_id: &str) -> Vec<String> {
        lock(&self.shared)
            .stores
            .iter()
            .find(|store| store.team_id == team_id)
            .map(|store| store.devices.iter().map(|(_, id)| id.clone()).collect())
            .unwrap_or_default()
    }

    /// The challenge reports `origin` (a Connect behind another address, or a hostile
    /// one).
    pub fn report_origin(&self, origin: &str) {
        lock(&self.shared).reported_origin = Some(origin.to_owned());
    }

    /// Every open nonce is gone, as after a restart of Connect.
    pub fn drop_nonces(&self) {
        lock(&self.shared).nonces.clear();
    }

    /// The next `count` token calls find no nonce: Connect restarted after the challenge.
    pub fn restart_before_next_tokens(&self, count: usize) {
        lock(&self.shared).token_restarts = count;
    }

    /// The next `count` token calls are `401 unauthenticated`.
    pub fn refuse_next_tokens(&self, count: usize) {
        lock(&self.shared).token_unauthenticated = count;
    }

    /// The next `count` token calls are `503 busy`; their nonces stay unused.
    pub fn busy_next_tokens(&self, count: usize) {
        lock(&self.shared).token_busy = count;
    }

    /// The next join answers name `confirmer` (`{"device_id","name","public_key"}`)
    /// instead of the device that made the link; `None` ends it.
    pub fn answer_confirmer(&self, confirmer: Option<Value>) {
        lock(&self.shared).confirmer = confirmer;
    }

    /// A device row of `account` that no device of the list confirmed: the list does not
    /// hold it. Returns its id.
    pub fn insert_device(&self, account: &str, name: &str, public_key: &[u8]) -> String {
        let mut state = lock(&self.shared);
        let first = state
            .devices
            .iter()
            .find(|device| device.account == account)
            .map(|device| device.id.clone());
        new_device(&mut state, account, name, "mac", public_key.to_vec(), first).id
    }

    /// A hostile Connect lists the device `device` (of any account) in the store
    /// `team_id`, in its store view and in the relay team. Returns its store device id.
    pub fn list_in_store(&self, team_id: &str, device: &str) -> u64 {
        let mut state = lock(&self.shared);
        let (name, key) = state
            .devices
            .iter()
            .find(|entry| entry.id == device)
            .map(|entry| (entry.name.clone(), entry.public_key.clone()))
            .expect("device");
        let relay = state.relay.clone().expect("a relay");
        let number = relay.add_store_device(team_id, &name, &key);
        state
            .stores
            .iter_mut()
            .find(|store| store.team_id == team_id)
            .expect("store")
            .devices
            .push((number, device.to_owned()));
        number
    }

    /// A vault store `team_id` of `account` with the device `device` in it, made without its
    /// `store` entry, as a build before the entry made stores.
    pub fn store_without_entry(&self, account: &str, device: &str, team_id: &str, name: &str) {
        let mut state = lock(&self.shared);
        state.next += 1;
        let vault_id = format!("4b1d9a77-0f3c-4a10-8c21-{:012}", state.next);
        let number = match state.relay.clone() {
            Some(relay) => {
                let me = state
                    .devices
                    .iter()
                    .find(|entry| entry.id == device)
                    .cloned()
                    .expect("the device");
                relay.add_store_team(team_id, name, &me.name, &me.public_key)
            }
            None => 1,
        };
        state.stores.push(Store {
            team_id: team_id.to_owned(),
            vault_id,
            name: name.to_owned(),
            account: account.to_owned(),
            created_at: now(),
            devices: vec![(number, device.to_owned())],
            void: Vec::new(),
        });
    }

    /// The signed device list of `account`, as Connect answers it.
    pub fn device_list(&self, account: &str) -> Vec<Value> {
        lock(&self.shared)
            .accounts
            .get(account)
            .map(|entry| entry.list.clone())
            .unwrap_or_default()
    }

    /// Connect answers `list` as the device list of `account` from now on (an older list,
    /// another history, a changed entry). The hashes are not checked here.
    pub fn set_device_list(&self, account: &str, list: Vec<Value>) {
        if let Some(entry) = lock(&self.shared).accounts.get_mut(account) {
            entry.list = list;
        }
    }

    /// A revoked device is live again; the device list stays as it is.
    pub fn unrevoke(&self, device: &str) {
        for entry in &mut lock(&self.shared).devices {
            if entry.id == device {
                entry.live = true;
            }
        }
    }

    /// The device `device` gets the key `public_key`; the device list stays as it is.
    pub fn swap_key(&self, device: &str, public_key: &[u8]) {
        for entry in &mut lock(&self.shared).devices {
            if entry.id == device {
                entry.public_key = public_key.to_vec();
            }
        }
    }

    /// The `DeviceView` of `device`, as Connect answers it.
    pub fn device_view(&self, device: &str) -> Option<Value> {
        let state = lock(&self.shared);
        state
            .devices
            .iter()
            .find(|entry| entry.id == device)
            .map(|entry| device_view(&state, entry))
    }

    /// Every link of `account` expires now, and its pending joins with it: a later join
    /// with such a link is `403 forbidden`, and the challenge of a waiting device is
    /// `403 join_refused` (section 7).
    pub fn expire_links(&self, account: &str) {
        let mut state = lock(&self.shared);
        let mut expired = Vec::new();
        for link in state
            .links
            .iter_mut()
            .filter(|link| link.account == account)
        {
            link.expires_at = 0;
            expired.push(link.id);
        }
        for join in state.joins.iter_mut().filter(|join| {
            join.account == account
                && expired.contains(&join.link_id)
                && join.state == JoinState::Pending
        }) {
            join.state = JoinState::Refused;
        }
    }

    /// Tokens live `seconds`.
    pub fn set_token_lifetime(&self, seconds: u64) {
        lock(&self.shared).token_seconds = seconds;
    }

    /// The next `count` creations answer `409 account_id_taken`, as for an id that an
    /// account holds or held.
    pub fn take_next_ids(&self, count: usize) {
        lock(&self.shared).taken_ids = count;
    }

    /// Connect reports `name` as the device name of every pending join (a name that the
    /// joining key did not sign).
    pub fn rename_pending_joins(&self, name: &str) {
        for join in &mut lock(&self.shared).joins {
            join.name = name.to_owned();
        }
    }

    /// Every answer arrives again: the lost answers of [`Self::lose_next_answers`] end.
    pub fn keep_answers(&self) {
        lock(&self.shared).lost_answers.clear();
    }

    /// The next `count` requests that start with `prefix` do their step and lose the
    /// answer (the connection closes).
    pub fn lose_next_answers(&self, prefix: &str, count: usize) {
        lock(&self.shared)
            .lost_answers
            .push((prefix.to_owned(), count));
    }

    /// The next `count` requests that start with `prefix` wait `delay` before their step
    /// (a slow Connect).
    pub fn slow_next_answers(&self, prefix: &str, count: usize, delay: std::time::Duration) {
        lock(&self.shared)
            .slow_answers
            .push((prefix.to_owned(), count, delay));
    }

    /// `GET /v1/account/group` answers `view` from now on (`None`: the group again).
    pub fn answer_group(&self, view: Option<Value>) {
        lock(&self.shared).group_view = view;
    }

    /// No request that starts with `prefix` answers an error of [`Self::answer_route_error`]
    /// any more (the other prefixes keep theirs).
    pub fn clear_route_errors_of(&self, prefix: &str) {
        lock(&self.shared)
            .route_errors
            .retain(|(held, _, _)| held != prefix);
    }

    /// Every request that starts with `prefix` answers `status` with the error `code`.
    pub fn answer_route_error(&self, prefix: &str, status: u16, code: &str) {
        lock(&self.shared)
            .route_errors
            .push((prefix.to_owned(), status, code.to_owned()));
    }

    /// Another device of `account` (`device`) made a new recovery code with the public key
    /// `key` now, as `POST /v1/account/recovery` would record it.
    pub fn rotate_recovery_by(&self, account: &str, key: &[u8], device: &str) {
        let mut state = lock(&self.shared);
        if let Some(entry) = state.accounts.get_mut(account) {
            entry.recovery_key = key.to_vec();
        }
        state
            .rotated
            .insert(account.to_owned(), (now(), device.to_owned()));
    }

    /// The errors of [`Self::answer_route_error`] end.
    pub fn clear_route_errors(&self) {
        lock(&self.shared).route_errors.clear();
    }

    /// The account gets an entitled plan (Personal).
    pub fn entitle(&self, account: &str) {
        if let Some(account) = lock(&self.shared).accounts.get_mut(account) {
            account.entitled = true;
        }
    }

    /// Hide a device behind the app's back: its row is not live any more, and the device
    /// list (which no device signed for this) still holds it.
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
    /// The public recovery key that Connect stores for `account` (32 bytes).
    pub fn recovery_key(&self, account: &str) -> Vec<u8> {
        lock(&self.shared)
            .accounts
            .get(account)
            .map(|entry| entry.recovery_key.clone())
            .unwrap_or_default()
    }

    /// `POST /v1/account/recovery` answers 200 with the key that it still holds and keeps
    /// it (`true`), or takes the key as Connect does (`false`).
    pub fn keep_recovery_key(&self, keep: bool) {
        lock(&self.shared).keep_recovery_key = keep;
    }

    /// The recovery-key rotations (section 9.1): the account and the device of each.
    pub fn rotations(&self) -> Vec<(String, String)> {
        lock(&self.shared).rotations.clone()
    }

    /// Connect answers each pending join without its `signature` field.
    pub fn drop_pending_signatures(&self) {
        lock(&self.shared).pending_without_signature = true;
    }

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

    /// Delete the vault store `team_id` with its copy at the relay, as a recovery of its
    /// account does (section 9), without anything else of a recovery.
    pub fn delete_store(&self, team_id: &str) {
        let relay = {
            let mut state = lock(&self.shared);
            state.stores.retain(|store| store.team_id != team_id);
            state.relay.clone()
        };
        if let Some(relay) = relay {
            relay.remove_team(team_id);
        }
    }

    /// The `PlanView` that `GET /v1/account` and `GET /v1/account/plan` answer for
    /// `account`; `entitled` follows its `entitled` field.
    pub fn set_plan(&self, account: &str, plan: Value) {
        let pushes = plan["entitled"].as_bool().unwrap_or(false);
        let (relay, stores) = {
            let mut state = lock(&self.shared);
            if let Some(entry) = state.accounts.get_mut(account) {
                entry.entitled = pushes;
                entry.plan = Some(plan);
            }
            let stores: Vec<String> = state
                .stores
                .iter()
                .filter(|store| store.account == account)
                .map(|store| store.team_id.clone())
                .collect();
            (state.relay.clone(), stores)
        };
        // A read-only plan: pulls work, pushes are `403 plan_required`.
        if let Some(relay) = relay {
            for team in stores {
                relay.set_team_sync_bytes(&team, if pushes { STORE_BYTES } else { 0 });
            }
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
    /// The path with its query, as it came.
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// A relay-sync-v1 route of a vault store: it goes to the relay of the stores.
fn relay_route(path: &str) -> bool {
    path.starts_with("/v1/auth/") || path.starts_with("/v1/sync") || path.starts_with("/v1/devices")
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
    let path = target.split('?').next().unwrap_or_default().to_owned();
    // A snapshot for the relay of the stores comes whole.
    let cap = if relay_route(&path) {
        128 * 1024 * 1024
    } else {
        64 * 1024
    };
    let mut body = vec![0u8; length.min(cap)];
    reader.read_exact(&mut body).ok()?;
    Some(Incoming {
        method,
        path,
        target,
        headers,
        body,
    })
}

fn handle(shared: &Arc<Mutex<State>>, mut stream: TcpStream) {
    let Some(request) = read_request(&stream) else {
        return;
    };
    let line = format!("{} {}", request.method, request.path);
    let relay = lock(shared).relay.clone();
    if let Some(relay) = relay.filter(|_| relay_route(&request.path)) {
        lock(shared).log.push(line);
        proxy(&relay.url(), &request, &mut stream);
        return;
    }
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
    let slow = lock(shared)
        .slow_answers
        .iter_mut()
        .find(|(prefix, left, _)| *left > 0 && line.starts_with(prefix.as_str()))
        .map(|(_, left, delay)| {
            *left -= 1;
            *delay
        });
    if let Some(delay) = slow {
        std::thread::sleep(delay);
    }
    let forced = lock(shared)
        .route_errors
        .iter()
        .find(|(prefix, _, _)| line.starts_with(prefix.as_str()))
        .map(|(_, status, code)| fail(*status, code));
    let answer = forced.unwrap_or_else(|| route(shared, &request));
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

/// Send `request` to the relay at `url` and its answer back, byte for byte.
fn proxy(url: &str, request: &Incoming, stream: &mut TcpStream) {
    let Ok(mut relay) = TcpStream::connect(url.trim_start_matches("http://")) else {
        return;
    };
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.target);
    for (name, value) in &request.headers {
        if !matches!(name.as_str(), "connection" | "content-length") {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        request.body.len()
    ));
    if relay.write_all(head.as_bytes()).is_err() || relay.write_all(&request.body).is_err() {
        return;
    }
    let mut answer = Vec::new();
    let _ = relay.read_to_end(&mut answer);
    let _ = stream.write_all(&answer);
    let _ = stream.flush();
}

/// Whether the device link of the store `team` may add the key `key` (relay device
/// `number`): a live device of the store's account, or of an active member of the same
/// group. A device that may is recorded in the store.
fn store_link_allowed(state: &mut State, team: &str, key: &[u8], number: u64) -> bool {
    let Some(owner) = state
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .map(|store| store.account.clone())
    else {
        return false;
    };
    let Some((device, account)) = state
        .devices
        .iter()
        .find(|device| device.live && device.public_key == key)
        .map(|device| (device.id.clone(), device.account.clone()))
    else {
        return false;
    };
    if !same_group(state, &owner, &account) {
        return false;
    }
    if let Some(store) = state.stores.iter_mut().find(|store| store.team_id == team)
        && !store.devices.iter().any(|(_, held)| *held == device)
    {
        store.devices.push((number, device));
    }
    true
}

/// Whether `a` and `b` are the same account, or active members of one group.
fn same_group(state: &State, a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let active = |account: &str| {
        membership(state, account)
            .filter(|(_, member)| member.state == "active")
            .map(|(group, _)| group.id.clone())
    };
    active(a).is_some_and(|group| active(b) == Some(group))
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

fn device_view(_state: &State, device: &Device) -> Value {
    json!({"device_id": device.id, "name": device.name, "platform": device.platform,
           "public_key": encode_b64u(&device.public_key), "created_at": device.created_at,
           "last_seen_at": null})
}

/// The confirmer of a join answer: the device that made the link.
fn confirmer_view(state: &State, device: &Device) -> Value {
    if let Some(confirmer) = &state.confirmer {
        return confirmer.clone();
    }
    json!({"device_id": device.id, "name": device.name,
           "public_key": encode_b64u(&device.public_key)})
}

/// The device list of `account` in an answer.
fn list_of(state: &State, account: &str) -> Value {
    json!(
        state
            .accounts
            .get(account)
            .map(|entry| entry.list.clone())
            .unwrap_or_default()
    )
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
    let shared = devices
        .iter()
        .any(|device| device["account_id"] != json!(store.account));
    json!({"team_id": store.team_id, "vault_id": store.vault_id, "name": store.name,
           "account_id": store.account, "created_at": store.created_at, "shared": shared,
           "devices": devices, "void": store.void})
}

fn new_device(
    state: &mut State,
    account: &str,
    name: &str,
    platform: &str,
    public_key: Vec<u8>,
    added_by: Option<String>,
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
        added_by,
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
                "account_id",
                "name",
                "device_name",
                "platform",
                "public_key",
                "recovery_key",
                "signature",
                "statement",
            ];
            if !strict(&body, &keys) {
                return fail(400, "invalid_request");
            }
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            let Some(recovery_key) =
                decode_b64u(text(&body, "recovery_key")).filter(|key| key.len() == 32)
            else {
                return fail(400, "invalid_request");
            };
            let message = joined(&[
                "apassy-connect account v1",
                &origin,
                text(&body, "public_key"),
                text(&body, "recovery_key"),
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
            // The device made the id; its root entry names it.
            let account_id = text(&body, "account_id").to_owned();
            let statement = decode_b64u(text(&body, "statement")).unwrap_or_default();
            if !account_id_form(&account_id)
                || !root_statement_verifies(
                    &origin,
                    &account_id,
                    &public_key,
                    text(&body, "device_name"),
                    &statement,
                )
            {
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
            if state.taken_ids > 0 {
                state.taken_ids -= 1;
                return fail(409, "account_id_taken");
            }
            if state.accounts.contains_key(&account_id) || state.used_ids.contains(&account_id) {
                return fail(409, "account_id_taken");
            }
            state.used_ids.insert(account_id.clone());
            state.next += 1;
            state.accounts.insert(
                account_id.clone(),
                Account {
                    name: text(&body, "name").to_owned(),
                    created_at: now(),
                    recovery_key,
                    recovered: None,
                    entitled: false,
                    plan: None,
                    customer: false,
                    list: Vec::new(),
                    hashes: Vec::new(),
                    before_reset: Vec::new(),
                },
            );
            if let Some(entry) = state.accounts.get_mut(&account_id) {
                entry.start_list(
                    &origin,
                    &account_id,
                    &public_key,
                    text(&body, "device_name"),
                    &statement,
                );
            }
            let device = new_device(
                &mut state,
                &account_id,
                text(&body, "device_name"),
                text(&body, "platform"),
                public_key.clone(),
                None,
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
            // A key that is or was a device of the account gets a nonce.
            let device = state
                .devices
                .iter()
                .any(|device| device.account == account && device.public_key == public_key);
            if !device {
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
            let expires_at = now() + 60;
            state
                .nonces
                .insert(nonce.clone(), (account, public_key, expires_at));
            let reported = state.reported_origin.clone().unwrap_or(origin);
            ok(json!({"nonce": nonce, "expires_at": expires_at, "origin": reported}))
        }
        ("POST", ["v1", "account", "token"]) => {
            if !strict(&body, &["account_id", "public_key", "nonce", "signature"]) {
                return fail(400, "invalid_request");
            }
            if state.token_restarts > 0 {
                state.token_restarts -= 1;
                state.nonces.clear();
            }
            // 1. The nonce, the key, and the signature: any failure is one `401`, and
            // nothing is used up.
            let nonce = text(&body, "nonce").to_owned();
            let Some((account, public_key, expires_at)) = state.nonces.get(&nonce).cloned() else {
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
            if expires_at <= now()
                || text(&body, "account_id") != account
                || point(text(&body, "public_key")).as_deref() != Some(public_key.as_slice())
                || !verify(&public_key, &message, &signature)
            {
                return fail(401, "unauthenticated");
            }
            // 2. The device: live goes on; a key that was a device of the account is
            // `403 device_removed`, which only a valid signature reaches.
            let was_device = state
                .devices
                .iter()
                .any(|entry| entry.account == account && entry.public_key == public_key);
            if !was_device {
                return fail(401, "unauthenticated");
            }
            let Some(device) = state
                .devices
                .iter()
                .find(|entry| {
                    entry.live && entry.account == account && entry.public_key == public_key
                })
                .map(|entry| entry.id.clone())
            else {
                return fail(403, "device_removed");
            };
            if state.token_unauthenticated > 0 {
                state.token_unauthenticated -= 1;
                return fail(401, "unauthenticated");
            }
            // 3. A busy Connect keeps the nonce unused.
            if state.token_busy > 0 {
                state.token_busy -= 1;
                return fail(503, "busy");
            }
            state.nonces.remove(&nonce);
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
            // The signature covers the device name in its canonical form.
            let Some(name) = canonical_name(text(&body, "device_name")) else {
                return fail(400, "invalid_request");
            };
            let message = joined(&[
                "apassy-connect join v1",
                &origin,
                &account,
                text(&body, "link_hash"),
                text(&body, "public_key"),
                name,
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
            let name = name.to_owned();
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
                    "confirmer": confirmer_view(&state, confirmer),
                    "expires_at": link.expires_at, "device_list": list_of(&state, &account)}));
            }
            let at = now();
            // A key that is or was a device of an account (the relay's `key_used`), checked
            // after the link, as the relay does.
            let used = state
                .devices
                .iter()
                .any(|device| device.public_key == public_key);
            let Some(link) = state.links.iter_mut().find(|link| {
                link.account == account
                    && link.hash == text(&body, "link_hash")
                    && !link.used
                    && link.expires_at > at
            }) else {
                return fail(403, "forbidden");
            };
            if used {
                return fail(409, "conflict");
            }
            link.used = true;
            let (link_id, creator, expires_at) = (link.id, link.device.clone(), link.expires_at);
            state.next += 1;
            let join_id = state.next;
            state.joins.push(Join {
                id: join_id,
                link_id,
                account: account.clone(),
                name,
                platform: text(&body, "platform").to_owned(),
                public_key,
                signature,
                state: JoinState::Pending,
                body: body.clone(),
            });
            let confirmer = state
                .devices
                .iter()
                .find(|device| device.id == creator)
                .expect("confirmer");
            ok(json!({"join_id": join_id, "account_id": account,
                "confirmer": confirmer_view(&state, confirmer),
                "expires_at": expires_at, "device_list": list_of(&state, &account)}))
        }
        ("POST", ["v1", "account", "devices", "join", "cancel"]) => {
            if !strict(
                &body,
                &["account_id", "link_hash", "public_key", "signature"],
            ) {
                return fail(400, "invalid_request");
            }
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            let message = joined(&[
                "apassy-connect join-cancel v1",
                &origin,
                text(&body, "account_id"),
                text(&body, "link_hash"),
                text(&body, "public_key"),
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            if !verify(&public_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
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
                "device_name",
                "platform",
                "public_key",
                "recovery_key",
                "signature",
                "recovery_signature",
                "statement",
            ];
            if !strict(&body, &keys) {
                return fail(400, "invalid_request");
            }
            let account = text(&body, "account_id").to_owned();
            let Some(public_key) = point(text(&body, "public_key")) else {
                return fail(400, "invalid_request");
            };
            let Some(new_recovery_key) =
                decode_b64u(text(&body, "recovery_key")).filter(|key| key.len() == 32)
            else {
                return fail(400, "invalid_request");
            };
            let message = joined(&[
                "apassy-connect recover v1",
                &origin,
                &account,
                text(&body, "public_key"),
                text(&body, "recovery_key"),
            ]);
            let signature = decode_b64u(text(&body, "signature")).unwrap_or_default();
            let statement = decode_b64u(text(&body, "statement")).unwrap_or_default();
            if !verify(&public_key, &message, &signature)
                || !root_statement_verifies(
                    &origin,
                    &account,
                    &public_key,
                    text(&body, "device_name"),
                    &statement,
                )
            {
                return fail(400, "invalid_request");
            }
            // The same body again, while the device it made is live: the same answer.
            if let Some((earlier, answer, at, device)) = state
                .accounts
                .get(&account)
                .and_then(|entry| entry.recovered.clone())
                && earlier == body
                && now() < at + REPEAT_SECONDS
                && state
                    .devices
                    .iter()
                    .any(|entry| entry.id == device && entry.live)
            {
                return ok(answer);
            }
            state.recover_tries += 1;
            let recovery_signature =
                decode_b64u(text(&body, "recovery_signature")).unwrap_or_default();
            let live = state
                .devices
                .iter()
                .any(|device| device.live && device.account == account);
            let proven = state.accounts.get(&account).is_some_and(|entry| {
                verify_ed25519(&entry.recovery_key, &message, &recovery_signature)
            });
            if live || !proven {
                return fail(403, "forbidden");
            }
            // A key that is or was a device of an account (the relay's `key_used`), checked
            // after the recovery signature, as the relay does.
            if state
                .devices
                .iter()
                .any(|device| device.public_key == public_key)
            {
                return fail(409, "conflict");
            }
            let deleted = state
                .stores
                .iter()
                .filter(|store| store.account == account)
                .count();
            // Section 9: the stores go with their copies at the relay too.
            let gone: Vec<String> = state
                .stores
                .iter()
                .filter(|store| store.account == account)
                .map(|store| store.team_id.clone())
                .collect();
            if let Some(relay) = state.relay.clone() {
                for team in &gone {
                    relay.remove_team(team);
                }
            }
            state.stores.retain(|store| store.account != account);
            if let Some(entry) = state.accounts.get_mut(&account) {
                entry.before_reset = std::mem::take(&mut entry.list);
                entry.start_list(
                    &origin,
                    &account,
                    &public_key,
                    text(&body, "device_name"),
                    &statement,
                );
            }
            let device = new_device(
                &mut state,
                &account,
                text(&body, "device_name"),
                text(&body, "platform"),
                public_key,
                None,
            );
            let answer = json!({"account_id": account, "device_id": device.id,
                                "deleted_stores": deleted});
            if let Some(entry) = state.accounts.get_mut(&account) {
                entry.recovery_key = new_recovery_key;
                entry.recovered = Some((body.clone(), answer.clone(), now(), device.id));
                state.rotated.remove(&account);
            }
            ok(answer)
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
    if let Some(answer) = share::route(state, method, rest, body, account, device, origin) {
        return answer;
    }
    match (method, rest) {
        ("GET", []) => {
            let entry = state.accounts.get(account).expect("account").clone();
            let devices: Vec<Value> = state
                .devices
                .iter()
                .filter(|entry| entry.live && entry.account == account)
                .map(|entry| device_view(state, entry))
                .collect();
            ok(
                json!({"account_id": account, "name": entry.name, "email": null,
                      "created_at": entry.created_at,
                      "plan": account_plan(state, account),
                      "devices": devices, "group": account_group(state, account),
                      "device_list": entry.list,
                      "recovery_key": encode_b64u(&entry.recovery_key),
                      "recovery_rotated_at": state.rotated.get(account).map(|(at, _)| *at),
                      "recovery_rotated_by": state.rotated.get(account).map(|(_, by)| by.clone())}),
            )
        }
        ("POST", ["recovery"]) => {
            if !strict(body, &["previous", "recovery_key", "signature"]) {
                return fail(400, "invalid_request");
            }
            let (Some(previous), Some(recovery_key)) = (
                decode_b64u(text(body, "previous")).filter(|key| key.len() == 32),
                decode_b64u(text(body, "recovery_key")).filter(|key| key.len() == 32),
            ) else {
                return fail(400, "invalid_request");
            };
            let Some(caller_key) = state
                .devices
                .iter()
                .find(|entry| entry.id == device)
                .map(|entry| entry.public_key.clone())
            else {
                return fail(401, "unauthenticated");
            };
            let message = joined(&[
                "apassy-connect recovery-rotate v1",
                origin,
                account,
                &encode_b64u(&caller_key),
                text(body, "previous"),
                text(body, "recovery_key"),
            ]);
            let signature = decode_b64u(text(body, "signature")).unwrap_or_default();
            if !verify(&caller_key, &message, &signature) {
                return fail(400, "invalid_request");
            }
            let at = now();
            let keep = state.keep_recovery_key;
            let entry = state.accounts.get_mut(account).expect("account");
            if keep {
                // Answers as if it took the key, and names the key that it still holds.
                let held = encode_b64u(&entry.recovery_key);
                return ok(json!({"account_id": account, "rotated_at": at, "recovery_key": held}));
            }
            let answer = json!({"account_id": account, "rotated_at": at,
                                "recovery_key": text(body, "recovery_key")});
            if entry.recovery_key == recovery_key {
                return ok(answer);
            }
            if entry.recovery_key != previous {
                return fail(409, "conflict");
            }
            entry.recovery_key = recovery_key;
            state
                .rotations
                .push((account.to_owned(), device.to_owned()));
            state
                .rotated
                .insert(account.to_owned(), (at, device.to_owned()));
            ok(answer)
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
                           "signature": encode_b64u(&join.signature),
                           "created_at": now(), "expires_at": now() + 600})
                })
                .map(|mut join| {
                    if state.pending_without_signature
                        && let Some(map) = join.as_object_mut()
                    {
                        map.remove("signature");
                    }
                    join
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
            if !strict_versioned(body, &["public_key", "statement"]) {
                return fail(400, "invalid_request");
            }
            if point(text(body, "public_key")).as_deref()
                != Some(state.joins[index].public_key.as_slice())
            {
                return fail(409, "conflict");
            }
            // The `add` entry of the caller for the joining key and the link of the join.
            let link_hash = state
                .links
                .iter()
                .find(|link| link.id == link_id)
                .map(|link| link.hash.clone())
                .unwrap_or_default();
            let statement = decode_b64u(text(body, "statement")).unwrap_or_default();
            let caller_key = state
                .devices
                .iter()
                .find(|entry| entry.id == device)
                .map(|entry| entry.public_key.clone())
                .unwrap_or_default();
            let joining = state.joins[index].public_key.clone();
            let joining_name = state.joins[index].name.clone();
            let version = body["version"].as_u64().unwrap_or(0);
            let appended = state.accounts.get_mut(account).expect("account").append(
                origin,
                account,
                version,
                "add",
                &joining,
                (Some(&link_hash), Some(&joining_name)),
                &caller_key,
                &statement,
            );
            if let Err(refused) = appended {
                return refused;
            }
            state.joins[index].state = JoinState::Confirmed;
            let join = &state.joins[index];
            let (name, platform, key) = (
                join.name.clone(),
                join.platform.clone(),
                join.public_key.clone(),
            );
            let added = new_device(
                state,
                account,
                &name,
                &platform,
                key,
                Some(device.to_owned()),
            );
            ok(device_view(state, &added))
        }
        ("DELETE", ["devices", target]) => {
            if !strict_versioned(body, &["statement"]) {
                return fail(400, "invalid_request");
            }
            let Some(target_key) = state
                .devices
                .iter()
                .find(|entry| entry.id == *target && entry.account == account && entry.live)
                .map(|entry| entry.public_key.clone())
            else {
                return fail(404, "not_found");
            };
            // The `remove` entry of the caller for the device's key.
            let caller_key = state
                .devices
                .iter()
                .find(|entry| entry.id == device)
                .map(|entry| entry.public_key.clone())
                .unwrap_or_default();
            let statement = decode_b64u(text(body, "statement")).unwrap_or_default();
            let version = body["version"].as_u64().unwrap_or(0);
            let appended = state.accounts.get_mut(account).expect("account").append(
                origin,
                account,
                version,
                "remove",
                &target_key,
                (None, None),
                &caller_key,
                &statement,
            );
            if let Err(refused) = appended {
                return refused;
            }
            if let Some(entry) = state
                .devices
                .iter_mut()
                .find(|entry| entry.id == *target && entry.account == account)
            {
                entry.live = false;
            }
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
            if !strict_versioned(body, &["vault_id", "name", "team_id", "statement"]) {
                return fail(400, "invalid_request");
            }
            let vault_id = text(body, "vault_id").to_owned();
            if let Some(store) = state
                .stores
                .iter()
                .find(|store| store.account == account && store.vault_id == vault_id)
            {
                return ok(store_view(store, state));
            }
            if !state
                .accounts
                .get(account)
                .is_some_and(|entry| entry.entitled)
            {
                return fail(403, "plan_required");
            }
            // The `store` entry of the new id, made by the caller, in the step that makes
            // the store (connect-account-v1 section 8).
            let team_id = text(body, "team_id").to_owned();
            if !share::store_id_free(state, &team_id) {
                return fail(409, "conflict");
            }
            if let Err(answer) = share::append_store(state, body, account, device, origin) {
                return answer;
            }
            state.next += 1;
            let number = match state.relay.clone() {
                Some(relay) => {
                    let me = state
                        .devices
                        .iter()
                        .find(|entry| entry.id == device)
                        .cloned()
                        .expect("the caller");
                    relay.add_store_team(&team_id, text(body, "name"), &me.name, &me.public_key)
                }
                None => 1,
            };
            let store = Store {
                team_id,
                vault_id,
                name: text(body, "name").to_owned(),
                account: account.to_owned(),
                created_at: now(),
                devices: vec![(number, device.to_owned())],
                void: Vec::new(),
            };
            let view = store_view(&store, state);
            state.stores.push(store);
            ok(view)
        }
        ("POST", ["vaults", team, "devices"]) => {
            if !strict(body, &["device_id", "public_key"]) {
                return fail(400, "invalid_request");
            }
            let device_id = text(body, "device_id").to_owned();
            let Some((added, name, key)) = state
                .devices
                .iter()
                .find(|entry| entry.id == device_id && entry.live)
                .map(|entry| {
                    (
                        entry.account.clone(),
                        entry.name.clone(),
                        entry.public_key.clone(),
                    )
                })
            else {
                // Unknown or revoked: the answer of a device of another account.
                return fail(403, "not_in_group");
            };
            // The caller must be a device in the store.
            let Some(owner) = state
                .stores
                .iter()
                .find(|store| {
                    store.team_id == *team && store.devices.iter().any(|(_, held)| held == device)
                })
                .map(|store| store.account.clone())
            else {
                return fail(404, "not_found");
            };
            if !same_group(state, &owner, &added) {
                return fail(403, "not_in_group");
            };
            if point(text(body, "public_key")).as_deref() != Some(key.as_slice()) {
                return fail(409, "conflict");
            }
            let relay = state.relay.clone();
            let store = state
                .stores
                .iter_mut()
                .find(|store| store.team_id == *team)
                .expect("the store");
            let number = match store.devices.iter().find(|(_, id)| *id == device_id) {
                Some((number, _)) => *number,
                None => {
                    let number = match &relay {
                        Some(relay) => relay.add_store_device(team, &name, &key),
                        None => store.devices.len() as u64 + 1,
                    };
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
            if let Some(relay) = state.relay.clone() {
                relay.remove_team(team);
            }
            ok(json!({"team_id": team}))
        }
        ("GET", ["vaults"]) => {
            // The stores that hold a device of this account.
            let views: Vec<Value> = state
                .stores
                .iter()
                .filter(|store| {
                    store.account == account
                        || store.devices.iter().any(|(_, held)| {
                            state
                                .devices
                                .iter()
                                .any(|entry| entry.id == *held && entry.account == account)
                        })
                })
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
            if let Some(view) = state.group_view.clone() {
                return ok(view);
            }
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
