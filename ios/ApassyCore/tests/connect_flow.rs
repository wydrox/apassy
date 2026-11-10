//! The iPhone as a device of an Apassy Connect account (plan s7 unit I1, contract
//! ios-core-v1 section 5.14): the core joins the account of a Mac on the in-process fake
//! Connect of the app's tests (`tests/common/fake_connect.rs`), with its own account
//! device key in a memory key store in the place of the Keychain. The Mac is the app's
//! own Connect client (`apassy::connect`, unit M1). Synthetic values only.

#[path = "../../../tests/common/fake_connect.rs"]
mod fake_connect;

/// The fake Connect reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{
    ConnectGroupChange, OwnerAction, OwnerCheck, OwnerGate, OwnerProof,
};
use apassy::connect::device_key::join_message;
use apassy::connect::{
    AccountSigner, CheckoutRequest, ConnectAccount, ConnectClient, ConnectError, DeviceKeyStore,
    DeviceLink, MemoryKeyStore, account_file, safety_words,
};
use apassy::sync::{WORDS, decode_b64u, verify_signature};
use apassy::vault::Vault;
use apassy_core::Core;
use fake_connect::FakeConnect;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-connect-pass";
const VECTORS: &str = include_str!("../../../tests/fixtures/connect-account-v1/vectors.json");
const PLAN_STATES: &str =
    include_str!("../../../tests/fixtures/connect-billing-v1/plan-states.json");

/// The iPhone of a test: its core, its key store, and its data directory.
struct Phone {
    dir: TempDir,
    keys: Arc<MemoryKeyStore>,
    core: Core,
}

fn phone_with(connect: &FakeConnect, role: &str) -> Phone {
    let dir = TempDir::new().expect("dir");
    let config = json!({"data_dir": dir.path(), "device_name": "Synthetic iPhone",
                        "role": role, "connect_url": connect.url});
    let core = Core::new(&config.to_string()).expect("core");
    let keys = Arc::new(MemoryKeyStore::new());
    assert!(core.set_account_key_store(keys.clone()));
    Phone { dir, keys, core }
}

fn phone(connect: &FakeConnect) -> Phone {
    phone_with(connect, "app")
}

impl Phone {
    fn state_file(&self) -> PathBuf {
        account_file(self.dir.path())
    }

    /// The public key of the account key of this iPhone, X9.63.
    fn public_key(&self) -> Vec<u8> {
        AccountSigner::open(self.keys.as_ref())
            .expect("open")
            .expect("a key")
            .public_key()
            .to_vec()
    }
}

/// A call that must work: its result.
fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

/// A call that must fail: its error code.
fn fail(core: &Core, request: Value) -> String {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    answer["error"]["code"].as_str().expect("code").to_owned()
}

/// An unlocked vault on the Mac and its owner gate, for the owner checks (Touch ID in
/// the app).
struct Owner {
    _dir: TempDir,
    shared: SharedVault,
    gate: OwnerGate,
}

fn owner() -> Owner {
    let dir = TempDir::new().expect("dir");
    let mut vault = Vault::create(&dir.path().join("owner.db"), PASS).expect("vault");
    vault.unlock(PASS).expect("unlock");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    Owner {
        _dir: dir,
        shared,
        gate,
    }
}

impl Owner {
    fn proof(&self, action: OwnerAction) -> (OwnerProof, [u8; 32]) {
        let proof = self
            .gate
            .authorize(action, OwnerCheck::passphrase(PASS))
            .expect("owner check");
        let epoch = self.shared.lock().unwrap().as_ref().expect("vault").epoch();
        (proof, epoch)
    }
}

/// A Mac with its own account (the device that shows "Add a device…").
struct Mac {
    _dir: TempDir,
    store: MemoryKeyStore,
    account: ConnectAccount,
}

fn mac(connect: &FakeConnect, name: &str) -> Mac {
    let dir = TempDir::new().expect("dir");
    let store = MemoryKeyStore::new();
    let path = account_file(dir.path());
    let client = ConnectClient::new(&connect.url).expect("client");
    let (account, _recovery) =
        ConnectAccount::create(client, &store, &path, name, "MacBook Pro").expect("create");
    Mac {
        _dir: dir,
        store,
        account,
    }
}

impl Mac {
    fn id(&self) -> String {
        self.account.state().account_id.clone()
    }

    fn public_key(&self) -> Vec<u8> {
        AccountSigner::open(&self.store)
            .expect("open")
            .expect("key")
            .public_key()
            .to_vec()
    }
}

/// The iPhone asks to join with the link of `mac`; the Mac sees the join with the same
/// words and confirms it after an owner check. Returns the link and the words.
fn join(mac: &mut Mac, owner: &Owner, phone: &Phone) -> (DeviceLink, String) {
    let link = mac.account.start_link().expect("link");
    let waiting = call(
        &phone.core,
        json!({"op": "connect_join", "link": link.code()}),
    );
    assert_eq!(waiting["state"], "waiting");
    let words = words_of(&waiting);
    let polled = call(&phone.core, json!({"op": "connect_join_poll"}));
    assert_eq!(polled["state"], "waiting");
    let pending = mac.account.pending_joins(&link).expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].words, words, "both devices show the same words");
    let (proof, epoch) = owner.proof(pending[0].owner_action(&mac.id()));
    mac.account
        .confirm_join(&link, &pending[0], proof, &epoch)
        .expect("confirm");
    let confirmed = call(&phone.core, json!({"op": "connect_join_poll"}));
    assert_eq!(confirmed["state"], "confirmed");
    assert_eq!(confirmed["account_id"], mac.id());
    (link, words)
}

fn words_of(view: &Value) -> String {
    view["words"]
        .as_array()
        .expect("words")
        .iter()
        .map(|word| word.as_str().expect("word"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The six safety words of section 7.3, computed here from their definition with `ring`
/// and the word list of relay-sync-v1 section 16, not with the app's code.
fn words_by_definition(account: &str, code: &str, confirmer: &[u8], joiner: &[u8]) -> String {
    let mut message = b"apassy-connect safety v1".to_vec();
    for part in [account.as_bytes(), code.as_bytes(), confirmer, joiner] {
        message.push(0);
        message.extend_from_slice(part);
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &message);
    digest.as_ref()[..6]
        .iter()
        .map(|byte| WORDS[usize::from(*byte)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Text that the iPhone must never show or keep about a purchase (plan section 6).
fn assert_no_purchase_text(text: &str) {
    for banned in [
        "\"amount\"",
        "\"extra\"",
        "\"currency\"",
        "\"price",
        "eur",
        "EUR",
        "€",
        "http",
        "checkout",
        "portal",
        "lookup_key",
        "email",
    ] {
        assert!(!text.contains(banned), "{banned} in {text}");
    }
}

/// The account file and the key hold no token, no private key, no code, no email.
fn assert_state_file_holds_no_secret(path: &Path, link: &DeviceLink) {
    let text = std::fs::read_to_string(path).expect("state file");
    for banned in [
        "apassy_act_",
        "apassy_alk_",
        "apassy_rec_",
        "token",
        "private",
        "email",
    ] {
        assert!(!text.contains(banned), "{banned} in the state file");
    }
    assert!(!text.contains(link.code()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o077, 0, "the state file is private");
    }
}

// ---- Joining. ----

#[test]
fn the_iphone_joins_with_its_own_key_and_the_mac_confirms() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    assert_eq!(
        call(&phone.core, json!({"op": "connect_status"}))["state"],
        "none"
    );
    assert!(!phone.keys.has_key());

    let (link, words) = join(&mut mac, &owner, &phone);

    // The join went out signed with this iPhone's key, over Connect's own origin, as an
    // iPhone, under the iPhone's name.
    let key = phone.public_key();
    assert_ne!(key, mac.public_key());
    let body: Value = connect
        .bodies()
        .iter()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .find(|body| body.get("link_hash").is_some() && body.get("signature").is_some())
        .expect("the join body");
    assert_eq!(body["platform"], "iphone");
    assert_eq!(body["device_name"], "Synthetic iPhone");
    assert_eq!(
        decode_b64u(body["public_key"].as_str().unwrap()).unwrap(),
        key
    );
    let message = join_message(
        &connect.url,
        &mac.id(),
        &apassy::connect::link_hash(link.code()),
        body["public_key"].as_str().unwrap(),
    );
    let signature = decode_b64u(body["signature"].as_str().unwrap()).unwrap();
    assert!(verify_signature(&key, &message, &signature));
    // Connect saw only the public key and the link hash: never the code or a private key.
    let sent = connect.bodies().join("\n");
    assert!(!sent.contains(link.code()));
    let pkcs8 = phone.keys.read().unwrap().unwrap();
    assert!(!sent.contains(&apassy::sync::encode_b64u(&pkcs8)));
    assert!(connect.known_keys().contains(&key));

    // The words are those of section 7.3 for the Mac's key and the iPhone's key.
    assert_eq!(
        words,
        words_by_definition(&mac.id(), link.code(), &mac.public_key(), &key)
    );

    // The iPhone is a device of the account now.
    assert_eq!(connect.live_devices(&mac.id()).len(), 2);
    let status = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(status["state"], "account");
    assert_eq!(status["account_id"], mac.id());
    assert_eq!(status["device_name"], "Synthetic iPhone");
    assert_eq!(status["plan"]["status"], "none");
    assert_eq!(status["dial_route"], false);
    // Both devices of the account, each verified by the iPhone.
    let devices = status["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().all(|device| device["verified"] == true));
    assert_eq!(
        devices
            .iter()
            .filter(|device| device["this"] == true)
            .count(),
        1
    );
    assert_no_purchase_text(&status.to_string());
    assert_state_file_holds_no_secret(&phone.state_file(), &link);

    // A second join is refused while the iPhone has an account.
    let other = mac.account.start_link().expect("link");
    assert_eq!(
        fail(
            &phone.core,
            json!({"op": "connect_join", "link": other.code()})
        ),
        "already_connected"
    );
}

#[test]
fn the_words_follow_the_fixture_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let account = vectors["account_id"].as_str().unwrap();
    let code = vectors["link"]["code"].as_str().unwrap();
    let a = hex(vectors["device_a"]["public_hex"].as_str().unwrap());
    let b = hex(vectors["device_b"]["public_hex"].as_str().unwrap());
    let expected = vectors["safety"]["words"].as_str().unwrap();
    // The function that the core shows its words with, and the definition.
    assert_eq!(safety_words(account, code, &a, &b), expected);
    assert_eq!(words_by_definition(account, code, &a, &b), expected);
    // The link hash that the iPhone sends.
    assert_eq!(
        apassy::connect::link_hash(code),
        vectors["link"]["link_hash"].as_str().unwrap()
    );
}

#[test]
fn a_code_that_does_not_work_is_refused_and_leaves_nothing() {
    let connect = FakeConnect::start();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);

    // Not a code at all: nothing is sent and no key is made.
    let before = connect.log().len();
    for text in [
        "",
        "apassy_lnk_t_7k2m5q4x3c_00",
        "https://apassy.wyderka.cc/pricing",
    ] {
        assert_eq!(
            fail(&phone.core, json!({"op": "connect_join", "link": text})),
            "link_invalid"
        );
    }
    assert_eq!(connect.log().len(), before);
    assert!(!phone.keys.has_key());

    // A well-formed code that Connect does not know.
    let unknown = format!(
        "apassy_alk_{}_{}_{}",
        mac.id(),
        "ab".repeat(32),
        "ab".repeat(16)
    );
    assert_eq!(
        fail(&phone.core, json!({"op": "connect_join", "link": unknown})),
        "link_invalid"
    );

    // A code that was used already.
    let link = mac.account.start_link().expect("link");
    let first = phone_with(&connect, "app");
    call(
        &first.core,
        json!({"op": "connect_join", "link": link.code()}),
    );
    assert_eq!(
        fail(
            &phone.core,
            json!({"op": "connect_join", "link": link.code()})
        ),
        "link_invalid"
    );

    // An expired code: Connect refuses the join.
    let expired = mac.account.start_link().expect("link");
    connect.expire_links(&mac.id());
    assert_eq!(
        fail(
            &phone.core,
            json!({"op": "connect_join", "link": expired.code()})
        ),
        "link_invalid"
    );

    // A code that expires while the iPhone waits: the join ends.
    assert_eq!(
        fail(&first.core, json!({"op": "connect_join_poll"})),
        "join_refused"
    );
    assert_eq!(
        fail(&first.core, json!({"op": "connect_join_poll"})),
        "invalid_input"
    );
    for device in [&phone, &first] {
        assert!(!device.state_file().exists());
        assert_eq!(
            call(&device.core, json!({"op": "connect_status"}))["state"],
            "none"
        );
    }
    assert_eq!(connect.live_devices(&mac.id()).len(), 1);
}

#[test]
fn the_mac_refuses_and_the_join_ends() {
    let connect = FakeConnect::start();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    let link = mac.account.start_link().expect("link");
    let waiting = call(
        &phone.core,
        json!({"op": "connect_join", "link": format!("  {}\n", link.code())}),
    );
    assert_eq!(waiting["confirmer"], "MacBook Pro");
    assert_eq!(waiting["words"].as_array().unwrap().len(), 6);
    // The status of a waiting iPhone shows the join and no account.
    let status = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(status["state"], "none");
    assert_eq!(status["join"]["words"], waiting["words"]);

    let pending = mac.account.pending_joins(&link).expect("pending");
    mac.account.refuse_join(pending[0].join_id).expect("refuse");
    assert_eq!(
        fail(&phone.core, json!({"op": "connect_join_poll"})),
        "join_refused"
    );
    assert!(!phone.state_file().exists());
    assert_eq!(connect.live_devices(&mac.id()).len(), 1);
}

#[test]
fn a_cancelled_join_reaches_connect() {
    let connect = FakeConnect::start();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    let link = mac.account.start_link().expect("link");
    call(
        &phone.core,
        json!({"op": "connect_join", "link": link.code()}),
    );
    call(&phone.core, json!({"op": "connect_join_cancel"}));
    assert_eq!(connect.count("POST /v1/account/devices/join/cancel"), 1);
    assert!(
        mac.account
            .pending_joins(&link)
            .expect("pending")
            .is_empty()
    );
    assert_eq!(
        fail(&phone.core, json!({"op": "connect_join_poll"})),
        "invalid_input"
    );
}

// ---- Forget, revoke, lock. ----

#[test]
fn connect_forget_removes_the_key_and_the_state() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    assert!(phone.keys.has_key());
    assert!(phone.state_file().exists());

    let forgot = call(&phone.core, json!({"op": "connect_forget"}));
    assert_eq!(forgot["forgotten"], true);
    assert!(!phone.keys.has_key());
    assert!(!phone.state_file().exists());
    assert_eq!(
        call(&phone.core, json!({"op": "connect_status"}))["state"],
        "none"
    );
    assert_eq!(
        call(&phone.core, json!({"op": "connect_forget"}))["forgotten"],
        false
    );
    // The iPhone can join again with a new key.
    let (_, _) = join(&mut mac, &owner, &phone);
    assert!(phone.keys.has_key());
}

/// The id of this iPhone in the device list of `status`.
fn own_device_id(status: &Value) -> String {
    status["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|device| device["this"] == true)
        .and_then(|device| device["device_id"].as_str())
        .expect("this iPhone")
        .to_owned()
}

/// Whether the device `device_id` is verified in `status`; `None` when it is not listed.
fn listed_verified(status: &Value, device_id: &str) -> Option<bool> {
    status["devices"]
        .as_array()?
        .iter()
        .find(|device| device["device_id"] == device_id)
        .and_then(|device| device["verified"].as_bool())
}

#[test]
fn a_revoke_on_the_mac_shows_removed_and_keeps_the_key_until_forget() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    let device = mac
        .account
        .view()
        .expect("view")
        .devices
        .into_iter()
        .find(|device| device.platform == "iphone")
        .expect("the iPhone");
    let (proof, epoch) = owner.proof(mac.account.revoke_action(&device));
    mac.account.revoke(&device, proof, &epoch).expect("revoke");

    // Connect says the iPhone was removed; the core deletes nothing.
    for _ in 0..2 {
        let status = call(&phone.core, json!({"op": "connect_status"}));
        assert_eq!(status["state"], "account");
        assert_eq!(status["removed"], true);
        assert_eq!(status["account_id"], mac.id());
        assert!(phone.keys.has_key());
        assert!(phone.state_file().exists());
    }
    // After a lock the core asks again, and the answer is the same.
    call(&phone.core, json!({"op": "lock"}));
    let status = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(status["removed"], true);
    assert!(phone.keys.has_key());
    // Only the owner's forget deletes the key and the state file.
    let forgot = call(&phone.core, json!({"op": "connect_forget"}));
    assert_eq!(forgot["forgotten"], true);
    assert!(!phone.keys.has_key());
    assert!(!phone.state_file().exists());
    let again = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(again["state"], "none");
    assert!(again.get("removed").is_none());
}

#[test]
fn a_lost_nonce_or_a_refused_token_is_never_a_removal_on_the_iphone() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    let hooks: [&dyn Fn(&FakeConnect); 3] = [
        &|connect: &FakeConnect| connect.restart_before_next_tokens(1),
        &|connect: &FakeConnect| connect.refuse_next_tokens(1),
        &|connect: &FakeConnect| connect.busy_next_tokens(1),
    ];
    for hook in hooks {
        call(&phone.core, json!({"op": "lock"}));
        hook(&connect);
        let sign_ins = connect.count("POST /v1/account/token");
        let status = call(&phone.core, json!({"op": "connect_status"}));
        assert_eq!(status["state"], "account");
        assert!(status.get("removed").is_none(), "{status}");
        assert_eq!(connect.count("POST /v1/account/token"), sign_ins + 2);
        assert!(phone.keys.has_key());
        assert!(phone.state_file().exists());
    }
}

#[test]
fn the_iphone_marks_every_device_that_it_cannot_verify() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let account_id = mac.id();
    connect.entitle(&account_id);
    let store = mac
        .account
        .create_vault_store("0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77", "Personal")
        .expect("store");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    let (second, third) = (phone_with(&connect, "app"), phone_with(&connect, "app"));
    join(&mut mac, &owner, &second);
    join(&mut mac, &owner, &third);
    let second_id = own_device_id(&call(&second.core, json!({"op": "connect_status"})));
    let third_id = own_device_id(&call(&third.core, json!({"op": "connect_status"})));
    // The iPhone sees both new devices verified: the Mac confirmed them.
    let status = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(listed_verified(&status, &second_id), Some(true));
    assert_eq!(listed_verified(&status, &third_id), Some(true));

    // (a) A row that no device confirmed.
    let stranger = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
    let inserted = connect.insert_device(&account_id, "Mac Studio", stranger.public_key());
    // (b) A device that left the account and comes back.
    connect.revoke(&second_id);
    let status = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(listed_verified(&status, &second_id), None);
    connect.unrevoke(&second_id);
    // (c) A device whose key Connect swapped.
    let swapped = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
    connect.swap_key(&third_id, swapped.public_key());

    let status = call(&phone.core, json!({"op": "connect_status"}));
    for device_id in [&inserted, &second_id, &third_id] {
        assert_eq!(
            listed_verified(&status, device_id),
            Some(false),
            "{device_id}"
        );
    }
    assert_eq!(
        listed_verified(&status, &own_device_id(&status)),
        Some(true)
    );

    // The same account of this iPhone, opened from its state file and its key, refuses
    // them for a vault store and leaves their keys out of the head signers.
    call(&phone.core, json!({"op": "lock"}));
    let mut account = ConnectAccount::open(phone.keys.as_ref(), &phone.state_file())
        .expect("open")
        .expect("the account");
    let keys = account.verified_keys().expect("verified keys");
    assert!(keys.contains(&mac.public_key()));
    assert!(keys.contains(&phone.public_key()));
    assert!(!keys.contains(&stranger.public_key().to_vec()));
    assert!(!keys.contains(&swapped.public_key().to_vec()));
    assert!(!keys.contains(&second.public_key()));
    for device_id in [&inserted, &second_id, &third_id] {
        let (proof, epoch) = owner.proof(ConnectAccount::add_store_device_action(
            &store.team_id,
            device_id,
            &account_id,
        ));
        assert_eq!(
            account
                .add_store_device(&store.team_id, device_id, &account_id, proof, &epoch)
                .unwrap_err(),
            ConnectError::NotVerified,
            "{device_id}"
        );
    }
    assert!(!connect.store_devices(&store.team_id).contains(&inserted));
}

#[test]
fn lock_drops_the_key_and_the_token_from_memory() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    call(&phone.core, json!({"op": "connect_status"}));
    let reads = phone.keys.reads();
    let sign_ins = connect.count("POST /v1/account/token");
    // In memory: no new read of the key, no new sign-in.
    call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(phone.keys.reads(), reads);
    assert_eq!(connect.count("POST /v1/account/token"), sign_ins);
    // After a lock the key is read again and the iPhone signs in again.
    call(&phone.core, json!({"op": "lock"}));
    assert_eq!(
        call(&phone.core, json!({"op": "connect_status"}))["state"],
        "account"
    );
    assert_eq!(phone.keys.reads(), reads + 1);
    assert_eq!(connect.count("POST /v1/account/token"), sign_ins + 1);
}

#[test]
fn a_key_that_the_keychain_lost_shows_removed_until_forget() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    call(&phone.core, json!({"op": "lock"}));
    assert!(phone.keys.delete().unwrap());
    let status = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(status["state"], "account");
    assert_eq!(status["removed"], true);
    assert!(phone.state_file().exists());
    assert_eq!(
        call(&phone.core, json!({"op": "connect_forget"}))["forgotten"],
        true
    );
    assert!(!phone.state_file().exists());
    assert_eq!(
        call(&phone.core, json!({"op": "connect_status"}))["state"],
        "none"
    );
}

#[test]
fn only_the_app_with_a_key_store_uses_connect() {
    let connect = FakeConnect::start();
    for role in ["autofill", "watch"] {
        let device = phone_with(&connect, role);
        for op in [
            "connect_status",
            "connect_join_poll",
            "connect_join_cancel",
            "connect_forget",
        ] {
            assert_eq!(
                fail(&device.core, json!({"op": op})),
                "not_allowed",
                "{role} {op}"
            );
        }
    }
    // Without the Keychain store the app cannot hold an account.
    let dir = TempDir::new().expect("dir");
    let config = json!({"data_dir": dir.path(), "connect_url": connect.url});
    let core = Core::new(&config.to_string()).expect("core");
    let code = format!(
        "apassy_alk_acc_k7m2q4x3ca_{}_{}",
        "cd".repeat(32),
        "ab".repeat(16)
    );
    assert_eq!(
        fail(&core, json!({"op": "connect_join", "link": code})),
        "not_allowed"
    );
    // The first store is taken; a second one is refused.
    assert!(core.set_account_key_store(Arc::new(MemoryKeyStore::new())));
    assert!(!core.set_account_key_store(Arc::new(MemoryKeyStore::new())));
    // A Connect address that is not https (outside loopback) is refused.
    let bad = json!({"data_dir": dir.path(), "connect_url": "http://connect.example.test"});
    assert!(Core::new(&bad.to_string()).is_err());
}

// ---- The plan (connect-billing-v1 section 8). ----

#[test]
fn the_status_follows_every_plan_state_of_the_fixture() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    let states: Value = serde_json::from_str(PLAN_STATES).expect("plan states");
    for case in states["cases"].as_array().expect("cases") {
        let expect = &case["expect"];
        let status = expect["status"].as_str().unwrap();
        let plan_name = if status == "none" {
            Value::Null
        } else {
            json!("personal")
        };
        connect.set_plan(
            &mac.id(),
            json!({"plan": plan_name, "status": status, "entitled": expect["entitled"],
                   "interval": "month", "quantity": 1, "renews_at": expect["renews_at"],
                   "ends_at": expect["ends_at"], "grace_until": expect["grace_until"],
                   "read_only_until": expect["read_only_until"],
                   "delete_at": expect["delete_at"], "group_id": null}),
        );
        let answer = call(&phone.core, json!({"op": "connect_status"}));
        let name = case["name"].as_str().unwrap();
        assert_eq!(answer["state"], "account", "{name}");
        let plan = &answer["plan"];
        assert_eq!(plan["plan"], plan_name, "{name}");
        for field in [
            "status",
            "entitled",
            "renews_at",
            "ends_at",
            "grace_until",
            "read_only_until",
            "delete_at",
        ] {
            assert_eq!(plan[field], expect[field], "{name} {field}");
        }
        assert_eq!(plan["group"], Value::Null, "{name}");
        assert_eq!(plan["people"], Value::Null, "{name}");
        assert_no_purchase_text(&answer.to_string());
    }
}

#[test]
fn a_family_shows_its_people_to_the_organizer_and_to_a_member() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut organizer = mac(&connect, "Rafal");
    let checkout = organizer
        .account
        .checkout(&CheckoutRequest::new("family", "month", 4))
        .expect("checkout");
    assert!(connect.complete_checkout(&checkout.session_id));
    let group_id = organizer
        .account
        .group()
        .expect("group")
        .expect("a group")
        .group_id;
    let mut members = Vec::new();
    for name in ["Ala", "Olek"] {
        let mut member = mac(&connect, name);
        let invite = organizer.account.invite("member").expect("invite");
        member.account.join_group(&invite.url).expect("join group");
        let action = organizer.account.group_change_action(
            &group_id,
            ConnectGroupChange::ConfirmMember {
                account_id: member.id(),
                name: name.to_owned(),
            },
        );
        let (proof, epoch) = owner.proof(action);
        organizer
            .account
            .confirm_member(&group_id, &member.id(), name, proof, &epoch)
            .expect("confirm member");
        members.push(member);
    }

    let phone = phone(&connect);
    join(&mut organizer, &owner, &phone);
    let status = call(&phone.core, json!({"op": "connect_status"}));
    let plan = &status["plan"];
    assert_eq!(plan["plan"], "family");
    assert_eq!(plan["status"], "active");
    assert_eq!(plan["group"], json!({"kind": "family", "role": "owner"}));
    assert_eq!(plan["people"], json!({"active": 3, "of": 4}));
    assert_no_purchase_text(&status.to_string());

    // The iPhone of a member sees the plan of the family and the same people.
    let member_phone = phone_with(&connect, "app");
    join(&mut members[0], &owner, &member_phone);
    let status = call(&member_phone.core, json!({"op": "connect_status"}));
    let plan = &status["plan"];
    assert_eq!(plan["plan"], "family");
    assert_eq!(plan["entitled"], true);
    assert_eq!(plan["group"], json!({"kind": "family", "role": "member"}));
    assert_eq!(plan["people"], json!({"active": 3, "of": 4}));
    assert_no_purchase_text(&status.to_string());
}

#[test]
fn the_status_without_connect_keeps_the_last_plan_and_marks_it() {
    let connect = FakeConnect::start();
    let owner = owner();
    let mut mac = mac(&connect, "Rafal");
    let phone = phone(&connect);
    join(&mut mac, &owner, &phone);
    connect.set_plan(
        &mac.id(),
        json!({"plan": "personal", "status": "active", "entitled": true, "interval": "month",
               "quantity": 1, "renews_at": 1_792_592_000u64, "ends_at": null,
               "grace_until": null, "read_only_until": null, "delete_at": null,
               "group_id": null}),
    );
    let fresh = call(&phone.core, json!({"op": "connect_status"}));
    assert!(fresh.get("stale").is_none());
    // The next answers of Connect are lost: the core shows the last plan, marked stale.
    connect.lose_next_answers("GET /v1/account", 4);
    let stale = call(&phone.core, json!({"op": "connect_status"}));
    assert_eq!(stale["state"], "account");
    assert_eq!(stale["stale"], true);
    assert_eq!(stale["plan"], fresh["plan"]);
    // The account stays on this iPhone.
    assert!(phone.state_file().exists());
    assert!(phone.keys.has_key());
}
