#![cfg(feature = "vault")]

//! The Apassy Connect account on the Mac (plan s7 unit M1, contract connect-account-v1)
//! against the in-process fake Connect (`common/fake_connect.rs`) and the fake relay.
//! Synthetic values only; no real Connect, Stripe, or Keychain.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof, ProofRefusal};
use apassy::connect::account::{Clock, Sleeper};
use apassy::connect::device_key::{
    account_message, brain_sign_in_message, join_cancel_message, join_message, list_hash,
    list_message, recover_message, sign_in_message,
};
use apassy::connect::entitlement::{self, EntitlementError, EntitlementKey, Feature};
use apassy::connect::trust::{ListEntry, Pin, root_hash, verify_list};
use apassy::connect::{
    AccountSigner, AccountState, ConnectAccount, ConnectClient, ConnectError, DeviceKeyStore,
    JoinPoll, JoinRequest, LinkCode, MemoryKeyStore, RecoveryCode, account_file, drop_account_rows,
    drop_stale_account_rows, forget_this_device, link_fingerprint, link_hash, safety_words,
    same_safety_words,
};
use apassy::sync::{
    DeviceKey, HeadFields, NO_PREVIOUS, decode_b64u, encode_b64u, sha256_hex, verify_signature,
};
use apassy::vault::Vault;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::common::fake_connect::{FakeConnect, KID};
use crate::common::fake_relay::FakeRelay;

const PASS: &str = "synthetic-connect-pass";
const VECTORS: &str = include_str!("fixtures/connect-account-v1/vectors.json");
const VAULT_ID: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

/// A device of the test: its key store and its account file.
struct Device {
    _dir: TempDir,
    store: MemoryKeyStore,
    path: PathBuf,
}

fn device() -> Device {
    let dir = TempDir::new().expect("dir");
    let path = account_file(dir.path());
    Device {
        _dir: dir,
        store: MemoryKeyStore::new(),
        path,
    }
}

/// An unlocked vault and its owner gate, for the owner checks (the passphrase in a test,
/// Touch ID in the app).
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

    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.shared.lock().unwrap().as_mut().expect("vault"))
    }
}

fn client(connect: &FakeConnect) -> ConnectClient {
    ConnectClient::new(&connect.url).expect("client")
}

/// The waits of the sign-in rounds, recorded instead of slept.
fn recorded_waits() -> (Sleeper, Arc<Mutex<Vec<Duration>>>) {
    let waits = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&waits);
    let sleeper: Sleeper = Arc::new(move |wait| seen.lock().unwrap().push(wait));
    (sleeper, waits)
}

/// A new account on device `a`. Its sign-in rounds do not sleep.
fn create(connect: &FakeConnect, a: &Device) -> (ConnectAccount, RecoveryCode) {
    let (mut account, recovery) =
        ConnectAccount::create(client(connect), &a.store, &a.path, "Rafal", "MacBook Pro")
            .expect("create");
    account.set_sleeper(recorded_waits().0);
    (account, recovery)
}

/// Device `b` joins the account of `account` on `a`, confirmed with a fresh owner check.
fn join(
    connect: &FakeConnect,
    account: &mut ConnectAccount,
    b: &Device,
    owner: &Owner,
) -> ConnectAccount {
    join_named(connect, account, b, owner, "iPhone")
}

/// [`join`] with the device name `name`.
fn join_named(
    connect: &FakeConnect,
    account: &mut ConnectAccount,
    b: &Device,
    owner: &Owner,
    name: &str,
) -> ConnectAccount {
    let link = account.start_link().expect("link");
    let mut request =
        JoinRequest::start(client(connect), &b.store, &b.path, link.code(), name).expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = account.pending_joins(&link).expect("pending");
    assert_eq!(pending.len(), 1);
    let (proof, epoch) = owner.proof(pending[0].owner_action(&account.state().account_id));
    account
        .confirm_join(&link, &pending[0], proof, &epoch)
        .expect("confirm");
    match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => {
            let mut joined = *joined;
            joined.set_sleeper(recorded_waits().0);
            joined
        }
        other => panic!("not confirmed: {other:?}"),
    }
}

/// Whether the device `device_id` is verified in a fresh view of `account`.
fn verified(account: &mut ConnectAccount, device_id: &str) -> Option<bool> {
    account
        .view()
        .expect("view")
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .map(|device| device.verified)
}

// ---- The vectors of section 15. ----

/// The link code with its fingerprint, the link hash, the six safety words, the recovery
/// words and key, the recovery signature, the chain of device B, and every message of the
/// device key are those of the fixture; the fixture signatures verify over the messages
/// that this build makes, and a signature of this build verifies too.
#[test]
fn the_vectors_reproduce_the_words_hashes_keys_and_messages() {
    let v = vectors();
    let origin = v["origin"].as_str().unwrap();
    let brain = v["brain_origin"].as_str().unwrap();
    let account = v["account_id"].as_str().unwrap();
    let nonce = v["nonce_b64u"].as_str().unwrap();
    let a_public = hex(v["device_a"]["public_hex"].as_str().unwrap());
    let b_public = hex(v["device_b"]["public_hex"].as_str().unwrap());
    let a64 = v["device_a"]["public_b64u"].as_str().unwrap();
    let b64 = v["device_b"]["public_b64u"].as_str().unwrap();

    let code = LinkCode::parse(v["link"]["code"].as_str().unwrap()).expect("code");
    assert_eq!(code.account_id(), account);
    assert_eq!(code.link_hash(), v["link"]["link_hash"].as_str().unwrap());
    assert_eq!(link_hash(code.expose()), code.link_hash());
    // Device A is the root of the account and makes the link.
    assert_eq!(
        code.fingerprint(),
        v["link"]["fingerprint"].as_str().unwrap()
    );
    assert_eq!(link_fingerprint(&a_public, &a_public), code.fingerprint());
    assert_ne!(link_fingerprint(&a_public, &b_public), code.fingerprint());

    let words = safety_words(account, code.expose(), &a_public, &b_public);
    assert_eq!(words, v["safety"]["words"].as_str().unwrap());
    assert!(same_safety_words(&words, &words.to_uppercase()));
    // The other order of the keys gives other words.
    assert_ne!(
        safety_words(account, code.expose(), &b_public, &a_public),
        words
    );

    let recovery_bytes: [u8; 16] = hex(v["recovery"]["bytes_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let recovery = RecoveryCode::from_bytes(recovery_bytes);
    assert_eq!(
        recovery.words().as_str(),
        v["recovery"]["words"].as_str().unwrap()
    );
    assert_eq!(
        recovery.text().as_str(),
        v["recovery"]["code"].as_str().unwrap()
    );
    let recovery_key = recovery.key().unwrap().public_key_b64u();
    assert_eq!(recovery_key, v["recovery"]["public_b64u"].as_str().unwrap());
    assert_eq!(
        RecoveryCode::parse(v["recovery"]["words"].as_str().unwrap())
            .unwrap()
            .key()
            .unwrap()
            .public_key_b64u(),
        recovery_key
    );
    let new_bytes: [u8; 16] = hex(v["new_recovery"]["bytes_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let new_key = RecoveryCode::from_bytes(new_bytes)
        .key()
        .unwrap()
        .public_key_b64u();
    assert_eq!(new_key, v["new_recovery"]["public_b64u"].as_str().unwrap());

    let signer_a = AccountSigner::with_key(
        DeviceKey::from_raw(
            &hex(v["device_a"]["private_hex"].as_str().unwrap()),
            &a_public,
        )
        .unwrap(),
    );
    let signer_b = AccountSigner::with_key(
        DeviceKey::from_raw(
            &hex(v["device_b"]["private_hex"].as_str().unwrap()),
            &b_public,
        )
        .unwrap(),
    );
    assert_eq!(signer_a.public_key_b64u(), a64);
    assert_eq!(
        signer_a.public_key_sha256(),
        v["device_a"]["public_key_sha256"].as_str().unwrap()
    );
    let hash = code.link_hash();
    let name_a = v["device_a"]["name"].as_str().unwrap();
    let name_b = v["device_b"]["name"].as_str().unwrap();
    let hashes: Vec<String> = v["device_list"]["hashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hash| hash.as_str().unwrap().to_owned())
        .collect();
    let mut names = Vec::new();
    for message in v["messages"].as_array().unwrap() {
        let name = message["name"].as_str().unwrap();
        names.push(name.to_owned());
        let (bytes, signer_public) = match name {
            "account" => (account_message(origin, a64, &recovery_key), &a_public),
            "sign_in" => (sign_in_message(origin, account, a64, nonce), &a_public),
            "join" => (join_message(origin, account, &hash, b64), &b_public),
            "join_cancel" => (join_cancel_message(origin, account, &hash, b64), &b_public),
            "device_list_root" => (
                list_message(origin, account, 1, "-", "root", a64, "-", name_a, a64),
                &a_public,
            ),
            "device_list_add" => (
                list_message(
                    origin, account, 2, &hashes[0], "add", b64, &hash, name_b, a64,
                ),
                &a_public,
            ),
            "device_list_remove" => (
                list_message(origin, account, 3, &hashes[1], "remove", b64, "-", "-", a64),
                &a_public,
            ),
            "device_list_member_root" => (
                list_message(
                    origin,
                    "acc_m3n5p7q2rb",
                    1,
                    "-",
                    "root",
                    b64,
                    "-",
                    name_b,
                    b64,
                ),
                &b_public,
            ),
            "device_list_recovery_root" => (
                list_message(
                    origin,
                    account,
                    1,
                    "-",
                    "root",
                    b64,
                    "-",
                    "MacBook Air",
                    b64,
                ),
                &b_public,
            ),
            "recover" => (recover_message(origin, account, b64, &new_key), &b_public),
            "brain_sign_in" => (brain_sign_in_message(brain, account, a64, nonce), &a_public),
            other => panic!("unknown message {other}"),
        };
        assert_eq!(
            bytes,
            decode_b64u(message["message_b64u"].as_str().unwrap()).unwrap(),
            "{name}"
        );
        assert_eq!(sha256_hex(&bytes), message["sha256"].as_str().unwrap());
        let signature = decode_b64u(message["signature_b64u"].as_str().unwrap()).unwrap();
        assert!(
            verify_signature(signer_public, &bytes, &signature),
            "{name}"
        );
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            !verify_signature(signer_public, &changed, &signature),
            "{name}"
        );
    }
    assert_eq!(
        names,
        [
            "account",
            "sign_in",
            "join",
            "join_cancel",
            "device_list_root",
            "device_list_add",
            "device_list_remove",
            "recover",
            "device_list_member_root",
            "device_list_recovery_root",
            "brain_sign_in"
        ]
    );

    // The Ed25519 recovery signature is deterministic: this build makes the same one.
    let recover = recover_message(origin, account, b64, &new_key);
    assert_eq!(
        encode_b64u(&recovery.key().unwrap().sign_recover(&recover).unwrap()),
        v["recovery"]["recover_signature_b64u"].as_str().unwrap()
    );

    // The device list starts at device A, the root: A adds B, then A removes B. Each hash
    // is the one of the vectors, and the list verifies only from A.
    let list: Vec<ListEntry> = serde_json::from_value(v["device_list"]["entries"].clone()).unwrap();
    assert_eq!(root_hash(origin, account, &a_public, name_a), hashes[0]);
    let verified = verify_list(origin, account, &a_public, &list).unwrap();
    assert_eq!(verified.hashes, hashes);
    assert_eq!(verified.live, std::slice::from_ref(&a_public));
    let at_two = verify_list(origin, account, &a_public, &list[..2]).unwrap();
    assert_eq!(at_two.live, [a_public.clone(), b_public.clone()]);
    // Each name is the one that its entry signed.
    assert_eq!(at_two.name_of(&a_public), Some(name_a));
    assert_eq!(at_two.name_of(&b_public), Some(name_b));
    let mut renamed = list.clone();
    renamed[1].name = Some("Other".to_owned());
    assert!(verify_list(origin, account, &a_public, &renamed).is_none());
    assert!(verify_list(origin, account, &b_public, &list).is_none());
    // A device that pinned version 3 refuses the list of version 2.
    let pin = Pin {
        version: 3,
        head: &hashes[2],
    };
    assert!(pin.accepts(&verified) && !pin.accepts(&at_two));
    assert_eq!(
        list_hash(&decode_b64u(v["device_list"]["root_message_b64u"].as_str().unwrap()).unwrap()),
        hashes[0]
    );

    // The signer of this build makes signatures that verify over the same messages.
    for (bytes, signature, public) in [
        (
            account_message(origin, a64, &recovery_key),
            signer_a.sign_account(origin, &recovery_key).unwrap(),
            &a_public,
        ),
        (
            sign_in_message(origin, account, a64, nonce),
            signer_a.sign_sign_in(origin, account, nonce).unwrap(),
            &a_public,
        ),
        (
            list_message(
                origin, account, 2, &hashes[0], "add", b64, &hash, name_b, a64,
            ),
            signer_a
                .sign_list_entry(
                    origin,
                    account,
                    (2, &hashes[0]),
                    "add",
                    b64,
                    Some(&hash),
                    Some(name_b),
                )
                .unwrap()
                .0,
            &a_public,
        ),
        (
            list_message(origin, account, 1, "-", "root", a64, "-", name_a, a64),
            signer_a.sign_root(origin, account, name_a).unwrap().0,
            &a_public,
        ),
        (
            join_cancel_message(origin, account, &hash, b64),
            signer_b.sign_join_cancel(origin, account, &hash).unwrap(),
            &b_public,
        ),
        (
            recover_message(origin, account, b64, &new_key),
            signer_b.sign_recover(origin, account, &new_key).unwrap(),
            &b_public,
        ),
        (
            brain_sign_in_message(brain, account, a64, nonce),
            signer_a.sign_brain_sign_in(brain, account, nonce).unwrap(),
            &a_public,
        ),
    ] {
        assert!(verify_signature(public, &bytes, &signature));
    }
}

/// The account key signs the nine tags of section 5 and nothing else.
#[test]
fn the_account_key_refuses_every_other_tag() {
    let store = MemoryKeyStore::new();
    let signer = AccountSigner::open_or_create(&store).unwrap();
    let refused: [&[u8]; 9] = [
        &b"apassy-relay connect v1\0https://connect.example.test\0key"[..],
        b"apassy-connect entitlement v1\0payload",
        b"apassy-connect safety v1\0acc",
        b"apassy-connect recovery key v1\0bytes",
        b"apassy-connect link-keys v1\0keys",
        b"apassy-relay sign-in v2\0origin",
        b"apassy-connect sign-in v1",
        b"apassy-connect device v1",
        b"",
    ];
    for refused in refused {
        assert_eq!(signer.sign(refused).unwrap_err(), ConnectError::TagRefused);
        assert_eq!(
            apassy::connect::sign(&signer, refused).unwrap_err(),
            ConnectError::TagRefused
        );
    }
    assert_eq!(apassy::connect::SIGNING_TAGS.len(), 11);
}

/// The entitlement tokens of the vectors verify with the published key and fail with a
/// changed claim, after `exp`, with another key, another account, or another feature.
#[test]
fn the_entitlement_vectors_verify_and_fail_as_the_contract_says() {
    let v = vectors();
    let ent = &v["entitlement"];
    let key = EntitlementKey::from_published(
        ent["kid"].as_str().unwrap(),
        "Ed25519",
        ent["public_b64u"].as_str().unwrap(),
    )
    .expect("key");
    assert_eq!(ent["kid"], KID);
    assert_eq!(ent["public_b64u"], FakeConnect::entitlement_public_key());
    let other = EntitlementKey {
        kid: key.kid.clone(),
        public_key: [7; 32],
    };
    for token in ent["tokens"].as_array().unwrap() {
        let text = token["token"].as_str().unwrap();
        let claims = &token["claims"];
        let account = claims["acc"].as_str().unwrap();
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        let read = entitlement::verify(
            text,
            std::slice::from_ref(&key),
            Feature::Brain,
            account,
            iat + 10,
        )
        .expect("verifies");
        assert_eq!(read.exp, exp);
        assert_eq!(read.group.as_deref(), claims["group"].as_str());
        assert_eq!(
            entitlement::verify(
                text,
                std::slice::from_ref(&key),
                Feature::Brain,
                account,
                exp
            ),
            Err(EntitlementError::Expired)
        );
        assert_eq!(
            entitlement::verify(
                text,
                std::slice::from_ref(&other),
                Feature::Brain,
                account,
                iat + 10
            ),
            Err(EntitlementError::Signature)
        );
        assert_eq!(
            entitlement::verify(
                text,
                std::slice::from_ref(&key),
                Feature::Brain,
                "acc_aaaaaaaaaa",
                iat
            ),
            Err(EntitlementError::OtherAccount)
        );
        // A changed claim breaks the signature.
        let (payload, signature) = text.split_once('.').unwrap();
        let mut claims_text = String::from_utf8(decode_b64u(payload).unwrap()).unwrap();
        claims_text = claims_text.replace("\"exp\":", "\"exp\":9");
        let forged = format!("{}.{signature}", encode_b64u(claims_text.as_bytes()));
        assert_eq!(
            entitlement::verify(
                &forged,
                std::slice::from_ref(&key),
                Feature::Brain,
                account,
                iat
            ),
            Err(EntitlementError::Signature)
        );
        assert_eq!(
            entitlement::verify(
                &format!("{text}.x"),
                std::slice::from_ref(&key),
                Feature::Brain,
                account,
                iat
            ),
            Err(EntitlementError::Malformed)
        );
    }
}

// ---- Creation and sign-in (section 6). ----

/// The device key is made once and stays in the key store; Connect sees only the public
/// key and the public key of the recovery code; the account file holds no key, token,
/// email, or code, with mode 0600, and pins this Mac as the account root.
#[test]
fn creating_an_account_keeps_the_key_in_the_store_and_no_secret_in_the_file() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, recovery) = create(&connect, &a);
    assert!(a.store.has_key());
    let state = account.state().clone();
    assert_eq!(state.origin, connect.url);
    assert_eq!(
        connect.live_devices(&state.account_id),
        std::slice::from_ref(&state.device_id)
    );
    assert_eq!(
        connect.known_keys(),
        [account.signer().unwrap().public_key().to_vec()]
    );
    // The recovery code is never sent; only the public key of its Ed25519 key.
    let words = recovery.words();
    for body in connect.bodies() {
        assert!(!body.contains(recovery.text().as_str()));
        assert!(!body.contains(words.as_str()));
    }
    let recovery_key = recovery.key().unwrap().public_key_b64u();
    assert!(
        connect
            .bodies()
            .iter()
            .any(|body| body.contains(&recovery_key))
    );
    // This Mac is the root and the only known device: version 1 of the device list.
    assert_eq!(state.root, state.public_key);
    assert_eq!(state.known, std::slice::from_ref(&state.public_key));
    assert!(state.left.is_empty());
    assert_eq!(state.list_version, 1);
    assert_eq!(
        state.list_head,
        root_hash(
            &connect.url,
            &state.account_id,
            &decode_b64u(&state.public_key).unwrap(),
            "MacBook Pro"
        )
    );
    // A view signs in once, and the token stays in memory.
    let view = account.view().expect("view");
    assert_eq!(view.name, "Rafal");
    assert_eq!(view.devices.len(), 1);
    assert!(view.devices[0].verified);
    assert!(view.list_verified);
    assert_eq!(view.device_list.len(), 1);
    assert!(account.is_signed_in());
    account.view().expect("view again");
    assert_eq!(connect.count("POST /v1/account/token"), 1);
    // The account file: ids, names, the origin, the public keys. No secret.
    let file = std::fs::read_to_string(&a.path).expect("file");
    for absent in [
        "token",
        "apassy_act_",
        "apassy_rec_",
        "email",
        "pkcs8",
        "private",
    ] {
        assert!(!file.contains(absent), "{absent} in {file}");
    }
    assert!(!file.contains(recovery.text().as_str()));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(AccountState::load(&a.path).unwrap().as_ref(), Some(&state));
    // The edge routes carried no Authorization; every other route the account token,
    // and only to this Connect.
    for (line, authorization) in connect.authorizations() {
        let edge = line == "POST /v1/account"
            || line == "POST /v1/account/challenge"
            || line == "POST /v1/account/token";
        assert_eq!(authorization.is_none(), edge, "{line}");
    }
    // Opening the account again reads the same key; a second account is refused.
    let opened = ConnectAccount::open(&a.store, &a.path)
        .unwrap()
        .expect("account");
    assert_eq!(
        opened.signer().unwrap().public_key(),
        account.signer().unwrap().public_key()
    );
    assert_eq!(
        ConnectAccount::create(client(&connect), &a.store, &a.path, "Rafal", "Mac").unwrap_err(),
        ConnectError::AccountExists
    );
    // Another key in the store than the account file names is a lost key.
    let other = MemoryKeyStore::new();
    AccountSigner::open_or_create(&other).unwrap();
    assert_eq!(
        ConnectAccount::open(&other, &a.path).unwrap_err(),
        ConnectError::KeyLost
    );
    assert_eq!(
        ConnectAccount::open(&MemoryKeyStore::new(), &a.path).unwrap_err(),
        ConnectError::KeyLost
    );
}

/// A creation whose answer is lost is sent again with the same body, and Connect
/// answers the same account: one account, one device.
#[test]
fn a_lost_creation_answer_is_retried_with_the_same_body() {
    let connect = FakeConnect::start();
    connect.lose_next_answers("POST /v1/account", 1);
    let a = device();
    let (account, _) = create(&connect, &a);
    let creations = connect
        .log()
        .iter()
        .filter(|line| *line == "POST /v1/account")
        .count();
    assert_eq!(creations, 2);
    assert_eq!(connect.accounts(), [account.state().account_id.clone()]);
    assert_eq!(connect.live_devices(&account.state().account_id).len(), 1);
}

/// The client stops when the challenge names another origin: nothing is signed for it.
#[test]
fn sign_in_refuses_a_challenge_from_another_origin() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    connect.report_origin("https://connect.example.test");
    assert_eq!(account.sign_in().unwrap_err(), ConnectError::OriginMismatch);
    assert_eq!(connect.count("POST /v1/account/token"), 0);
    assert!(!account.is_signed_in());
}

/// The account token is renewed before it ends, and never kept beyond 15 minutes.
#[test]
fn the_token_lives_in_memory_and_is_renewed_before_it_ends() {
    static NOW: AtomicU64 = AtomicU64::new(0);
    let connect = FakeConnect::start();
    connect.set_token_lifetime(3_600);
    let a = device();
    let (mut account, _) = create(&connect, &a);
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    NOW.store(start, Ordering::SeqCst);
    let clock: Clock = Arc::new(|| NOW.load(Ordering::SeqCst));
    account.set_clock(clock);
    account.view().unwrap();
    assert_eq!(connect.count("POST /v1/account/token"), 1);
    // Connect said an hour; this Mac keeps it 15 minutes at most.
    NOW.store(start + 850, Ordering::SeqCst);
    account.view().unwrap();
    assert_eq!(connect.count("POST /v1/account/token"), 2);
    // A sign-out drops it.
    account.sign_out();
    assert!(!account.is_signed_in());
}

/// The device keeps its key and its account file and signs in on the next round.
fn assert_still_a_device(account: &ConnectAccount, a: &Device) {
    assert!(!account.is_removed());
    assert!(a.store.has_key());
    assert!(a.path.exists());
    assert!(account.is_signed_in());
}

/// The nonces that Connect lost between the challenge and the token (a restart) are a
/// `401` at the token: never a removal. The next round takes a fresh challenge after a
/// wait, and signs in.
#[test]
fn a_nonce_lost_at_the_token_signs_in_on_the_next_round() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    let (sleeper, waits) = recorded_waits();
    account.set_sleeper(sleeper);
    connect.restart_before_next_tokens(1);
    account.view().expect("signed in on the second round");
    assert_eq!(connect.count("POST /v1/account/challenge"), 2);
    assert_eq!(connect.count("POST /v1/account/token"), 2);
    assert_eq!(*waits.lock().unwrap(), [Duration::from_secs(1)]);
    assert_still_a_device(&account, &a);
    // A restart while no sign-in runs changes nothing either.
    connect.drop_nonces();
    account.sign_in().expect("sign in");
    assert_still_a_device(&account, &a);
}

/// A stranger who asks for many challenges for this Mac's key ends no challenge of this
/// Mac: a challenge never ends another one.
#[test]
fn challenges_of_a_stranger_end_no_challenge_of_this_mac() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    let state = account.state().clone();
    for _ in 0..12 {
        let nonce = http(
            &connect.url,
            "POST",
            "/v1/account/challenge",
            &[],
            json!({"account_id": state.account_id, "public_key": state.public_key})
                .to_string()
                .as_bytes(),
        );
        assert!(nonce["nonce"].is_string());
    }
    account.sign_in().expect("sign in");
    assert_eq!(connect.count("POST /v1/account/token"), 1);
    assert_still_a_device(&account, &a);
}

/// A busy Connect at the token call: the same body is never sent again (its nonce stays
/// unused); the next round signs a fresh nonce.
#[test]
fn a_busy_token_call_is_never_repeated_with_the_same_body() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    connect.busy_next_tokens(1);
    account.sign_in().expect("sign in");
    let nonces: Vec<String> = connect
        .bodies()
        .iter()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .filter(|body| body.get("nonce").is_some())
        .map(|body| body["nonce"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
    assert_still_a_device(&account, &a);
}

/// Three refused rounds end the sign-in with `Unauthenticated`, after waits of 1 s and
/// 3 s. The account is not removed: the next sign-in works.
#[test]
fn refused_sign_in_rounds_are_unauthenticated_and_never_a_removal() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    let (sleeper, waits) = recorded_waits();
    account.set_sleeper(sleeper);
    connect.refuse_next_tokens(3);
    assert_eq!(
        account.sign_in().unwrap_err(),
        ConnectError::Unauthenticated
    );
    assert_eq!(connect.count("POST /v1/account/challenge"), 3);
    assert_eq!(
        *waits.lock().unwrap(),
        [Duration::from_secs(1), Duration::from_secs(3)]
    );
    assert!(!account.is_removed());
    assert!(a.store.has_key() && a.path.exists());
    account.sign_in().expect("the next sign-in works");
    assert_still_a_device(&account, &a);
    // A call refused with `401` again after a fresh sign-in is `Unauthenticated`.
    connect.set_token_lifetime(0);
    account
        .sign_in()
        .expect("a token that Connect ends at once");
    assert_eq!(account.view().unwrap_err(), ConnectError::Unauthenticated);
    assert!(!account.is_signed_in());
    assert!(!account.is_removed());
    assert!(a.store.has_key() && a.path.exists());
}

// ---- Devices (section 7). ----

/// A device joins only by a confirmation on the live device: both show the same six
/// words, the confirmation needs a fresh owner check for exactly that join, and a proof
/// for another action changes nothing. The confirmation sends the signed `add` entry, and
/// both devices verify each other afterwards.
#[test]
fn adding_a_device_needs_the_owner_check_and_both_sides_show_the_same_words() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b) = (device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    let link = account.start_link().expect("link");
    assert!(!format!("{link:?}").contains(link.code()));
    let code = LinkCode::parse(link.code()).expect("code");
    let root = decode_b64u(&account.state().root).unwrap();
    assert_eq!(code.fingerprint(), link_fingerprint(&root, &root));
    let mut request =
        JoinRequest::start(client(&connect), &b.store, &b.path, link.code(), "iPhone")
            .expect("join");
    assert_eq!(request.confirmer_name(), "MacBook Pro");
    assert!(matches!(request.poll().unwrap(), JoinPoll::Waiting));
    let pending = account.pending_joins(&link).expect("pending");
    assert_eq!(pending.len(), 1);
    let join = &pending[0];
    assert_eq!(join.device_name, "iPhone");
    assert_eq!(join.words, request.words());
    assert_eq!(join.words.split(' ').count(), 6);
    // The link code never reached Connect, only its hash.
    for body in connect.bodies() {
        assert!(!body.contains(link.code()));
    }

    // A proof for another action, or for the same join with other words, is refused.
    let (wrong, epoch) = owner.proof(OwnerAction::DeleteConnectAccount {
        account_id: account_id.clone(),
    });
    assert_eq!(
        account
            .confirm_join(&link, join, wrong, &epoch)
            .unwrap_err(),
        ConnectError::OwnerCheck(ProofRefusal::WrongAction)
    );
    let mut changed = join.clone();
    changed.words = "blaze cable flute board seal tiger".to_owned();
    let (proof, epoch) = owner.proof(changed.owner_action(&account_id));
    if changed.words != join.words {
        assert_eq!(
            account
                .confirm_join(&link, &changed, proof, &epoch)
                .unwrap_err(),
            ConnectError::WordsMismatch
        );
    }
    assert_eq!(connect.live_devices(&account_id).len(), 1);
    assert_eq!(connect.count("POST /v1/account/devices/pending/"), 0);

    // The right proof adds exactly the key of the words, with this Mac's statement.
    let (proof, epoch) = owner.proof(join.owner_action(&account_id));
    let added = account
        .confirm_join(&link, join, proof, &epoch)
        .expect("confirm");
    assert_eq!(added.name, "iPhone");
    assert!(added.verified);
    // The list has this Mac's `add` of that key and link, and this Mac pinned it.
    let list = connect.device_list(&account_id);
    assert_eq!(list.len(), 2);
    assert_eq!(list[1]["op"], "add");
    assert_eq!(list[1]["key"], added.public_key.as_str());
    assert_eq!(list[1]["by"], account.state().public_key.as_str());
    assert_eq!(list[1]["link_hash"], link_hash(link.code()).as_str());
    assert_eq!(account.state().list_version, 2);
    assert!(account.state().known.contains(&added.public_key));
    let joined = match request.poll().unwrap() {
        JoinPoll::Confirmed(joined) => joined,
        other => panic!("not confirmed: {other:?}"),
    };
    assert_eq!(joined.state().account_id, account_id);
    assert_eq!(joined.state().device_id, added.device_id);
    assert_eq!(joined.state().name.as_deref(), Some("Rafal"));
    // The new device pinned the root of the code and knows the confirming device.
    assert_eq!(joined.state().root, account.state().root);
    assert!(joined.state().known.contains(&account.state().public_key));
    assert_eq!(connect.live_devices(&account_id).len(), 2);
    assert!(b.path.exists());
    let mut joined = *joined;
    let view = joined.view().expect("view on the new device");
    assert!(view.devices.iter().all(|device| device.verified));
    assert_eq!(verified(&mut account, &added.device_id), Some(true));
    // The link worked once.
    let c = device();
    assert_eq!(
        JoinRequest::start(client(&connect), &c.store, &c.path, link.code(), "Mac mini")
            .unwrap_err(),
        ConnectError::Forbidden
    );
}

/// The new device refuses a confirming device that the code does not name: another
/// device of the account, the same key with a device list from another root, the right
/// key with a list that does not hold it, or a key that is no point of the curve. The join
/// is cancelled with a signed cancel, and nothing is joined.
#[test]
fn a_join_refuses_any_confirmer_that_the_code_does_not_name() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b) = (device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    let phone = join(&connect, &mut account, &b, &owner);
    let own_key = account.state().public_key.clone();

    // Another root: a key that Connect could make, with a list that adds A's key.
    let other_root = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
    let other_root_key = other_root.public_key_b64u();
    let (other_root_statement, other_head) = other_root
        .sign_root(&connect.url, &account_id, "Other Mac")
        .unwrap();
    let fake_hash = encode_b64u(&[3u8; 32]);
    let (statement, _) = other_root
        .sign_list_entry(
            &connect.url,
            &account_id,
            (2, &other_head),
            "add",
            &own_key,
            Some(&fake_hash),
            Some("MacBook Pro"),
        )
        .unwrap();
    let other_list = vec![
        json!({"version": 1, "op": "root", "key": other_root_key, "link_hash": null,
               "name": "Other Mac", "by": other_root_key,
               "signature": encode_b64u(&other_root_statement)}),
        json!({"version": 2, "op": "add", "key": own_key, "link_hash": fake_hash,
               "name": "MacBook Pro", "by": other_root_key,
               "signature": encode_b64u(&statement)}),
    ];
    // The right root, without the confirmer: the root removed itself.
    let own_root = connect.device_list(&account_id)[0].clone();
    let own_head = root_hash(
        &connect.url,
        &account_id,
        &decode_b64u(&own_key).unwrap(),
        "MacBook Pro",
    );
    let (gone, _) = account
        .signer()
        .unwrap()
        .sign_list_entry(
            &connect.url,
            &account_id,
            (2, &own_head),
            "remove",
            &own_key,
            None,
            None,
        )
        .unwrap();
    let only_root = vec![
        own_root,
        json!({"version": 2, "op": "remove", "key": own_key, "link_hash": null,
               "name": null, "by": own_key, "signature": encode_b64u(&gone)}),
    ];
    let real_list = connect.device_list(&account_id);
    let mut off = vec![4u8];
    off.extend_from_slice(&[9; 64]);
    let me = json!({"device_id": account.state().device_id, "name": "MacBook Pro",
                    "public_key": own_key});
    let cases = [
        (
            connect
                .device_view(&phone.state().device_id)
                .expect("the phone"),
            None,
            ConnectError::LinkMismatch,
        ),
        (me.clone(), Some(other_list), ConnectError::LinkMismatch),
        (me.clone(), Some(only_root), ConnectError::LinkMismatch),
        (
            me.clone(),
            Some(real_list[..0].to_vec()),
            ConnectError::LinkMismatch,
        ),
        (
            json!({"device_id": account.state().device_id, "name": "MacBook Pro",
                   "public_key": encode_b64u(&off)}),
            None,
            ConnectError::BadAnswer,
        ),
    ];
    for (confirmer, list, expected) in cases {
        let link = account.start_link().expect("link");
        connect.answer_confirmer(Some(confirmer));
        if let Some(list) = list {
            connect.set_device_list(&account_id, list);
        }
        let c = device();
        let cancels = connect.count("POST /v1/account/devices/join/cancel");
        assert_eq!(
            JoinRequest::start(client(&connect), &c.store, &c.path, link.code(), "Mac mini")
                .unwrap_err(),
            expected
        );
        connect.set_device_list(&account_id, real_list.clone());
        if expected == ConnectError::LinkMismatch {
            assert_eq!(
                connect.count("POST /v1/account/devices/join/cancel"),
                cancels + 1
            );
            // The cancel was signed: Connect took it, and the join no longer waits.
            assert!(account.pending_joins(&link).unwrap().is_empty());
        }
        assert!(!c.path.exists());
    }
    connect.answer_confirmer(None);
    assert_eq!(connect.live_devices(&account_id).len(), 2);
    // A code without the fingerprint is not a code.
    let old = format!("apassy_alk_{account_id}_{}", "cd".repeat(32));
    let c = device();
    assert_eq!(
        JoinRequest::start(client(&connect), &c.store, &c.path, &old, "Mac mini").unwrap_err(),
        ConnectError::Invalid
    );
}

/// A device row that the signed list does not hold, a device that the list removed and
/// whose row comes back, and a device whose key was swapped are not verified: each is
/// refused for a vault store (nothing is sent) and is not among the keys that may sign a
/// head of a store. A device that Connect only hides (no entry of the list) stays a device
/// of the list. A confirmed device is verified and joins the store with the key that this
/// Mac verified.
#[test]
fn only_verified_devices_count_for_stores_and_heads() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b, c, d, e) = (device(), device(), device(), device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    connect.entitle(&account_id);
    let store = account
        .create_vault_store(VAULT_ID, "Personal")
        .expect("store");
    let team = store.team_id.clone();
    let phone = join(&connect, &mut account, &b, &owner);
    let tablet = join(&connect, &mut account, &c, &owner);
    let laptop = join(&connect, &mut account, &d, &owner);
    let watch = join(&connect, &mut account, &e, &owner);
    let (phone_id, tablet_id, laptop_id, watch_id) = (
        phone.state().device_id.clone(),
        tablet.state().device_id.clone(),
        laptop.state().device_id.clone(),
        watch.state().device_id.clone(),
    );

    // A confirmed device is verified and joins the store with its verified key.
    assert_eq!(verified(&mut account, &phone_id), Some(true));
    let (proof, epoch) = owner.proof(ConnectAccount::add_store_device_action(
        &team,
        &phone_id,
        &account_id,
    ));
    account
        .add_store_device(&team, &phone_id, &account_id, proof, &epoch)
        .expect("add the phone");
    let sent: Value = connect
        .bodies()
        .iter()
        .rev()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .find(|body| body.get("device_id").is_some())
        .expect("the store device body");
    assert_eq!(
        sent,
        json!({"device_id": phone_id, "public_key": phone.state().public_key})
    );

    // (a) A row that no device of the list confirmed.
    let stranger = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
    let inserted = connect.insert_device(&account_id, "Mac Studio", stranger.public_key());
    // (b) A device that the list removed (this Mac signed it), whose row comes back.
    let tablet_view = account
        .view()
        .unwrap()
        .devices
        .into_iter()
        .find(|device| device.device_id == tablet_id)
        .unwrap();
    let (proof, epoch) = owner.proof(account.revoke_action(&tablet_view));
    account.revoke(&tablet_view, proof, &epoch).expect("revoke");
    assert!(account.state().left.contains(&tablet.state().public_key));
    connect.unrevoke(&tablet_id);
    // (c) A device whose key Connect swapped; the list keeps the old key.
    let swapped = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
    connect.swap_key(&laptop_id, swapped.public_key());
    // (d) A device that Connect only hides: no device signed its removal.
    connect.revoke(&watch_id);

    let keys = account.verified_keys().expect("verified keys");
    assert!(keys.contains(&account.signer().unwrap().public_key().to_vec()));
    assert!(keys.contains(&decode_b64u(&phone.state().public_key).unwrap()));
    for (device_id, key) in [
        (&inserted, stranger.public_key().to_vec()),
        (&tablet_id, decode_b64u(&tablet.state().public_key).unwrap()),
        (&laptop_id, swapped.public_key().to_vec()),
    ] {
        assert_eq!(
            verified(&mut account, device_id),
            Some(false),
            "{device_id}"
        );
        assert!(!keys.contains(&key), "{device_id}");
        let posts = connect.count(&format!("POST /v1/account/vaults/{team}/devices"));
        let (proof, epoch) = owner.proof(ConnectAccount::add_store_device_action(
            &team,
            device_id,
            &account_id,
        ));
        assert_eq!(
            account
                .add_store_device(&team, device_id, &account_id, proof, &epoch)
                .unwrap_err(),
            ConnectError::NotVerified,
            "{device_id}"
        );
        assert_eq!(
            connect.count(&format!("POST /v1/account/vaults/{team}/devices")),
            posts,
            "nothing sent for {device_id}"
        );
        assert!(!connect.store_devices(&team).contains(device_id));
    }
    // The heads of a store: the keys of the list, never one that Connect added or swapped
    // in; the tablet only up to what this Mac had merged; the hidden watch still signs.
    let policy = apassy::connect::signer_policy(account.state());
    let tablet_key = decode_b64u(&tablet.state().public_key).unwrap();
    let laptop_key = decode_b64u(&laptop.state().public_key).unwrap();
    let watch_key = decode_b64u(&watch.state().public_key).unwrap();
    assert!(policy.allows(&laptop_key, 9, 0));
    assert!(policy.allows(&watch_key, 9, 0));
    assert!(!policy.allows(stranger.public_key(), 1, 9));
    assert!(!policy.allows(swapped.public_key(), 1, 9));
    assert!(policy.allows(&tablet_key, 3, 3) && !policy.allows(&tablet_key, 4, 3));
    assert_eq!(verified(&mut account, &watch_id), None);
    assert!(account.state().known.contains(&watch.state().public_key));
    // The trust store is in the account file.
    let file = AccountState::load(&a.path).unwrap().unwrap();
    assert_eq!(&file, account.state());
    // The phone, which pinned an older list, verifies the same way.
    let mut phone = phone;
    assert_eq!(verified(&mut phone, &inserted), Some(false));
    assert_eq!(verified(&mut phone, &laptop_id), Some(false));
    assert_eq!(verified(&mut phone, &tablet_id), Some(false));
    assert_eq!(verified(&mut phone, &account.state().device_id), Some(true));
    assert_eq!(phone.state().list_version, account.state().list_version);
    // The tablet joined and left after the phone's last view: the list that the phone
    // verified removed it, so it is among the phone's keys that left. As a current head it
    // signs only up to the phone's anchor, never a later version.
    assert!(phone.state().left.contains(&tablet.state().public_key));
    let phone_policy = apassy::connect::signer_policy(phone.state());
    assert!(!phone_policy.accepts(&tablet_key));
    assert!(!phone_policy.allows(&tablet_key, 4, 3));
}

/// The signed list decides, not Connect's word: a list that is older than the one this
/// device pinned (a rollback), another history from the pinned version (a fork), or a
/// changed entry verifies no device and changes nothing here; the real list verifies
/// again. A removal reaches every device through the list, also a device that learns it
/// later, and an account file from before the removal learns it at the next view.
#[test]
fn a_rolled_back_or_forked_device_list_verifies_no_device() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b, c) = (device(), device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    let mut phone = join(&connect, &mut account, &b, &owner);
    let tablet = join(&connect, &mut account, &c, &owner);
    phone.view().expect("the phone pins version 3");
    let pinned = phone.state().clone();
    assert_eq!(pinned.list_version, 3);
    let old_file = std::fs::read(&b.path).unwrap();
    let real = connect.device_list(&account_id);

    // A rollback: the list of version 2.
    connect.set_device_list(&account_id, real[..2].to_vec());
    let view = phone.view().expect("view");
    assert!(!view.list_verified);
    assert!(view.devices.iter().all(|device| !device.verified));
    assert_eq!(phone.state(), &pinned);
    // A fork: version 3 is another entry, signed by a device of the list.
    let other = AccountSigner::open_or_create(&MemoryKeyStore::new()).unwrap();
    let at_two = head_of(&connect, &account_id, &real[..2]);
    let (statement, _) = account
        .signer()
        .unwrap()
        .sign_list_entry(
            &connect.url,
            &account_id,
            (3, &at_two),
            "add",
            &other.public_key_b64u(),
            Some(&encode_b64u(&[5u8; 32])),
            Some("Other Mac"),
        )
        .unwrap();
    let mut forked = real[..2].to_vec();
    forked.push(
        json!({"version": 3, "op": "add", "key": other.public_key_b64u(),
        "link_hash": encode_b64u(&[5u8; 32]), "name": "Other Mac",
        "by": account.state().public_key, "signature": encode_b64u(&statement)}),
    );
    connect.set_device_list(&account_id, forked);
    let view = phone.view().expect("view");
    assert!(!view.list_verified);
    assert_eq!(phone.state(), &pinned);
    // A changed entry: its signature does not verify.
    let mut changed = real.clone();
    changed[2]["link_hash"] = json!(encode_b64u(&[6u8; 32]));
    connect.set_device_list(&account_id, changed);
    assert!(!phone.view().expect("view").list_verified);
    assert_eq!(phone.state(), &pinned);
    connect.set_device_list(&account_id, real);
    assert!(phone.view().expect("view").list_verified);

    // The Mac removes the tablet: the phone learns it from the list.
    let tablet_view = account
        .view()
        .unwrap()
        .devices
        .into_iter()
        .find(|device| device.device_id == tablet.state().device_id)
        .unwrap();
    let (proof, epoch) = owner.proof(account.revoke_action(&tablet_view));
    account.revoke(&tablet_view, proof, &epoch).expect("revoke");
    assert_eq!(verified(&mut phone, &tablet.state().device_id), None);
    assert!(phone.state().left.contains(&tablet.state().public_key));
    assert!(!phone.state().known.contains(&tablet.state().public_key));
    // The phone's account file from before the removal learns it at its next view.
    drop(phone);
    std::fs::write(&b.path, &old_file).unwrap();
    let mut restored = ConnectAccount::open(&b.store, &b.path)
        .expect("open")
        .expect("account");
    assert!(restored.state().known.contains(&tablet.state().public_key));
    assert!(restored.view().expect("view").list_verified);
    assert!(!restored.state().known.contains(&tablet.state().public_key));
    assert!(restored.state().left.contains(&tablet.state().public_key));
    assert_eq!(restored.state().list_version, 4);
}

/// The short fingerprint of a key that the owner check shows: the first 6 bytes of the
/// SHA-256 of its 65 bytes, in hex groups of four.
fn key_fingerprint(key: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key);
    let hex: String = digest.as_ref()[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{} {} {}", &hex[..4], &hex[4..8], &hex[8..12])
}

/// The row of `device_id` in a fresh view of `account`.
fn row(account: &mut ConnectAccount, device_id: &str) -> apassy::connect::DeviceView {
    account
        .view()
        .expect("view")
        .devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .expect("row")
}

/// A join pins only a list that holds this device's own `add`, made by the confirmer that
/// the code named: an older list that verifies (a prefix from before a removal) is not
/// pinned, so the device that left before signs nothing here. And a list that does not
/// hold this device's own key as a device never counts on it.
#[test]
fn a_join_answered_with_an_older_valid_prefix_pins_nothing() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, x, j, b) = (device(), device(), device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    let tablet = join_named(&connect, &mut account, &x, &owner, "iPad");
    let tablet_key = decode_b64u(&tablet.state().public_key).unwrap();
    let tablet_row = row(&mut account, &tablet.state().device_id);
    let (proof, epoch) = owner.proof(account.revoke_action(&tablet_row));
    account.revoke(&tablet_row, proof, &epoch).expect("revoke");
    let real = connect.device_list(&account_id);
    assert_eq!(real.len(), 3);
    let prefix = real[..2].to_vec();

    // Connect answers the join, and the account after the confirmation, with the list of
    // version 2, in which the tablet is still a device.
    connect.set_device_list(&account_id, prefix.clone());
    let link = account.start_link().expect("link");
    let mut request = JoinRequest::start(
        client(&connect),
        &j.store,
        &j.path,
        link.code(),
        "MacBook Air",
    )
    .expect("join");
    connect.set_device_list(&account_id, real);
    let pending = account.pending_joins(&link).expect("pending");
    let (proof, epoch) = owner.proof(pending[0].owner_action(&account_id));
    account
        .confirm_join(&link, &pending[0], proof, &epoch)
        .expect("confirm");
    let full = connect.device_list(&account_id);
    connect.set_device_list(&account_id, prefix);
    let polled = request.poll();
    let takes_tablet = matches!(
        &polled,
        Ok(JoinPoll::Confirmed(joined))
            if apassy::connect::signer_policy(joined.state()).accepted.contains(&tablet_key)
    );
    assert!(
        !takes_tablet,
        "the tablet that left signs nothing on the new Mac"
    );
    assert!(
        !matches!(polled, Ok(JoinPoll::Confirmed(_))),
        "a list without this Mac's own add is not pinned"
    );

    assert!(!j.path.exists(), "no account file");
    // A live device that Connect shows a list in which it is not a device any more (a
    // removal that Connect does not enforce) pins nothing of it.
    connect.set_device_list(&account_id, full);
    let mut phone = join(&connect, &mut account, &b, &owner);
    let phone_id = phone.state().device_id.clone();
    let phone_row = row(&mut account, &phone_id);
    let (proof, epoch) = owner.proof(account.revoke_action(&phone_row));
    account.revoke(&phone_row, proof, &epoch).expect("revoke");
    connect.unrevoke(&phone_id);
    let pinned = phone.state().clone();
    let view = phone.view().expect("view");
    assert!(
        !view.list_verified,
        "a list without this device counts for nothing"
    );
    assert_eq!(phone.state(), &pinned);
}

/// A revoke removes the key that this Mac's verified list holds for the row, shows its
/// signed name and short fingerprint in the owner check, and refuses a row whose key is
/// this Mac's own while its id is not (and the reverse). Nothing is sent for a refusal.
#[test]
fn a_revoke_names_the_key_of_the_verified_list_and_refuses_a_swapped_row() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b, c) = (device(), device(), device());
    let (mut account, _) = create(&connect, &a);
    let phone = join_named(&connect, &mut account, &b, &owner, "Synthetic iPhone");
    let tablet = join_named(&connect, &mut account, &c, &owner, "Synthetic iPad");
    let own_id = account.state().device_id.clone();
    let own_key = decode_b64u(&account.state().public_key).unwrap();
    let phone_id = phone.state().device_id.clone();
    let phone_key = decode_b64u(&phone.state().public_key).unwrap();
    let tablet_key = decode_b64u(&tablet.state().public_key).unwrap();
    let deletes = || connect.count("DELETE /v1/account/devices");

    // The phone's row with this Mac's key.
    connect.swap_key(&phone_id, &own_key);
    let swapped = row(&mut account, &phone_id);
    let before = deletes();
    let (proof, epoch) = owner.proof(account.revoke_action(&swapped));
    assert!(account.revoke(&swapped, proof, &epoch).is_err());
    assert_eq!(deletes(), before, "nothing was sent");
    connect.swap_key(&phone_id, &phone_key);
    // This Mac's own row with the phone's key.
    connect.swap_key(&own_id, &phone_key);
    let swapped = row(&mut account, &own_id);
    let (proof, epoch) = owner.proof(account.revoke_action(&swapped));
    assert!(account.revoke(&swapped, proof, &epoch).is_err());
    assert_eq!(deletes(), before, "nothing was sent");
    connect.swap_key(&own_id, &own_key);

    // The phone's row with the tablet's key: the owner check names the tablet, by the
    // name that its `add` signed and by its fingerprint.
    connect.swap_key(&phone_id, &tablet_key);
    let swapped = row(&mut account, &phone_id);
    let action = format!("{:?}", account.revoke_action(&swapped));
    assert!(
        action.contains(&key_fingerprint(&tablet_key)),
        "the fingerprint of the key that goes: {action}"
    );
    assert!(action.contains("Synthetic iPad"), "{action}");
    assert!(!action.contains("Synthetic iPhone"), "{action}");
}

/// An account file of an earlier version (no signed device list): creating, joining, and
/// recovering say that this device must join its account again, and the owner forgets the
/// file here with an owner check; then a creation works.
#[test]
fn an_account_file_of_an_earlier_version_is_forgotten_with_an_owner_check() {
    let connect = FakeConnect::start();
    let owner = owner();
    let a = device();
    let (account, _) = create(&connect, &a);
    drop(account);
    let mut value: Value = serde_json::from_slice(&std::fs::read(&a.path).unwrap()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.insert("v".to_owned(), json!(2));
    for field in ["list_version", "list_head", "left"] {
        object.remove(field);
    }
    std::fs::write(&a.path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(apassy::connect::is_old_account_file(&a.path));
    let refused =
        ConnectAccount::create(client(&connect), &a.store, &a.path, "Rafal", "MacBook Pro")
            .map(|_| ())
            .unwrap_err();
    assert_eq!(refused, ConnectError::OldAccountFile);
    // Another owner action does not forget it.
    let (wrong, epoch) = owner.proof(OwnerAction::DeleteConnectAccount {
        account_id: "acc_k7m2q4x3ca".to_owned(),
    });
    assert!(apassy::connect::forget_old_account_file(&a.store, &a.path, wrong, &epoch).is_err());
    assert!(a.path.exists());
    let (proof, epoch) = owner.proof(OwnerAction::ForgetOldConnectAccount);
    apassy::connect::forget_old_account_file(&a.store, &a.path, proof, &epoch).expect("forget");
    assert!(!a.path.exists());
    assert!(!a.store.has_key());
    ConnectAccount::create(client(&connect), &a.store, &a.path, "Rafal", "MacBook Pro")
        .expect("a new account works");
}

/// The list hash of the last entry of `list` of `account`, computed as a device does.
fn head_of(connect: &FakeConnect, account: &str, list: &[Value]) -> String {
    let mut previous = "-".to_owned();
    for entry in list {
        previous = list_hash(&list_message(
            &connect.url,
            account,
            entry["version"].as_u64().unwrap(),
            &previous,
            entry["op"].as_str().unwrap(),
            entry["key"].as_str().unwrap(),
            entry["link_hash"].as_str().unwrap_or("-"),
            entry["name"].as_str().unwrap_or("-"),
            entry["by"].as_str().unwrap(),
        ));
    }
    previous
}

/// A device that a later-removed device confirmed stays a device: a new device of the
/// account verifies it, because its `add` precedes the `remove` in the signed list.
#[test]
fn a_device_confirmed_before_its_confirmer_left_verifies_on_a_later_device() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b, c, d) = (device(), device(), device(), device());
    let (mut account, _) = create(&connect, &a);
    let mut phone = join(&connect, &mut account, &b, &owner);
    // The phone confirms the tablet.
    let tablet = join(&connect, &mut phone, &c, &owner);
    // The Mac removes the phone.
    let phone_view = account
        .view()
        .unwrap()
        .devices
        .into_iter()
        .find(|device| device.device_id == phone.state().device_id)
        .unwrap();
    let (proof, epoch) = owner.proof(account.revoke_action(&phone_view));
    account.revoke(&phone_view, proof, &epoch).expect("revoke");
    // A device that joins later verifies the tablet, and not the phone.
    let mut late = join(&connect, &mut account, &d, &owner);
    assert_eq!(verified(&mut late, &tablet.state().device_id), Some(true));
    assert_eq!(verified(&mut late, &phone.state().device_id), None);
    assert!(
        late.state().known.contains(&tablet.state().public_key),
        "the tablet is a device of the list"
    );
}

/// No account sign-in adds a device: a key that is not a device of the account gets
/// `401` at the challenge, also with the account id; the account keeps its devices, and
/// the `401` is no removal.
#[test]
fn an_account_sign_in_never_adds_a_device() {
    let connect = FakeConnect::start();
    let a = device();
    let (account, _) = create(&connect, &a);
    let state = account.state().clone();
    // A stranger writes an account file with its own key and the real account id.
    let stranger = device();
    let key = AccountSigner::open_or_create(&stranger.store).unwrap();
    let forged = AccountState {
        device_id: state.device_id.clone(),
        public_key: key.public_key_b64u(),
        known: vec![key.public_key_b64u()],
        ..state.clone()
    };
    std::fs::create_dir_all(stranger.path.parent().unwrap()).unwrap();
    std::fs::write(&stranger.path, serde_json::to_vec(&forged).unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&stranger.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut intruder = ConnectAccount::open(&stranger.store, &stranger.path)
        .unwrap()
        .expect("account");
    assert_eq!(
        intruder.sign_in().unwrap_err(),
        ConnectError::Unauthenticated
    );
    assert_eq!(intruder.view().unwrap_err(), ConnectError::Unauthenticated);
    assert!(!intruder.is_removed());
    assert_eq!(connect.live_devices(&state.account_id), [state.device_id]);
    assert_eq!(connect.count("POST /v1/account/token"), 0);
}

/// A refused join ends on the new device, and a cancelled join ends too.
#[test]
fn a_refused_or_cancelled_join_ends_on_the_new_device() {
    let connect = FakeConnect::start();
    let (a, b, c) = (device(), device(), device());
    let (mut account, _) = create(&connect, &a);
    let link = account.start_link().unwrap();
    let mut request =
        JoinRequest::start(client(&connect), &b.store, &b.path, link.code(), "iPhone").unwrap();
    let pending = account.pending_joins(&link).unwrap();
    account.refuse_join(pending[0].join_id).unwrap();
    assert!(matches!(request.poll().unwrap(), JoinPoll::Refused));
    assert!(!b.path.exists());

    let link = account.start_link().unwrap();
    let request =
        JoinRequest::start(client(&connect), &c.store, &c.path, link.code(), "Mac mini").unwrap();
    let join_id = request.join_id();
    request.cancel().unwrap();
    assert!(account.pending_joins(&link).unwrap().is_empty());
    assert!(
        account
            .pending_joins(&link)
            .unwrap()
            .iter()
            .all(|join| join.join_id != join_id)
    );
    // The cancel carried the signature of the joining key.
    let cancel: Value = connect
        .bodies()
        .iter()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .rfind(|body| {
            body.as_object()
                .is_some_and(|map| map.len() == 4 && map.contains_key("link_hash"))
        })
        .expect("the cancel body");
    assert!(cancel["signature"].is_string());
    assert_eq!(connect.live_devices(&account.state().account_id).len(), 1);
}

/// `403 device_removed` is a removal only as the answer of the token call: the same code
/// from another route is a refusal, the device is not marked removed, and nothing offers
/// to forget it.
#[test]
fn device_removed_from_another_route_is_no_removal() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    account.view().expect("signed in");
    connect.answer_route_error("GET /v1/account/vaults", 403, "device_removed");
    let error = account.vault_stores().unwrap_err();
    assert_ne!(error, ConnectError::Revoked);
    assert!(!account.is_removed());
    assert!(account.signer().is_ok());
    account.view().expect("still a device");
}

/// Only `403 device_removed` is a removal. The removed device keeps its key and its
/// account file, and every later call is `Revoked` without asking Connect; the vault rows
/// of the account key go only after the owner forgets the account on that device.
#[test]
fn a_removed_device_keeps_its_key_until_the_owner_forgets_the_account() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b) = (device(), device());
    let (mut account, _) = create(&connect, &a);
    let mut phone = join(&connect, &mut account, &b, &owner);
    phone.view().expect("signed in");
    let phone_key = phone.signer().unwrap().public_key().to_vec();
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&connect.url, "t_aaaaaaaaaa", 2, &phone_key)
            .unwrap();
    });

    let view = account.view().unwrap();
    let target = view
        .devices
        .iter()
        .find(|device| device.device_id == phone.state().device_id)
        .unwrap()
        .clone();
    // The revoke needs its own proof.
    let (wrong, epoch) = owner.proof(account.delete_action());
    assert!(matches!(
        account.revoke(&target, wrong, &epoch),
        Err(ConnectError::OwnerCheck(ProofRefusal::WrongAction))
    ));
    let (proof, epoch) = owner.proof(account.revoke_action(&target));
    let outcome = account.revoke(&target, proof, &epoch).expect("revoke");
    assert!(!outcome.this_device);
    assert!(account.state().left.contains(&target.public_key));
    assert!(!account.state().known.contains(&target.public_key));
    // The removal is an entry of the list that this Mac signed.
    let list = connect.device_list(&account.state().account_id);
    let last = list.last().unwrap();
    assert_eq!(
        (last["op"].as_str(), last["key"].as_str()),
        (Some("remove"), Some(target.public_key.as_str()))
    );
    assert_eq!(account.state().list_version, list.len() as u64);

    // The removed device: Connect says so after its valid signature.
    assert_eq!(phone.view().unwrap_err(), ConnectError::Revoked);
    assert!(phone.is_removed());
    assert!(!phone.is_signed_in());
    let tokens = connect.count("POST /v1/account/token");
    assert_eq!(phone.view().unwrap_err(), ConnectError::Revoked);
    assert_eq!(connect.count("POST /v1/account/token"), tokens);
    // Nothing was deleted on the device.
    assert!(b.store.has_key());
    assert!(b.path.exists());
    assert!(owner.with_vault(|vault| vault.relay_device().unwrap().is_some()));
    // Opened again (a restart), it is removed again, and still nothing is deleted.
    let mut again = ConnectAccount::open(&b.store, &b.path).unwrap().unwrap();
    assert_eq!(again.view().unwrap_err(), ConnectError::Revoked);
    assert!(b.store.has_key() && b.path.exists());
    // The owner forgets the account on the device: then the key, the file, and the
    // rows go.
    let forgotten = forget_this_device(&b.store, &b.path).unwrap();
    assert!(!b.store.has_key());
    assert!(!b.path.exists());
    let removed = owner.with_vault(|vault| drop_account_rows(vault, &forgotten).unwrap());
    assert_eq!(removed, 1);
    assert!(owner.with_vault(|vault| vault.relay_device().unwrap().is_none()));
    assert_eq!(connect.live_devices(&account.state().account_id).len(), 1);
}

/// A row of another account key goes; a row of this Mac's key stays.
#[test]
fn only_rows_of_another_key_are_stale() {
    let connect = FakeConnect::start();
    let owner = owner();
    let a = device();
    let (account, _) = create(&connect, &a);
    let key = account.signer().unwrap().public_key().to_vec();
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&connect.url, "t_aaaaaaaaaa", 1, &key)
            .unwrap();
    });
    let state = account.state().clone();
    assert_eq!(
        owner.with_vault(|vault| drop_stale_account_rows(vault, &state).unwrap()),
        0
    );
    let other = DeviceKey::generate().unwrap();
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&connect.url, "t_bbbbbbbbbb", 1, other.public_key())
            .unwrap();
    });
    assert_eq!(
        owner.with_vault(|vault| drop_stale_account_rows(vault, &state).unwrap()),
        1
    );
}

// ---- Recovery and deletion (sections 9 and 6). ----

/// Recovery works only when the account has no live device, with the right code, and a
/// new code replaces the old one. The code never leaves the Mac: its key signs.
#[test]
fn recovery_replaces_the_code_and_works_only_without_a_live_device() {
    let connect = FakeConnect::start();
    let a = device();
    let (account, recovery) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    let device_id = account.state().device_id.clone();
    let b = device();
    // A live device: refused.
    assert_eq!(
        ConnectAccount::recover(
            client(&connect),
            &b.store,
            &b.path,
            &account_id,
            &recovery.words(),
            "MacBook Air",
        )
        .unwrap_err(),
        ConnectError::Forbidden
    );
    connect.revoke(&device_id);
    // A wrong code: refused, with the same answer.
    let wrong = RecoveryCode::generate().unwrap();
    assert_eq!(
        ConnectAccount::recover(
            client(&connect),
            &b.store,
            &b.path,
            &account_id,
            &wrong.words(),
            "MacBook Air",
        )
        .unwrap_err(),
        ConnectError::Forbidden
    );
    let (mut recovered, new_code, _) = ConnectAccount::recover(
        client(&connect),
        &b.store,
        &b.path,
        &account_id,
        &recovery.words().to_uppercase(),
        "MacBook Air",
    )
    .expect("recover");
    assert_ne!(
        new_code.key().unwrap().public_key_b64u(),
        recovery.key().unwrap().public_key_b64u()
    );
    // The recovered Mac is the new root.
    assert_eq!(recovered.state().root, recovered.state().public_key);
    let view = recovered.view().unwrap();
    assert_eq!(view.devices.len(), 1);
    assert!(view.devices[0].verified);
    assert_eq!(connect.live_devices(&account_id).len(), 1);
    // No code, in no form, was ever sent.
    for code in [&recovery, &wrong, &new_code] {
        for body in connect.bodies() {
            assert!(!body.contains(code.text().as_str()));
            assert!(!body.contains(code.words().as_str()));
        }
    }
    // The old code is spent; the new one works after the device is gone.
    connect.revoke(&recovered.state().device_id);
    let c = device();
    assert_eq!(
        ConnectAccount::recover(
            client(&connect),
            &c.store,
            &c.path,
            &account_id,
            &recovery.text(),
            "Mac mini",
        )
        .unwrap_err(),
        ConnectError::Forbidden
    );
    ConnectAccount::recover(
        client(&connect),
        &c.store,
        &c.path,
        &account_id,
        &new_code.text(),
        "Mac mini",
    )
    .expect("the new code works");
}

/// A recovery whose answer is lost is sent again with the same body, and Connect answers
/// the same device: one device, and the new code works.
#[test]
fn a_lost_recovery_answer_is_retried_with_the_same_body() {
    let connect = FakeConnect::start();
    let a = device();
    let (account, recovery) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    connect.revoke(&account.state().device_id);
    connect.lose_next_answers("POST /v1/account/recover", 1);
    let b = device();
    let (mut recovered, _, _) = ConnectAccount::recover(
        client(&connect),
        &b.store,
        &b.path,
        &account_id,
        &recovery.words(),
        "MacBook Air",
    )
    .expect("recover");
    assert_eq!(connect.count("POST /v1/account/recover"), 2);
    assert_eq!(
        connect.live_devices(&account_id),
        [recovered.state().device_id.clone()]
    );
    let bodies: Vec<String> = connect
        .bodies()
        .into_iter()
        .filter(|body| body.contains("recovery_signature"))
        .collect();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
    recovered.view().expect("signed in");
}

/// The deletion needs a fresh owner check for it, then forgets the account on this Mac.
#[test]
fn deleting_the_account_needs_the_owner_check() {
    let connect = FakeConnect::start();
    let owner = owner();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    // A proof for another account deletes nothing.
    let (wrong, epoch) = owner.proof(OwnerAction::DeleteConnectAccount {
        account_id: "acc_aaaaaaaaaa".to_owned(),
    });
    let reopened = ConnectAccount::open(&a.store, &a.path).unwrap().unwrap();
    assert_eq!(
        reopened.delete(&a.store, wrong, &epoch).unwrap_err(),
        ConnectError::OwnerCheck(ProofRefusal::WrongAction)
    );
    assert!(a.path.exists());
    assert_eq!(connect.accounts(), std::slice::from_ref(&account_id));
    account.view().unwrap();
    let (proof, epoch) = owner.proof(account.delete_action());
    let (deleted, _forgotten) = account.delete(&a.store, proof, &epoch).expect("delete");
    assert_eq!(deleted.account_id, account_id);
    assert!(connect.accounts().is_empty());
    assert!(!a.path.exists());
    assert!(!a.store.has_key());
}

// ---- The entitlement token (section 10). ----

/// Without a plan there is no token; with one, the token verifies with the published key
/// and stays in memory.
#[test]
fn the_entitlement_token_is_checked_and_kept_in_memory() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    assert!(account.entitlement().unwrap().is_none());
    connect.entitle(&account.state().account_id);
    let account_id = account.state().account_id.clone();
    {
        let token = account.entitlement().unwrap().expect("entitled");
        assert_eq!(token.claims().acc, account_id);
        assert!(
            token.has(Feature::Brain) && token.has(Feature::Sync) && token.has(Feature::Tunnel)
        );
        assert!(!format!("{token:?}").contains(token.token()));
    }
    account.entitlement().unwrap().expect("cached");
    assert_eq!(connect.count("GET /v1/account/entitlement"), 2);
    let file = std::fs::read_to_string(&a.path).unwrap();
    assert!(!file.contains("entitlement"));
}

// ---- Vault stores and relay sync (section 8). ----

/// A vault store needs a plan; a vault row of key source `account` signs relay-sync-v1
/// sign-ins and heads with the account key, and the fake relay verifies the head.
#[test]
fn account_rows_sign_relay_heads_that_the_fake_relay_verifies() {
    let connect = FakeConnect::start();
    let owner = owner();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    assert_eq!(
        account
            .create_vault_store(VAULT_ID, "Personal")
            .unwrap_err(),
        ConnectError::PlanRequired
    );
    connect.entitle(&account.state().account_id);
    let store = account
        .create_vault_store(VAULT_ID, "Personal")
        .expect("store");
    assert_eq!(store.devices[0].store_device_id, 1);
    assert_eq!(account.vault_stores().unwrap().len(), 1);

    // The fake relay stands in for the relay-sync-v1 endpoints of the store: a team
    // whose device key is the account key.
    let relay = FakeRelay::start();
    let signer = account.signer().unwrap();
    let created = http(
        &relay.url,
        "POST",
        "/v1/teams",
        &[],
        json!({"code": relay.team_code(), "team": "Personal", "device_name": "MacBook Pro",
               "public_key": signer.public_key_b64u()})
        .to_string()
        .as_bytes(),
    );
    let team_id = created["team_id"].as_str().unwrap().to_owned();
    let device_id = created["device_id"].as_u64().unwrap();
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&relay.url, &team_id, device_id, signer.public_key())
            .unwrap();
    });
    let row = owner.with_vault(|vault| vault.relay_device().unwrap().unwrap());
    assert!(row.uses_account_key());
    assert!(row.key_pkcs8.is_empty());
    assert_eq!(row.public_key, signer.public_key());

    // Team sign-in with the account key.
    let challenge = http(
        &relay.url,
        "POST",
        "/v1/auth/challenge",
        &[],
        json!({"team_id": team_id, "public_key": signer.public_key_b64u()})
            .to_string()
            .as_bytes(),
    );
    let nonce = challenge["nonce"].as_str().unwrap();
    let signature = signer
        .sign_relay_sign_in(&relay.url, &team_id, nonce)
        .unwrap();
    let token = http(
        &relay.url,
        "POST",
        "/v1/auth/token",
        &[],
        json!({"team_id": team_id, "public_key": signer.public_key_b64u(), "nonce": nonce,
               "signature": encode_b64u(&signature)})
        .to_string()
        .as_bytes(),
    );
    let bearer = format!("Bearer {}", token["token"].as_str().unwrap());

    // A head of version 1 signed with the account key: the fake relay checks it.
    let snapshot = b"synthetic ciphertext of the vault store".to_vec();
    let head = signer
        .sign_head(HeadFields {
            vault_id: VAULT_ID.to_owned(),
            version: 1,
            snapshot_sha256: sha256_hex(&snapshot),
            size: snapshot.len() as u64,
            previous: NO_PREVIOUS.to_owned(),
            team_id: team_id.clone(),
            device_id,
            time: 1_790_000_000,
        })
        .unwrap();
    let pushed = http(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        &[
            ("Authorization", bearer.as_str()),
            ("If-Match", "\"0\""),
            ("X-Apassy-Sync-Head", &head.head_b64u()),
            ("X-Apassy-Sync-Signature", &head.signature_b64u()),
        ],
        &snapshot,
    );
    assert_eq!(pushed["version"], 1, "{pushed}");
    assert_eq!(relay.version(), 1);
}

/// B-M1: adding a device to a vault store and deleting a vault store each need a fresh
/// owner check for exactly that store and device; a proof for another action, store, or
/// device changes nothing at Connect.
#[test]
fn vault_store_devices_and_deletion_need_the_owner_check() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b) = (device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    connect.entitle(&account_id);
    let store = account
        .create_vault_store(VAULT_ID, "Personal")
        .expect("store");
    let team = store.team_id.clone();
    let phone = join(&connect, &mut account, &b, &owner);
    let phone_id = phone.state().device_id.clone();
    let devices = |account: &mut ConnectAccount| account.vault_stores().unwrap()[0].devices.len();

    let other_device = "dev_aaaaaaaaaa".to_owned();
    for wrong in [
        account.delete_action(),
        ConnectAccount::delete_vault_store_action(&team),
        ConnectAccount::add_store_device_action(&team, &other_device, &account_id),
        ConnectAccount::add_store_device_action(&team, &phone_id, "acc_aaaaaaaaaa"),
    ] {
        let (proof, epoch) = owner.proof(wrong);
        assert_eq!(
            account
                .add_store_device(&team, &phone_id, &account_id, proof, &epoch)
                .unwrap_err(),
            ConnectError::OwnerCheck(ProofRefusal::WrongAction)
        );
    }
    assert_eq!(devices(&mut account), 1);
    let (proof, epoch) = owner.proof(ConnectAccount::add_store_device_action(
        &team,
        &phone_id,
        &account_id,
    ));
    let added = account
        .add_store_device(&team, &phone_id, &account_id, proof, &epoch)
        .expect("add to the store");
    assert_eq!(
        (added.device_id.as_str(), added.store_device_id),
        (phone_id.as_str(), 2)
    );
    assert_eq!(devices(&mut account), 2);
    // A device of another account is not a verified device of this one.
    let (proof, epoch) = owner.proof(ConnectAccount::add_store_device_action(
        &team,
        &other_device,
        "acc_aaaaaaaaaa",
    ));
    assert_eq!(
        account
            .add_store_device(&team, &other_device, "acc_aaaaaaaaaa", proof, &epoch)
            .unwrap_err(),
        ConnectError::NotVerified
    );

    // Deleting the store: only its own proof.
    for wrong in [
        account.delete_action(),
        ConnectAccount::delete_vault_store_action("t_aaaaaaaaaa"),
        ConnectAccount::add_store_device_action(&team, &phone_id, &account_id),
    ] {
        let (proof, epoch) = owner.proof(wrong);
        assert_eq!(
            account
                .delete_vault_store(&team, proof, &epoch)
                .unwrap_err(),
            ConnectError::OwnerCheck(ProofRefusal::WrongAction)
        );
    }
    assert_eq!(connect.stores(&account_id), std::slice::from_ref(&team));
    let (proof, epoch) = owner.proof(ConnectAccount::delete_vault_store_action(&team));
    account
        .delete_vault_store(&team, proof, &epoch)
        .expect("delete the store");
    assert!(connect.stores(&account_id).is_empty());
}

/// B-L2: the rows of the account key go only after this Mac forgot the account: no
/// answer of Connect, and no missing account file, makes the proof for that.
#[test]
fn account_rows_go_only_after_a_forget() {
    let connect = FakeConnect::start();
    let owner = owner();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    let key = account.signer().unwrap().public_key().to_vec();
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&connect.url, "t_aaaaaaaaaa", 1, &key)
            .unwrap();
    });
    // The account file of this key keeps the row.
    let state = account.state().clone();
    assert_eq!(
        owner.with_vault(|vault| drop_stale_account_rows(vault, &state).unwrap()),
        0
    );
    // Connect says the device was removed: the row stays.
    connect.revoke(&state.device_id);
    assert_eq!(account.view().unwrap_err(), ConnectError::Revoked);
    assert!(owner.with_vault(|vault| vault.relay_device().unwrap().is_some()));
    let forgotten = forget_this_device(&a.store, &a.path).unwrap();
    assert_eq!(
        owner.with_vault(|vault| drop_account_rows(vault, &forgotten).unwrap()),
        1
    );
    assert!(owner.with_vault(|vault| vault.relay_device().unwrap().is_none()));
}

/// B-L5: a sign-out (as at a lock) drops the account key from memory; the account then
/// signs nothing until it reads the same key again from the Keychain.
#[test]
fn a_sign_out_drops_the_account_key_from_memory() {
    let connect = FakeConnect::start();
    let a = device();
    let (mut account, _) = create(&connect, &a);
    account.view().expect("signed in");
    account.sign_out();
    assert_eq!(account.signer().unwrap_err(), ConnectError::SignedOut);
    let tokens = connect.count("POST /v1/account/token");
    assert_eq!(account.view().unwrap_err(), ConnectError::SignedOut);
    assert_eq!(
        connect.count("POST /v1/account/token"),
        tokens,
        "no sign-in"
    );
    // Another Keychain (another key) is not this account's key.
    assert_eq!(
        account.reopen_signer(&MemoryKeyStore::new()).unwrap_err(),
        ConnectError::KeyLost
    );
    account.reopen_signer(&a.store).expect("the same key");
    account.view().expect("signed in again");
}

/// One plain HTTP/1.1 request to a fake on loopback; the `result` of the envelope.
fn http(origin: &str, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Value {
    let address = origin.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let mut length = 0usize;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut answer = vec![0u8; length];
    reader.read_exact(&mut answer).unwrap();
    let envelope: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(envelope["ok"], true, "{method} {path}: {envelope}");
    envelope["result"].clone()
}

/// The key store trait object works for the Keychain-free stores of the tests.
#[test]
fn a_memory_store_is_a_key_store() {
    let store: Box<dyn DeviceKeyStore> = Box::new(MemoryKeyStore::new());
    let signer = AccountSigner::open_or_create(store.as_ref()).unwrap();
    assert_eq!(
        AccountSigner::open(store.as_ref())
            .unwrap()
            .unwrap()
            .public_key(),
        signer.public_key()
    );
}
