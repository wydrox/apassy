#![cfg(feature = "vault")]

//! The Apassy Connect account on the Mac (plan s7 unit M1, contract connect-account-v1)
//! against the in-process fake Connect (`common/fake_connect.rs`) and the fake relay.
//! Synthetic values only; no real Connect, Stripe, or Keychain.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof, ProofRefusal};
use apassy::connect::account::Clock;
use apassy::connect::device_key::{
    account_message, brain_sign_in_message, join_message, recover_message, sign_in_message,
};
use apassy::connect::entitlement::{self, EntitlementError, EntitlementKey, Feature};
use apassy::connect::{
    AccountSigner, AccountState, ConnectAccount, ConnectClient, ConnectError, DeviceKeyStore,
    JoinPoll, JoinRequest, LinkCode, MemoryKeyStore, RecoveryCode, account_file,
    drop_stale_account_rows, forget_this_device, link_hash, safety_words, same_safety_words,
};
use apassy::sync::{DeviceKey, HeadFields, NO_PREVIOUS, decode_b64u, sha256_hex, verify_signature};
use apassy::vault::Vault;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::common::fake_connect::{FakeConnect, KID};
use crate::common::fake_relay::FakeRelay;

const PASS: &str = "synthetic-connect-pass";
const VECTORS: &str = include_str!("fixtures/connect-account-v1/vectors.json");

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

/// A new account on device `a`.
fn create(connect: &FakeConnect, a: &Device) -> (ConnectAccount, RecoveryCode) {
    ConnectAccount::create(client(connect), &a.store, &a.path, "Rafal", "MacBook Pro")
        .expect("create")
}

/// Device `b` joins the account of `account` on `a`, confirmed with a fresh owner check.
fn join(
    connect: &FakeConnect,
    account: &mut ConnectAccount,
    b: &Device,
    owner: &Owner,
) -> ConnectAccount {
    let link = account.start_link().expect("link");
    let mut request = JoinRequest::start(client(connect), &b.store, &b.path, link.code(), "iPhone")
        .expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = account.pending_joins(&link).expect("pending");
    assert_eq!(pending.len(), 1);
    let (proof, epoch) = owner.proof(pending[0].owner_action(&account.state().account_id));
    account
        .confirm_join(&link, &pending[0], &proof, &epoch)
        .expect("confirm");
    match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => *joined,
        other => panic!("not confirmed: {other:?}"),
    }
}

// ---- The vectors of section 15. ----

/// The link hash, the six safety words, the recovery words and hash, and every message
/// of the device key are those of the fixture; the fixture signatures verify over the
/// messages that this build makes, and a signature of this build verifies too.
#[test]
fn the_vectors_reproduce_the_words_hashes_and_messages() {
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

    let words = safety_words(account, code.expose(), &a_public, &b_public);
    assert_eq!(words, v["safety"]["words"].as_str().unwrap());
    assert_eq!(words, "blaze cable flute board seal tiger");
    assert!(same_safety_words(
        &words,
        " BLAZE cable flute board seal tiger "
    ));
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
        recovery.wire().as_str(),
        v["recovery"]["code"].as_str().unwrap()
    );
    assert_eq!(
        recovery.hash(),
        v["recovery"]["recovery_hash"].as_str().unwrap()
    );
    assert_eq!(
        RecoveryCode::parse(v["recovery"]["words"].as_str().unwrap())
            .unwrap()
            .hash(),
        recovery.hash()
    );

    let signer_a = AccountSigner::with_key(
        DeviceKey::from_raw(
            &hex(v["device_a"]["private_hex"].as_str().unwrap()),
            &a_public,
        )
        .unwrap(),
    );
    assert_eq!(signer_a.public_key_b64u(), a64);
    assert_eq!(
        signer_a.public_key_sha256(),
        v["device_a"]["public_key_sha256"].as_str().unwrap()
    );
    let hash = code.link_hash();
    for message in v["messages"].as_array().unwrap() {
        let name = message["name"].as_str().unwrap();
        let (bytes, signer_public) = match name {
            "account" => (account_message(origin, a64), &a_public),
            "sign_in" => (sign_in_message(origin, account, a64, nonce), &a_public),
            "join" => (join_message(origin, account, &hash, b64), &b_public),
            "recover" => (recover_message(origin, account, b64), &b_public),
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
    // The signer of this build makes signatures that verify over the same messages.
    for (bytes, signature) in [
        (
            account_message(origin, a64),
            signer_a.sign_account(origin).unwrap(),
        ),
        (
            sign_in_message(origin, account, a64, nonce),
            signer_a.sign_sign_in(origin, account, nonce).unwrap(),
        ),
        (
            brain_sign_in_message(brain, account, a64, nonce),
            signer_a.sign_brain_sign_in(brain, account, nonce).unwrap(),
        ),
    ] {
        assert!(verify_signature(&a_public, &bytes, &signature));
    }
}

/// The account key signs the seven tags of section 5 and nothing else.
#[test]
fn the_account_key_refuses_every_other_tag() {
    let store = MemoryKeyStore::new();
    let signer = AccountSigner::open_or_create(&store).unwrap();
    let refused: [&[u8]; 7] = [
        &b"apassy-relay connect v1\0https://connect.example.test\0key"[..],
        b"apassy-connect entitlement v1\0payload",
        b"apassy-connect safety v1\0acc",
        b"apassy-connect recovery v1\0bytes",
        b"apassy-relay sign-in v2\0origin",
        b"apassy-connect sign-in v1",
        b"",
    ];
    for refused in refused {
        assert_eq!(signer.sign(refused).unwrap_err(), ConnectError::TagRefused);
        assert_eq!(
            apassy::connect::sign(&signer, refused).unwrap_err(),
            ConnectError::TagRefused
        );
    }
    assert_eq!(apassy::connect::SIGNING_TAGS.len(), 7);
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
        let forged = format!(
            "{}.{signature}",
            apassy::sync::encode_b64u(claims_text.as_bytes())
        );
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
/// key; the account file holds no key, token, email, or code, with mode 0600.
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
        [account.signer().public_key().to_vec()]
    );
    // The recovery code is never sent; only its hash.
    let words = recovery.words();
    for body in connect.bodies() {
        assert!(!body.contains(recovery.wire().as_str()));
        assert!(!body.contains(words.as_str()));
    }
    assert!(
        connect
            .bodies()
            .iter()
            .any(|body| body.contains(&recovery.hash()))
    );
    // A view signs in once, and the token stays in memory.
    let view = account.view().expect("view");
    assert_eq!(view.name, "Rafal");
    assert_eq!(view.devices.len(), 1);
    assert!(account.is_signed_in());
    account.view().expect("view again");
    assert_eq!(connect.count("POST /v1/account/token"), 1);
    // The account file: ids, names, the origin, the public key. No secret.
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
    assert!(!file.contains(recovery.wire().as_str()));
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
    assert_eq!(opened.signer().public_key(), account.signer().public_key());
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

// ---- Devices (section 7). ----

/// A device joins only by a confirmation on the live device: both show the same six
/// words, the confirmation needs a fresh owner check for exactly that join, and a proof
/// for another action changes nothing.
#[test]
fn adding_a_device_needs_the_owner_check_and_both_sides_show_the_same_words() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b) = (device(), device());
    let (mut account, _) = create(&connect, &a);
    let account_id = account.state().account_id.clone();
    let link = account.start_link().expect("link");
    assert!(!format!("{link:?}").contains(link.code()));
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
            .confirm_join(&link, join, &wrong, &epoch)
            .unwrap_err(),
        ConnectError::OwnerCheck(ProofRefusal::WrongAction)
    );
    let mut changed = join.clone();
    changed.words = "blaze cable flute board seal tiger".to_owned();
    let (proof, epoch) = owner.proof(changed.owner_action(&account_id));
    if changed.words != join.words {
        assert_eq!(
            account
                .confirm_join(&link, &changed, &proof, &epoch)
                .unwrap_err(),
            ConnectError::WordsMismatch
        );
    }
    assert_eq!(connect.live_devices(&account_id).len(), 1);
    assert_eq!(connect.count("POST /v1/account/devices/pending/"), 0);

    // The right proof adds exactly the key of the words.
    let (proof, epoch) = owner.proof(join.owner_action(&account_id));
    let added = account
        .confirm_join(&link, join, &proof, &epoch)
        .expect("confirm");
    assert_eq!(added.name, "iPhone");
    let joined = match request.poll().unwrap() {
        JoinPoll::Confirmed(joined) => joined,
        other => panic!("not confirmed: {other:?}"),
    };
    assert_eq!(joined.state().account_id, account_id);
    assert_eq!(joined.state().device_id, added.device_id);
    assert_eq!(joined.state().name.as_deref(), Some("Rafal"));
    assert_eq!(connect.live_devices(&account_id).len(), 2);
    assert!(b.path.exists());
    // The link worked once.
    let c = device();
    assert_eq!(
        JoinRequest::start(client(&connect), &c.store, &c.path, link.code(), "Mac mini")
            .unwrap_err(),
        ConnectError::Forbidden
    );
}

/// No account sign-in adds a device: a key that is not a live device gets `401` at the
/// challenge, also with the account id, and the account keeps its devices.
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
        ..state.clone()
    };
    std::fs::create_dir_all(stranger.path.parent().unwrap()).unwrap();
    std::fs::write(&stranger.path, serde_json::to_vec(&forged).unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&stranger.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut intruder = ConnectAccount::open(&stranger.store, &stranger.path)
        .unwrap()
        .expect("account");
    assert_eq!(intruder.sign_in().unwrap_err(), ConnectError::Revoked);
    assert_eq!(intruder.view().unwrap_err(), ConnectError::Revoked);
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
    assert_eq!(connect.live_devices(&account.state().account_id).len(), 1);
}

/// A revoked device drops its token at its next call, forgets the account, and its vault
/// rows that signed with the account key go; the vault rows with their own keys stay.
#[test]
fn a_revoked_device_drops_its_token_and_its_rows() {
    let connect = FakeConnect::start();
    let owner = owner();
    let (a, b) = (device(), device());
    let (mut account, _) = create(&connect, &a);
    let mut phone = join(&connect, &mut account, &b, &owner);
    phone.view().expect("signed in");
    let phone_key = phone.signer().public_key().to_vec();
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
        account.revoke(&target, &wrong, &epoch),
        Err(ConnectError::OwnerCheck(ProofRefusal::WrongAction))
    ));
    let (proof, epoch) = owner.proof(account.revoke_action(&target));
    let outcome = account.revoke(&target, &proof, &epoch).expect("revoke");
    assert!(!outcome.this_device);

    // The revoked device: its token is dropped at the next call.
    assert_eq!(phone.view().unwrap_err(), ConnectError::Revoked);
    assert!(!phone.is_signed_in());
    forget_this_device(&b.store, &b.path).unwrap();
    assert!(!b.store.has_key());
    assert!(!b.path.exists());
    let removed = owner.with_vault(|vault| drop_stale_account_rows(vault, None).unwrap());
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
    let key = account.signer().public_key().to_vec();
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&connect.url, "t_aaaaaaaaaa", 1, &key)
            .unwrap();
    });
    let state = account.state().clone();
    assert_eq!(
        owner.with_vault(|vault| drop_stale_account_rows(vault, Some(&state)).unwrap()),
        0
    );
    let mut point = vec![4];
    point.extend_from_slice(&[9; 64]);
    owner.with_vault(|vault| {
        vault
            .set_account_relay_device(&connect.url, "t_bbbbbbbbbb", 1, &point)
            .unwrap();
    });
    assert_eq!(
        owner.with_vault(|vault| drop_stale_account_rows(vault, Some(&state)).unwrap()),
        1
    );
}

// ---- Recovery and deletion (sections 9 and 6). ----

/// Recovery works only when the account has no live device, with the right code, and a
/// new code replaces the old one.
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
    assert_ne!(new_code.hash(), recovery.hash());
    assert_eq!(recovered.view().unwrap().devices.len(), 1);
    assert_eq!(connect.live_devices(&account_id).len(), 1);
    // The old code is spent; the new one works after the device is gone.
    connect.revoke(&recovered.state().device_id);
    let c = device();
    assert_eq!(
        ConnectAccount::recover(
            client(&connect),
            &c.store,
            &c.path,
            &account_id,
            &recovery.wire(),
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
        &new_code.wire(),
        "Mac mini",
    )
    .expect("the new code works");
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
        reopened.delete(&a.store, &wrong, &epoch).unwrap_err(),
        ConnectError::OwnerCheck(ProofRefusal::WrongAction)
    );
    assert!(a.path.exists());
    assert_eq!(connect.accounts(), std::slice::from_ref(&account_id));
    account.view().unwrap();
    let (proof, epoch) = owner.proof(account.delete_action());
    let deleted = account.delete(&a.store, &proof, &epoch).expect("delete");
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
    let vault_id = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
    assert_eq!(
        account
            .create_vault_store(vault_id, "Personal")
            .unwrap_err(),
        ConnectError::PlanRequired
    );
    connect.entitle(&account.state().account_id);
    let store = account
        .create_vault_store(vault_id, "Personal")
        .expect("store");
    assert_eq!(store.devices[0].store_device_id, 1);
    assert_eq!(account.vault_stores().unwrap().len(), 1);

    // The fake relay stands in for the relay-sync-v1 endpoints of the store: a team
    // whose device key is the account key.
    let relay = FakeRelay::start();
    let signer = account.signer();
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
               "signature": apassy::sync::encode_b64u(&signature)})
        .to_string()
        .as_bytes(),
    );
    let bearer = format!("Bearer {}", token["token"].as_str().unwrap());

    // A head of version 1 signed with the account key: the fake relay checks it.
    let snapshot = b"synthetic ciphertext of the vault store".to_vec();
    let head = signer
        .sign_head(HeadFields {
            vault_id: vault_id.to_owned(),
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
