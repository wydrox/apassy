#![cfg(feature = "vault")]

//! A vault shared between the accounts of one family (contract connect-account-v1 section
//! 16) on the Mac, against the in-process fake Connect and the fake relay of the stores.
//! The fake checks the shapes and the signatures of the share routes, and plays a lying
//! Connect where it can: it keeps a member's devices in a store that no `share` names,
//! serves another list for an account, inserts entries, names another inviter, and gives
//! an answer of a share code another key. Each test is a property of section 16 that one
//! of those lies must not break. Synthetic values only.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::connect::device_key::share_list_message;
use apassy::connect::{
    AccountSigner, ConnectAccount, ConnectClient, ConnectError, JoinPoll, JoinRequest, LeftStore,
    MemoryKeyStore, ShareNames, account_file, signer_policy,
};
use apassy::contracts::CredentialKind;
use apassy::sync::{RelayConfig, RelaySync, StoreError, encode_b64u};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::common::fake_connect::FakeConnect;
use crate::common::fake_relay::FakeRelay;

const PASS: &str = "synthetic-share-pass";

struct Cloud {
    root: TempDir,
    relay: Arc<FakeRelay>,
    connect: FakeConnect,
}

fn cloud() -> Cloud {
    let relay = Arc::new(FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    Cloud {
        root: TempDir::new().expect("temp dir"),
        relay,
        connect,
    }
}

/// One device: its data folder, its relay sync for the Connect origin, its key store, and
/// its account file.
struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: RelaySync,
    keys: MemoryKeyStore,
    account_path: PathBuf,
}

fn mac(cloud: &Cloud, name: &str) -> Mac {
    let data = cloud.root.path().join(name).join("Apassy");
    fs::create_dir_all(&data).expect("data dir");
    let vault_path = data.join("vault.db");
    Mac {
        sync: RelaySync::new(RelayConfig::in_data_dir(
            &data,
            &vault_path,
            &cloud.connect.url,
            "vault",
        )),
        account_path: account_file(&data),
        keys: MemoryKeyStore::new(),
        data,
        vault_path,
    }
}

fn client(cloud: &Cloud) -> ConnectClient {
    ConnectClient::new(&cloud.connect.url).expect("client")
}

fn new_account(cloud: &Cloud, mac: &Mac, name: &str) -> ConnectAccount {
    new_account_with_code(cloud, mac, name).0
}

fn new_account_with_code(
    cloud: &Cloud,
    mac: &Mac,
    name: &str,
) -> (ConnectAccount, apassy::connect::RecoveryCode) {
    let (account, code) = ConnectAccount::create(
        client(cloud),
        &mac.keys,
        &mac.account_path,
        name,
        "Synthetic MacBook",
    )
    .expect("create account");
    cloud.connect.entitle(&account.state().account_id);
    (account, code)
}

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

fn join_account(
    cloud: &Cloud,
    account: &mut ConnectAccount,
    b: &Mac,
    name: &str,
) -> ConnectAccount {
    let owner = owner();
    let link = account.start_link().expect("link");
    let mut request =
        JoinRequest::start(client(cloud), &b.keys, &b.account_path, link.code(), name)
            .expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = account.pending_joins(&link).expect("pending");
    let (proof, epoch) = owner.proof(pending[0].owner_action(&account.state().account_id));
    account
        .confirm_join(&link, &pending[0], proof, &epoch)
        .expect("confirm");
    match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => *joined,
        other => panic!("not confirmed: {other:?}"),
    }
}

fn item(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(format!("SYNTH-{title}")),
            secret: true,
        }],
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .search("")
        .expect("search")
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    titles
}

fn key_of(account: &ConnectAccount) -> Vec<u8> {
    account.signer().expect("signer").public_key().to_vec()
}

fn hand_over(mac: &Mac, account: &ConnectAccount) {
    mac.sync
        .set_account_signer(Some(account.signer().expect("signer")));
    mac.sync
        .set_account_signers(Some(signer_policy(account.state())));
}

/// Rafal (A) has a family; Ola (X) is a member. A's vault syncs through its store.
struct Family {
    cloud: Cloud,
    a: Mac,
    x: Mac,
    account_a: ConnectAccount,
    account_x: ConnectAccount,
    owner_a: Owner,
    owner_x: Owner,
    vault_a: Vault,
    team: String,
    /// The recovery code of X's account.
    recovery_x: apassy::connect::RecoveryCode,
}

fn family() -> Family {
    let cloud = cloud();
    let (a, x) = (mac(&cloud, "a"), mac(&cloud, "x"));
    let mut account_a = new_account(&cloud, &a, "Rafal");
    let (account_x, recovery_x) = new_account_with_code(&cloud, &x, "Ola");
    let a_id = account_a.state().account_id.clone();
    cloud.connect.make_group(&a_id, "family");
    cloud
        .connect
        .add_member(&a_id, &account_x.state().account_id);
    let mut vault_a = Vault::create(&a.vault_path, PASS).expect("vault");
    vault_a.unlock(PASS).expect("unlock");
    vault_a.add(item("Alpha")).expect("add");
    let team = a
        .sync
        .enable_on_connect(&mut vault_a, &mut account_a, "Family")
        .expect("enable")
        .team_id;
    Family {
        cloud,
        a,
        x,
        account_a,
        account_x,
        owner_a: owner(),
        owner_x: owner(),
        vault_a,
        team,
        recovery_x,
    }
}

impl Family {
    fn a_id(&self) -> String {
        self.account_a.state().account_id.clone()
    }

    fn x_id(&self) -> String {
        self.account_x.state().account_id.clone()
    }

    /// The ceremony on one device of each account, the share, and X's join.
    fn share(&mut self) {
        let x_id = self.x_id();
        let link = self
            .account_a
            .start_share(&x_id, &self.team)
            .expect("share code");
        let answer = self.account_x.accept_code(link.code()).expect("answer");
        let requests = self.account_a.share_requests(&link).expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].words, answer.words);
        let names = ShareNames::default();
        let (proof, epoch) = self.owner_a.proof(
            self.account_a
                .share_action(&link, &requests[0], &names)
                .expect("action"),
        );
        self.account_a
            .confirm_share(&link, &requests[0], &names, proof, &epoch)
            .expect("confirm");
        let (proof, epoch) = self.owner_x.proof(
            self.account_x
                .accept_action(&answer, &names)
                .expect("action"),
        );
        self.account_x
            .accept_share(&answer, &names, proof, &epoch)
            .expect("accept");
        let status = self.account_x.refresh_shares(&[]).expect("refresh");
        assert_eq!(status.offers.len(), 1, "{status:?}");
        let a_id = self.a_id();
        let (proof, epoch) = self
            .owner_x
            .proof(self.account_x.join_action(&self.team, &a_id, &names));
        self.account_x
            .join_shared_store(&self.team, &a_id, &[], &names, proof, &epoch)
            .expect("join");
        self.account_a.refresh_shares(&[]).expect("A refreshes");
    }

    /// X downloads the shared vault and adopts it with the passphrase of the copy.
    fn x_vault(&mut self) -> Vault {
        let store = self
            .account_x
            .vault_stores()
            .expect("stores")
            .into_iter()
            .find(|store| store.team_id == self.team)
            .expect("X is in the store");
        let joined = RelaySync::joined_from_store(&mut self.account_x, &store).expect("joined");
        let download = joined
            .download(&self.x.data.join("sync"))
            .expect("download");
        let (vault, _) = self.x.sync.adopt(&joined, &download, PASS).expect("adopt");
        drop((vault, download, joined));
        hand_over(&self.x, &self.account_x);
        let mut vault = Vault::open(&self.x.vault_path).expect("open");
        vault.unlock(PASS).expect("unlock");
        vault
    }

    /// The entries of A's list, as Connect serves it.
    fn list_of(&self, account: &str) -> Vec<Value> {
        self.cloud.connect.device_list(account)
    }
}

/// A share entry of section 16 signed by `signer`, as the entry of `account` at the next
/// version: what a Connect that inserts entries would serve.
fn forged_entry(
    f: &Family,
    account: &str,
    signer: &AccountSigner,
    op: &str,
    peer: &str,
    team: Option<&str>,
) -> (Value, String) {
    let list = f.list_of(account);
    let version = list.len() as u64 + 1;
    let previous = f.cloud.connect.list_head(account);
    let message = share_list_message(
        &f.cloud.connect.url,
        account,
        version,
        &previous,
        op,
        peer,
        "-",
        team.unwrap_or("-"),
        &signer.public_key_b64u(),
    );
    let signature = signer.sign(&message).expect("sign");
    let hash = apassy::connect::device_key::list_hash(&message);
    (
        json!({"version": version, "op": op, "key": null, "link_hash": null, "name": null,
               "by": signer.public_key_b64u(), "signature": encode_b64u(&signature),
               "account_id": peer, "root": null, "team_id": team}),
        hash,
    )
}

/// The ceremony, the share, the join, the download, and syncs in both directions.
#[test]
fn a_family_shares_a_vault_and_both_accounts_sync_it() {
    let mut f = family();
    f.share();
    let mut vault_x = f.x_vault();
    assert_eq!(titles(&vault_x), vec!["Alpha"]);
    hand_over(&f.a, &f.account_a);
    vault_x.add(item("Beta")).expect("add");
    assert!(f.x.sync.sync(&mut vault_x).expect("X").pushed);
    f.a.sync.sync(&mut f.vault_a).expect("A merges X");
    assert_eq!(titles(&f.vault_a), vec!["Alpha", "Beta"]);
    f.vault_a.add(item("Gamma")).expect("add");
    assert!(f.a.sync.sync(&mut f.vault_a).expect("A").pushed);
    f.x.sync.sync(&mut vault_x).expect("X merges A");
    assert_eq!(titles(&vault_x), vec!["Alpha", "Beta", "Gamma"]);
}

/// P1: a store that Connect marks shared, with a member's device rows in it and an active
/// group, but no `share` entry: the member's heads are refused, and the member's device
/// does not open the store.
#[test]
fn without_a_share_the_member_signs_nothing_and_opens_nothing() {
    let mut f = family();
    let x_device = f.account_x.state().device_id.clone();
    // A lying Connect lists X's device in A's store (the store is "shared" now).
    f.cloud.connect.list_in_store(&f.team, &x_device);
    let store = f
        .account_x
        .vault_stores()
        .expect("stores")
        .into_iter()
        .find(|store| store.team_id == f.team)
        .expect("listed");
    assert!(store.shared);
    let refused = RelaySync::joined_from_store(&mut f.account_x, &store).err();
    assert!(
        matches!(refused, Some(StoreError::OtherAccount)),
        "{refused:?}"
    );
    // A's devices take no head of X's key in that store.
    f.account_a.refresh_shares(&[]).expect("A refreshes");
    let policy = signer_policy(f.account_a.state()).for_team(&f.team);
    assert!(!policy.accepts(&key_of(&f.account_x)));
    assert!(!policy.left_key(&key_of(&f.account_x)));
}

/// P1: with a share, a list of X from another root suspends X, and a list with a key that
/// no device of X signed is not taken.
#[test]
fn a_list_of_another_root_or_with_an_unsigned_key_is_refused() {
    let mut f = family();
    f.share();
    let x_id = f.x_id();
    let x_key = key_of(&f.account_x);
    assert!(
        signer_policy(f.account_a.state())
            .for_team(&f.team)
            .accepts(&x_key)
    );
    // An extra device row and list entry that no device of X signed.
    let stranger = apassy::sync::DeviceKey::generate().expect("key");
    let mut list = f.list_of(&x_id);
    let mut extra = list[0].clone();
    extra["version"] = json!(list.len() + 1);
    extra["op"] = json!("add");
    extra["key"] = json!(encode_b64u(stranger.public_key()));
    extra["link_hash"] = json!(encode_b64u(&[7u8; 32]));
    extra["name"] = json!("Synthetic stranger");
    list.push(extra);
    f.cloud.connect.serve_peer_list(&x_id, Some(list));
    f.account_a.refresh_shares(&[]).expect("A refreshes");
    let policy = signer_policy(f.account_a.state()).for_team(&f.team);
    assert!(!policy.accepts(stranger.public_key()));
    assert!(policy.accepts(&x_key), "the pin keeps what it verified");
    // X's list from another root: X is suspended; its keys sign nothing new.
    let other = TempDir::new().expect("dir");
    let other_keys = MemoryKeyStore::new();
    let (other_account, _) = ConnectAccount::create(
        client(&f.cloud),
        &other_keys,
        &account_file(other.path()),
        "Ola",
        "Synthetic iMac",
    )
    .expect("another account");
    let reset = f.list_of(&other_account.state().account_id);
    f.cloud.connect.serve_peer_list(&x_id, Some(reset));
    let status = f.account_a.refresh_shares(&[]).expect("A refreshes");
    assert_eq!(status.suspended, vec![x_id.clone()]);
    let policy = signer_policy(f.account_a.state()).for_team(&f.team);
    assert!(!policy.accepts(&x_key) && policy.left_key(&x_key));
    assert!(!policy.accepts(&key_of(&other_account)));
}

/// P2: a second device of A and a second device of X read the lists and take the share,
/// with no ceremony.
#[test]
fn second_devices_take_the_share_from_the_lists() {
    let mut f = family();
    let a2 = mac(&f.cloud, "a2");
    let x2 = mac(&f.cloud, "x2");
    let mut account_a2 = join_account(&f.cloud, &mut f.account_a, &a2, "Synthetic Mac mini");
    let mut account_x2 = join_account(&f.cloud, &mut f.account_x, &x2, "Synthetic MacBook Air");
    f.share();
    account_a2.refresh_shares(&[]).expect("A2");
    let policy = signer_policy(account_a2.state()).for_team(&f.team);
    assert!(policy.accepts(&key_of(&f.account_x)));
    assert!(
        policy.accepts(&key_of(&account_x2)),
        "X's second device, from X's list"
    );
    account_x2.refresh_shares(&[]).expect("X2");
    let policy = signer_policy(account_x2.state()).for_team(&f.team);
    assert!(policy.accepts(&key_of(&f.account_a)));
    assert!(policy.accepts(&key_of(&account_a2)));
    assert!(account_x2.shares_store(&f.team));
}

/// P3: after `unshare`, X's head at the anchor stays and a later one is refused on A's
/// devices, also while a lying store keeps X in it; a `remove` in X's list ends that
/// device in the store the same way.
#[test]
fn after_unshare_a_later_head_of_the_member_is_refused() {
    let mut f = family();
    f.share();
    let mut vault_x = f.x_vault();
    hand_over(&f.a, &f.account_a);
    vault_x.add(item("Beta")).expect("add");
    assert!(f.x.sync.sync(&mut vault_x).expect("X").pushed);
    f.a.sync.sync(&mut f.vault_a).expect("A merges X");
    // A stops sharing; the store keeps X's device (the fake does not take it out of the
    // relay team), so X still pushes.
    let (team, x_id) = (f.team.clone(), f.x_id());
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, &names, false));
    f.account_a
        .stop_sharing(&team, &x_id, &names, proof, &epoch)
        .expect("unshare");
    hand_over(&f.a, &f.account_a);
    // A's head at its anchor is X's: it stays merged.
    assert_eq!(titles(&f.vault_a), vec!["Alpha", "Beta"]);
    let policy = signer_policy(f.account_a.state()).for_team(&team);
    assert!(policy.left_key(&key_of(&f.account_x)) && !policy.accepts(&key_of(&f.account_x)));
    let before = f.cloud.relay.version_of(&team);
    vault_x.add(item("Delta")).expect("add");
    assert!(
        f.x.sync
            .sync(&mut vault_x)
            .expect("X, kept in the store")
            .pushed
    );
    assert!(f.cloud.relay.version_of(&team) > before);
    let refused = f.a.sync.sync(&mut f.vault_a);
    assert!(
        refused.is_err(),
        "a later head of X is not merged: {refused:?}"
    );
    assert_eq!(titles(&f.vault_a), vec!["Alpha", "Beta"]);
}

/// P4: a `share` that Connect inserts, signed by a key of its own, by a device of X, or by
/// a device that A removed, counts for nothing: the list does not verify, and the store
/// stays as it was.
#[test]
fn a_share_signed_by_another_than_a_live_device_of_the_owner_counts_for_nothing() {
    let mut f = family();
    let a_id = f.a_id();
    let x_id = f.x_id();
    // A pins X first (a real entry), with nothing shared yet.
    let link = f.account_a.start_share(&x_id, &f.team).expect("code");
    let answer = f.account_x.accept_code(link.code()).expect("answer");
    let requests = f.account_a.share_requests(&link).expect("requests");
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_x
        .proof(f.account_x.accept_action(&answer, &names).expect("action"));
    f.account_x
        .accept_share(&answer, &names, proof, &epoch)
        .expect("X pins A");
    // X's own view of A: no offers.
    assert!(
        f.account_x
            .refresh_shares(&[])
            .expect("X")
            .offers
            .is_empty()
    );
    drop(requests);
    let service = AccountSigner::with_key(apassy::sync::DeviceKey::generate().expect("key"));
    let x_signer = f.account_x.signer().expect("X signer");
    for signer in [&service, x_signer.as_ref()] {
        let (entry, hash) = forged_entry(&f, &a_id, signer, "share", &x_id, Some(&f.team));
        let saved = f.list_of(&a_id);
        f.cloud.connect.push_list_entry(&a_id, entry, hash);
        let status = f.account_x.refresh_shares(&[]).expect("X refreshes");
        assert!(status.offers.is_empty(), "{status:?}");
        assert!(!f.account_x.shares_store(&f.team));
        f.cloud.connect.set_device_list(&a_id, saved);
    }
}

/// P4: an answer of a share code from another key than the answering device's, and an
/// inviter that is not the device of the code: the words differ or the fingerprint fails,
/// and nothing is signed.
#[test]
fn a_substituted_inviter_or_answering_key_is_caught() {
    let mut f = family();
    let x_id = f.x_id();
    let a_id = f.a_id();
    // Another inviter key: the fingerprint of the code fails.
    let link = f.account_a.start_share(&x_id, &f.team).expect("code");
    let stranger = apassy::sync::DeviceKey::generate().expect("key");
    f.cloud.connect.answer_inviter(Some(
        json!({"account_id": a_id, "device_id": "dev_aaaaaaaaaa",
        "name": "Rafal", "public_key": encode_b64u(stranger.public_key())}),
    ));
    let refused = f.account_x.accept_code(link.code()).unwrap_err();
    assert_eq!(refused, ConnectError::ShareMismatch);
    assert_eq!(
        refused.to_string(),
        "The code does not match the account that answered. Nothing was signed. Ask for a new code."
    );
    f.cloud.connect.answer_inviter(None);
    // Another live device of A as the inviter: a device of A's list, but not the device
    // that the code names. Only the fingerprint of the code catches it before the words.
    let a2 = mac(&f.cloud, "a2");
    let account_a2 = join_account(&f.cloud, &mut f.account_a, &a2, "Synthetic Mac mini");
    let link = f.account_a.start_share(&x_id, &f.team).expect("code");
    f.cloud
        .connect
        .answer_inviter(Some(json!({"account_id": a_id,
        "device_id": account_a2.state().device_id, "name": "Rafal",
        "public_key": account_a2.state().public_key})));
    assert_eq!(
        f.account_x.accept_code(link.code()).unwrap_err(),
        ConnectError::ShareMismatch
    );
    f.cloud.connect.answer_inviter(None);
    let head = f.list_of(&a_id).len();
    // Another answering key: the signature over the answer fails, so A sees no request.
    let link = f.account_a.start_share(&x_id, &f.team).expect("code");
    let _answer = f.account_x.accept_code(link.code()).expect("answer");
    f.cloud
        .connect
        .answer_pending_key(Some(stranger.public_key().to_vec()));
    assert!(
        f.account_a
            .share_requests(&link)
            .expect("requests")
            .is_empty()
    );
    // Another live device of X as the answering key: in X's list, but it signed nothing.
    let x2 = mac(&f.cloud, "x2");
    let account_x2 = join_account(&f.cloud, &mut f.account_x, &x2, "Synthetic MacBook Air");
    f.cloud
        .connect
        .answer_pending_key(Some(key_of(&account_x2)));
    assert!(
        f.account_a
            .share_requests(&link)
            .expect("requests")
            .is_empty()
    );
    f.cloud.connect.answer_pending_key(None);
    // Another list for X in the answer (a swapped root): the words that A computes differ
    // from X's.
    let requests = f.account_a.share_requests(&link).expect("requests");
    assert_eq!(requests.len(), 1);
    let other = TempDir::new().expect("dir");
    let other_keys = MemoryKeyStore::new();
    let (other_account, _) = ConnectAccount::create(
        client(&f.cloud),
        &other_keys,
        &account_file(other.path()),
        "Ola",
        "Synthetic iMac",
    )
    .expect("another account");
    let real = f.list_of(&x_id);
    f.cloud
        .connect
        .set_device_list(&x_id, f.list_of(&other_account.state().account_id));
    let swapped = f.account_a.share_requests(&link).expect("requests");
    assert!(
        swapped
            .iter()
            .all(|request| request.words != requests[0].words)
    );
    f.cloud.connect.set_device_list(&x_id, real);
    // Nothing was signed in A's list.
    assert_eq!(f.list_of(&a_id).len(), head);
}

/// P4: a device that verified A's `unshare` keeps it when Connect serves A's list cut
/// before it, and a list that forks from its pin is not taken.
#[test]
fn a_cut_or_forked_list_of_the_owner_is_not_taken() {
    let mut f = family();
    f.share();
    let (team, x_id, a_id) = (f.team.clone(), f.x_id(), f.a_id());
    let before_unshare = f.list_of(&a_id);
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, &names, false));
    f.account_a
        .stop_sharing(&team, &x_id, &names, proof, &epoch)
        .expect("unshare");
    let status = f.account_x.refresh_shares(&[]).expect("X");
    assert!(
        status
            .stores
            .iter()
            .any(|store| store.team_id == team && store.ended),
        "{status:?}"
    );
    // Connect serves A's list without the unshare: X keeps the end.
    f.cloud.connect.serve_peer_list(&a_id, Some(before_unshare));
    let status = f.account_x.refresh_shares(&[]).expect("X");
    assert!(
        status
            .stores
            .iter()
            .any(|store| store.team_id == team && store.ended)
    );
    let policy = signer_policy(f.account_x.state()).for_team(&team);
    assert!(policy.accepted.is_empty());
}

/// (iii) While Connect shows both accounts in the group, a refresh ends nothing; when it
/// shows the member outside the group, the owner's device signs `unshare` by itself (no
/// owner check: a lying Connect can end a share this way, never start one), once, and says
/// so with the verified name.
#[test]
fn a_member_outside_the_group_ends_the_share_without_an_owner_check() {
    let mut f = family();
    f.share();
    let (team, x_id, a_id) = (f.team.clone(), f.x_id(), f.a_id());
    let status = f.account_a.refresh_shares(&[]).expect("A");
    assert!(status.notes.is_empty(), "{status:?}");
    let head = f.list_of(&a_id).len();
    f.cloud.connect.remove_member(&a_id, &x_id);
    let status = f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(f.list_of(&a_id).len(), head + 1, "one unshare");
    assert_eq!(
        f.list_of(&a_id).last().expect("entry")["op"],
        json!("unshare")
    );
    assert!(
        status.notes.iter().any(
            |note| note.ends_with("ended: no longer in your family or team.")
                && !note.contains(&x_id)
        ),
        "{status:?}"
    );
    assert!(
        !signer_policy(f.account_a.state())
            .for_team(&team)
            .accepts(&key_of(&f.account_x))
    );
    // Again: nothing more is signed.
    f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(f.list_of(&a_id).len(), head + 1);
}

/// A device of an account that downloads the account's own store (`account` is a device of
/// the account that made it, in the store already) and adopts it under `mac`.
fn own_copy(mac: &Mac, account: &mut ConnectAccount, team: &str) -> Vault {
    let store = account
        .vault_stores()
        .expect("stores")
        .into_iter()
        .find(|store| store.team_id == team)
        .expect("in the store");
    let joined = RelaySync::joined_from_store(account, &store).expect("joined");
    let download = joined.download(&mac.data.join("sync")).expect("download");
    let (vault, _) = mac.sync.adopt(&joined, &download, PASS).expect("adopt");
    drop((vault, download, joined));
    hand_over(mac, account);
    let mut vault = Vault::open(&mac.vault_path).expect("open");
    vault.unlock(PASS).expect("unlock");
    vault
}

/// C5: the ended keys of a store come from the lists. A second device of A that was
/// offline while A shared the store with X, X pushed, A pushed over it, and A ended the
/// share, reads the `share` and the `unshare` at once: it holds X's keys as ended keys,
/// and the chain from its anchor (X's head below A's head) merges.
#[test]
fn a_device_that_reads_a_share_and_its_end_at_once_follows_the_chain() {
    let mut f = family();
    let a2 = mac(&f.cloud, "a2");
    let mut account_a2 = join_account(&f.cloud, &mut f.account_a, &a2, "Synthetic Mac mini");
    f.a.sync
        .register_account_devices(&mut f.account_a)
        .expect("A2 in the store");
    let mut vault_a2 = own_copy(&a2, &mut account_a2, &f.team.clone());
    assert_eq!(titles(&vault_a2), vec!["Alpha"]);
    // A2 is offline from here.
    f.share();
    let mut vault_x = f.x_vault();
    hand_over(&f.a, &f.account_a);
    vault_x.add(item("Beta")).expect("add");
    assert!(f.x.sync.sync(&mut vault_x).expect("X").pushed);
    f.a.sync.sync(&mut f.vault_a).expect("A merges X");
    f.vault_a.add(item("Gamma")).expect("add");
    assert!(f.a.sync.sync(&mut f.vault_a).expect("A").pushed);
    let (team, x_id) = (f.team.clone(), f.x_id());
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, &names, false));
    f.account_a
        .stop_sharing(&team, &x_id, &names, proof, &epoch)
        .expect("unshare");
    // A2 reads A's list with both entries, and X's list.
    account_a2.refresh_shares(&[]).expect("A2");
    let policy = signer_policy(account_a2.state()).for_team(&team);
    assert!(policy.left_key(&key_of(&f.account_x)), "{policy:?}");
    assert!(!policy.accepts(&key_of(&f.account_x)));
    hand_over(&a2, &account_a2);
    a2.sync.sync(&mut vault_a2).expect("A2 follows the chain");
    assert_eq!(titles(&vault_a2), vec!["Alpha", "Beta", "Gamma"]);
}

/// C4: the owner confirmed and the member did not finish the words (its list does not pin
/// the owner): the owner shows a new code and the words again, the member finishes, and
/// the owner signs nothing twice.
#[test]
fn a_member_who_did_not_finish_the_words_gets_a_new_code() {
    let mut f = family();
    let (team, x_id, a_id) = (f.team.clone(), f.x_id(), f.a_id());
    let names = ShareNames::default();
    let link = f.account_a.start_share(&x_id, &team).expect("code");
    let answer = f.account_x.accept_code(link.code()).expect("answer");
    let requests = f.account_a.share_requests(&link).expect("requests");
    let (proof, epoch) = f.owner_a.proof(
        f.account_a
            .share_action(&link, &requests[0], &names)
            .expect("action"),
    );
    f.account_a
        .confirm_share(&link, &requests[0], &names, proof, &epoch)
        .expect("confirm");
    // X stops here (a lock, Cancel, a failed owner check).
    drop(answer);
    let status = f.account_a.refresh_shares(&[]).expect("A");
    let member = &status
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .expect("store")
        .members[0];
    assert!(!member.accepted, "{member:?}");
    assert!(f.account_a.needs_share_code(&x_id).expect("check"));
    let head = f.list_of(&a_id).len();
    let link = f.account_a.start_share(&x_id, &team).expect("a new code");
    let answer = f.account_x.accept_code(link.code()).expect("answer");
    let requests = f.account_a.share_requests(&link).expect("requests");
    assert_eq!(requests[0].words, answer.words);
    let action = f
        .account_a
        .share_action(&link, &requests[0], &names)
        .expect("action");
    assert!(
        matches!(action, OwnerAction::ShareConnectVault { .. }),
        "{action:?}"
    );
    let (proof, epoch) = f.owner_a.proof(action);
    f.account_a
        .confirm_share(&link, &requests[0], &names, proof, &epoch)
        .expect("confirm again");
    assert_eq!(f.list_of(&a_id).len(), head, "nothing was signed twice");
    let (proof, epoch) = f
        .owner_x
        .proof(f.account_x.accept_action(&answer, &names).expect("action"));
    f.account_x
        .accept_share(&answer, &names, proof, &epoch)
        .expect("X finishes");
    assert!(!f.account_a.needs_share_code(&x_id).expect("check"));
    let status = f.account_x.refresh_shares(&[]).expect("X");
    assert_eq!(status.offers.len(), 1, "{status:?}");
}

/// (i) and (ii): X leaves the shared vault on one device. X's other device reads the
/// `leave` and says on which device; A's device reads X's verified `leave` and signs
/// `unshare` by itself, once ("<name> left this vault."); X gets no offer of the same
/// share again until A shares it again, and a new share is not ended by the old leave.
#[test]
fn a_leave_ends_the_share_on_every_device_once() {
    let mut f = family();
    let x2 = mac(&f.cloud, "x2");
    let mut account_x2 = join_account(&f.cloud, &mut f.account_x, &x2, "Synthetic MacBook Air");
    f.share();
    let (team, a_id) = (f.team.clone(), f.a_id());
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_x
        .proof(f.account_x.end_share_action(&team, &a_id, &names, true));
    f.account_x
        .leave_shared_store(&team, &a_id, &names, proof, &epoch)
        .expect("leave");
    let status = account_x2.refresh_shares(&[]).expect("X2");
    assert_eq!(
        status.left,
        vec![LeftStore {
            team_id: team.clone(),
            owner: a_id.clone(),
            device: "Synthetic MacBook".to_owned(),
            here: false,
        }],
        "{status:?}"
    );
    assert!(
        status.offers.is_empty(),
        "the same share is not offered again"
    );
    let head = f.list_of(&a_id).len();
    let status = f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(f.list_of(&a_id).len(), head + 1);
    assert!(
        status
            .notes
            .iter()
            .any(|note| note.ends_with("left this vault.")),
        "{status:?}"
    );
    f.account_a.refresh_shares(&[]).expect("A again");
    assert_eq!(f.list_of(&a_id).len(), head + 1, "once");
    // A shares again (no words: the pair is pinned both ways). The old leave ends
    // nothing of the new share, and X is offered the store again.
    let x_id = f.x_id();
    assert!(!f.account_a.needs_share_code(&x_id).expect("check"));
    let (proof, epoch) = f.owner_a.proof(
        f.account_a
            .share_again_action(&team, &x_id, &names)
            .expect("action"),
    );
    f.account_a
        .share_again(&team, &x_id, &names, proof, &epoch)
        .expect("share again");
    let head = f.list_of(&a_id).len();
    f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(f.list_of(&a_id).len(), head);
    let status = f.account_x.refresh_shares(&[]).expect("X");
    assert_eq!(status.offers.len(), 1, "{status:?}");
}

/// C2: a list of a peer that names a store of this account in a `share` gives no offer of
/// it, and this account signs no `join` of its own store: neither of a store that this
/// computer syncs as its own (the local vault list), nor of one that its own list shares.
/// Connect (or a peer) cannot turn this account's store into one that the peer's devices
/// sign.
#[test]
fn a_store_of_this_account_is_never_offered_or_joined() {
    let mut f = family();
    f.share();
    let (a_id, x_id) = (f.a_id(), f.x_id());
    let second = f
        .account_a
        .create_vault_store("0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77", "Second")
        .expect("second store")
        .team_id;
    let signer = f.account_x.signer().expect("signer");
    let (entry, hash) = forged_entry(&f, &x_id, &signer, "share", &a_id, Some(&second));
    f.cloud.connect.push_list_entry(&x_id, entry, hash);
    let names = ShareNames::default();
    let refused = |f: &mut Family, local: &[String]| {
        let status = f.account_a.refresh_shares(local).expect("refresh");
        assert!(
            !status.offers.iter().any(|offer| offer.team_id == second),
            "{status:?}"
        );
        let before = f.cloud.connect.count("POST /v1/account/list");
        let (proof, epoch) = f
            .owner_a
            .proof(f.account_a.join_action(&second, &x_id, &names));
        assert_eq!(
            f.account_a
                .join_shared_store(&second, &x_id, local, &names, proof, &epoch)
                .unwrap_err(),
            ConnectError::Invalid
        );
        assert_eq!(
            f.cloud.connect.count("POST /v1/account/list"),
            before,
            "nothing was signed"
        );
    };
    // This computer syncs the store as its own vault.
    refused(&mut f, std::slice::from_ref(&second));
    // The own list shares the store (with X): it is this account's.
    let (proof, epoch) = f.owner_a.proof(
        f.account_a
            .share_again_action(&second, &x_id, &names)
            .expect("action"),
    );
    f.account_a
        .share_again(&second, &x_id, &names, proof, &epoch)
        .expect("share the second store");
    refused(&mut f, &[]);
}

/// An account file of version 3 (before the peers) is read as version 4 and written as
/// version 4: no device joins its account again.
#[test]
fn an_account_file_of_version_3_moves_in_place() {
    let cloud = cloud();
    let a = mac(&cloud, "a");
    let account = new_account(&cloud, &a, "Rafal");
    let mut value: Value =
        serde_json::from_slice(&fs::read(&a.account_path).expect("read")).expect("json");
    let object = value.as_object_mut().expect("object");
    object.insert("v".into(), json!(3));
    object.remove("peers");
    object.remove("stores");
    fs::write(&a.account_path, serde_json::to_vec(&value).expect("json")).expect("write");
    let state = apassy::connect::AccountState::load(&a.account_path)
        .expect("load")
        .expect("state");
    assert_eq!(state.v, 4);
    assert_eq!(state.account_id, account.state().account_id);
    assert!(state.peers.is_empty() && state.stores.is_empty());
}

const SHARE_VECTORS: &str = include_str!("fixtures/connect-account-v1/share-vectors.json");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The vectors of section 16: the share-list messages and the peer-join message are those
/// of this build, each signature verifies over its message and fails over a changed byte,
/// the share code, its fingerprint, its hash, and the six words come from their inputs,
/// and both lists verify from their roots with the peers, the share, and the join.
#[test]
fn the_share_vectors_reproduce_the_messages_and_words() {
    use apassy::connect::device_key::{list_hash, peer_join_message};
    use apassy::connect::trust::{ListEntry, verify_list};
    use apassy::connect::{ShareCode, share_fingerprint, share_link_hash, share_safety_words};
    use apassy::sync::{decode_b64u, verify_signature};

    let v: Value = serde_json::from_str(SHARE_VECTORS).expect("vectors");
    let origin = v["origin"].as_str().unwrap();
    let (a, x, store) = (
        v["account_a"].as_str().unwrap(),
        v["account_x"].as_str().unwrap(),
        v["store"].as_str().unwrap(),
    );
    let pub_a = hex(v["device_a"]["public_hex"].as_str().unwrap());
    let pub_b = hex(v["device_b"]["public_hex"].as_str().unwrap());
    let (a64, b64) = (encode_b64u(&pub_a), encode_b64u(&pub_b));
    let code = v["code"]["code"].as_str().unwrap();
    let parsed = ShareCode::parse(code).expect("a share code");
    assert_eq!(parsed.account_id(), a);
    assert_eq!(
        parsed.fingerprint(),
        v["code"]["fingerprint"].as_str().unwrap()
    );
    assert_eq!(share_fingerprint(&pub_a, &pub_a), parsed.fingerprint());
    assert_eq!(
        share_link_hash(code),
        v["code"]["link_hash"].as_str().unwrap()
    );
    assert_eq!(
        share_safety_words(code, (a, &pub_a, &pub_a), (x, &pub_b, &pub_b)),
        v["words"]["words"].as_str().unwrap()
    );
    let made: Vec<(&str, Vec<u8>)> = vec![
        (
            "share_list_peer",
            share_list_message(
                origin,
                a,
                2,
                v["lists"]["a"]["hashes"][0].as_str().unwrap(),
                "peer",
                x,
                &b64,
                "-",
                &a64,
            ),
        ),
        (
            "share_list_store",
            share_list_message(
                origin,
                a,
                3,
                v["lists"]["a"]["hashes"][1].as_str().unwrap(),
                "store",
                "-",
                "-",
                store,
                &a64,
            ),
        ),
        (
            "share_list_share",
            share_list_message(
                origin,
                a,
                4,
                v["lists"]["a"]["hashes"][2].as_str().unwrap(),
                "share",
                x,
                "-",
                store,
                &a64,
            ),
        ),
        (
            "share_list_member_peer",
            share_list_message(
                origin,
                x,
                2,
                v["lists"]["x"]["hashes"][0].as_str().unwrap(),
                "peer",
                a,
                &a64,
                "-",
                &b64,
            ),
        ),
        (
            "share_list_join",
            share_list_message(
                origin,
                x,
                3,
                v["lists"]["x"]["hashes"][1].as_str().unwrap(),
                "join",
                a,
                v["lists"]["a"]["hashes"][3].as_str().unwrap(),
                store,
                &b64,
            ),
        ),
        (
            "peer_join",
            peer_join_message(origin, a, &share_link_hash(code), x, &b64, &b64),
        ),
    ];
    for (name, message) in made {
        let vector = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(
            encode_b64u(&message),
            vector["message_b64u"].as_str().unwrap(),
            "{name}"
        );
        assert!(message.starts_with(vector["tag"].as_str().unwrap().as_bytes()));
        let key = if vector["signer"] == "device_a" {
            &pub_a
        } else {
            &pub_b
        };
        let signature = decode_b64u(vector["signature_b64u"].as_str().unwrap()).unwrap();
        assert!(verify_signature(key, &message, &signature), "{name}");
        let mut changed = message.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(!verify_signature(key, &changed, &signature), "{name}");
        if name.starts_with("share_list") {
            assert!(
                v["lists"].to_string().contains(&list_hash(&message)),
                "{name}"
            );
        }
    }
    for (account, root, list, pinned) in
        [(a, &pub_a, "a", (x, &pub_b)), (x, &pub_b, "x", (a, &pub_a))]
    {
        let entries: Vec<ListEntry> =
            serde_json::from_value(v["lists"][list]["entries"].clone()).expect("entries");
        let verified = verify_list(origin, account, root, &entries).expect("the list verifies");
        assert_eq!(verified.shares.root_of(pinned.0), Some(pinned.1.as_slice()));
        assert_eq!(
            verified.hashes,
            v["lists"][list]["hashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|hash| hash.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
        if list == "a" {
            assert_eq!(verified.shares.members_of(store), [x.to_owned()]);
            assert!(verified.shares.made(store));
        } else {
            assert_eq!(verified.shares.owner_of(store), Some(a));
            assert_eq!(
                verified.shares.join_share(store, a),
                v["lists"]["a"]["hashes"][3].as_str()
            );
        }
        // From another root, nothing verifies.
        assert!(verify_list(origin, account, pinned.1, &entries).is_none());
    }
}

/// A recovery of the member starts a new root: the owner's devices mark the member
/// reset and its old keys sign nothing new; sharing again with the same pin is refused,
/// and a new code with new words pins the new root (the old share and pin end first) and
/// shares the store again, for the new keys only.
#[test]
fn a_reset_account_is_shared_again_only_with_new_words() {
    let mut f = family();
    f.share();
    let (team, x_id) = (f.team.clone(), f.x_id());
    let old_key = key_of(&f.account_x);
    // X's only device leaves the account, and X recovers it on a new Mac.
    let device_id = f.account_x.state().device_id.clone();
    let row = f
        .account_x
        .view()
        .expect("view")
        .devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .expect("this device");
    let (proof, epoch) = f.owner_x.proof(f.account_x.revoke_action(&row));
    f.account_x
        .revoke(&row, proof, &epoch)
        .expect("X removes itself");
    let fresh = mac(&f.cloud, "x-fresh");
    let code = f.recovery_x.text();
    let (mut new_x, _, _) = ConnectAccount::recover(
        client(&f.cloud),
        &fresh.keys,
        &fresh.account_path,
        &x_id,
        &code,
        "Synthetic iMac",
    )
    .expect("recover X");
    let status = f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(status.suspended, vec![x_id.clone()]);
    let policy = signer_policy(f.account_a.state()).for_team(&team);
    assert!(!policy.accepts(&old_key) && policy.left_key(&old_key));
    assert!(!policy.accepts(&key_of(&new_x)));
    // The same pin is not enough: new words are needed.
    let names = ShareNames::default();
    let (proof, epoch) = f.owner_a.proof(
        f.account_a
            .share_again_action(&team, &x_id, &names)
            .expect("action"),
    );
    assert_eq!(
        f.account_a
            .share_again(&team, &x_id, &names, proof, &epoch)
            .unwrap_err(),
        ConnectError::NotVerified
    );
    // A new code, new words, and the new root.
    let link = f.account_a.start_share(&x_id, &team).expect("code");
    let answer = new_x.accept_code(link.code()).expect("answer");
    let requests = f.account_a.share_requests(&link).expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].words, answer.words);
    // A re-pin of its own: it says which shares end, and shares the store after it.
    let action = f
        .account_a
        .share_action(&link, &requests[0], &names)
        .expect("action");
    match &action {
        OwnerAction::RepinConnectPeer { ends, team_id, .. } => {
            assert_eq!(ends.len(), 1, "{action:?}");
            assert_eq!(team_id.as_deref(), Some(team.as_str()));
        }
        other => panic!("not a re-pin: {other:?}"),
    }
    let (proof, epoch) = f.owner_a.proof(action);
    f.account_a
        .confirm_share(&link, &requests[0], &names, proof, &epoch)
        .expect("A shares again");
    f.account_a.refresh_shares(&[]).expect("A");
    let policy = signer_policy(f.account_a.state()).for_team(&team);
    assert!(policy.accepts(&key_of(&new_x)));
    assert!(!policy.accepts(&old_key));
    assert!(
        f.account_a
            .state()
            .peers
            .iter()
            .any(|pin| pin.account_id == x_id && !pin.suspended)
    );
}

/// C8: a re-pin of a reset account near the end of the list checks the room for all of
/// its entries (the ends of the old root, `unpeer`, `peer`, and `share`) before the first
/// one: at version 819 the `share` would come at 823, so nothing is signed.
#[test]
fn a_re_pin_near_the_end_of_the_list_signs_nothing() {
    let mut f = family();
    f.share();
    let (team, x_id, a_id) = (f.team.clone(), f.x_id(), f.a_id());
    let signer = f.account_a.signer().expect("signer");
    if f.list_of(&a_id).len().is_multiple_of(2) {
        // One entry that changes nothing of X: the pairs below then end at 819.
        push_entry(
            &f.cloud,
            &a_id,
            &signer,
            "store",
            None,
            None,
            Some("t_fillaaaaaa"),
        );
    }
    while f.list_of(&a_id).len() < 819 {
        for op in ["unshare", "share"] {
            let (entry, hash) = forged_entry(&f, &a_id, &signer, op, &x_id, Some(&team));
            f.cloud.connect.push_list_entry(&a_id, entry, hash);
        }
    }
    assert_eq!(f.list_of(&a_id).len(), 819);
    // X's only device leaves and X recovers its account: a new root.
    let device_id = f.account_x.state().device_id.clone();
    let row = f
        .account_x
        .view()
        .expect("view")
        .devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .expect("this device");
    let (proof, epoch) = f.owner_x.proof(f.account_x.revoke_action(&row));
    f.account_x.revoke(&row, proof, &epoch).expect("revoke");
    let fresh = mac(&f.cloud, "x-fresh");
    let code = f.recovery_x.text();
    let (mut new_x, _, _) = ConnectAccount::recover(
        client(&f.cloud),
        &fresh.keys,
        &fresh.account_path,
        &x_id,
        &code,
        "Synthetic iMac",
    )
    .expect("recover X");
    f.account_a.refresh_shares(&[]).expect("A");
    let link = f.account_a.start_share(&x_id, &team).expect("code");
    let answer = new_x.accept_code(link.code()).expect("answer");
    let requests = f.account_a.share_requests(&link).expect("requests");
    assert_eq!(requests[0].words, answer.words);
    let names = ShareNames::default();
    let (proof, epoch) = f.owner_a.proof(
        f.account_a
            .share_action(&link, &requests[0], &names)
            .expect("action"),
    );
    assert_eq!(
        f.account_a
            .confirm_share(&link, &requests[0], &names, proof, &epoch)
            .unwrap_err(),
        ConnectError::AccountLimit
    );
    assert_eq!(f.list_of(&a_id).len(), 819, "nothing was signed");
}

// ---- Third pass: the group answer, the share a join answers, the co-members of a join,
// the copy of an ended member, exact owner checks, new devices of members, the `store`
// entry, the batch reads, and the void marks. ----

/// An entry of section 16 of `account`'s list at its next version, signed by `signer`:
/// `peer` none for a `store`, `root` the root of a `peer` or the share hash of a `join`
/// (b64u). What a device of that account signs (or a Connect that inserts entries serves).
fn signed_entry(
    cloud: &Cloud,
    account: &str,
    signer: &AccountSigner,
    op: &str,
    peer: Option<&str>,
    root: Option<String>,
    team: Option<&str>,
) -> (Value, String) {
    let version = cloud.connect.device_list(account).len() as u64 + 1;
    let previous = cloud.connect.list_head(account);
    let message = share_list_message(
        &cloud.connect.url,
        account,
        version,
        &previous,
        op,
        peer.unwrap_or("-"),
        root.as_deref().unwrap_or("-"),
        team.unwrap_or("-"),
        &signer.public_key_b64u(),
    );
    let signature = signer.sign(&message).expect("sign");
    let hash = apassy::connect::device_key::list_hash(&message);
    (
        json!({"version": version, "op": op, "key": null, "link_hash": null, "name": null,
               "by": signer.public_key_b64u(), "signature": encode_b64u(&signature),
               "account_id": peer, "root": root, "team_id": team}),
        hash,
    )
}

/// Append a signed entry of section 16 to `account`'s list at Connect.
fn push_entry(
    cloud: &Cloud,
    account: &str,
    signer: &AccountSigner,
    op: &str,
    peer: Option<&str>,
    root: Option<String>,
    team: Option<&str>,
) -> String {
    let (entry, hash) = signed_entry(cloud, account, signer, op, peer, root, team);
    cloud.connect.push_list_entry(account, entry, hash.clone());
    hash
}

/// A third person of A's family: a device, its account, and its owner checks.
fn third(f: &Family, dir: &str, name: &str) -> (Mac, ConnectAccount, Owner) {
    let device = mac(&f.cloud, dir);
    let account = new_account(&f.cloud, &device, name);
    f.cloud
        .connect
        .add_member(&f.a_id(), &account.state().account_id);
    (device, account, owner())
}

/// The ceremony of `owner_account` with `member` for `team`, the share, and the member's
/// join (as [`Family::share`] for X).
fn ceremony(
    owner_account: &mut ConnectAccount,
    owner_checks: &Owner,
    team: &str,
    member: &mut ConnectAccount,
    member_checks: &Owner,
) {
    let member_id = member.state().account_id.clone();
    let owner_id = owner_account.state().account_id.clone();
    let names = ShareNames::default();
    let link = owner_account
        .start_share(&member_id, team)
        .expect("share code");
    let answer = member.accept_code(link.code()).expect("answer");
    let requests = owner_account.share_requests(&link).expect("requests");
    let (proof, epoch) = owner_checks.proof(
        owner_account
            .share_action(&link, &requests[0], &names)
            .expect("action"),
    );
    owner_account
        .confirm_share(&link, &requests[0], &names, proof, &epoch)
        .expect("confirm");
    let (proof, epoch) =
        member_checks.proof(member.accept_action(&answer, &names).expect("action"));
    member
        .accept_share(&answer, &names, proof, &epoch)
        .expect("accept");
    member.refresh_shares(&[]).expect("refresh");
    let (proof, epoch) = member_checks.proof(member.join_action(team, &owner_id, &names));
    member
        .join_shared_store(team, &owner_id, &[], &names, proof, &epoch)
        .expect("join");
}

/// The member `account` downloads the shared vault `team` under `device`.
fn member_copy(device: &Mac, account: &mut ConnectAccount, team: &str) -> Vault {
    let store = account
        .vault_stores()
        .expect("stores")
        .into_iter()
        .find(|store| store.team_id == team)
        .expect("in the store");
    let joined = RelaySync::joined_from_store(account, &store).expect("joined");
    let download = joined
        .download(&device.data.join("sync"))
        .expect("download");
    let (vault, _) = device.sync.adopt(&joined, &download, PASS).expect("adopt");
    drop((vault, download, joined));
    hand_over(device, account);
    let mut vault = Vault::open(&device.vault_path).expect("open");
    vault.unlock(PASS).expect("unlock");
    vault
}

/// F1: a share ends by itself only for a member that the group answer names as removed,
/// or that is not in an answer that shows this account as an active member: a 404 or a
/// 405, an empty answer, an answer without this account, or one where this account is not
/// active ends nothing; a named end comes once.
#[test]
fn only_a_clear_group_answer_ends_a_share() {
    let mut f = family();
    f.share();
    let (a_id, x_id) = (f.a_id(), f.x_id());
    let head = f.list_of(&a_id).len();
    for (status, code) in [(404, "not_found"), (405, "method_not_allowed")] {
        f.cloud
            .connect
            .answer_route_error("GET /v1/account/group", status, code);
        let refreshed = f.account_a.refresh_shares(&[]).expect("A");
        assert!(refreshed.notes.is_empty(), "{code}: {refreshed:?}");
        assert_eq!(f.list_of(&a_id).len(), head, "{code}");
        f.cloud
            .connect
            .clear_route_errors_of("GET /v1/account/group");
    }
    let group = |members: Value| {
        json!({"group_id": "grp_aaaaaaaaaa", "kind": "family", "role": "owner",
               "owner_account": a_id, "included": 4, "quantity": 4, "members": members})
    };
    let member = |account: &str, state: &str| {
        json!({"account_id": account, "name": "Synthetic", "role": "member", "state": state,
               "joined_at": 1_790_000_000})
    };
    for view in [
        group(json!([])),
        group(json!([member(&x_id, "active")])),
        group(json!([member(&a_id, "pending")])),
    ] {
        f.cloud.connect.answer_group(Some(view.clone()));
        f.account_a.refresh_shares(&[]).expect("A");
        assert_eq!(f.list_of(&a_id).len(), head, "{view}");
    }
    f.cloud.connect.answer_group(Some(group(json!([
        member(&a_id, "active"),
        member(&x_id, "removed")
    ]))));
    let refreshed = f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(f.list_of(&a_id).len(), head + 1, "{refreshed:?}");
    assert_eq!(
        f.list_of(&a_id).last().expect("entry")["op"],
        json!("unshare")
    );
    f.account_a.refresh_shares(&[]).expect("A again");
    assert_eq!(f.list_of(&a_id).len(), head + 1, "once");
}

/// F2: after A ends the share and shares the store again, with no `leave` of X, X's old
/// join is over: X's row says that A stopped sharing, the new share is offered, X joins it
/// with a new `join` (an owner check as before), and both accounts sync again.
#[test]
fn a_member_joins_a_new_share_after_its_end() {
    let mut f = family();
    f.share();
    let mut vault_x = f.x_vault();
    let (team, a_id, x_id) = (f.team.clone(), f.a_id(), f.x_id());
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, &names, false));
    f.account_a
        .stop_sharing(&team, &x_id, &names, proof, &epoch)
        .expect("unshare");
    let local = [team.clone()];
    let status = f.account_x.refresh_shares(&local).expect("X");
    let store = status
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .expect("the store");
    assert!(store.ended && !store.void, "{status:?}");
    assert!(status.offers.is_empty());
    let (proof, epoch) = f.owner_a.proof(
        f.account_a
            .share_again_action(&team, &x_id, &names)
            .expect("action"),
    );
    f.account_a
        .share_again(&team, &x_id, &names, proof, &epoch)
        .expect("share again");
    let status = f.account_x.refresh_shares(&local).expect("X");
    assert_eq!(status.offers.len(), 1, "{status:?}");
    let x_head = f.list_of(&x_id).len();
    let (proof, epoch) = f
        .owner_x
        .proof(f.account_x.join_action(&team, &a_id, &names));
    f.account_x
        .join_shared_store(&team, &a_id, &local, &names, proof, &epoch)
        .expect("join the new share");
    assert_eq!(f.list_of(&x_id).len(), x_head + 1);
    assert_eq!(f.list_of(&x_id).last().expect("entry")["op"], json!("join"));
    let status = f.account_x.refresh_shares(&local).expect("X");
    assert!(status.offers.is_empty(), "{status:?}");
    let store = status
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .expect("the store");
    assert!(!store.ended, "{status:?}");
    hand_over(&f.x, &f.account_x);
    let status = f.account_a.refresh_shares(&[]).expect("A");
    hand_over(&f.a, &f.account_a);
    assert!(status.stores[0].members[0].joined, "{status:?}");
    vault_x.add(item("Beta")).expect("add");
    assert!(f.x.sync.sync(&mut vault_x).expect("X").pushed);
    f.a.sync.sync(&mut f.vault_a).expect("A merges X");
    assert_eq!(titles(&f.vault_a), vec!["Alpha", "Beta"]);
}

/// F3: with three accounts, a join reads the lists of the co-members before the first
/// download: X joins after Y, a co-member, pushed last, and X's download takes Y's head.
#[test]
fn a_join_downloads_a_copy_that_a_co_member_pushed_last() {
    let mut f = family();
    let (y_mac, mut account_y, owner_y) = third(&f, "y", "Ewa");
    let team = f.team.clone();
    ceremony(
        &mut f.account_a,
        &f.owner_a,
        &team,
        &mut account_y,
        &owner_y,
    );
    let mut vault_y = member_copy(&y_mac, &mut account_y, &team);
    hand_over(&f.a, &f.account_a);
    vault_y.add(item("Beta")).expect("add");
    assert!(y_mac.sync.sync(&mut vault_y).expect("Y").pushed);
    f.share();
    let vault_x = f.x_vault();
    assert_eq!(titles(&vault_x), vec!["Alpha", "Beta"]);
}

/// F5: a head of a member whose share ended, after this device's anchor: "Use the Copy
/// That … Left…" takes it with the signers of that store (the member's key is an ended key
/// there), and the refresh names its device and the person from the verified lists.
#[test]
fn the_copy_that_an_ended_member_left_is_taken_once() {
    let mut f = family();
    f.share();
    let mut vault_x = f.x_vault();
    hand_over(&f.a, &f.account_a);
    vault_x.add(item("Beta")).expect("add");
    assert!(f.x.sync.sync(&mut vault_x).expect("X").pushed);
    let (team, x_id) = (f.team.clone(), f.x_id());
    let names = ShareNames::default();
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, &names, false));
    f.account_a
        .stop_sharing(&team, &x_id, &names, proof, &epoch)
        .expect("unshare");
    let status = f.account_a.refresh_shares(&[]).expect("A");
    hand_over(&f.a, &f.account_a);
    let waiting = f.a.sync.sync(&mut f.vault_a);
    assert_eq!(
        waiting.err(),
        Some(apassy::sync::SyncError::WaitsForAccountDevice)
    );
    let head = f.a.sync.waiting_head().expect("the head that waits");
    assert_eq!(head.key, key_of(&f.account_x));
    let named = status.device_of(&head.key).expect("named");
    assert!(named.contains("Synthetic MacBook"), "{named}");
    f.a.sync
        .use_departed_copy(&mut f.vault_a, &head)
        .expect("the copy of X");
    assert_eq!(titles(&f.vault_a), vec!["Alpha", "Beta"]);
}

/// F7: an owner check names the exact entries that its step signs. A confirmation whose
/// check was built before another device of the account pinned another root for the member
/// signs nothing (the list needs a re-pin now, which the check does not name), and so does
/// an accept whose check was built before another device pinned another root for the owner.
#[test]
fn a_check_covers_only_the_entries_that_it_names() {
    let mut f = family();
    let a2 = mac(&f.cloud, "a2");
    let account_a2 = join_account(&f.cloud, &mut f.account_a, &a2, "Synthetic Mac mini");
    let x2 = mac(&f.cloud, "x2");
    let account_x2 = join_account(&f.cloud, &mut f.account_x, &x2, "Synthetic MacBook Air");
    let (team, a_id, x_id) = (f.team.clone(), f.a_id(), f.x_id());
    let names = ShareNames::default();
    let link = f.account_a.start_share(&x_id, &team).expect("code");
    let answer = f.account_x.accept_code(link.code()).expect("answer");
    let requests = f.account_a.share_requests(&link).expect("requests");
    let action = f
        .account_a
        .share_action(&link, &requests[0], &names)
        .expect("action");
    let ops = |action: &OwnerAction| match action {
        OwnerAction::ShareConnectVault { entries, .. }
        | OwnerAction::AcceptConnectShare { entries, .. } => entries
            .iter()
            .map(|entry| entry.op.clone())
            .collect::<Vec<_>>(),
        other => panic!("{other:?}"),
    };
    assert_eq!(ops(&action), ["peer", "share"]);
    let accept = f.account_x.accept_action(&answer, &names).expect("action");
    assert_eq!(ops(&accept), ["peer"]);
    let (proof, epoch) = f.owner_a.proof(action);
    let (accept_proof, accept_epoch) = f.owner_x.proof(accept);
    // Meanwhile A2 pins another root for X, and X2 another root for A.
    let other = apassy::sync::DeviceKey::generate().expect("key");
    let root = encode_b64u(other.public_key());
    let a2_signer = account_a2.signer().expect("signer");
    push_entry(
        &f.cloud,
        &a_id,
        &a2_signer,
        "peer",
        Some(&x_id),
        Some(root.clone()),
        None,
    );
    let x2_signer = account_x2.signer().expect("signer");
    push_entry(
        &f.cloud,
        &x_id,
        &x2_signer,
        "peer",
        Some(&a_id),
        Some(root),
        None,
    );
    let (a_head, x_head) = (f.list_of(&a_id).len(), f.list_of(&x_id).len());
    let refused = f
        .account_a
        .confirm_share(&link, &requests[0], &names, proof, &epoch);
    assert!(
        matches!(refused, Err(ConnectError::OwnerCheck(_))),
        "{refused:?}"
    );
    assert_eq!(f.list_of(&a_id).len(), a_head, "A signed nothing");
    let refused = f
        .account_x
        .accept_share(&answer, &names, accept_proof, &accept_epoch);
    assert!(
        matches!(refused, Err(ConnectError::OwnerCheck(_))),
        "{refused:?}"
    );
    assert_eq!(f.list_of(&x_id).len(), x_head, "X signed nothing");
}

/// F9: a device that joins a member's account after the share is added to the store by the
/// owner's next refresh (no owner check: the share covers the member's verified devices);
/// before that, its copy says that the person who shares the vault adds it.
#[test]
fn a_new_device_of_a_member_is_added_by_the_owner() {
    let mut f = family();
    f.share();
    let x2 = mac(&f.cloud, "x2");
    let mut account_x2 = join_account(&f.cloud, &mut f.account_x, &x2, "Synthetic MacBook Air");
    account_x2.refresh_shares(&[]).expect("X2");
    let me = account_x2.state().device_id.clone();
    let store = account_x2
        .vault_stores()
        .expect("stores")
        .into_iter()
        .find(|store| store.team_id == f.team)
        .expect("listed for the account");
    assert!(!store.devices.iter().any(|device| device.device_id == me));
    let refused = RelaySync::joined_from_store(&mut account_x2, &store).err();
    assert!(
        matches!(refused, Some(StoreError::NotInSharedStore)),
        "{refused:?}"
    );
    let status = f.account_a.refresh_shares(&[]).expect("A adds X2");
    assert!(
        status.added.iter().any(|device| device.device_id == me),
        "{status:?}"
    );
    let added = f.cloud.connect.count("POST /v1/account/vaults/");
    f.account_a.refresh_shares(&[]).expect("A again");
    assert_eq!(
        f.cloud.connect.count("POST /v1/account/vaults/"),
        added,
        "once"
    );
    let vault = member_copy(&x2, &mut account_x2, &f.team);
    assert_eq!(titles(&vault), vec!["Alpha"]);
}

/// F10: the account that made a store signs `store` in the step that makes it; a share of
/// a store that the own list did not make is refused before anything is signed; a store
/// that the own list made is never offered, also on a device that does not sync it.
#[test]
fn the_store_entry_says_which_account_made_a_store() {
    let mut f = family();
    let (a_id, x_id) = (f.a_id(), f.x_id());
    let list = f.list_of(&a_id);
    assert!(
        list.iter()
            .any(|entry| entry["op"] == "store" && entry["team_id"] == json!(f.team)),
        "{list:?}"
    );
    f.share();
    let names = ShareNames::default();
    // A share of X's store by A: not a store of A's list.
    let x_store = f
        .account_x
        .create_vault_store("4b1d9a77-0f3c-4a10-8c21-6f0e5b7e2a10", "Theirs")
        .expect("X's store")
        .team_id;
    let head = f.list_of(&a_id).len();
    let refused = f.account_a.share_again_action(&x_store, &x_id, &names);
    assert_eq!(refused.unwrap_err(), ConnectError::Conflict);
    assert_eq!(f.list_of(&a_id).len(), head);
    // A2, a device of A that syncs no vault; A's second store, never shared; X's list claims
    // it (a `store` and a `share` of it with A, as a lying Connect could serve them).
    let second = f
        .account_a
        .create_vault_store("0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77", "Second")
        .expect("second store")
        .team_id;
    let a2 = mac(&f.cloud, "a2");
    let mut account_a2 = join_account(&f.cloud, &mut f.account_a, &a2, "Synthetic Mac mini");
    let x_signer = f.account_x.signer().expect("signer");
    push_entry(
        &f.cloud,
        &x_id,
        &x_signer,
        "store",
        None,
        None,
        Some(&second),
    );
    push_entry(
        &f.cloud,
        &x_id,
        &x_signer,
        "share",
        Some(&a_id),
        None,
        Some(&second),
    );
    let status = account_a2.refresh_shares(&[]).expect("A2");
    assert!(
        !status.offers.iter().any(|offer| offer.team_id == second),
        "{status:?}"
    );
    let before = f.list_of(&a_id).len();
    let (proof, epoch) = f
        .owner_a
        .proof(account_a2.join_action(&second, &x_id, &names));
    let refused = account_a2.join_shared_store(&second, &x_id, &[], &names, proof, &epoch);
    assert_eq!(refused.unwrap_err(), ConnectError::Invalid);
    assert_eq!(f.list_of(&a_id).len(), before);
}

/// G3: a share that Connect counts as void (a quick removal from the group and a new
/// admission) is ended by the owner's device by itself, once, and its row offers to share
/// again; the member's device shows its store as ended meanwhile.
#[test]
fn a_void_share_is_ended_by_the_owner_and_shown_to_the_member() {
    let mut f = family();
    f.share();
    let (team, a_id, x_id) = (f.team.clone(), f.a_id(), f.x_id());
    f.cloud.connect.void_share(&a_id, &team, &x_id);
    let status = f.account_x.refresh_shares(&[]).expect("X");
    let store = status
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .expect("the store");
    assert!(store.void, "{status:?}");
    assert!(
        store_policy_accepts_nothing(&f.account_x, &team),
        "the store has ended here"
    );
    let head = f.list_of(&a_id).len();
    let status = f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(f.list_of(&a_id).len(), head + 1);
    assert_eq!(
        f.list_of(&a_id).last().expect("entry")["op"],
        json!("unshare")
    );
    let own = status
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .expect("A's store");
    assert!(own.members.is_empty());
    assert_eq!(own.ended_members[0].account_id, x_id);
    f.account_a.refresh_shares(&[]).expect("A again");
    assert_eq!(f.list_of(&a_id).len(), head + 1, "once");
}

fn store_policy_accepts_nothing(account: &ConnectAccount, team: &str) -> bool {
    apassy::connect::store_signer_policy(account.state(), team)
        .is_some_and(|policy| policy.accepted.is_empty())
}

/// G1: a refresh reads the lists of 64 own pins and 236 pins through owners in batches of
/// 64 (five requests, no single reads); the next refresh asks again with the pins it holds
/// (the lists come back `same`); a `429` stops the reads, ends nothing, and the refresh
/// within its `Retry-After` reads nothing.
#[test]
fn a_refresh_of_300_pins_reads_in_batches() {
    let f = family();
    let x_id = f.x_id();
    let x_signer = f.account_x.signer().expect("signer");
    let dir = TempDir::new().expect("dir");
    let make = |name: &str| {
        let keys = MemoryKeyStore::new();
        let (account, _) = ConnectAccount::create(
            client(&f.cloud),
            &keys,
            &account_file(&dir.path().join(name)),
            "Synthetic",
            "Synthetic device",
        )
        .expect("account");
        f.cloud
            .connect
            .add_member(&f.a_id(), &account.state().account_id);
        account
    };
    let root_of = |account: &ConnectAccount| encode_b64u(&key_of(account));
    // 4 owners, each with a store shared with X and 59 others.
    let teams = [
        "t_qaaaaaaaaa",
        "t_qbaaaaaaaa",
        "t_qcaaaaaaaa",
        "t_qdaaaaaaaa",
    ];
    let mut via = 0;
    let mut owners = Vec::new();
    for (index, team) in teams.iter().enumerate() {
        let owner = make(&format!("owner{index}"));
        let id = owner.state().account_id.clone();
        let signer = owner.signer().expect("signer");
        push_entry(&f.cloud, &id, &signer, "store", None, None, Some(team));
        push_entry(
            &f.cloud,
            &id,
            &signer,
            "peer",
            Some(&x_id),
            Some(root_of(&f.account_x)),
            None,
        );
        push_entry(
            &f.cloud,
            &id,
            &signer,
            "share",
            Some(&x_id),
            None,
            Some(team),
        );
        for member in 0..59 {
            let other = make(&format!("member{index}-{member}"));
            let other_id = other.state().account_id.clone();
            push_entry(
                &f.cloud,
                &id,
                &signer,
                "peer",
                Some(&other_id),
                Some(root_of(&other)),
                None,
            );
            push_entry(
                &f.cloud,
                &id,
                &signer,
                "share",
                Some(&other_id),
                None,
                Some(team),
            );
            via += 1;
        }
        owners.push(owner);
    }
    // X pins 60 more accounts and the 4 owners (64 own pins) and joins the 4 stores.
    for index in 0..60 {
        let other = make(&format!("peer{index}"));
        push_entry(
            &f.cloud,
            &x_id,
            &x_signer,
            "peer",
            Some(&other.state().account_id),
            Some(root_of(&other)),
            None,
        );
    }
    for (owner, team) in owners.iter().zip(teams) {
        let id = owner.state().account_id.clone();
        push_entry(
            &f.cloud,
            &x_id,
            &x_signer,
            "peer",
            Some(&id),
            Some(root_of(owner)),
            None,
        );
        let share = f
            .cloud
            .connect
            .device_list(&id)
            .iter()
            .position(|entry| entry["op"] == "share" && entry["account_id"] == json!(x_id))
            .expect("the share");
        let hash = lists_hash(&f.cloud, &id, share);
        push_entry(
            &f.cloud,
            &x_id,
            &x_signer,
            "join",
            Some(&id),
            Some(hash),
            Some(team),
        );
    }
    assert_eq!(via, 236);
    let mut account_x = f.account_x;
    let status = account_x.refresh_shares(&[]).expect("X");
    assert_eq!(f.cloud.connect.count("POST /v1/account/peers/lists"), 5);
    assert_eq!(f.cloud.connect.count("GET /v1/account/peers/acc_"), 0);
    let pins = &account_x.state().peers;
    assert_eq!(pins.iter().filter(|pin| pin.via.is_none()).count(), 64);
    assert_eq!(pins.iter().filter(|pin| pin.via.is_some()).count(), 236);
    assert!(
        pins.iter().all(|pin| pin.list_version > 0),
        "every list read"
    );
    assert!(status.unpinned.is_empty());
    let before = account_x.state().clone();
    account_x.refresh_shares(&[]).expect("X again");
    assert_eq!(f.cloud.connect.count("POST /v1/account/peers/lists"), 10);
    assert_eq!(*account_x.state(), before);
    // A 429: the reads stop, nothing ends, and the next refresh waits.
    f.cloud
        .connect
        .answer_route_error("POST /v1/account/peers/lists", 429, "rate_limited");
    let status = account_x.refresh_shares(&[]).expect("X, asked to wait");
    assert!(status.wait.is_some(), "{:?}", status.wait);
    assert_eq!(*account_x.state(), before);
    let asked = f.cloud.connect.count("POST /v1/account/peers/lists");
    account_x.refresh_shares(&[]).expect("X within the wait");
    assert_eq!(f.cloud.connect.count("POST /v1/account/peers/lists"), asked);
    assert_eq!(*account_x.state(), before);
}

/// The list hash of the entry at `index` of `account`'s list at Connect.
fn lists_hash(cloud: &Cloud, account: &str, index: usize) -> String {
    cloud.connect.list_hashes(account)[index].clone()
}

/// F4: a device of a co-member that was offline while a member wrote to the store, and
/// the member then left the group, still reads that member's list (Connect serves the
/// lists of the accounts of a store that both are or were in): the member's head below
/// the owner's head is an ended key there, and the chain merges.
#[test]
fn an_offline_co_member_reads_the_keys_of_a_member_that_left_the_group() {
    let mut f = family();
    let (y_mac, mut account_y, owner_y) = third(&f, "y", "Ewa");
    let team = f.team.clone();
    ceremony(
        &mut f.account_a,
        &f.owner_a,
        &team,
        &mut account_y,
        &owner_y,
    );
    let mut vault_y = member_copy(&y_mac, &mut account_y, &team);
    // Y is offline from here. X joins and writes; A merges and writes over it.
    f.share();
    let mut vault_x = f.x_vault();
    hand_over(&f.a, &f.account_a);
    vault_x.add(item("Beta")).expect("add");
    assert!(f.x.sync.sync(&mut vault_x).expect("X").pushed);
    f.a.sync.sync(&mut f.vault_a).expect("A merges X");
    f.vault_a.add(item("Gamma")).expect("add");
    assert!(f.a.sync.sync(&mut f.vault_a).expect("A").pushed);
    // X leaves the group at Connect; A's device ends the share by itself.
    let (a_id, x_id) = (f.a_id(), f.x_id());
    f.cloud.connect.remove_member(&a_id, &x_id);
    f.account_a.refresh_shares(&[]).expect("A");
    assert_eq!(
        f.list_of(&a_id).last().expect("entry")["op"],
        json!("unshare")
    );
    // Y comes back: X's list is still served to it, X's key is an ended key of the store.
    account_y.refresh_shares(&[]).expect("Y");
    let policy = signer_policy(account_y.state()).for_team(&team);
    assert!(policy.left_key(&key_of(&f.account_x)), "{policy:?}");
    assert!(!policy.accepts(&key_of(&f.account_x)));
    hand_over(&y_mac, &account_y);
    y_mac.sync.sync(&mut vault_y).expect("Y follows the chain");
    assert_eq!(titles(&vault_y), vec!["Alpha", "Beta", "Gamma"]);
}

/// F11: a head of a shared store that was refused for a signer not verified yet is decided
/// only by device lists asked after the refusal that verified. A refresh whose reads of the
/// other accounts' lists fail gives the store no time (it keeps checking, never a damaged
/// copy), a time from before the refusal ends nothing, and a refresh that reads the lists
/// takes the new device.
#[test]
fn a_shared_store_is_decided_only_by_lists_asked_after_its_refusal() {
    let mut f = family();
    f.share();
    let team = f.team.clone();
    hand_over(&f.a, &f.account_a);
    // A second device of X that A has not read yet writes to the store.
    let x2 = mac(&f.cloud, "x2");
    let mut account_x2 = join_account(&f.cloud, &mut f.account_x, &x2, "Synthetic MacBook Air");
    account_x2.refresh_shares(&[]).expect("X2");
    let device = account_x2.state().device_id.clone();
    f.cloud.connect.list_in_store(&team, &device);
    let mut vault_x2 = member_copy(&x2, &mut account_x2, &team);
    vault_x2.add(item("Beta")).expect("add");
    assert!(x2.sync.sync(&mut vault_x2).expect("X2").pushed);
    let before = std::time::Instant::now();
    let checking = f.a.sync.sync(&mut f.vault_a);
    assert_eq!(
        checking.err(),
        Some(apassy::sync::SyncError::ChecksDeviceList)
    );
    // Every read of another account's list fails: no time for the store.
    f.cloud
        .connect
        .answer_route_error("POST /v1/account/peers/lists", 500, "relay_error");
    let status = f.account_a.refresh_shares(&[]).expect("A, reads failed");
    assert!(status.read.is_empty(), "{:?}", status.read);
    assert_eq!(status.asked_for(&team), None);
    // A time from before the refusal (a read in flight then) ends nothing either.
    f.a.sync.note_device_list(before);
    let again = f.a.sync.sync(&mut f.vault_a);
    assert_eq!(again.err(), Some(apassy::sync::SyncError::ChecksDeviceList));
    // The reads work again: the lists were asked after the refusal, and X2 signs.
    f.cloud
        .connect
        .clear_route_errors_of("POST /v1/account/peers/lists");
    let status = f.account_a.refresh_shares(&[]).expect("A");
    let asked = status.asked_for(&team).expect("every list read");
    assert!(asked > before);
    hand_over(&f.a, &f.account_a);
    f.a.sync.note_device_list(asked);
    f.a.sync.sync(&mut f.vault_a).expect("A takes X2's head");
    assert_eq!(titles(&f.vault_a), vec!["Alpha", "Beta"]);
}

/// F12: the signers of the account file and the time of the newest list that verified in
/// them are published as one value: a later verified list moves the time only together
/// with signers that hold it, and a write without a verified list keeps the time.
#[test]
fn the_signers_and_the_time_of_their_list_are_one_value() {
    let mut f = family();
    let feed: apassy::connect::account::SignerFeed = Arc::new(Mutex::new((0, None)));
    f.account_a.set_signer_feed(Arc::clone(&feed));
    let held = || feed.lock().unwrap().1.clone().expect("published");
    let before = std::time::Instant::now();
    f.account_a.view().expect("A");
    let first = held();
    let first_at = first.verified_at.expect("a verified list");
    assert!(first_at >= before);
    // A second device joins: A's next verified list holds it, with a later time.
    let a2 = mac(&f.cloud, "a2");
    let account_a2 = join_account(&f.cloud, &mut f.account_a, &a2, "Synthetic Mac mini");
    let joined = held();
    assert!(joined.policy.accepts(&key_of(&account_a2)));
    f.account_a.view().expect("A again");
    let second = held();
    let second_at = second.verified_at.expect("a verified list");
    assert!(second_at > first_at);
    assert!(
        second.policy.accepts(&key_of(&account_a2)),
        "the time comes with its list"
    );
    // A share step writes the account file: the time of the list stays with it.
    f.share();
    let shared = held();
    assert!(shared.verified_at.is_some_and(|at| at >= second_at));
    assert!(
        shared
            .policy
            .stores
            .iter()
            .any(|store| store.team_id == f.team)
    );
}
