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
    AccountSigner, ConnectAccount, ConnectClient, ConnectError, JoinPoll, JoinRequest,
    MemoryKeyStore, account_file, signer_policy,
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
    let (account, _) = ConnectAccount::create(
        client(cloud),
        &mac.keys,
        &mac.account_path,
        name,
        "Synthetic MacBook",
    )
    .expect("create account");
    cloud.connect.entitle(&account.state().account_id);
    account
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
}

fn family() -> Family {
    let cloud = cloud();
    let (a, x) = (mac(&cloud, "a"), mac(&cloud, "x"));
    let mut account_a = new_account(&cloud, &a, "Rafal");
    let account_x = new_account(&cloud, &x, "Ola");
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
        let (proof, epoch) = self
            .owner_a
            .proof(self.account_a.share_action(&link, &requests[0]));
        self.account_a
            .confirm_share(&link, &requests[0], proof, &epoch)
            .expect("confirm");
        let (proof, epoch) = self.owner_x.proof(self.account_x.accept_action(&answer));
        self.account_x
            .accept_share(&answer, proof, &epoch)
            .expect("accept");
        let status = self.account_x.refresh_shares().expect("refresh");
        assert_eq!(status.offers.len(), 1, "{status:?}");
        let a_id = self.a_id();
        self.account_x
            .join_shared_store(&self.team, &a_id)
            .expect("join");
        self.account_a.refresh_shares().expect("A refreshes");
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
    f.account_a.refresh_shares().expect("A refreshes");
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
    f.account_a.refresh_shares().expect("A refreshes");
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
    let status = f.account_a.refresh_shares().expect("A refreshes");
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
    account_a2.refresh_shares().expect("A2");
    let policy = signer_policy(account_a2.state()).for_team(&f.team);
    assert!(policy.accepts(&key_of(&f.account_x)));
    assert!(
        policy.accepts(&key_of(&account_x2)),
        "X's second device, from X's list"
    );
    account_x2.refresh_shares().expect("X2");
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
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, "Ola", false));
    f.account_a
        .stop_sharing(&team, &x_id, "Ola", Some(proof), &epoch)
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
    let (proof, epoch) = f.owner_x.proof(f.account_x.accept_action(&answer));
    f.account_x
        .accept_share(&answer, proof, &epoch)
        .expect("X pins A");
    // X's own view of A: no offers.
    assert!(f.account_x.refresh_shares().expect("X").offers.is_empty());
    drop(requests);
    let service = AccountSigner::with_key(apassy::sync::DeviceKey::generate().expect("key"));
    let x_signer = f.account_x.signer().expect("X signer");
    for signer in [&service, x_signer.as_ref()] {
        let (entry, hash) = forged_entry(&f, &a_id, signer, "share", &x_id, Some(&f.team));
        let saved = f.list_of(&a_id);
        f.cloud.connect.push_list_entry(&a_id, entry, hash);
        let status = f.account_x.refresh_shares().expect("X refreshes");
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
    let head = f.list_of(&a_id).len();
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
    let (proof, epoch) = f
        .owner_a
        .proof(f.account_a.end_share_action(&team, &x_id, "Ola", false));
    f.account_a
        .stop_sharing(&team, &x_id, "Ola", Some(proof), &epoch)
        .expect("unshare");
    let status = f.account_x.refresh_shares().expect("X");
    assert!(
        status
            .stores
            .iter()
            .any(|store| store.team_id == team && store.ended),
        "{status:?}"
    );
    // Connect serves A's list without the unshare: X keeps the end.
    f.cloud.connect.serve_peer_list(&a_id, Some(before_unshare));
    let status = f.account_x.refresh_shares().expect("X");
    assert!(
        status
            .stores
            .iter()
            .any(|store| store.team_id == team && store.ended)
    );
    let policy = signer_policy(f.account_x.state()).for_team(&team);
    assert!(policy.accepted.is_empty());
}

/// "Stop Sharing with <name>…" needs an owner check while Connect shows both accounts in
/// the group, and none when it shows the member outside: a lying Connect can end a share
/// this way, never start one.
#[test]
fn an_unshare_without_an_owner_check_needs_the_member_outside_the_group() {
    let mut f = family();
    f.share();
    let (team, x_id) = (f.team.clone(), f.x_id());
    let refused = f
        .account_a
        .stop_sharing(&team, &x_id, "Ola", None, &[0u8; 32])
        .unwrap_err();
    assert!(
        matches!(refused, ConnectError::OwnerCheck(_)),
        "{refused:?}"
    );
    f.cloud.connect.remove_member(&f.a_id(), &x_id);
    f.account_a
        .stop_sharing(&team, &x_id, "Ola", None, &[0u8; 32])
        .expect("unshare outside the group");
    assert!(
        !signer_policy(f.account_a.state())
            .for_team(&team)
            .accepts(&key_of(&f.account_x))
    );
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
