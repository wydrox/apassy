//! The app's sync of a vault through Apassy Connect against this relay (contract
//! connect-account-v1 sections 7.5 and 8; docs/SPEC.md section 33): the real `src/connect`
//! client and the real relay sync of the app (`apassy::sync::RelaySync`) on a relay with the
//! account routes. A second device of the same account gets the vault from the store that
//! lists it, with no link and no local copy; the relay makes no device link for a store;
//! and a device that is behind a head of a device that left waits until a live device
//! signs over it. Each test starts its own relay on a free loopback port in a temporary
//! directory. Synthetic values only.

#[path = "common/relay.rs"]
mod relay;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::connect::{
    ConnectAccount, ConnectClient, JoinPoll, JoinRequest, MemoryKeyStore, account_file,
    signer_policy,
};
use apassy::contracts::CredentialKind;
use apassy::sync::{RelayConfig as AppRelayConfig, RelaySync, SyncError};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_relay::api::PlanView;
use apassy_relay::config::{ConnectConfig, ConnectSigningKey, EdgeMode, UpstreamOptions};
use apassy_relay::server::account::Plans;
use apassy_relay::server::store::Store;
use relay::{TestRelay, start_with};

const PASS: &str = "synthetic-connect-pass";

/// The Ed25519 seed bytes 32 to 63 as a PKCS#8 v1 DER file: the entitlement key.
fn signing_key() -> ConnectSigningKey {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend(32u8..64);
    ConnectSigningKey::from_file_bytes(&der).expect("signing key")
}

/// The plans of the tests: every account that a test entitles has Connect Personal.
#[derive(Default)]
struct TestPlans(Mutex<HashMap<String, PlanView>>);

impl Plans for TestPlans {
    fn plan(
        &self,
        _directory: &Store,
        account: &str,
        _now: u64,
    ) -> apassy_relay::error::RelayResult<PlanView> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .unwrap_or_else(PlanView::none))
    }
}

fn entitled() -> PlanView {
    PlanView {
        plan: Some("personal".into()),
        status: "active".into(),
        entitled: true,
        interval: Some("month".into()),
        quantity: Some(1),
        ..PlanView::none()
    }
}

/// A relay with the account routes and the plans of the test.
fn connect() -> (TestRelay, Arc<TestPlans>) {
    let relay = start_with(
        |cfg| {
            cfg.connect = ConnectConfig::accounts(Some(signing_key()));
            cfg.edge = EdgeMode::Off;
        },
        UpstreamOptions::default(),
    );
    let plans = Arc::new(TestPlans::default());
    relay.hub().set_plans(plans.clone());
    (relay, plans)
}

/// One device of the app: its data folder, its key store, its account file, and the
/// relay sync of its vault for the Connect origin.
struct AppDevice {
    _dir: tempfile::TempDir,
    data: PathBuf,
    store: MemoryKeyStore,
    path: PathBuf,
    vault_path: PathBuf,
    sync: RelaySync,
}

fn app_device(origin: &str) -> AppDevice {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("Apassy");
    std::fs::create_dir_all(&data).unwrap();
    let vault_path = data.join("vault.db");
    AppDevice {
        sync: RelaySync::new(AppRelayConfig::in_data_dir(
            &data,
            &vault_path,
            origin,
            "vault",
        )),
        path: account_file(&data),
        store: MemoryKeyStore::new(),
        data,
        vault_path,
        _dir: dir,
    }
}

/// The owner checks of the tests: a vault of their own and its gate.
struct Owner {
    _dir: tempfile::TempDir,
    shared: SharedVault,
    gate: OwnerGate,
}

fn owner() -> Owner {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::create(&dir.path().join("owner.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
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
            .unwrap();
        let epoch = self.shared.lock().unwrap().as_ref().unwrap().epoch();
        (proof, epoch)
    }
}

fn client(relay: &TestRelay) -> ConnectClient {
    ConnectClient::new(&relay.url).unwrap()
}

/// `device` joins the account of `account` with the words and a fresh owner check.
fn join(
    relay: &TestRelay,
    owner: &Owner,
    account: &mut ConnectAccount,
    device: &AppDevice,
    name: &str,
) -> ConnectAccount {
    let link = account.start_link().expect("link");
    let mut request = JoinRequest::start(
        client(relay),
        &device.store,
        &device.path,
        link.code(),
        name,
    )
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
        .unwrap()
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    titles
}

/// A vault at `path` that holds the items of the vault at `from` (the same vault id and
/// passphrase), unlocked.
fn copy_of(from: &Path, path: &Path) -> Vault {
    std::fs::copy(from, path).unwrap();
    let mut vault = Vault::open(path).unwrap();
    vault.unlock(PASS).unwrap();
    vault
}

/// The window's hand-over of the account to the relay sync of a vault: the key and the
/// signer policy of the account file.
fn hand_over(device: &AppDevice, account: &ConnectAccount) {
    device
        .sync
        .set_account_signer(Some(account.signer().unwrap()));
    device
        .sync
        .set_account_signers(Some(signer_policy(account.state())));
}

/// Revoke `device_id` from `account` with a fresh owner check.
fn revoke(owner: &Owner, account: &mut ConnectAccount, device_id: &str) {
    let target = account
        .view()
        .unwrap()
        .devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .expect("the device");
    let (proof, epoch) = owner.proof(account.revoke_action(&target));
    account.revoke(&target, proof, &epoch).expect("revoke");
}

/// A second device of the account, with no copy of the vault, gets it from the store that
/// lists it: a device in the store registers it (`POST /v1/account/vaults/{team}/devices`),
/// then the store join, the download, the adoption with the passphrase, and later syncs in
/// both directions, all against this relay. The relay makes no device link for the store.
#[test]
fn a_second_device_of_the_account_gets_the_vault_from_its_store() {
    let (relay, plans) = connect();
    let owner = owner();
    let a = app_device(&relay.url);
    let b = app_device(&relay.url);
    let (mut account_a, _) = ConnectAccount::create(
        client(&relay),
        &a.store,
        &a.path,
        "Rafal",
        "Synthetic MacBook",
    )
    .expect("create");
    plans
        .0
        .lock()
        .unwrap()
        .insert(account_a.state().account_id.clone(), entitled());
    let mut account_b = join(&relay, &owner, &mut account_a, &b, "Synthetic Mac mini");

    let mut vault_a = Vault::create(&a.vault_path, PASS).unwrap();
    vault_a.unlock(PASS).unwrap();
    vault_a.add(item("Alpha")).unwrap();
    let report = a
        .sync
        .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
        .expect("enable on A");
    assert_eq!(report.registered, vec!["Synthetic Mac mini".to_owned()]);
    let team = report.team_id;
    // The relay makes no device link for a vault store.
    assert!(a.sync.create_link(&vault_a).is_err());

    let store = account_b
        .vault_stores()
        .expect("stores")
        .into_iter()
        .find(|store| store.team_id == team)
        .expect("B is in the store");
    assert!(!store.shared);
    let joined = RelaySync::joined_from_store(&mut account_b, &store).expect("joined");
    let download = joined.download(&b.data.join("sync")).expect("download");
    let (vault, _) = b.sync.adopt(&joined, &download, PASS).expect("adopt");
    drop((vault, download, joined));
    hand_over(&b, &account_b);
    let mut vault_b = Vault::open(&b.vault_path).unwrap();
    vault_b.unlock(PASS).unwrap();
    assert_eq!(titles(&vault_b), vec!["Alpha"]);

    vault_a.add(item("Beta")).unwrap();
    assert!(a.sync.sync(&mut vault_a).expect("A").pushed);
    b.sync.sync(&mut vault_b).expect("B merges A");
    assert_eq!(titles(&vault_b), vec!["Alpha", "Beta"]);
    vault_b.add(item("Gamma")).unwrap();
    assert!(b.sync.sync(&mut vault_b).expect("B").pushed);
    a.sync.sync(&mut vault_a).expect("A merges B");
    assert_eq!(titles(&vault_a), vec!["Alpha", "Beta", "Gamma"]);
}

/// Three devices of one account on this relay; B is behind when C pushes, and A then
/// revokes C. B waits ("Waiting for another device of this account to sync", never
/// "damaged"); A, whose own last head is C's, signs a head of its own over it at its next
/// sync, and B takes the copy again with C's head inside the chain.
#[test]
fn a_device_behind_a_head_of_a_revoked_device_waits_until_a_live_device_signs_over_it() {
    let (relay, plans) = connect();
    let owner = owner();
    let (a, b, c) = (
        app_device(&relay.url),
        app_device(&relay.url),
        app_device(&relay.url),
    );
    let (mut account_a, _) = ConnectAccount::create(
        client(&relay),
        &a.store,
        &a.path,
        "Rafal",
        "Synthetic MacBook",
    )
    .expect("create");
    plans
        .0
        .lock()
        .unwrap()
        .insert(account_a.state().account_id.clone(), entitled());
    let mut account_b = join(&relay, &owner, &mut account_a, &b, "Synthetic Mac mini");
    let mut account_c = join(&relay, &owner, &mut account_a, &c, "Synthetic iMac");

    let mut vault_a = Vault::create(&a.vault_path, PASS).unwrap();
    vault_a.unlock(PASS).unwrap();
    vault_a.add(item("Alpha")).unwrap();
    drop(vault_a);
    let mut vault_b = copy_of(&a.vault_path, &b.vault_path);
    let mut vault_c = copy_of(&a.vault_path, &c.vault_path);
    let mut vault_a = Vault::open(&a.vault_path).unwrap();
    vault_a.unlock(PASS).unwrap();
    a.sync
        .enable_on_connect(&mut vault_a, &mut account_a, "Personal")
        .expect("enable on A");
    b.sync
        .enable_on_connect(&mut vault_b, &mut account_b, "Personal")
        .expect("enable on B");
    c.sync
        .enable_on_connect(&mut vault_c, &mut account_c, "Personal")
        .expect("enable on C");

    // C pushes; A merges it; B is behind. Then A revokes C.
    vault_c.add(item("Gamma")).unwrap();
    assert!(c.sync.sync(&mut vault_c).expect("C").pushed);
    a.sync.sync(&mut vault_a).expect("A merges C");
    let c_id = account_c.state().device_id.clone();
    revoke(&owner, &mut account_a, &c_id);
    hand_over(&a, &account_a);
    account_b.view().expect("B views");
    hand_over(&b, &account_b);

    let waiting = b.sync.sync(&mut vault_b).unwrap_err();
    assert_eq!(waiting, SyncError::WaitsForAccountDevice, "{waiting}");
    assert_eq!(titles(&vault_b), vec!["Alpha"]);
    // A signs over C's head with the same content, once.
    assert!(a.sync.sync(&mut vault_a).expect("A").pushed);
    assert!(!a.sync.sync(&mut vault_a).expect("A again").pushed);
    b.sync.sync(&mut vault_b).expect("B goes on");
    assert_eq!(titles(&vault_b), vec!["Alpha", "Gamma"]);
    // C's store sign-in is refused from the revoke on.
    assert!(c.sync.sync(&mut vault_c).is_err());
}
