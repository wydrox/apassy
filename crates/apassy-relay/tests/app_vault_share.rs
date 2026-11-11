//! A vault shared between two accounts of one Family group (contract connect-account-v1
//! section 16; docs/SPEC.md section 33): the real `src/connect` client and the real relay
//! sync of the app (`apassy::sync::RelaySync`) against this relay with the account routes.
//! A shares its store with X after the ceremony of six words, X joins it and downloads the
//! copy with its passphrase, both sync in both directions, and after A's `unshare` the
//! relay refuses X's sign-in to the store and A's devices take no later head of X. Each
//! test starts its own relay on a free loopback port in a temporary directory. Synthetic
//! values only.

#[path = "common/relay.rs"]
mod relay;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::connect::{
    ConnectAccount, ConnectClient, MemoryKeyStore, ShareNames, account_file, signer_policy,
};
use apassy::contracts::CredentialKind;
use apassy::sync::{RelayConfig as AppRelayConfig, RelaySync};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_relay::api::PlanView;
use apassy_relay::config::{ConnectConfig, ConnectSigningKey, EdgeMode, UpstreamOptions};
use apassy_relay::server::account::Plans;
use apassy_relay::server::store::Store;
use relay::{TestRelay, start_with};

const PASS: &str = "synthetic-share-pass";

/// The Ed25519 seed bytes 32 to 63 as a PKCS#8 v1 DER file: the entitlement key.
fn signing_key() -> ConnectSigningKey {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend(32u8..64);
    ConnectSigningKey::from_file_bytes(&der).expect("signing key")
}

/// Every account of the test has Connect Family.
#[derive(Default)]
struct FamilyPlans(Mutex<HashMap<String, PlanView>>);

impl Plans for FamilyPlans {
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

fn family_plan() -> PlanView {
    PlanView {
        plan: Some("family".into()),
        status: "active".into(),
        entitled: true,
        interval: Some("month".into()),
        quantity: Some(2),
        ..PlanView::none()
    }
}

fn connect() -> (TestRelay, Arc<FamilyPlans>) {
    let relay = start_with(
        |cfg| {
            cfg.connect = ConnectConfig::accounts(Some(signing_key()));
            cfg.edge = EdgeMode::Off;
        },
        UpstreamOptions::default(),
    );
    let plans = Arc::new(FamilyPlans::default());
    relay.hub().set_plans(plans.clone());
    (relay, plans)
}

/// One device of the app: its data folder, key store, account file, and the relay sync of
/// its vault for the Connect origin.
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

/// The window's hand-over of the account to the relay sync of a vault.
fn hand_over(device: &AppDevice, account: &ConnectAccount) {
    device
        .sync
        .set_account_signer(Some(account.signer().unwrap()));
    device
        .sync
        .set_account_signers(Some(signer_policy(account.state())));
}

/// `owner` and `member` as active members of one Family group, in the directory as the
/// groups of connect-billing-v1 keep them.
fn same_family(relay: &TestRelay, owner: &str, member: &str) {
    let sql = format!(
        "INSERT INTO \"group\" (id, kind, owner_account, created_at) VALUES ('grp_f4m6n2p7qa', 'family', '{owner}', 1);
         INSERT INTO group_member (group_id, account_id, role, state, created_at, joined_at) VALUES
           ('grp_f4m6n2p7qa', '{owner}', 'owner', 'active', 1, 1),
           ('grp_f4m6n2p7qa', '{member}', 'member', 'active', 1, 1);
         UPDATE account SET group_id = 'grp_f4m6n2p7qa' WHERE id IN ('{owner}', '{member}');"
    );
    relay
        .hub()
        .directory
        .store
        .with(|conn| {
            conn.execute_batch(&sql)
                .map_err(apassy_relay::server::store::db)
        })
        .unwrap();
}

/// A shares its vault with X (another account of its family): the ceremony with six words
/// on one device of each, the share, X's join, the download with the passphrase of the
/// copy, and syncs in both directions. After A's `unshare` the relay refuses X's sign-in
/// to the store, and A keeps its vault and syncs on.
#[test]
fn two_accounts_of_a_family_share_a_vault_and_end_it() {
    let (relay, plans) = connect();
    let (owner_a, owner_x) = (owner(), owner());
    let (a, x) = (app_device(&relay.url), app_device(&relay.url));
    let (mut account_a, _) = ConnectAccount::create(
        client(&relay),
        &a.store,
        &a.path,
        "Rafal",
        "Synthetic MacBook",
    )
    .expect("create A");
    let (mut account_x, _) =
        ConnectAccount::create(client(&relay), &x.store, &x.path, "Ola", "Synthetic iMac")
            .expect("create X");
    let (a_id, x_id) = (
        account_a.state().account_id.clone(),
        account_x.state().account_id.clone(),
    );
    for account in [&a_id, &x_id] {
        plans
            .0
            .lock()
            .unwrap()
            .insert(account.clone(), family_plan());
    }
    same_family(&relay, &a_id, &x_id);

    let mut vault_a = Vault::create(&a.vault_path, PASS).unwrap();
    vault_a.unlock(PASS).unwrap();
    vault_a.add(item("Alpha")).unwrap();
    let team = a
        .sync
        .enable_on_connect(&mut vault_a, &mut account_a, "Family")
        .expect("enable on A")
        .team_id;

    // The ceremony: A makes the code, X answers it, both show the same six words.
    let link = account_a.start_share(&x_id, &team).expect("share code");
    let answer = account_x.accept_code(link.code()).expect("answer");
    let requests = account_a.share_requests(&link).expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].words, answer.words);
    assert_eq!(requests[0].account_id, x_id);
    let names = ShareNames::default();
    let (proof, epoch) = owner_a.proof(account_a.share_action(&link, &requests[0], &names));
    let confirmed = account_a
        .confirm_share(&link, &requests[0], &names, proof, &epoch)
        .expect("A confirms");
    assert_eq!(confirmed.added.len(), 1, "{confirmed:?}");
    let (proof, epoch) = owner_x.proof(account_x.accept_action(&answer, &names));
    account_x
        .accept_share(&answer, &names, proof, &epoch)
        .expect("X accepts");

    // X sees the offer and joins it.
    let status = account_x.refresh_shares(&[]).expect("X refreshes");
    assert_eq!(status.offers.len(), 1, "{status:?}");
    assert_eq!(status.offers[0].team_id, team);
    let (proof, epoch) = owner_x.proof(account_x.join_action(&team, &a_id, &names));
    account_x
        .join_shared_store(&team, &a_id, &[], &names, proof, &epoch)
        .expect("X joins");
    let store = account_x
        .vault_stores()
        .expect("stores")
        .into_iter()
        .find(|store| store.team_id == team)
        .expect("X is in the store");
    assert!(store.shared);
    let joined = RelaySync::joined_from_store(&mut account_x, &store).expect("joined");
    let download = joined.download(&x.data.join("sync")).expect("download");
    let (vault, _) = x.sync.adopt(&joined, &download, PASS).expect("adopt");
    drop((vault, download, joined));
    hand_over(&x, &account_x);
    let mut vault_x = Vault::open(&x.vault_path).unwrap();
    vault_x.unlock(PASS).unwrap();
    assert_eq!(titles(&vault_x), vec!["Alpha"]);

    // Both sync in both directions.
    account_a.refresh_shares(&[]).expect("A refreshes");
    hand_over(&a, &account_a);
    vault_x.add(item("Beta")).unwrap();
    assert!(x.sync.sync(&mut vault_x).expect("X").pushed);
    a.sync.sync(&mut vault_a).expect("A merges X");
    assert_eq!(titles(&vault_a), vec!["Alpha", "Beta"]);
    vault_a.add(item("Gamma")).unwrap();
    assert!(a.sync.sync(&mut vault_a).expect("A").pushed);
    x.sync.sync(&mut vault_x).expect("X merges A");
    assert_eq!(titles(&vault_x), vec!["Alpha", "Beta", "Gamma"]);

    // A stops sharing with X: the relay removes X from the store in the same step.
    let (proof, epoch) = owner_a.proof(account_a.end_share_action(&team, &x_id, &names, false));
    account_a
        .stop_sharing(&team, &x_id, &names, proof, &epoch)
        .expect("unshare");
    hand_over(&a, &account_a);
    let policy = signer_policy(account_a.state()).for_team(&team);
    assert!(!policy.accepts(account_x.signer().unwrap().public_key()));
    assert!(policy.left_key(account_x.signer().unwrap().public_key()));
    vault_x.add(item("Delta")).unwrap();
    assert!(x.sync.sync(&mut vault_x).is_err(), "X is out of the store");
    vault_a.add(item("Epsilon")).unwrap();
    assert!(a.sync.sync(&mut vault_a).expect("A goes on").pushed);
    assert_eq!(titles(&vault_a), vec!["Alpha", "Beta", "Epsilon", "Gamma"]);
    // X's list keeps its join until X leaves; the pin of the pair stays, so a new share
    // needs no words.
    assert!(account_a.is_pinned_peer(&x_id));
}
