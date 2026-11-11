//! The Connect scenes of the tour (`APASSY_TOUR_SCENE`, scripts/screenshots-linux.sh):
//! the real window against the in-process fake Connect of the tests
//! (`tests/common/fake_connect.rs`) and its fake relay, on 127.0.0.1, never the network.
//! The other people and devices are accounts of this process with keys in memory:
//! "Alex" (the owner of a family) and "Ola" (a member). Synthetic names and values only.
//!
//! - `connect-owner`: this computer is Alex's: an account with a family, Ola in it, a
//!   second device. The tour turns on Apassy Connect sync in the window and shares the
//!   vault with Ola; Ola answers here ([`Scene::hook`]).
//! - `connect-member`: this computer is Ola's. Alex shares a vault from this process.
//! - `start-join`: no vault and no account: the start screen › Apassy Connect.
//! - `start-connect`: no vault; this computer is a device of Alex's account, whose
//!   vault is in Apassy Connect.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::connect::account::{JoinPoll, JoinRequest};
use apassy::connect::{
    ConnectAccount, ConnectClient, MemoryKeyStore, ShareLink, ShareNames, SharePeerJoin,
    account_file,
};
use apassy::sync::{RelayConfig, RelaySync};
use apassy::vault::Vault;
use eframe::egui;
use serde_json::json;
use tempfile::TempDir;

use super::fake_connect::{FakeConnect, StoreGuard, StoreRelay};
use super::fake_relay::FakeRelay;
use super::{PASS, item_draft};

/// The scenes, in the order of a full run.
pub const SCENES: &[&str] = &[
    "connect-owner",
    "connect-member",
    "start-join",
    "start-connect",
];

/// The fake relay keeps the vault stores of the fake Connect, as in tests/common/mod.rs.
impl StoreRelay for FakeRelay {
    fn url(&self) -> String {
        self.url.clone()
    }
    fn set_origin(&self, origin: &str) {
        FakeRelay::set_origin(self, origin);
    }
    fn add_store_team(
        &self,
        team_id: &str,
        name: &str,
        device_name: &str,
        public_key: &[u8],
    ) -> u64 {
        FakeRelay::add_store_team(self, team_id, name, device_name, public_key)
    }
    fn add_store_device(&self, team_id: &str, device_name: &str, public_key: &[u8]) -> u64 {
        FakeRelay::add_store_device(self, team_id, device_name, public_key)
    }
    fn remove_team(&self, team_id: &str) {
        FakeRelay::remove_team(self, team_id);
    }
    fn set_team_sync_bytes(&self, team_id: &str, bytes: u64) {
        FakeRelay::set_team_sync_bytes(self, team_id, bytes);
    }
    fn set_store_guard(&self, guard: StoreGuard) {
        FakeRelay::set_store_guard(self, guard);
    }
}

/// An owner check of a person of this process: a scratch vault with the tour passphrase.
struct Owner {
    _dir: TempDir,
    shared: SharedVault,
    gate: OwnerGate,
}

impl Owner {
    fn new() -> Self {
        let dir = TempDir::new().expect("dir");
        let mut vault = Vault::create(&dir.path().join("owner.db"), PASS).expect("vault");
        vault.unlock(PASS).expect("unlock");
        let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
        let gate = OwnerGate::new(Arc::clone(&shared), None);
        Self {
            _dir: dir,
            shared,
            gate,
        }
    }

    fn proof(&self, action: OwnerAction) -> (OwnerProof, [u8; 32]) {
        let proof = self
            .gate
            .authorize(action, OwnerCheck::passphrase(PASS))
            .expect("owner check");
        let epoch = self
            .shared
            .lock()
            .expect("vault")
            .as_ref()
            .expect("vault")
            .epoch();
        (proof, epoch)
    }
}

/// A device of a person of this process, with its own data folder.
struct Peer {
    dir: TempDir,
    /// The key store of the account: it lives as long as the account.
    _keys: MemoryKeyStore,
    account: ConnectAccount,
    owner: Owner,
}

impl Peer {
    fn data(&self) -> PathBuf {
        self.dir.path().join("Apassy")
    }

    fn id(&self) -> String {
        self.account.state().account_id.clone()
    }
}

/// A scene: the fake services and the people of this process.
pub struct Scene {
    pub connect: FakeConnect,
    _relay: Arc<FakeRelay>,
    /// The other person: Ola in `connect-owner`, Alex in `connect-member` and `start-*`.
    other: Option<Peer>,
    /// The id of the account of this computer.
    this_account: Option<String>,
    /// The store that Alex's vault syncs through, when Alex is in this process.
    team: Option<String>,
    /// The last text that the window copied (the share code of the sheet).
    pub copied: Option<String>,
    /// The share code that Alex made in this process (`connect-member`).
    pub code: Option<ShareLink>,
    /// Ola's answer to the share code of the window (`connect-owner`).
    answer: Option<SharePeerJoin>,
    /// The device link that Alex made for this computer (`start-join`).
    link: Option<apassy::connect::DeviceLink>,
}

fn client(connect: &FakeConnect) -> ConnectClient {
    ConnectClient::new(&connect.url).expect("client")
}

/// A person of this process: an account with a key in memory, entitled.
fn peer(connect: &FakeConnect, name: &str, device: &str) -> Peer {
    let dir = TempDir::new().expect("dir");
    let data = dir.path().join("Apassy");
    std::fs::create_dir_all(&data).expect("data");
    let keys = MemoryKeyStore::new();
    let (account, _code) =
        ConnectAccount::create(client(connect), &keys, &account_file(&data), name, device)
            .expect("account");
    connect.entitle(&account.state().account_id);
    Peer {
        dir,
        _keys: keys,
        account,
        owner: Owner::new(),
    }
}

/// The account of this computer, in its data folder, with the key store of the window.
fn this_account(connect: &FakeConnect, data: &Path, name: &str, device: &str) -> ConnectAccount {
    let store = apassy::connect::key_file::platform_store(data).expect("key store");
    let (account, _code) = ConnectAccount::create(
        client(connect),
        store.as_ref(),
        &account_file(data),
        name,
        device,
    )
    .expect("account of this computer");
    connect.entitle(&account.state().account_id);
    account
}

/// Join `device` to the account of `by` (the add of a device: link, join, confirm).
fn join(
    connect: &FakeConnect,
    by: &mut ConnectAccount,
    owner: &Owner,
    store: &dyn apassy::connect::DeviceKeyStore,
    path: &Path,
    device: &str,
    platform: &'static str,
) -> ConnectAccount {
    let link = by.start_link().expect("link");
    let mut request =
        JoinRequest::start_on(client(connect), store, path, link.code(), device, platform)
            .expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = by.pending_joins(&link).expect("pending");
    let id = by.state().account_id.clone();
    let (proof, epoch) = owner.proof(pending[0].owner_action(&id));
    by.confirm_join(&link, &pending[0], proof, &epoch)
        .expect("confirm");
    match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => *joined,
        other => panic!("not confirmed: {other:?}"),
    }
}

/// Alex in this process, with a family and the vault "Family" in Apassy Connect.
fn alex_with_store(connect: &FakeConnect) -> (Peer, String) {
    let mut alex = peer(connect, "Alex", "Alex's MacBook Pro");
    connect.make_group(&alex.id(), "family");
    let data = alex.data();
    let vault_path = data.join("vault.db");
    let sync = RelaySync::new(RelayConfig::in_data_dir(
        &data,
        &vault_path,
        &connect.url,
        "vault",
    ));
    let mut vault = Vault::create(&vault_path, PASS).expect("vault");
    vault.unlock(PASS).expect("unlock");
    for title in ["Garden gate code", "Streaming service", "Home router"] {
        vault.add(item_draft(title)).expect("item");
    }
    let team = sync
        .enable_on_connect(&mut vault, &mut alex.account, "Family")
        .expect("enable on Connect")
        .team_id;
    vault.lock().expect("lock");
    (alex, team)
}

/// Set up `name` before the window opens. `None` for a name that is no scene.
pub fn setup(name: &str) -> Option<Scene> {
    if !SCENES.contains(&name) {
        return None;
    }
    let relay = Arc::new(FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as Arc<dyn StoreRelay>);
    // New accounts and joins of the window go to the fake (an account keeps the origin
    // that it was made at).
    apassy::connect::client::set_configured_origin(&connect.url);
    let data = apassy::paths::data_dir();
    std::fs::create_dir_all(&data).expect("data dir");
    let mut scene = Scene {
        connect,
        _relay: relay,
        other: None,
        this_account: None,
        team: None,
        copied: None,
        code: None,
        answer: None,
        link: None,
    };
    let connect = &scene.connect;
    match name {
        "connect-owner" => {
            let mut alex = this_account(connect, &data, "Alex", "Linux desktop");
            let a_id = alex.state().account_id.clone();
            connect.make_group(&a_id, "family");
            // A second device of Alex's account: an iPhone.
            let owner = Owner::new();
            let phone = TempDir::new().expect("dir");
            let phone_keys = MemoryKeyStore::new();
            let _phone = join(
                connect,
                &mut alex,
                &owner,
                &phone_keys,
                &account_file(phone.path()),
                "Alex's iPhone",
                "iphone",
            );
            let ola = peer(connect, "Ola", "Ola's MacBook Air");
            connect.add_member(&a_id, &ola.id());
            scene.this_account = Some(a_id);
            scene.other = Some(ola);
            std::mem::forget(phone);
        }
        "connect-member" => {
            let ola = this_account(connect, &data, "Ola", "Linux desktop");
            let o_id = ola.state().account_id.clone();
            let (alex, team) = alex_with_store(connect);
            connect.add_member(&alex.id(), &o_id);
            scene.this_account = Some(o_id);
            scene.team = Some(team);
            scene.other = Some(alex);
        }
        "start-join" => scene.other = Some(peer(connect, "Alex", "Alex's MacBook Pro")),
        "start-connect" => {
            // Alex's vault goes to Apassy Connect after this computer joined, so its
            // store lists this computer.
            let mut alex = peer(connect, "Alex", "Alex's MacBook Pro");
            let store = apassy::connect::key_file::platform_store(&data).expect("key store");
            let this = join(
                connect,
                &mut alex.account,
                &alex.owner,
                store.as_ref(),
                &account_file(&data),
                "Linux desktop",
                "linux",
            );
            scene.this_account = Some(this.state().account_id.clone());
            scene.other = Some(alex);
        }
        _ => unreachable!(),
    }
    println!("scene {name} on {}", scene.connect.url);
    Some(scene)
}

impl Scene {
    /// A step of the tour that acts for the other person or on the fake (`scene NAME`).
    pub fn hook(&mut self, hook: &str) {
        let names = ShareNames {
            vaults: BTreeMap::new(),
            stores: BTreeMap::new(),
            people: BTreeMap::new(),
        };
        match hook {
            // Ola answers the share code that the window copied.
            "member-answers" => {
                let code = self.copied.clone().expect("the window copied no code");
                let ola = self.other.as_mut().expect("Ola");
                self.answer = Some(ola.account.accept_code(code.trim()).expect("answer"));
            }
            // Ola compares the words and accepts the share.
            "member-accepts" => {
                let ola = self.other.as_mut().expect("Ola");
                let answer = self.answer.take().expect("an answer");
                let action = ola.account.accept_action(&answer, &names).expect("action");
                let (proof, epoch) = ola.owner.proof(action);
                ola.account
                    .accept_share(&answer, &names, proof, &epoch)
                    .expect("accept");
            }
            // Ola joins every vault that is offered.
            "member-joins" => {
                let ola = self.other.as_mut().expect("Ola");
                let status = ola.account.refresh_shares(&[]).expect("refresh");
                let a_id = self.this_account.clone().expect("Alex");
                for offer in &status.offers {
                    let team = offer.team_id.clone();
                    let (proof, epoch) = ola
                        .owner
                        .proof(ola.account.join_action(&team, &a_id, &names));
                    ola.account
                        .join_shared_store(&team, &a_id, &[], &names, proof, &epoch)
                        .expect("join");
                }
            }
            // Alex makes a share code for this computer's account (`connect-member`).
            "owner-shares" => {
                let o_id = self.this_account.clone().expect("Ola");
                let team = self.team.clone().expect("store");
                let alex = self.other.as_mut().expect("Alex");
                self.code = Some(alex.account.start_share(&o_id, &team).expect("share code"));
            }
            // Alex confirms the words of the answer of this computer.
            "owner-confirms" => {
                let alex = self.other.as_mut().expect("Alex");
                let link = self.code.take().expect("a share code");
                let requests = alex.account.share_requests(&link).expect("requests");
                let request = requests.first().expect("an answer of this computer");
                let action = alex
                    .account
                    .share_action(&link, request, &names)
                    .expect("action");
                let (proof, epoch) = alex.owner.proof(action);
                alex.account
                    .confirm_share(&link, request, &names, proof, &epoch)
                    .expect("confirm");
            }
            // Alex makes a link to add this computer to the account (`start-join`).
            "owner-link" => {
                let alex = self.other.as_mut().expect("Alex");
                self.link = Some(alex.account.start_link().expect("link"));
            }
            // Alex sees the join of this computer and confirms it.
            "owner-confirms-join" => {
                let alex = self.other.as_mut().expect("Alex");
                let link = self.link.as_ref().expect("a link");
                let pending = alex.account.pending_joins(link).expect("pending");
                let request = pending.first().expect("the join of this computer");
                let id = alex.id();
                let (proof, epoch) = alex.owner.proof(request.owner_action(&id));
                alex.account
                    .confirm_join(link, request, proof, &epoch)
                    .expect("confirm");
            }
            // Alex puts the vault "Family" in Apassy Connect (`start-connect`).
            "owner-store" => {
                let alex = self.other.as_mut().expect("Alex");
                let data = alex.data();
                let vault_path = data.join("vault.db");
                let sync = RelaySync::new(RelayConfig::in_data_dir(
                    &data,
                    &vault_path,
                    &self.connect.url,
                    "vault",
                ));
                let mut vault = Vault::create(&vault_path, PASS).expect("vault");
                vault.unlock(PASS).expect("unlock");
                vault.add(item_draft("Garden gate code")).expect("item");
                self.team = Some(
                    sync.enable_on_connect(&mut vault, &mut alex.account, "Family")
                        .expect("enable")
                        .team_id,
                );
                vault.lock().expect("lock");
            }
            // The plan of this computer's account in another state.
            "plan-past-due" => self.plan(json!({"plan": "family", "status": "past_due",
                "entitled": true, "interval": "month", "quantity": 4, "renews_at": null,
                "ends_at": null, "grace_until": now() + 7 * 86_400, "read_only_until": null,
                "delete_at": null})),
            "plan-read-only" => self.plan(json!({"plan": "family", "status": "read_only",
                "entitled": false, "interval": "month", "quantity": 4, "renews_at": null,
                "ends_at": null, "grace_until": null, "read_only_until": now() + 55 * 86_400,
                "delete_at": now() + 113 * 86_400})),
            "plan-active" => self.plan(json!({"plan": "family", "status": "active",
                "entitled": true, "interval": "month", "quantity": 4,
                "renews_at": now() + 30 * 86_400, "ends_at": null, "grace_until": null,
                "read_only_until": null, "delete_at": null})),
            // The stores of the account cannot be read (the start screen › Apassy Connect).
            "stores-error" => {
                self.connect
                    .answer_route_error("GET /v1/account/vaults", 503, "unavailable");
            }
            // A device row that the signed list does not hold.
            "unlisted-device" => {
                let id = self.this_account.clone().expect("account");
                self.connect
                    .insert_device(&id, "Unknown MacBook", &[7u8; 65]);
            }
            other => panic!("unknown scene hook {other}"),
        }
    }

    /// The share code or the device link that Alex made, for a paste in the window.
    pub fn code_text(&self) -> String {
        self.code
            .as_ref()
            .map(|link| link.code().to_owned())
            .or_else(|| self.link.as_ref().map(|link| link.code().to_owned()))
            .expect("owner-shares or owner-link first")
    }

    fn plan(&self, plan: serde_json::Value) {
        let id = self.this_account.clone().expect("account");
        self.connect.set_plan(&id, plan);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The rows of the Settings list (points of the 1100 x 760 window).
const SETTINGS_X: f32 = 366.0;
const VAULT_ROW: f32 = 70.0;
const SECURITY_ROW: f32 = 118.0;
const DEVICES_ROW: f32 = 166.0;
const CONNECT_ROW: f32 = 214.0;
const TOOLS_ROW: f32 = 310.0;

/// The steps of a scene after the unlock (or the start, for `start-*`). Positions are in
/// points of the 1100 x 760 window of scripts/screenshots-linux.sh; they were read from
/// snaps of a live tour (`APASSY_TOUR_LIVE`). A Shot that misses its state shows the
/// state it reached: check each image.
pub(crate) fn steps(name: &str) -> Vec<super::Step> {
    use super::Step::*;
    let cmd = egui::Modifiers::COMMAND;
    let enter = || Key(egui::Key::Enter, egui::Modifiers::NONE);
    let escape = || Key(egui::Key::Escape, egui::Modifiers::NONE);
    let bottom = || Scroll(800.0, 450.0, -3000.0);
    let top = || Scroll(800.0, 450.0, 3000.0);
    let settings = [Key(egui::Key::Comma, cmd), Wait(1.5)];
    let mut steps = Vec::new();
    match name {
        "linux" => {
            steps.extend(settings);
            steps.extend([
                Click(SETTINGS_X, VAULT_ROW),
                Wait(1.0),
                Shot("linux-settings-vault"),
                Click(SETTINGS_X, SECURITY_ROW),
                Wait(1.0),
                Pages("linux-settings-security"),
                Click(SETTINGS_X, DEVICES_ROW),
                Wait(1.5),
                Pages("linux-settings-devices"),
                Click(SETTINGS_X, CONNECT_ROW),
                Wait(1.5),
                Pages("linux-settings-connect-none"),
                Click(SETTINGS_X, TOOLS_ROW),
                Wait(2.0),
                Pages("linux-settings-tools"),
            ]);
        }
        "connect-owner" => {
            steps.extend(settings);
            steps.extend([
                // Settings › Vault › Sync: the picker, the setup sheet, Apassy Connect.
                Click(SETTINGS_X, VAULT_ROW),
                Wait(3.0),
                Click(950.0, 268.0),
                Wait(1.0),
                Shot("sync-picker"),
                Click(891.0, 330.0),
                Wait(1.5),
                Shot("sync-setup-default"),
                Click(292.0, 290.0),
                Wait(1.0),
                Shot("sync-setup-connect"),
                Click(860.0, 485.0),
                Wait(4.0),
                Shot("sync-connect-on"),
                // Settings › Connect: the account, then Shared Vaults.
                Click(SETTINGS_X, CONNECT_ROW),
                Wait(3.0),
                Pages("connect-live-account"),
                top(),
                Wait(1.0),
                Click(1025.0, 432.0),
                Wait(1.5),
                Shot("connect-live-revoke"),
                Click(720.0, 417.0),
                Wait(2.0),
                Shot("owner-check-revoke"),
                escape(),
                // Shared Vaults lists the new store after its next read (every 60 s).
                Wait(62.0),
                bottom(),
                Wait(1.0),
                Shot("share-section"),
                Click(1016.0, 659.0),
                Wait(1.5),
                Shot("share-pick"),
                Click(370.0, 384.0),
                Wait(0.8),
                Shot("share-pick-chosen"),
                Click(721.0, 436.0),
                Wait(3.0),
                Shot("share-code"),
                // Copy the code: Ola answers it from this process.
                Click(726.0, 407.0),
                Wait(1.0),
                Hook("member-answers"),
                Wait(7.0),
                Shot("share-words-owner"),
                Click(717.0, 465.0),
                Wait(2.0),
                Shot("owner-check-share"),
                Type(super::PASS),
                enter(),
                Wait(4.0),
                Shot("share-done"),
                Click(732.0, 410.0),
                Wait(1.0),
                bottom(),
                Wait(1.0),
                Shot("share-not-compared"),
                Hook("member-accepts"),
                // The section reads the lists again every 60 s while it shows.
                Wait(63.0),
                bottom(),
                Wait(1.0),
                Shot("share-not-joined"),
                Hook("member-joins"),
                Wait(63.0),
                bottom(),
                Wait(1.0),
                Shot("share-syncs"),
                Click(913.0, 659.0),
                Wait(1.5),
                Shot("share-stop"),
                escape(),
                Wait(1.0),
                Click(991.0, 457.0),
                Wait(2.0),
                Shot("owner-check-recovery"),
                Type(super::PASS),
                enter(),
                Wait(4.0),
                Shot("recovery-new-code"),
                // "I Saved It": the sheet of the code does not close with Escape.
                Click(730.0, 512.0),
                Wait(1.0),
                // The hooks plan-past-due, plan-read-only and unlisted-device change the
                // fake, but the window reads the account again only on its own schedule:
                // within a scene the plan rows and the Sync tags keep their first state.
            ]);
        }
        "connect-member" => {
            steps.extend(settings);
            steps.extend([
                Click(SETTINGS_X, CONNECT_ROW),
                Wait(3.0),
                Pages("connect-live-member"),
                bottom(),
                Wait(1.0),
                Hook("owner-shares"),
                Click(987.0, 697.0),
                Wait(1.5),
                Shot("share-accept-empty"),
                PasteCode,
                Wait(1.0),
                Shot("share-accept-code"),
                Click(721.0, 429.0),
                Wait(4.0),
                Shot("share-words-member"),
                Click(690.0, 465.0),
                Wait(2.0),
                Shot("owner-check-accept"),
                Type(super::PASS),
                enter(),
                Wait(4.0),
                Shot("share-accepted"),
                escape(),
                Hook("owner-confirms"),
                Wait(63.0),
                bottom(),
                Wait(1.0),
                Shot("share-offer-join"),
                Click(1040.0, 659.0),
                Wait(2.0),
                Shot("owner-check-join"),
                Type(super::PASS),
                enter(),
                Wait(6.0),
                bottom(),
                Wait(1.0),
                Shot("share-joined"),
                Click(983.0, 659.0),
                Wait(1.5),
                Shot("share-leave"),
                escape(),
                Wait(1.0),
                // The vault menu › Use a vault from Apassy Connect…, with a vault open.
                Click(100.0, 723.0),
                Wait(1.0),
                Shot("vault-menu"),
                Click(120.0, 643.0),
                Wait(4.0),
                Shot("open-connect-list"),
                Click(685.0, 464.0),
                Wait(6.0),
                Shot("open-connect-passphrase"),
            ]);
        }
        "start-connect" => steps.extend([
            Wait(1.0),
            Shot("start-screen"),
            Click(550.0, 466.0),
            Wait(1.5),
            Click(612.0, 350.0),
            Wait(4.0),
            Shot("start-connect-empty"),
            Hook("owner-store"),
            Click(390.0, 481.0),
            Wait(4.0),
            Shot("start-connect-list"),
            Click(685.0, 464.0),
            Wait(6.0),
            Shot("start-connect-passphrase"),
            Click(371.0, 552.0),
            Wait(2.0),
            Shot("start-connect-after-cancel"),
            Click(380.0, 244.0),
            Wait(1.5),
            Hook("stores-error"),
            Click(550.0, 466.0),
            Wait(1.5),
            Click(612.0, 350.0),
            Wait(5.0),
            Shot("start-connect-error"),
        ]),
        "start-join" => steps.extend([
            Wait(1.0),
            Click(550.0, 466.0),
            Wait(1.5),
            Click(612.0, 350.0),
            Wait(3.0),
            Shot("start-connect-join"),
            Hook("owner-link"),
            Click(550.0, 460.0),
            Wait(1.5),
            Shot("start-join-code-empty"),
            PasteCode,
            Wait(1.0),
            Shot("start-join-code"),
            Click(721.0, 429.0),
            Wait(4.0),
            Shot("start-join-words"),
            Hook("owner-confirms-join"),
            Wait(8.0),
            Shot("start-join-added"),
            Click(732.0, 435.0),
            Wait(4.0),
            Shot("start-join-after"),
        ]),
        _ => steps.extend([Wait(2.0), Shot(leak(&format!("{name}-start")))]),
    }
    steps
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_owned().into_boxed_str())
}
