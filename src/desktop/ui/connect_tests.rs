//! Headless tests of the fixes of the Apassy Connect review on the Mac:
//!
//! - a `401` of the questions team (a team that the relay forgot, or suspended) deletes
//!   nothing: a read of another vault or team is dropped, a `401` that passes heals, and
//!   only "Connect again?" with the owner check puts a new team in place of the old one;
//! - "Stop approvals here" on the only Mac, then "Approve here…", connects again;
//! - a proof names its purpose and team, and a late confirmation keeps its team;
//! - "Use another relay…" closes an unused pairing window;
//! - a pasted link follows its `r`.
//!
//! A fake relay runs on this computer. All values are synthetic.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::devices::{DevicesSheet, HubProblem};
use super::sync::questions::{CONNECT_AGAIN, CONNECT_AGAIN_NO_MAC};
use super::sync::relay::CONNECT_LINK_IN_SYNC;
use super::{Sheet, draw, start};
use crate::broker::approvals::{OwnerAction, OwnerCheck};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::OwnerRequest;
use crate::relay::membership::{QuestionsAvailability, questions_availability};
use crate::sync::{PendingJoin, SyncError, SyncFolder};
use crate::vault::{RelayMembership, TrustedDevice, TrustedDeviceKind};

/// The fake relay reads the app's sync module under this name.
use crate::sync as relay_api;
/// The sync tests load the same file for their own use.
#[allow(clippy::duplicate_mod)]
#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

const PASS: &str = "connect-ui-pass-ok";
const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);
const CODE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A temporary iCloud Drive with its Apassy folder.
struct Folders {
    root: TempDir,
    icloud: PathBuf,
}

fn folders() -> Folders {
    let root = TempDir::new().expect("temp dir");
    let drive = root
        .path()
        .join("Mobile Documents")
        .join("com~apple~CloudDocs");
    std::fs::create_dir_all(&drive).expect("icloud drive");
    Folders {
        icloud: drive.join("Apassy"),
        root,
    }
}

impl Folders {
    fn mac(&self, name: &str) -> DesktopApp {
        let mut app = DesktopApp::new();
        app.load_vault_list(self.root.path().join(name), true);
        app.sync.offered = true;
        app.sync.icloud = Some(self.icloud.clone());
        app.sync.folders = vec![SyncFolder {
            label: "iCloud Drive".to_owned(),
            path: self.icloud.clone(),
        }];
        app
    }
}

/// Three frames of the whole app. Returns the painted text of the last frame.
fn frames(app: &mut DesktopApp) -> String {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn collect(shape: &egui::Shape, out: &mut String) {
    match shape {
        egui::Shape::Text(text) => {
            out.push_str(text.galley.text());
            out.push('\n');
        }
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| collect(inner, out)),
        _ => {}
    }
}

fn create(app: &mut DesktopApp, name: &str, folder: &Path) {
    let ctx = egui::Context::default();
    app.vault_list.name_input = name.to_owned();
    app.owner_ui.passphrase.push_str(PASS);
    app.owner_ui.passphrase_confirm.push_str(PASS);
    app.sync.create_folder = Some(folder.to_path_buf());
    start::create_vault(app, &ctx);
    assert!(
        !app.owner_ui.session.is_locked(),
        "create failed: {}",
        app.status_text
    );
}

fn lock(app: &mut DesktopApp) {
    let ctx = egui::Context::default();
    app.lock_vault(Some(&ctx));
    assert!(app.owner_ui.session.is_locked());
}

fn unlock(app: &mut DesktopApp) {
    let ctx = egui::Context::default();
    app.owner_ui.passphrase.push_str(PASS);
    start::unlock_with_passphrase(app, &ctx);
    assert!(!app.owner_ui.session.is_locked(), "{}", app.status_text);
}

fn current_id(app: &DesktopApp) -> String {
    app.vault_list.current.clone().expect("open vault")
}

fn questions_of(app: &DesktopApp) -> Option<RelayMembership> {
    app.owner_ui
        .session
        .with_vault(|vault| crate::relay::membership::questions_membership(vault).expect("read"))
        .flatten()
}

fn named_team(app: &DesktopApp) -> Option<String> {
    app.owner_ui
        .session
        .with_vault(|vault| vault.questions_team().expect("read"))
        .flatten()
}

fn macs(app: &DesktopApp) -> Vec<TrustedDevice> {
    app.owner_ui
        .session
        .with_vault(|vault| vault.trusted_devices().expect("read"))
        .expect("open")
        .into_iter()
        .filter(|device| device.kind == TrustedDeviceKind::Mac)
        .collect()
}

/// Mac A with "Personal" in iCloud Drive, connected to Apassy Connect on the fake relay
/// by its first "Add a device…" and the owner check. Returns the app, the vault ID, and
/// the team; the "Add a device" sheet is open with the link of the team.
fn connected(folders: &Folders, relay: &fake_relay::FakeRelay) -> (DesktopApp, String, String) {
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", &folders.icloud);
    let id = current_id(&a);
    super::open_settings(&mut a, super::SettingsSection::Devices);
    assert!(a.set_connect_relay_url(&relay.url));
    a.devices_add(None);
    a.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    a.questions_settle_for_test();
    let team = questions_of(&a).expect("connected").team_id;
    assert_eq!(named_team(&a).as_deref(), Some(team.as_str()));
    (a, id, team)
}

/// Close the "Add a device" sheet.
fn close_add(app: &mut DesktopApp) {
    app.ui.sheet = None;
    app.relay_sheet_closed();
}

/// Ask the relay for the devices of the questions team now, and take the answer.
fn read_devices(app: &mut DesktopApp) -> Option<HubProblem> {
    app.questions_refresh_devices();
    let _ = app.devices_hub();
    app.questions_settle_for_test();
    app.devices_hub().problem
}

/// The relay forgets nothing for a `401` that passes (a suspended team that the next
/// sign-in wakes): Settings > Devices says the team is gone, keeps the membership, asks
/// again, and the next answer that works heals it.
#[test]
fn a_401_that_passes_heals_without_dropping_the_team() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, _, team) = connected(&folders, &relay);
    close_add(&mut a);
    assert_eq!(read_devices(&mut a), None);

    relay.fail_next("POST /v1/auth/challenge", 1, 401);
    assert_eq!(read_devices(&mut a), Some(HubProblem::Gone));
    assert_eq!(
        questions_of(&a).expect("kept").team_id,
        team,
        "nothing dropped"
    );
    assert_eq!(named_team(&a).as_deref(), Some(team.as_str()));

    assert_eq!(read_devices(&mut a), None, "healed");
    assert_eq!(questions_of(&a).expect("kept").team_id, team);
    assert_eq!(relay.team_ids(), [team], "no new team");
}

/// A read of the devices counts only for the vault and the team it was asked for, and a
/// lock forgets what the relay said.
#[test]
fn a_401_for_another_vault_or_team_is_ignored() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id, team) = connected(&folders, &relay);
    close_add(&mut a);
    a.questions_answer_for_test("another-vault", &team, Err(SyncError::RemovedFromRelay));
    a.questions_answer_for_test(&id, "t_aaaaaaaaaa", Err(SyncError::RemovedFromRelay));
    assert!(!a.sync.relay.questions.gone(&id, &team));
    assert!(!a.sync.relay.questions.gone("another-vault", &team));
    a.questions_answer_for_test(&id, &team, Err(SyncError::RemovedFromRelay));
    assert!(a.sync.relay.questions.gone(&id, &team));
    // A lock forgets it; the vault asks again after the unlock.
    lock(&mut a);
    assert!(!a.sync.relay.questions.gone(&id, &team));
    unlock(&mut a);
    assert!(!a.sync.relay.questions.gone(&id, &team));
    assert_eq!(questions_of(&a).expect("kept").team_id, team);
}

/// A team that the relay really forgot: "Add a device…" deletes nothing, asks the relay
/// once more, then asks "Connect again?". After the owner check the new Connect team takes
/// the place of the old one in the vault: one membership, the vault names the new team,
/// and the row of this Mac keeps its UUID with the new key, out of the old team.
#[test]
fn a_forgotten_team_connects_again_after_the_question_and_the_owner_check() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id, old) = connected(&folders, &relay);
    close_add(&mut a);
    let mac_before = macs(&a);
    assert_eq!(mac_before.len(), 1);
    relay.delete_team(&old);
    assert_eq!(read_devices(&mut a), Some(HubProblem::Gone));

    a.devices_add(None);
    assert!(
        matches!(
            &a.ui.sheet,
            Some(Sheet::Devices(DevicesSheet::ConnectAgain { team_id, gone: true })) if *team_id == old
        ),
        "{:?}",
        a.ui.sheet
    );
    assert!(a.owner.check.is_none(), "no owner check before the answer");
    assert_eq!(
        questions_of(&a).expect("kept").team_id,
        old,
        "nothing dropped"
    );
    // The sheet asks the relay once more; it still refuses, so the question shows.
    let _ = frames(&mut a);
    a.questions_settle_for_test();
    let text = frames(&mut a);
    for expected in [CONNECT_AGAIN, "Connect with Touch ID", "Cancel"] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert_eq!(questions_of(&a).expect("kept").team_id, old);

    let entry = a.vault_list.registry.get(&id).cloned().expect("entry");
    a.questions_ask_connect_again(&entry, &old, None);
    let request = a.owner.check.as_ref().expect("owner check").request.clone();
    assert!(
        matches!(request, OwnerRequest::ConnectVault { .. }),
        "{request:?}"
    );
    assert_eq!(
        request.action(),
        OwnerAction::EnableRelayQuestions {
            relay_url: relay.url.clone(),
            team_id: None,
        }
    );
    assert!(
        request
            .describe()
            .starts_with("Connect this vault to Apassy Connect.")
            && !request.describe().contains("code"),
        "{}",
        request.describe()
    );
    a.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    a.questions_settle_for_test();
    let new = questions_of(&a).expect("connected again");
    assert_ne!(new.team_id, old);
    assert_eq!(
        named_team(&a).as_deref(),
        Some(new.team_id.as_str()),
        "no stale team"
    );
    let memberships = a
        .owner_ui
        .session
        .with_vault(|vault| vault.relay_memberships().expect("read"))
        .expect("open");
    assert_eq!(memberships.len(), 1, "the old key is gone");
    let mac_after = macs(&a);
    assert_eq!(mac_after.len(), 1, "one row for this Mac");
    assert_eq!(mac_after[0].uuid, mac_before[0].uuid);
    assert_eq!(mac_after[0].sign_key, new.public_key);
    assert_eq!(
        mac_after[0].relay_devices.get(&new.team_id),
        Some(&new.device_id)
    );
    assert!(!mac_after[0].relay_devices.contains_key(&old));
    // "Add a device" goes on with the link of the new team.
    assert!(
        matches!(&a.ui.sheet, Some(Sheet::Devices(DevicesSheet::AddDevice))),
        "{:?}",
        a.ui.sheet
    );
    assert_eq!(read_devices(&mut a), None);
}

/// "Stop approvals here" on the only Mac of the team, then "Approve here…": no Mac is left
/// to add this one back, so it asks "Connect again?" instead of a link that no device can
/// make, and connects with a new team after the owner check.
#[test]
fn stop_approvals_on_the_only_mac_then_approve_here_connects_again() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id, old) = connected(&folders, &relay);
    close_add(&mut a);
    a.questions_turn_off();
    assert!(questions_of(&a).is_none());
    let availability = a
        .owner_ui
        .session
        .with_vault(|vault| questions_availability(vault).expect("read"))
        .expect("open");
    assert_eq!(
        availability,
        QuestionsAvailability::JoinTeam {
            team_id: old.clone()
        }
    );
    assert!(a.devices_hub().rows[0].approve_here);

    a.questions_turn_on(None);
    assert!(
        matches!(
            &a.ui.sheet,
            Some(Sheet::Devices(DevicesSheet::ConnectAgain { team_id, gone: false })) if *team_id == old
        ),
        "{:?}",
        a.ui.sheet
    );
    let text = frames(&mut a);
    assert!(text.contains(CONNECT_AGAIN_NO_MAC), "{text}");
    let entry = a.vault_list.registry.get(&id).cloned().expect("entry");
    a.questions_ask_connect_again(&entry, &old, None);
    a.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    a.questions_settle_for_test();
    let new = questions_of(&a).expect("approves again");
    assert_ne!(new.team_id, old);
    assert_eq!(named_team(&a).as_deref(), Some(new.team_id.as_str()));
    assert_eq!(macs(&a).len(), 1);
}

/// An iPhone asks with the link of the open "Add a device" sheet of `a`. Returns its join,
/// the name of its link, and the link number on the relay.
fn iphone_asks(a: &mut DesktopApp) -> (PendingJoin, String, u64, Vec<u8>) {
    a.relay_settle_for_test();
    let _ = frames(a);
    a.relay_settle_for_test();
    let link = a.relay_add_mac_link_for_test().expect("a link");
    let phone_key = crate::sync::DeviceKey::generate().expect("key");
    let link_name =
        crate::questions::device_link::link_device_name("Test iPhone", phone_key.public_key())
            .expect("name");
    let pending = PendingJoin::request(&link, "", &link_name).expect("join");
    a.relay_add_mac_poll_for_test();
    let links = a.relay_add_mac_links_for_test();
    assert_eq!(links.len(), 1);
    (pending, link_name, links[0].id, links[0].public_key.clone())
}

/// The proof of a confirmation names its purpose and its team: a proof for the sync of the
/// same link, or for the questions of another team, confirms nothing, and a questions
/// proof never goes the sync route.
#[test]
fn a_questions_proof_cannot_satisfy_a_sync_confirmation() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id, team) = connected(&folders, &relay);
    let (pending, link_name, link_id, public_key) = iphone_asks(&mut a);
    let questions = OwnerAction::ConfirmQuestionsDevice {
        team_id: team.clone(),
        link_id,
        device_name: link_name.clone(),
        public_key: public_key.clone(),
    };
    let sync = OwnerAction::ConfirmSyncDevice {
        link_id,
        device_name: link_name.clone(),
        public_key: public_key.clone(),
    };
    a.relay_ask_confirm_for_test(link_id);
    let request = a.owner.check.as_ref().expect("owner check").request.clone();
    assert_eq!(request.action(), questions);
    assert_ne!(questions, sync);

    // A proof for the sync confirmation of the same link.
    let proof = a
        .owner_gate()
        .authorize(sync, OwnerCheck::passphrase(PASS))
        .expect("proof");
    a.finish_owner_check_with(proof);
    a.relay_settle_for_test();
    assert!(pending.poll().expect("poll").is_none(), "not confirmed");

    // A proof for the questions of another team.
    a.relay_ask_confirm_for_test(link_id);
    let proof = a
        .owner_gate()
        .authorize(
            OwnerAction::ConfirmQuestionsDevice {
                team_id: "t_aaaaaaaaaa".to_owned(),
                link_id,
                device_name: link_name.clone(),
                public_key: public_key.clone(),
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    a.finish_owner_check_with(proof);
    a.relay_settle_for_test();
    assert!(pending.poll().expect("poll").is_none(), "not confirmed");

    // The right proof on the sync route: the sheet adds through the questions team.
    let proof = a
        .owner_gate()
        .authorize(questions.clone(), OwnerCheck::passphrase(PASS))
        .expect("proof");
    a.relay_confirm_link(&id, link_id, None, proof);
    a.relay_settle_for_test();
    assert!(
        a.status_text.contains("changed its team"),
        "{}",
        a.status_text
    );
    assert!(pending.poll().expect("poll").is_none(), "not confirmed");

    // The right proof on its route confirms.
    a.relay_ask_confirm_for_test(link_id);
    a.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    a.relay_settle_for_test();
    assert!(pending.poll().expect("poll").is_some(), "confirmed");
}

/// A confirmation whose answer comes after the sheet changed its team still writes the row
/// of the iPhone in the team that the owner confirmed it for.
#[test]
fn a_late_confirmation_writes_the_row_in_its_own_team() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id, team) = connected(&folders, &relay);
    let (pending, _, link_id, _) = iphone_asks(&mut a);
    a.relay_ask_confirm_for_test(link_id);
    a.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    // Before the answer, the sheet starts over on the route of relay sync.
    a.relay_add_device_start(&id, false);
    a.relay_settle_for_test();
    let joined = pending.poll().expect("poll").expect("confirmed");
    let row = a
        .owner_ui
        .session
        .with_vault(|vault| {
            vault
                .trusted_devices()
                .expect("read")
                .into_iter()
                .find(|device| device.kind == TrustedDeviceKind::Iphone)
        })
        .expect("open")
        .expect("the row of the iPhone");
    assert_eq!(row.relay_devices.get(&team), Some(&joined.device_id()));
    assert_eq!(row.relay_devices.len(), 1);
    assert_eq!(
        a.status_text, "Test iPhone is connected. It approves with Face ID.",
        "{}",
        a.status_text
    );
}

/// The removal of a Mac of two teams says so when the sync team did not remove it, even
/// when the questions team did.
#[test]
fn a_failed_sync_removal_is_not_hidden_by_the_questions_one() {
    let folders = folders();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", &folders.icloud);
    a.questions_revoked_for_test(
        "Mac mini",
        Some(Ok(())),
        Some(Err(SyncError::RelayUnreachable)),
    );
    assert!(
        a.status_text
            .starts_with("“Mac mini” can no longer answer, but it is not removed from the sync."),
        "{}",
        a.status_text
    );
    a.questions_revoked_for_test("Mac mini", Some(Ok(())), Some(Ok(())));
    assert!(
        a.status_text.starts_with(
            "“Mac mini” is removed. It can no longer sync or answer, and the relay removed its devices."
        ),
        "{}",
        a.status_text
    );
}

/// "Use another relay…" closes a pairing window that "Add a device" opened and no iPhone
/// used, as Done and Escape do.
#[test]
fn use_another_relay_closes_an_unused_pairing_window() {
    use crate::companion::pairing::PairingView;
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = super::owner_tests::unlocked_app_with_item(&dir);
    app.start_broker(&super::owner_tests::socket_dir(&dir));
    let port = std::net::TcpListener::bind(("0.0.0.0", 0))
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    {
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().expect("vault");
        guard
            .as_mut()
            .expect("open vault")
            .set_companion_port(port)
            .expect("port");
    }
    app.companion.test_options.link_hosts = Some(vec!["192.0.2.10".to_owned()]);
    app.companion.test_options.allow_local_peers = true;
    let ctx = egui::Context::default();
    app.set_companion_on(true);
    app.open_pairing(&ctx);
    let deadline = Instant::now() + Duration::from_secs(20);
    while app.companion.invite.is_none() {
        assert!(Instant::now() < deadline, "the pairing window");
        std::thread::sleep(Duration::from_millis(10));
        app.poll_companion(&ctx);
    }
    assert!(matches!(
        app.companion_controller().expect("running").view(),
        PairingView::Open { .. }
    ));
    app.ui.sheet = Some(Sheet::Devices(DevicesSheet::AddDevice));
    app.devices_use_other_relay("synthetic-vault", Some(&ctx));
    assert_eq!(
        app.companion_controller().expect("running").view(),
        PairingView::Closed
    );
}

/// A pasted link follows its `r`: a link of Apassy Connect is refused in "Use a vault from
/// another Mac" with where to paste it, and a link with an `r` that this version does not
/// know is refused in both places.
#[test]
fn a_pasted_link_follows_its_route() {
    let folders = folders();
    let mut b = folders.mac("mac-b");
    create(&mut b, "Personal", &folders.icloud);
    let code = format!("apassy_lnk_t_7k2m5q4x3c_{CODE_HEX}");
    let connect = format!("https://relay.example.test/link#{code}&r=connect&n=Mac%20mini");
    b.sync.relay.link_input = connect.clone();
    b.relay_join_request(None, None);
    assert_eq!(
        b.sync.relay.join_error.as_deref(),
        Some(CONNECT_LINK_IN_SYNC)
    );
    let unknown = format!("https://relay.example.test/link#{code}&r=share");
    b.sync.relay.link_input = unknown.clone();
    b.relay_join_request(None, None);
    assert!(
        b.sync
            .relay
            .join_error
            .as_deref()
            .is_some_and(|error| error.contains("newer version of Apassy")),
        "{:?}",
        b.sync.relay.join_error
    );
    let id = current_id(&b);
    let entry = b.vault_list.registry.get(&id).cloned().expect("entry");
    let refused = b
        .questions_ask_join(
            &entry,
            "t_7k2m5q4x3c",
            Zeroizing::new(unknown),
            "Synthetic Mac mini",
            None,
        )
        .unwrap_err();
    assert!(refused.contains("newer version of Apassy"), "{refused}");
    assert!(b.owner.check.is_none());
}
