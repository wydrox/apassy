//! Headless tests of iCloud sync in the app (ADR 0014). Synthetic values only. A
//! temporary folder stands in for iCloud Drive, and each "Mac" is an app with its own
//! data directory. No test touches the real iCloud Drive or the network.

use std::fs;
use std::path::PathBuf;

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::icloud::{Choice, IcloudSheet};
use super::start::{self, Step};
use super::vaults::VaultSheet;
use super::{Sheet, draw};
use crate::cloud::SyncStatus;
use crate::desktop::owner_store::SecretForm;
use crate::desktop::{DesktopApp, ItemDraft, OwnerView};

const PASS: &str = "icloud-ui-pass-ok";
const OTHER_PASS: &str = "icloud-ui-other-pass";
const CANARY: &str = "icloud-ui-token-canary";
const CLOUD_FILE: &str = "Personal.apassy";
const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

/// A temporary iCloud Drive with its Apassy folder (not created yet).
struct Cloud {
    root: TempDir,
    icloud: PathBuf,
    dir: PathBuf,
}

fn cloud() -> Cloud {
    let root = TempDir::new().expect("temp dir");
    let icloud = root
        .path()
        .join("Mobile Documents")
        .join("com~apple~CloudDocs");
    fs::create_dir_all(&icloud).expect("icloud drive");
    let dir = icloud.join("Apassy");
    Cloud { root, icloud, dir }
}

impl Cloud {
    fn file(&self) -> PathBuf {
        self.dir.join(CLOUD_FILE)
    }

    /// One Mac: an app with the data directory `<root>/<name>` that keeps its list.
    fn mac(&self, name: &str) -> DesktopApp {
        let mut app = DesktopApp::new();
        app.load_vault_list(self.root.path().join(name), true);
        app.icloud.cloud_dir = Some(self.dir.clone());
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

/// Create a vault on the Create screen, with or without "Keep a copy in iCloud Drive".
fn create(app: &mut DesktopApp, name: &str, pass: &str, icloud: bool) {
    let ctx = egui::Context::default();
    app.vault_list.name_input = name.to_owned();
    app.owner_ui.passphrase.push_str(pass);
    app.owner_ui.passphrase_confirm.push_str(pass);
    app.icloud.on_create = icloud;
    start::create_vault(app, &ctx);
    assert!(
        !app.owner_ui.session.is_locked(),
        "create failed: {}",
        app.status_text
    );
}

fn add_item(app: &mut DesktopApp, name: &str) {
    let mut secrets = SecretForm::default();
    secrets.token = CANARY.to_owned();
    app.owner_ui
        .session
        .add(
            &ItemDraft {
                name: name.to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
}

fn names(app: &DesktopApp) -> Vec<String> {
    let mut names: Vec<String> = app
        .owner_ui
        .session
        .search("")
        .expect("search")
        .into_iter()
        .map(|row| row.name)
        .collect();
    names.sort();
    names
}

fn id_of(app: &DesktopApp, name: &str) -> String {
    app.vault_list
        .registry
        .entries()
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.id.clone())
        .expect("listed vault")
}

fn current_id(app: &DesktopApp) -> String {
    app.vault_list.current.clone().expect("open vault")
}

fn status(app: &mut DesktopApp) -> SyncStatus {
    app.icloud_refresh();
    let id = current_id(app);
    app.icloud.statuses[&id].as_ref().expect("status").status
}

fn lock(app: &mut DesktopApp) {
    let ctx = egui::Context::default();
    app.lock_vault(Some(&ctx));
    assert!(app.owner_ui.session.is_locked());
}

fn unlock(app: &mut DesktopApp, pass: &str) {
    let ctx = egui::Context::default();
    app.owner_ui.passphrase.push_str(pass);
    start::unlock_with_passphrase(app, &ctx);
    assert!(
        !app.owner_ui.session.is_locked(),
        "unlock failed: {}",
        app.status_text
    );
}

/// Mac B opens the cloud file from iCloud with the name "Personal" and unlocks it.
fn adopt(app: &mut DesktopApp, pass: &str) {
    app.vault_list.name_input = "Personal".to_owned();
    app.owner_ui.passphrase.push_str(pass);
    app.icloud_adopt(CLOUD_FILE, None);
    assert!(
        !app.owner_ui.session.is_locked(),
        "adopt failed: {}",
        app.status_text
    );
}

/// Mac A creates "Personal" with iCloud on; Mac B opens it from iCloud. Both unlocked.
fn two_macs(cloud: &Cloud) -> (DesktopApp, DesktopApp) {
    let mut a = cloud.mac("mac-a");
    create(&mut a, "Personal", PASS, true);
    add_item(&mut a, "Alpha");
    lock(&mut a);
    unlock(&mut a, PASS);
    let mut b = cloud.mac("mac-b");
    adopt(&mut b, PASS);
    (a, b)
}

#[test]
fn create_with_icloud_on_pushes_the_first_copy() {
    let cloud = cloud();
    let mut app = cloud.mac("mac-a");
    let text = frames(&mut app);
    assert!(text.contains("Open a vault from iCloud"), "{text}");
    app.ui.start = Step::Create;
    let text = frames(&mut app);
    assert!(text.contains("Keep a copy in iCloud Drive"), "{text}");

    create(&mut app, "Personal", PASS, true);
    assert!(
        app.status_text
            .contains("A copy is in iCloud Drive as Personal.apassy"),
        "{}",
        app.status_text
    );
    assert!(cloud.file().is_file());
    let id = current_id(&app);
    let entry = app.vault_list.registry.get(&id).expect("entry");
    assert_eq!(entry.cloud_state(), Some(id.as_str()));
    let state = app
        .vault_list
        .data_dir
        .join("icloud")
        .join(format!("{id}.json"));
    assert!(state.is_file());
    assert_eq!(status(&mut app), SyncStatus::InSync);
    // The list on disk has the setting.
    let listed = crate::vaults::Registry::read(&app.vault_list.data_dir)
        .expect("read")
        .expect("list");
    assert_eq!(
        listed.get(&id).and_then(|entry| entry.cloud_state()),
        Some(id.as_str())
    );

    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    assert!(text.contains("iCloud Drive"), "{text}");
    assert!(text.contains("In sync with iCloud"), "{text}");
    assert!(text.contains("Personal.apassy"), "{text}");
    assert!(!text.contains(CANARY));
}

#[test]
fn turn_on_and_off_in_settings_keeps_the_icloud_file() {
    let cloud = cloud();
    let mut app = cloud.mac("mac-a");
    create(&mut app, "Personal", PASS, false);
    assert!(
        !cloud.dir.exists(),
        "nothing goes to iCloud without the setting"
    );
    let id = current_id(&app);
    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    assert!(text.contains("Turn on iCloud sync"), "{text}");

    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::TurnOn {
        id: id.clone(),
    })));
    let text = frames(&mut app);
    assert!(text.contains("Sync “Personal” with iCloud"), "{text}");

    let wrong = app.icloud_enable(&id, OTHER_PASS).unwrap_err();
    assert!(wrong.contains("not the passphrase"), "{wrong}");
    assert!(app.vault_list.registry.get(&id).unwrap().cloud.is_none());
    let report = app.icloud_enable(&id, PASS).expect("enable");
    assert!(report.pushed);
    assert_eq!(report.cloud_file_name, CLOUD_FILE);
    assert!(cloud.file().is_file());

    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::TurnOff {
        id: id.clone(),
    })));
    let text = frames(&mut app);
    assert!(text.contains("Stop syncing “Personal”?"), "{text}");
    assert!(text.contains("Personal.apassy"), "{text}");
    assert_eq!(app.icloud_disable(&id).as_deref(), Some(CLOUD_FILE));
    assert!(app.vault_list.registry.get(&id).unwrap().cloud.is_none());
    assert!(
        !app.vault_list
            .data_dir
            .join("icloud")
            .join(format!("{id}.json"))
            .exists(),
        "the sync state goes"
    );
    assert!(cloud.file().is_file(), "the iCloud file stays");

    // A lock after "off" does not push.
    let before = fs::read(cloud.file()).expect("cloud");
    add_item(&mut app, "After off");
    lock(&mut app);
    assert_eq!(fs::read(cloud.file()).expect("cloud"), before);

    // On again: the same vault links to its file.
    unlock(&mut app, PASS);
    let report = app.icloud_enable(&id, PASS).expect("enable again");
    assert!(!report.pushed);
    assert_eq!(report.cloud_file_name, CLOUD_FILE);
    assert_eq!(report.status, SyncStatus::Conflict, "a change while off");
}

#[test]
fn lock_pushes_and_a_failed_push_does_not_block_the_lock() {
    let cloud = cloud();
    let mut app = cloud.mac("mac-a");
    create(&mut app, "Personal", PASS, true);
    add_item(&mut app, "Pushed at lock");
    assert_eq!(status(&mut app), SyncStatus::PushNeeded);
    lock(&mut app);
    let pushed = fs::read(cloud.file()).expect("cloud");
    assert_eq!(
        fs::read(app.owner_ui.session.vault_path().unwrap()).expect("local"),
        pushed
    );

    // Every few minutes: a poll pushes an unlocked vault with changes.
    unlock(&mut app, PASS);
    add_item(&mut app, "Pushed by the poll");
    app.icloud_poll_now();
    assert_eq!(status(&mut app), SyncStatus::InSync);

    // iCloud Drive goes away. The lock still works, and the failure shows once.
    add_item(&mut app, "Stays on this Mac");
    let signed_out = cloud.root.path().join("signed-out");
    fs::rename(&cloud.icloud, &signed_out).expect("sign out");
    lock(&mut app);
    let _ = frames(&mut app);
    assert!(
        app.status_text.contains("iCloud Drive is off"),
        "{}",
        app.status_text
    );
    let seq = app.status_seq;
    let _ = frames(&mut app);
    assert_eq!(app.status_seq, seq, "the same failure shows once");
    // The unlock works without iCloud Drive.
    unlock(&mut app, PASS);
    fs::rename(&signed_out, &cloud.icloud).expect("sign in");
}

#[test]
fn unlock_pulls_a_newer_copy_and_the_banner_says_so() {
    let cloud = cloud();
    let (mut a, mut b) = two_macs(&cloud);
    assert_eq!(names(&b), vec!["Alpha"]);
    add_item(&mut b, "From B");
    lock(&mut b);

    // Mac A is unlocked: the banner tells the owner to lock and unlock.
    assert_eq!(status(&mut a), SyncStatus::PullAvailable);
    let text = frames(&mut a);
    assert!(
        text.contains("A newer copy of “Personal” is in iCloud"),
        "{text}"
    );
    assert!(text.contains("Lock and unlock to load it"), "{text}");
    lock(&mut a);
    let text = frames(&mut a);
    assert!(text.contains("Apassy loads it when you unlock"), "{text}");
    unlock(&mut a, PASS);
    assert!(
        a.status_text.contains("loaded the newer copy"),
        "{}",
        a.status_text
    );
    assert_eq!(names(&a), vec!["Alpha", "From B"]);
    assert_eq!(status(&mut a), SyncStatus::InSync);

    // Touch ID unlock pulls too: its key is the passphrase.
    unlock(&mut b, PASS);
    add_item(&mut b, "From B again");
    lock(&mut b);
    lock(&mut a);
    let ctx = egui::Context::default();
    a.finish_touch_id_unlock(Ok(Zeroizing::new(PASS.to_owned())), &ctx);
    assert!(!a.owner_ui.session.is_locked(), "{}", a.status_text);
    assert!(
        a.status_text.contains("loaded the newer copy"),
        "{}",
        a.status_text
    );
    assert!(names(&a).contains(&"From B again".to_owned()));
}

#[test]
fn a_refused_copy_does_not_block_the_unlock_of_this_mac() {
    let cloud = cloud();
    let (mut a, mut b) = two_macs(&cloud);
    let old = fs::read(cloud.file()).expect("generation 1");
    add_item(&mut a, "Generation 2");
    lock(&mut a);
    lock(&mut b);
    unlock(&mut b, PASS);
    assert_eq!(names(&b), vec!["Alpha", "Generation 2"]);
    lock(&mut b);

    // Someone puts the old copy back.
    fs::write(cloud.file(), &old).expect("rollback");
    unlock(&mut b, PASS);
    assert_eq!(names(&b), vec!["Alpha", "Generation 2"], "this Mac's file");
    let notice = b.icloud.notice.clone().expect("a note");
    assert!(notice.text.contains("older than the copy"), "{notice:?}");
    let text = frames(&mut b);
    assert!(
        text.contains("Apassy did not load the iCloud copy"),
        "{text}"
    );

    // Another vault at the cloud name.
    let mut other = cloud.mac("mac-d");
    create(&mut other, "Other", PASS, true);
    let other_file = cloud.dir.join("Other.apassy");
    b.icloud.notice = None;
    lock(&mut b);
    fs::copy(&other_file, cloud.file()).expect("replace");
    unlock(&mut b, PASS);
    let notice = b.icloud.notice.clone().expect("a note");
    assert!(notice.text.contains("holds another vault"), "{notice:?}");
    assert_eq!(names(&b), vec!["Alpha", "Generation 2"]);
}

#[test]
fn the_conflict_sheet_keeps_this_mac_and_saves_the_icloud_copy() {
    let cloud = cloud();
    let (mut a, mut b) = two_macs(&cloud);
    add_item(&mut b, "From B");
    lock(&mut b);
    add_item(&mut a, "From A");
    assert_eq!(status(&mut a), SyncStatus::Conflict);
    let text = frames(&mut a);
    assert!(
        text.contains("This Mac and iCloud both changed “Personal”"),
        "{text}"
    );
    let id = current_id(&a);
    a.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::Conflict {
        id: id.clone(),
    })));
    let text = frames(&mut a);
    for expected in [
        "Choose which version to keep",
        "Keep this Mac's version",
        "Use the iCloud version",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // A lock while the conflict waits does not push.
    let cloud_before = fs::read(cloud.file()).expect("cloud");
    lock(&mut a);
    assert_eq!(fs::read(cloud.file()).expect("cloud"), cloud_before);
    let text = frames(&mut a);
    assert!(text.contains("Keep this Mac's version"), "{text}");

    // The choice from the unlock screen, with the typed passphrase.
    assert!(a.icloud_resolve(Choice::KeepThisMac, PASS, None));
    assert!(!a.owner_ui.session.is_locked());
    let notice = a.icloud.notice.clone().expect("note");
    let saved = a.vault_list.data_dir.join("conflicts");
    assert!(
        notice.text.contains(&saved.display().to_string()),
        "{notice:?}"
    );
    let copies: Vec<PathBuf> = fs::read_dir(&saved)
        .expect("conflicts")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(copies.len(), 1);
    assert!(
        copies[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("Personal-icloud-")
    );
    assert_eq!(fs::read(&copies[0]).expect("copy"), cloud_before);
    assert_eq!(status(&mut a), SyncStatus::InSync);
    assert_eq!(names(&a), vec!["Alpha", "From A"]);

    // Mac B loads the kept version at its next unlock.
    unlock(&mut b, PASS);
    assert_eq!(names(&b), vec!["Alpha", "From A"]);
}

#[test]
fn the_conflict_sheet_uses_the_icloud_version_and_saves_this_mac() {
    let cloud = cloud();
    let (mut a, mut b) = two_macs(&cloud);
    add_item(&mut b, "From B");
    lock(&mut b);
    add_item(&mut a, "From A");
    assert_eq!(status(&mut a), SyncStatus::Conflict);
    let before = fs::read(a.owner_ui.session.vault_path().unwrap()).expect("local");
    a.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::Conflict {
        id: current_id(&a),
    })));
    let _ = frames(&mut a);
    // A wrong passphrase changes nothing and keeps the vault unlocked.
    assert!(!a.icloud_resolve(Choice::UseIcloud, OTHER_PASS, None));
    assert!(!a.owner_ui.session.is_locked());
    assert_eq!(status(&mut a), SyncStatus::Conflict);

    assert!(a.icloud_resolve(Choice::UseIcloud, PASS, None));
    assert!(!a.owner_ui.session.is_locked());
    assert_eq!(names(&a), vec!["Alpha", "From B"]);
    let saved: Vec<PathBuf> = fs::read_dir(a.vault_list.data_dir.join("conflicts"))
        .expect("conflicts")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(saved.len(), 1);
    assert!(
        saved[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("Personal-this-mac-")
    );
    assert_eq!(fs::read(&saved[0]).expect("copy"), before);
    assert_eq!(status(&mut a), SyncStatus::InSync);
}

#[test]
fn open_a_vault_from_icloud_adds_it_to_the_list() {
    let cloud = cloud();
    let mut a = cloud.mac("mac-a");
    create(&mut a, "Personal", PASS, true);
    add_item(&mut a, "Alpha");
    lock(&mut a);

    let mut b = cloud.mac("mac-b");
    b.ui.start = Step::Icloud;
    let text = frames(&mut b);
    assert!(text.contains("Open a vault from iCloud"), "{text}");
    assert!(text.contains("Personal"), "{text}");

    // A wrong passphrase adds nothing.
    b.vault_list.name_input = "Personal".to_owned();
    b.owner_ui.passphrase.push_str(OTHER_PASS);
    b.icloud_adopt(CLOUD_FILE, None);
    assert!(b.vault_list.registry.is_empty(), "{}", b.status_text);
    assert!(b.owner_ui.passphrase.is_empty(), "the field is erased");

    adopt(&mut b, PASS);
    let id = current_id(&b);
    let entry = b.vault_list.registry.get(&id).expect("entry").clone();
    assert_eq!(entry.name, "Personal");
    assert_eq!(
        entry.path,
        b.vault_list.data_dir.join("vaults").join("personal.db")
    );
    assert_eq!(entry.cloud_state(), Some(id.as_str()));
    assert_eq!(names(&b), vec!["Alpha"]);
    assert_eq!(status(&mut b), SyncStatus::InSync);
    // The vault is in the list now, so the screen does not offer it again.
    assert!(b.icloud_unlisted().expect("list").is_empty());
}

#[test]
fn a_rebuilt_list_links_a_proven_vault_again() {
    let cloud = cloud();
    let mut a = cloud.mac("mac-a");
    let data = a.vault_list.data_dir.clone();
    create(&mut a, "Personal", PASS, true);
    // The lock pushes, so the file matches its last sync.
    lock(&mut a);
    a.leave_vault_for(Step::Create, None);
    create(&mut a, "Work", PASS, true);
    let work_path = a.owner_ui.session.vault_path().expect("path");
    a.shut_down();
    drop(a);
    // "Work" changes after its last sync, outside the app.
    {
        let mut vault = crate::vault::Vault::open(&work_path).expect("open");
        vault.unlock(PASS).expect("unlock");
        vault
            .add(crate::vault::ItemDraft {
                title: "Outside".to_owned(),
                kind: crate::contracts::CredentialKind::Custom,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![crate::vault::Field {
                    name: "value".to_owned(),
                    value: crate::vault::SecretValue::new("synthetic".to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
    }

    fs::write(data.join("vaults.json"), b"{ damaged").expect("damage");
    let mut app = DesktopApp::new();
    app.icloud.cloud_dir = Some(cloud.dir.clone());
    app.load_vault_list(data.clone(), true);
    let note = app.vault_list.note.clone().expect("note");
    assert!(
        note.contains("iCloud sync is on again for “personal”"),
        "{note}"
    );
    assert!(note.contains("Turn iCloud sync on again"), "{note}");
    let personal = id_of(&app, "personal");
    assert!(
        app.vault_list
            .registry
            .get(&personal)
            .expect("entry")
            .cloud_state()
            .is_some()
    );
    let work = id_of(&app, "work");
    assert!(
        app.vault_list
            .registry
            .get(&work)
            .expect("entry")
            .cloud
            .is_none()
    );
    // The rebuilt list is saved with the link, and it works.
    let saved = crate::vaults::Registry::read(&data)
        .expect("read")
        .expect("list");
    assert!(
        saved
            .get(&personal)
            .and_then(|entry| entry.cloud_state())
            .is_some()
    );
    app.switch_vault(&personal, None);
    unlock(&mut app, PASS);
    assert_eq!(status(&mut app), SyncStatus::InSync);
}

#[test]
fn the_switch_does_not_push_into_the_wrong_vault() {
    let cloud = cloud();
    let mut app = cloud.mac("mac-a");
    create(&mut app, "Personal", PASS, true);
    let personal = current_id(&app);
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Plain", OTHER_PASS, false);
    let plain = current_id(&app);

    // A change in "Personal", then a switch: the switch pushes "Personal".
    app.switch_vault(&personal, None);
    unlock(&mut app, PASS);
    add_item(&mut app, "Personal item");
    app.switch_vault(&plain, None);
    let after_switch = fs::read(cloud.file()).expect("cloud");
    let personal_path = app.vault_list.registry.get(&personal).unwrap().path.clone();
    assert_eq!(fs::read(&personal_path).expect("local"), after_switch);

    // "Plain" has no sync: its changes and its lock do not reach iCloud.
    unlock(&mut app, OTHER_PASS);
    add_item(&mut app, "Plain item");
    lock(&mut app);
    assert_eq!(fs::read(cloud.file()).expect("cloud"), after_switch);
    assert_eq!(fs::read_dir(&cloud.dir).expect("dir").count(), 1);

    // "Plain" with sync on gets its own file; a lock of "Personal" does not touch it.
    unlock(&mut app, OTHER_PASS);
    app.icloud_enable(&plain, OTHER_PASS).expect("enable");
    let plain_file = cloud.dir.join("Plain.apassy");
    let plain_bytes = fs::read(&plain_file).expect("plain");
    app.switch_vault(&personal, None);
    unlock(&mut app, PASS);
    add_item(&mut app, "Personal again");
    lock(&mut app);
    assert_eq!(fs::read(&plain_file).expect("plain"), plain_bytes);
    assert_ne!(fs::read(cloud.file()).expect("cloud"), after_switch);
}

#[test]
fn downloading_shows_on_the_unlock_screen_and_does_not_block_it() {
    let cloud = cloud();
    let (mut a, _b) = two_macs(&cloud);
    lock(&mut a);
    fs::rename(cloud.file(), cloud.root.path().join("aside")).expect("evict");
    fs::write(
        cloud.dir.join(format!(".{CLOUD_FILE}.icloud")),
        b"synthetic placeholder",
    )
    .expect("placeholder");
    a.icloud_refresh();
    let text = frames(&mut a);
    assert!(text.contains("Downloading from iCloud"), "{text}");
    unlock(&mut a, PASS);
    assert_eq!(names(&a), vec!["Alpha"]);
}

#[test]
fn remove_from_list_stops_sync_and_keeps_the_icloud_file() {
    let cloud = cloud();
    let mut app = cloud.mac("mac-a");
    create(&mut app, "Personal", PASS, true);
    let personal = current_id(&app);
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Other", OTHER_PASS, false);
    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Remove {
        id: personal.clone(),
    }));
    let text = frames(&mut app);
    assert!(text.contains("Its copy in iCloud Drive stays"), "{text}");
    assert!(app.remove_vault(&personal));
    assert!(
        app.status_text
            .contains("The copy in iCloud Drive (Personal.apassy) stays"),
        "{}",
        app.status_text
    );
    assert!(cloud.file().is_file());
    let state = app
        .vault_list
        .data_dir
        .join("icloud")
        .join(format!("{personal}.json"));
    assert!(!state.exists());
    // The vault is not in the list, so "Open a vault from iCloud" offers it again.
    let offered: Vec<String> = app
        .icloud_unlisted()
        .expect("list")
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(offered, vec![CLOUD_FILE.to_owned()]);
}

#[test]
fn no_icloud_folder_hides_icloud() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    assert!(
        app.icloud.cloud_dir.is_none(),
        "a test never uses the real iCloud Drive"
    );
    let text = frames(&mut app);
    assert!(!text.contains("iCloud"), "{text}");
    create(&mut app, "Personal", PASS, true);
    let id = current_id(&app);
    assert!(app.vault_list.registry.get(&id).unwrap().cloud.is_none());
    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    assert!(!text.contains("iCloud Drive"), "{text}");
}

#[test]
fn sync_now_and_quit_push_the_changes() {
    let cloud = cloud();
    let (mut a, mut b) = two_macs(&cloud);
    add_item(&mut a, "Sync now");
    a.icloud_sync_now();
    assert!(
        a.status_text.contains("iCloud has the changes of this Mac"),
        "{}",
        a.status_text
    );
    assert_eq!(status(&mut a), SyncStatus::InSync);
    a.icloud_sync_now();
    assert!(
        a.status_text.contains("In sync with iCloud"),
        "{}",
        a.status_text
    );

    // B sees the newer copy; "Sync now" explains how to load it.
    b.icloud_sync_now();
    assert!(
        b.status_text.contains("Lock and unlock"),
        "{}",
        b.status_text
    );

    // Quit pushes too (the restart for an update locks the same way).
    add_item(&mut a, "At quit");
    let local = a.owner_ui.session.vault_path().expect("path");
    a.shut_down();
    assert_eq!(
        fs::read(&local).expect("local"),
        fs::read(cloud.file()).expect("cloud")
    );
}
