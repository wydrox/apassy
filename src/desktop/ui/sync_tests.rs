//! Headless tests of sync through a folder (ADR 0014) and through the Apassy relay (ADR
//! 0022) in the app. Synthetic values only. Temporary folders stand in for iCloud Drive
//! and Dropbox, the in-process fake relay of the engine tests stands in for the relay on
//! 127.0.0.1, and each "Mac" is an app with its own data directory. No test touches a
//! real synced folder or the network.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::start::{self, Step};
use super::sync::{SyncSheet, UiStatus};
use super::vaults::VaultSheet;
use super::{Sheet, draw};
use crate::broker::approvals::PendingRun;
use crate::desktop::owner_store::SecretForm;
use crate::desktop::sync_worker::{CHECK_EVERY, SETTLE};
use crate::desktop::{DesktopApp, ItemDraft, OwnerView};
use crate::sync::SyncFolder;
use crate::vault::{ActivityDecision, NewActivity};

/// The fake relay reads the app's sync module under this name.
use crate::sync as relay_api;
#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

const PASS: &str = "sync-ui-pass-ok";
const NEW_PASS: &str = "sync-ui-pass-new";
const OTHER_PASS: &str = "sync-ui-other-pass";
const CANARY: &str = "sync-ui-token-canary";
const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

/// A temporary iCloud Drive and Dropbox, each with its Apassy folder (not created yet).
struct Folders {
    root: TempDir,
    icloud: PathBuf,
    dropbox: PathBuf,
}

fn folders() -> Folders {
    let root = TempDir::new().expect("temp dir");
    let icloud_drive = root
        .path()
        .join("Mobile Documents")
        .join("com~apple~CloudDocs");
    let dropbox_root = root.path().join("Dropbox");
    fs::create_dir_all(&icloud_drive).expect("icloud drive");
    fs::create_dir_all(&dropbox_root).expect("dropbox");
    Folders {
        icloud: icloud_drive.join("Apassy"),
        dropbox: dropbox_root.join("Apassy"),
        root,
    }
}

impl Folders {
    /// One Mac: an app with the data directory `<root>/<name>` and these folders.
    fn mac(&self, name: &str) -> DesktopApp {
        let mut app = DesktopApp::new();
        app.load_vault_list(self.root.path().join(name), true);
        app.sync.offered = true;
        app.sync.icloud = Some(self.icloud.clone());
        app.sync.folders = vec![
            SyncFolder {
                label: "iCloud Drive".to_owned(),
                path: self.icloud.clone(),
            },
            SyncFolder {
                label: "Dropbox".to_owned(),
                path: self.dropbox.clone(),
            },
        ];
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

/// Create a vault on the Create screen, with sync in `folder` or off.
fn create(app: &mut DesktopApp, name: &str, pass: &str, folder: Option<&PathBuf>) {
    let ctx = egui::Context::default();
    app.vault_list.name_input = name.to_owned();
    app.owner_ui.passphrase.push_str(pass);
    app.owner_ui.passphrase_confirm.push_str(pass);
    app.sync.create_folder = folder.cloned();
    start::create_vault(app, &ctx);
    assert!(
        !app.owner_ui.session.is_locked(),
        "create failed: {}",
        app.status_text
    );
}

fn add_item(app: &mut DesktopApp, name: &str, token: &str) {
    let mut secrets = SecretForm::default();
    secrets.token = token.to_owned();
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

fn current_id(app: &DesktopApp) -> String {
    app.vault_list.current.clone().expect("open vault")
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

/// Mac B opens the synced file `file` with the name "Personal" and unlocks it.
fn open_synced(app: &mut DesktopApp, file: &Path, pass: &str) {
    app.vault_list.name_input = "Personal".to_owned();
    app.owner_ui.passphrase.push_str(pass);
    app.sync_open_vault(file, None);
    assert!(
        !app.owner_ui.session.is_locked(),
        "open failed: {}",
        app.status_text
    );
}

/// Mac A creates "Personal" synced in iCloud Drive; Mac B opens it. Both unlocked.
fn two_macs(folders: &Folders) -> (DesktopApp, DesktopApp) {
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, Some(&folders.icloud));
    add_item(&mut a, "Alpha", "SYNTH-alpha");
    lock(&mut a);
    unlock(&mut a, PASS);
    let mut b = folders.mac("mac-b");
    open_synced(&mut b, &folders.icloud.join("Personal.apassy"), PASS);
    (a, b)
}

#[test]
fn create_with_sync_writes_the_file_and_settings_shows_the_status() {
    let folders = folders();
    let mut app = folders.mac("mac-a");
    let text = frames(&mut app);
    assert!(text.contains("Use a vault from another Mac"), "{text}");
    app.ui.start = Step::Create;
    let text = frames(&mut app);
    assert!(text.contains("Sync"), "{text}");
    assert!(text.contains("Off"), "sync is off by default: {text}");

    create(&mut app, "Personal", PASS, Some(&folders.dropbox));
    assert!(
        app.status_text.contains("Folder sync is on for Dropbox"),
        "{}",
        app.status_text
    );
    let file = folders.dropbox.join("Personal.apassy");
    assert!(file.is_file());
    let id = current_id(&app);
    let entry = app.vault_list.registry.get(&id).expect("entry").clone();
    assert_eq!(entry.sync_file(), Some(file.clone()));
    let listed = crate::vaults::Registry::read(&app.vault_list.data_dir)
        .expect("read")
        .expect("list");
    assert_eq!(
        listed.get(&id).and_then(|entry| entry.sync_file()),
        Some(file)
    );

    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    for expected in [
        "Sync",
        "Saved to sync folder",
        "Personal.apassy",
        "Dropbox",
        "Sync now",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains(CANARY));
}

#[test]
fn the_sync_picker_turns_on_moves_and_turns_off() {
    let folders = folders();
    let mut app = folders.mac("mac-a");
    create(&mut app, "Personal", PASS, None);
    assert!(!folders.icloud.exists() && !folders.dropbox.exists());
    let id = current_id(&app);
    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    assert!(text.contains("Sync is off."), "{text}");

    let text = app.sync_enable(&id, &folders.icloud).expect("iCloud");
    assert!(text.contains("iCloud Drive"), "{text}");
    assert!(folders.icloud.join("Personal.apassy").is_file());

    // "Choose folder…" with a typed folder moves the sync there.
    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::ChooseFolder {
        id: id.clone(),
    })));
    let text = frames(&mut app);
    assert!(text.contains("Sync “Personal” with a folder"), "{text}");
    let share = folders.root.path().join("Share").join("Vaults");
    fs::create_dir_all(share.parent().expect("parent")).expect("share");
    app.sync_enable(&id, &share).expect("share");
    assert!(share.join("Personal.apassy").is_file());
    let entry = app.vault_list.registry.get(&id).expect("entry").clone();
    assert_eq!(entry.sync.as_ref().expect("link").folder, share);
    assert!(
        folders.icloud.join("Personal.apassy").is_file(),
        "the old synced copy stays"
    );
    assert!(
        app.sync_enable(&id, std::path::Path::new("relative"))
            .is_err()
    );

    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::TurnOff {
        id: id.clone(),
    })));
    let text = frames(&mut app);
    assert!(text.contains("Stop syncing “Personal”?"), "{text}");
    let (folder, file) = app.sync_disable(&id).expect("was on");
    assert_eq!((folder, file.as_str()), (share.clone(), "Personal.apassy"));
    assert!(
        app.vault_list
            .registry
            .get(&id)
            .expect("entry")
            .sync
            .is_none()
    );
    assert!(
        !app.vault_list
            .data_dir
            .join("sync")
            .join(format!("{id}.json"))
            .exists(),
        "the sync state goes"
    );
    // A lock after "off" does not write the synced file.
    let before = fs::read(share.join("Personal.apassy")).expect("file");
    add_item(&mut app, "After off", "SYNTH-off");
    lock(&mut app);
    assert_eq!(
        fs::read(share.join("Personal.apassy")).expect("file"),
        before
    );
}

#[test]
fn unlock_merges_before_the_list_and_a_lock_pushes() {
    let folders = folders();
    let (mut a, mut b) = two_macs(&folders);
    assert_eq!(names(&b), vec!["Alpha"]);
    // A locks first; B's change comes after, so A merges it at the unlock.
    lock(&mut a);
    add_item(&mut b, "From B", "SYNTH-b");
    lock(&mut b);
    unlock(&mut a, PASS);
    assert!(
        a.status_text.contains("Sync brought 1 changed credential"),
        "{}",
        a.status_text
    );
    assert_eq!(names(&a), vec!["Alpha", "From B"]);

    // Touch ID unlock syncs too: its key is the passphrase.
    lock(&mut a);
    unlock(&mut b, PASS);
    add_item(&mut b, "From B again", "SYNTH-b2");
    lock(&mut b);
    let ctx = egui::Context::default();
    a.finish_touch_id_unlock(Ok(Zeroizing::new(PASS.to_owned())), &ctx);
    assert!(!a.owner_ui.session.is_locked(), "{}", a.status_text);
    assert!(names(&a).contains(&"From B again".to_owned()));
}

#[test]
fn a_change_syncs_after_a_pause_and_a_changed_file_merges_while_unlocked() {
    let folders = folders();
    let (mut a, mut b) = two_macs(&folders);
    let file = folders.icloud.join("Personal.apassy");
    let before = fs::read(&file).expect("file");
    add_item(&mut a, "Edited", "SYNTH-edit");
    a.sync_tick_for_test(Instant::now());
    assert!(a.sync_change_waits_for_test(), "the worker sees the change");
    assert_eq!(
        fs::read(&file).expect("file"),
        before,
        "not yet: the change settles"
    );
    // Seven seconds later the change syncs.
    a.sync_force_settled_for_test(Instant::now() - Duration::from_secs(10));
    a.sync_tick_for_test(Instant::now());
    assert_ne!(fs::read(&file).expect("file"), before);

    // Mac B merges the changed file on its next look, without a lock.
    b.sync_tick_for_test(Instant::now());
    assert!(names(&b).contains(&"Edited".to_owned()), "{:?}", names(&b));
}

#[test]
fn agent_activity_alone_does_not_sync() {
    let folders = folders();
    let (mut a, _b) = two_macs(&folders);
    let file = folders.icloud.join("Personal.apassy");
    let before = fs::read(&file).expect("file");
    let (agent, _) = a.owner_ui.session.register_agent("Agent").expect("agent");
    a.owner_ui
        .session
        .with_vault(|vault| {
            vault.record_activity(&NewActivity {
                agent_id: Some(agent.id),
                agent_name: "Agent".to_owned(),
                item_id: None,
                operation: "run".to_owned(),
                decision: ActivityDecision::Deny,
                reason: "SYNTH".to_owned(),
            })
        })
        .expect("vault")
        .expect("activity");
    a.sync_tick_for_test(Instant::now());
    assert!(
        !a.sync_change_waits_for_test(),
        "activity is not a change to sync"
    );
    // Even a sync now writes nothing, and neither does the lock.
    a.sync_force_settled_for_test(Instant::now() - Duration::from_secs(10));
    a.sync_tick_for_test(Instant::now());
    lock(&mut a);
    assert_eq!(fs::read(&file).expect("file"), before);
}

#[test]
fn both_macs_editing_one_credential_keep_both_versions_with_a_notice() {
    let folders = folders();
    let (mut a, mut b) = two_macs(&folders);
    for (app, token) in [(&mut a, "SYNTH-from-a"), (&mut b, "SYNTH-from-b")] {
        let id = app.owner_ui.session.search("Alpha").expect("search")[0].id;
        app.select_item(id.to_string());
        let details = app.owner_ui.session.details(id).expect("details");
        let mut secrets = SecretForm::default();
        secrets.token = token.to_owned();
        app.owner_ui
            .session
            .update(id, details.revision, &details.to_draft(), &secrets)
            .expect("edit");
    }
    lock(&mut a);
    lock(&mut b);
    unlock(&mut b, PASS);
    let notice = b.sync.notice.clone().expect("a notice");
    assert!(
        notice.title.contains("Sync kept both versions"),
        "{notice:?}"
    );
    let text = frames(&mut b);
    assert!(
        text.contains("Sync kept both versions in “Personal”"),
        "{text}"
    );
    let all = b.owner_ui.session.search("").expect("search");
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(
        all.iter()
            .any(|row| row.name.starts_with("Alpha (conflict copy, "))
    );
}

#[test]
fn a_new_passphrase_from_another_mac_asks_once_and_rekeys() {
    let folders = folders();
    let (mut a, mut b) = two_macs(&folders);
    a.owner_ui
        .session
        .change_passphrase(PASS, NEW_PASS, NEW_PASS)
        .expect("change");
    add_item(&mut a, "After change", "SYNTH-after");
    lock(&mut a);
    add_item(&mut b, "On B", "SYNTH-on-b");
    assert!(matches!(
        b.sync_quietly(),
        Some(Err(crate::sync::SyncError::NeedsPassphrase))
    ));
    assert!(matches!(
        b.ui.sheet,
        Some(Sheet::Vault(VaultSheet::Sync(
            SyncSheet::NewPassphrase { .. }
        )))
    ));
    let text = frames(&mut b);
    assert!(text.contains("changed on another Mac"), "{text}");
    let err = b.sync_take_passphrase(OTHER_PASS).unwrap_err();
    assert!(err.contains("does not open"), "{err}");
    b.sync_take_passphrase(NEW_PASS).expect("new passphrase");
    assert_eq!(names(&b), vec!["After change", "Alpha", "On B"]);
    lock(&mut b);
    let ctx = egui::Context::default();
    b.owner_ui.passphrase.push_str(PASS);
    start::unlock_with_passphrase(&mut b, &ctx);
    assert!(
        b.owner_ui.session.is_locked(),
        "the old passphrase no longer opens B"
    );
    unlock(&mut b, NEW_PASS);
}

#[test]
fn open_a_synced_vault_adds_it_with_sync_on() {
    let folders = folders();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Team", PASS, Some(&folders.dropbox));
    add_item(&mut a, "Shared", "SYNTH-shared");
    lock(&mut a);

    let mut b = folders.mac("mac-b");
    b.ui.start = Step::OpenSynced;
    let text = frames(&mut b);
    assert!(text.contains("Use a vault from another Mac"), "{text}");
    assert!(text.contains("Team"), "the Dropbox file is listed: {text}");

    let file = folders.dropbox.join("Team.apassy");
    b.vault_list.name_input = "Team".to_owned();
    b.owner_ui.passphrase.push_str(OTHER_PASS);
    b.sync_open_vault(&file, None);
    assert!(b.vault_list.registry.is_empty(), "{}", b.status_text);
    assert!(b.owner_ui.passphrase.is_empty(), "the field is erased");

    b.vault_list.name_input = "Team".to_owned();
    b.owner_ui.passphrase.push_str(PASS);
    b.sync_open_vault(&file, None);
    assert!(!b.owner_ui.session.is_locked(), "{}", b.status_text);
    let id = current_id(&b);
    let entry = b.vault_list.registry.get(&id).expect("entry").clone();
    assert_eq!(
        entry.path,
        b.vault_list.data_dir.join("vaults").join("team.db")
    );
    assert_eq!(entry.sync_file(), Some(file));
    assert_eq!(names(&b), vec!["Shared"]);
    assert!(b.owner_ui.session.agents().expect("agents").is_empty());
    assert!(b.sync_unlisted().is_empty(), "the vault is in the list now");
}

#[test]
fn a_rebuilt_list_links_sync_again() {
    let folders = folders();
    let mut a = folders.mac("mac-a");
    let data = a.vault_list.data_dir.clone();
    create(&mut a, "Personal", PASS, Some(&folders.icloud));
    add_item(&mut a, "Alpha", "SYNTH-alpha");
    a.shut_down();
    drop(a);
    fs::write(data.join("vaults.json"), b"{ damaged").expect("damage");
    let mut app = DesktopApp::new();
    app.sync.offered = true;
    app.sync.icloud = Some(folders.icloud.clone());
    app.load_vault_list(data.clone(), true);
    let note = app.vault_list.note.clone().expect("note");
    assert!(note.contains("Sync is on again for “personal”"), "{note}");
    let id = app.vault_list.registry.entries()[0].id.clone();
    assert!(
        app.vault_list
            .registry
            .get(&id)
            .expect("entry")
            .sync_state()
            .is_some()
    );
    app.switch_vault(&id, None);
    unlock(&mut app, PASS);
    assert_eq!(names(&app), vec!["Alpha"]);
    assert!(matches!(
        app.sync.statuses.get(&id),
        Some(UiStatus::UpToDate(_))
    ));
}

#[test]
fn the_switch_does_not_sync_into_the_wrong_vault() {
    let folders = folders();
    let mut app = folders.mac("mac-a");
    create(&mut app, "Personal", PASS, Some(&folders.icloud));
    let personal = current_id(&app);
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Plain", OTHER_PASS, None);
    let plain = current_id(&app);
    let file = folders.icloud.join("Personal.apassy");

    app.switch_vault(&personal, None);
    unlock(&mut app, PASS);
    add_item(&mut app, "Personal item", "SYNTH-p");
    app.switch_vault(&plain, None);
    let after_switch = fs::read(&file).expect("file");
    unlock(&mut app, OTHER_PASS);
    add_item(&mut app, "Plain item", "SYNTH-plain");
    lock(&mut app);
    assert_eq!(fs::read(&file).expect("file"), after_switch);
    assert_eq!(fs::read_dir(&folders.icloud).expect("dir").count(), 1);
    // The switch synced "Personal": a second Mac sees its item.
    let mut b = folders.mac("mac-b");
    open_synced(&mut b, &file, PASS);
    assert_eq!(names(&b), vec!["Personal item"]);
}

#[test]
fn an_unreachable_folder_never_blocks_a_lock_or_an_unlock() {
    let folders = folders();
    let (mut a, _b) = two_macs(&folders);
    add_item(&mut a, "Offline", "SYNTH-offline");
    let away = folders.root.path().join("away");
    let drive = folders.icloud.parent().expect("drive").to_owned();
    fs::rename(&drive, &away).expect("sign out");
    lock(&mut a);
    let _ = frames(&mut a);
    assert!(a.status_text.contains("not available"), "{}", a.status_text);
    unlock(&mut a, PASS);
    a.sync_refresh();
    let id = current_id(&a);
    assert_eq!(a.sync.statuses.get(&id), Some(&UiStatus::FolderUnavailable));
    a.view = OwnerView::Settings;
    let text = frames(&mut a);
    assert!(text.contains("Folder not available"), "{text}");
    fs::rename(&away, &drive).expect("sign in");
    lock(&mut a);
}

#[test]
fn remove_from_list_stops_sync_and_keeps_the_synced_file() {
    let folders = folders();
    let mut app = folders.mac("mac-a");
    create(&mut app, "Personal", PASS, Some(&folders.icloud));
    let personal = current_id(&app);
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Other", OTHER_PASS, None);
    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Remove {
        id: personal.clone(),
    }));
    let text = frames(&mut app);
    assert!(text.contains("Its synced copy stays"), "{text}");
    assert!(app.remove_vault(&personal));
    assert!(
        app.status_text
            .contains("The synced copy Personal.apassy stays"),
        "{}",
        app.status_text
    );
    assert!(folders.icloud.join("Personal.apassy").is_file());
    let offered: Vec<String> = app
        .sync_unlisted()
        .into_iter()
        .map(|(_, entry)| entry.name)
        .collect();
    assert_eq!(offered, vec!["Personal.apassy".to_owned()]);
}

#[test]
fn without_sync_the_app_shows_no_sync_control() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    assert!(
        !app.sync.offered,
        "a test never uses the real synced folders"
    );
    let text = frames(&mut app);
    assert!(!text.contains("synced vault"), "{text}");
    create(&mut app, "Personal", PASS, None);
    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    assert!(!text.contains("Sync now"), "{text}");
    app.start_sync_worker(&egui::Context::default());
    assert!(!app.sync.worker.running(), "no sync thread without sync");
}

#[test]
fn second_mac_flow_shows_file_service_and_existing_passphrase_without_paths() {
    let folders = folders();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Team", PASS, Some(&folders.dropbox));
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    let file = folders.dropbox.join("Team.apassy");
    b.sync_select_open_file(file.clone(), false, None);
    assert_eq!(b.vault_list.name_input, "Team");
    let text = frames(&mut b);
    for expected in [
        "Team.apassy",
        "Dropbox",
        "Existing vault passphrase",
        "Choose another file",
        "Details",
        "Help with iCloud",
        "Refresh",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("sandbox"), "{text}");
    assert!(
        !text.contains(&file.display().to_string()),
        "full path belongs in Details: {text}"
    );
    b.ui.set_expanded("sync-open-details", true);
    let text = frames(&mut b);
    assert!(text.contains(&file.display().to_string()), "{text}");
    assert!(text.contains("Name"), "{text}");
}

#[test]
fn discovery_timeout_has_retry_and_help_and_preserves_safe_values() {
    let folders = folders();
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    let file = folders.dropbox.join("Team.apassy");
    b.sync_select_open_file(file.clone(), false, None);
    b.vault_list.name_input = "My local name".to_owned();
    b.sync_open_error_for_test(crate::sync::SyncError::TimedOut);
    let text = frames(&mut b);
    assert!(text.contains("did not respond in time"), "{text}");
    assert!(text.contains("cause is not known"), "{text}");
    assert!(
        text.contains("Retry") && text.contains("Help with iCloud"),
        "{text}"
    );
    assert_eq!(b.sync.open_pick, Some(file.clone()));
    assert_eq!(b.vault_list.name_input, "My local name");
    b.sync_retry_open();
    assert_eq!(b.sync.open_pick, Some(file.clone()));
    assert_eq!(b.sync.open_path, file.display().to_string());
    assert_eq!(b.vault_list.name_input, "My local name");
    assert!(b.vault_list.registry.is_empty());
}

#[test]
fn custom_folder_placeholder_keeps_selection_and_advances_when_ready() {
    let folders = folders();
    let custom = folders.root.path().join("Shared vaults");
    let mut a = folders.mac("mac-a");
    create(&mut a, "Team", PASS, Some(&custom));
    let file = custom.join("Team.apassy");
    let contents = fs::read(&file).expect("synced file");
    fs::remove_file(&file).expect("remove local downloaded content");
    let placeholder = custom.join(".Team.apassy.icloud");
    fs::write(&placeholder, b"").expect("placeholder");
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    b.sync_select_open_file(file.clone(), true, None);
    b.vault_list.name_input = "Local Team".to_owned();
    b.sync_retry_open();
    let text = frames(&mut b);
    assert!(b.sync_open_waiting_for_test());
    assert!(!text.contains("Existing vault passphrase"), "{text}");
    assert_eq!(b.sync.open_pick, Some(file.clone()));
    fs::remove_file(placeholder).expect("download removes placeholder");
    fs::write(&file, contents).expect("downloaded file");
    b.sync_retry_open();
    assert!(!b.sync_open_waiting_for_test());
    assert_eq!(b.sync.open_pick, Some(file.clone()));
    assert_eq!(b.vault_list.name_input, "Local Team");
    let text = frames(&mut b);
    assert!(text.contains("Existing vault passphrase"), "{text}");
    b.owner_ui.passphrase.push_str(PASS);
    b.sync_open_vault(&file, None);
    assert!(!b.owner_ui.session.is_locked(), "{}", b.status_text);
    assert_eq!(b.current_vault_name().as_deref(), Some("Local Team"));
    assert_eq!(
        b.sync.adopted_vault.as_deref(),
        b.vault_list.current.as_deref()
    );
}

#[test]
fn folder_sync_status_does_not_claim_receipt_on_another_mac() {
    for status in [UiStatus::UpToDate(None), UiStatus::UpToDate(Some(0))] {
        let text = status.words(true);
        assert!(text.contains("local file in the sync folder"), "{text}");
        assert!(
            text.contains("Receipt on another Mac is not confirmed"),
            "{text}"
        );
        assert_eq!(status.tag().0, "Saved to sync folder");
    }
    assert!(UiStatus::Syncing.words(false).contains("Saved on this Mac"));
    assert_eq!(UiStatus::Waiting.tag().0, "Waiting for file");
    let folders = folders();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Team", PASS, Some(&folders.dropbox));
    a.sync_now();
    assert!(
        a.status_text.contains("Saved to the sync folder"),
        "{}",
        a.status_text
    );
}

#[test]
fn retry_finds_a_provider_that_appears_after_an_empty_scan() {
    let home = TempDir::new().expect("synthetic home");
    let mut app = DesktopApp::new();
    app.load_vault_list(home.path().join("data"), true);
    app.sync.offered = true;
    super::sync::begin_open(&mut app);
    app.sync_retry_open_in_for_test(home.path());
    assert!(app.sync.folders.is_empty());
    let folder = home.path().join("Dropbox").join("Apassy");
    fs::create_dir_all(&folder).expect("new provider");
    fs::write(folder.join("Team.apassy"), b"synthetic list entry").expect("entry");
    app.sync_retry_open_in_for_test(home.path());
    assert_eq!(app.sync.folders.len(), 1);
    let text = frames(&mut app);
    assert!(text.contains("Team.apassy"), "{text}");
    assert!(text.contains("Dropbox"), "{text}");
    assert!(
        app.vault_list.registry.is_empty(),
        "discovery does not adopt a file"
    );
}

/// A hidden, minimized, or covered window draws no frame. The worker syncs anyway.
#[test]
fn the_worker_pushes_and_merges_without_any_frame() {
    let folders = folders();
    let (mut a, b) = two_macs(&folders);
    let file = folders.icloud.join("Personal.apassy");
    let before = fs::read(&file).expect("file");
    let id = current_id(&a);
    add_item(&mut a, "Hidden", "SYNTH-hidden");
    let start = Instant::now();
    a.sync.worker.tick(start);
    assert_eq!(
        fs::read(&file).expect("file"),
        before,
        "not yet: the change settles"
    );
    a.sync.worker.tick(start + SETTLE + Duration::from_secs(1));
    assert_ne!(
        fs::read(&file).expect("file"),
        before,
        "the worker pushed the change"
    );
    assert!(
        matches!(
            a.sync.worker.statuses().get(&id),
            Some(UiStatus::UpToDate(Some(_)))
        ),
        "{:?}",
        a.sync.worker.statuses()
    );
    assert!(!a.sync_change_waits_for_test());
    // Mac B merges it on its first look, also without a frame.
    b.sync.worker.tick(Instant::now());
    assert_eq!(names(&b), vec!["Alpha", "Hidden"]);
    // The next frame shows what the worker did.
    a.poll_sync(&egui::Context::default());
    assert!(matches!(
        a.sync.statuses.get(&id),
        Some(UiStatus::UpToDate(Some(_)))
    ));
}

#[test]
fn the_worker_does_not_sync_while_a_run_waits_for_the_owner() {
    let folders = folders();
    let (mut a, _b) = two_macs(&folders);
    let dir = TempDir::new().expect("temp dir");
    a.start_broker(&super::owner_tests::socket_dir(&dir));
    let approvals = a.approvals().expect("the broker runs");
    // The worker gets the approval queue with the open vault.
    a.sync_track_open_vault();
    let waiter = {
        let approvals = Arc::clone(&approvals);
        std::thread::spawn(move || {
            approvals.wait_for(
                PendingRun {
                    id: 0,
                    agent: "Sync agent".to_owned(),
                    command: vec!["npm".to_owned(), "test".to_owned()],
                    cwd: "/tmp".to_owned(),
                    env_names: vec!["DEMO_KEY".to_owned()],
                    purpose: "Run the tests.".to_owned(),
                    risk: String::new(),
                    user_request: "Run the tests.".to_owned(),
                    request_source: String::new(),
                    agent_request: String::new(),
                    remember: None,
                },
                Duration::from_secs(20),
                || true,
            )
        })
    };
    while approvals.pending().is_empty() {
        std::thread::sleep(Duration::from_millis(5));
    }
    let file = folders.icloud.join("Personal.apassy");
    let before = fs::read(&file).expect("file");
    add_item(&mut a, "While waiting", "SYNTH-wait");
    let start = Instant::now();
    a.sync.worker.tick(start);
    a.sync.worker.tick(start + SETTLE + Duration::from_secs(1));
    assert_eq!(
        fs::read(&file).expect("file"),
        before,
        "no sync while a run waits for the owner"
    );
    assert!(a.sync_change_waits_for_test(), "the change still waits");
    approvals.invalidate_all();
    let _ = waiter.join();
    a.sync.worker.tick(start + SETTLE + Duration::from_secs(5));
    assert_ne!(
        fs::read(&file).expect("file"),
        before,
        "the change syncs when no run waits"
    );
}

#[test]
fn the_worker_does_not_sync_a_locked_vault() {
    let folders = folders();
    let (mut a, mut b) = two_macs(&folders);
    let file = folders.icloud.join("Personal.apassy");
    add_item(&mut a, "Unsynced", "SYNTH-unsynced");
    // Lock without the step before a lock, so the change has not synced.
    a.owner_ui
        .session
        .with_vault(|vault| vault.lock())
        .expect("vault")
        .expect("lock");
    // Mac B moves the synced file too.
    add_item(&mut b, "From B", "SYNTH-b");
    assert!(matches!(b.sync_quietly(), Some(Ok(_))));
    let moved = fs::read(&file).expect("file");
    a.sync_force_settled_for_test(Instant::now() - Duration::from_secs(10));
    let start = Instant::now();
    a.sync.worker.tick(start);
    a.sync
        .worker
        .tick(start + CHECK_EVERY + Duration::from_secs(1));
    assert_eq!(
        fs::read(&file).expect("file"),
        moved,
        "a locked vault neither pushes nor merges"
    );
    unlock(&mut a, PASS);
    assert_eq!(names(&a), vec!["Alpha", "From B", "Unsynced"]);
    assert_ne!(fs::read(&file).expect("file"), moved, "the unlock syncs");
}

#[test]
fn a_new_passphrase_found_by_the_worker_opens_the_sheet_in_the_next_frame() {
    let folders = folders();
    let (mut a, mut b) = two_macs(&folders);
    a.owner_ui
        .session
        .change_passphrase(PASS, NEW_PASS, NEW_PASS)
        .expect("change");
    add_item(&mut a, "After change", "SYNTH-after");
    lock(&mut a);
    let id = current_id(&b);
    b.sync.worker.tick(Instant::now());
    assert!(b.ui.sheet.is_none(), "the worker opens no sheet itself");
    assert_eq!(
        b.sync.worker.statuses().get(&id),
        Some(&UiStatus::NeedsPassphrase)
    );
    b.poll_sync(&egui::Context::default());
    assert!(
        matches!(
            &b.ui.sheet,
            Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::NewPassphrase { id: asked })))
                if *asked == id
        ),
        "{:?}",
        b.ui.sheet
    );
    let text = frames(&mut b);
    assert!(text.contains("changed on another Mac"), "{text}");
}

#[test]
fn the_worker_thread_starts_only_with_sync_and_stops() {
    let folders = folders();
    let mut app = folders.mac("mac-a");
    let ctx = egui::Context::default();
    app.start_sync_worker(&ctx);
    assert!(app.sync.worker.running());
    app.stop_sync_worker();
    assert!(!app.sync.worker.running());
}

// ---- Sync through the Apassy relay (ADR 0022). ----

/// Frames of the whole app in one context, which keeps the focus between frames, with
/// `events` in the first frame. Returns the painted text of the last frame.
fn frames_in(ctx: &egui::Context, app: &mut DesktopApp, events: Vec<egui::Event>) -> String {
    let mut text = String::new();
    let mut events = Some(events);
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            events: events.take().unwrap_or_default(),
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

/// Mac A with "Personal" (one credential) on the fake relay, open and unlocked.
fn relay_mac_a(folders: &Folders, relay: &fake_relay::FakeRelay) -> (DesktopApp, String) {
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, None);
    add_item(&mut a, "Alpha", "SYNTH-alpha");
    let id = current_id(&a);
    a.relay_enable_new(&id, &relay.url, &relay.team_code(), "Synthetic MacBook")
        .expect("relay sync on");
    a.relay_settle_for_test();
    assert!(
        a.status_text.contains("syncs through the Apassy relay"),
        "{}",
        a.status_text
    );
    (a, id)
}

/// The relay calls end, then three frames.
fn settled_frames(app: &mut DesktopApp) -> String {
    app.relay_settle_for_test();
    let _ = frames(app);
    app.relay_settle_for_test();
    frames(app)
}

/// The words of the open "Add a Mac…" sheet of Mac A, after Mac B sent `link`.
fn send_link(b: &mut DesktopApp, link: &str) -> String {
    b.sync.relay.link_input = link.to_owned();
    b.sync.relay.device_input = "Synthetic Mac mini".to_owned();
    b.relay_join_request(None, None);
    b.relay_join_settle_for_test();
    match b.sync.relay.join_view(None) {
        Some(super::sync::relay::JoinView::Waiting { safety }) => safety,
        other => panic!("{other:?}: {:?}", b.sync.relay.join_error),
    }
}

#[test]
fn the_picker_offers_the_relay_after_the_detected_folders() {
    use super::sync::{Pick, picker_choices};
    let folders = folders();
    let app = folders.mac("mac-a");
    let labels: Vec<String> = picker_choices(&app.sync.folders, true)
        .into_iter()
        .map(|(_, label)| label)
        .collect();
    assert_eq!(
        labels,
        [
            "Off",
            "iCloud Drive",
            "Dropbox",
            "Apassy relay",
            "Choose folder…"
        ]
    );
    assert!(
        picker_choices(&app.sync.folders, true).contains(&(Pick::Relay, "Apassy relay".into()))
    );
    // The Create screen keeps folders only.
    assert!(
        !picker_choices(&app.sync.folders, false)
            .iter()
            .any(|(pick, _)| *pick == Pick::Relay)
    );
}

#[test]
fn the_relay_setup_sheet_asks_for_the_address_the_team_code_and_the_name() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, None);
    let id = current_id(&a);
    a.view = OwnerView::Settings;
    a.sync_open_sheet(SyncSheet::RelaySetup { id: id.clone() }, None);
    assert_eq!(a.sync.relay.url_input, crate::sync::DEFAULT_RELAY_URL);
    assert!(!a.sync.relay.device_input.is_empty(), "this Mac's name");
    let ctx = egui::Context::default();
    let text = frames_in(&ctx, &mut a, Vec::new());
    for expected in [
        "Sync “Personal” through the Apassy relay",
        "New relay copy",
        "Join from another Mac",
        "Relay address",
        "Team code",
        "Name of this Mac",
        "https://apassy-relay.wyderka.cc",
        "Turn on",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // The first field of the new sheet has the focus: typing goes into the address.
    a.sync.relay.url_input.clear();
    let _ = frames_in(&ctx, &mut a, vec![egui::Event::Text("h".to_owned())]);
    assert_eq!(a.sync.relay.url_input, "h");

    // A wrong team code changes nothing.
    let bad = format!("apassy_tcd_{}", "0".repeat(64));
    a.relay_enable_new(&id, &relay.url, &bad, "Synthetic MacBook")
        .expect("sent");
    a.relay_settle_for_test();
    assert!(
        a.status_text.contains("team code is wrong"),
        "{}",
        a.status_text
    );
    assert!(
        a.vault_list
            .registry
            .get(&id)
            .expect("entry")
            .sync
            .is_none()
    );
    let err = a
        .relay_enable_new(&id, "http://relay.example", &relay.team_code(), "Mac")
        .unwrap_err();
    assert!(err.contains("relay address is not valid"), "{err}");

    // "Turn on" with a good code: version 1 is on the relay and the list has the link.
    a.sync.relay.url_input = relay.url.clone();
    a.sync.relay.team_code = relay.team_code();
    a.sync.relay.device_input = "Synthetic MacBook".to_owned();
    let enter = egui::Event::Key {
        key: egui::Key::Enter,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::NONE,
    };
    let _ = frames_in(&ctx, &mut a, vec![enter]);
    a.relay_settle_for_test();
    assert!(a.ui.sheet.is_none(), "{}", a.status_text);
    assert!(
        a.status_text.contains("syncs through the Apassy relay"),
        "{}",
        a.status_text
    );
    assert!(a.sync.relay.team_code.is_empty(), "the code is erased");
    assert_eq!(relay.version(), 1);
    let entry = a.vault_list.registry.get(&id).expect("entry").clone();
    let link = entry.sync_relay().expect("relay link");
    assert_eq!(link.url, relay.url);
    assert!(entry.sync_file().is_none(), "no synced file");
    let listed = crate::vaults::Registry::read(&a.vault_list.data_dir)
        .expect("read")
        .expect("list");
    assert!(
        listed
            .get(&id)
            .and_then(|entry| entry.sync_relay())
            .is_some()
    );
}

#[test]
fn add_a_mac_shows_a_link_then_the_safety_words_and_confirm_needs_the_owner_check() {
    use crate::broker::approvals::{OwnerAction, OwnerAuthError, OwnerCheck};
    use crate::desktop::owner_check::OwnerRequest;

    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    a.view = OwnerView::Settings;
    let text = frames(&mut a);
    for expected in [
        "Saved to the relay",
        "Apassy relay",
        "Sync now",
        "Add a Mac…",
        "Devices…",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert_eq!(
        super::sync::sidebar_status(&a).0,
        "Synced just now · Apassy relay"
    );

    // Mac A: the link, and nobody asks yet.
    a.sync_open_sheet(SyncSheet::AddMac { id: id.clone() }, None);
    let text = settled_frames(&mut a);
    let link = a.relay_add_mac_link_for_test().expect("a link");
    assert!(
        link.starts_with(&format!("{}/link#apassy_lnk_", relay.url)),
        "{link}"
    );
    for expected in ["Add a Mac to “Personal”", "/link#apassy_lnk_", "Copy link"] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(text.contains("Waiting for the other Mac…"), "{text}");

    // Mac B pastes the link and shows its words.
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    b.sync.relay.source = super::sync::OpenSource::Relay;
    let text = frames(&mut b);
    assert!(text.contains("Connect") && text.contains("Link"), "{text}");
    let words = send_link(&mut b, &link);
    assert!(
        b.sync.relay.link_input.is_empty(),
        "the used code is erased"
    );
    let text = frames(&mut b);
    assert!(text.contains("Waiting for the other Mac…"), "{text}");
    assert!(text.contains(&words), "{words}: {text}");

    // Mac A shows the same words for the Mac that asks.
    a.relay_add_mac_poll_for_test();
    let links = a.relay_add_mac_links_for_test();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].device_name, "Synthetic Mac mini");
    assert_eq!(links[0].safety.as_deref(), Some(words.as_str()));
    let text = frames(&mut a);
    assert!(
        text.contains("“Synthetic Mac mini” asks to sync “Personal”"),
        "{text}"
    );
    assert!(text.contains(&words) && text.contains("Confirm…"), "{text}");

    // Confirm opens the owner check for exactly this Mac; a wrong passphrase adds nothing.
    a.relay_ask_confirm_for_test(links[0].id);
    let request = a.owner.check.as_ref().expect("owner check").request.clone();
    let expected = OwnerAction::ConfirmSyncDevice {
        link_id: links[0].id,
        device_name: "Synthetic Mac mini".to_owned(),
        public_key: links[0].public_key.clone(),
    };
    assert_eq!(request.action(), expected);
    assert_eq!(
        expected.reason(),
        "add the Mac \"Synthetic Mac mini\" to the sync of this vault"
    );
    assert!(matches!(request, OwnerRequest::ConfirmSyncDevice { ref vault, .. } if *vault == id));
    assert!(
        request
            .describe()
            .starts_with("Add the Mac \"Synthetic Mac mini\" to the sync of this vault")
    );
    assert_eq!(
        a.confirm_owner_now(OwnerCheck::passphrase(OTHER_PASS)),
        Err(OwnerAuthError::WrongPassphrase)
    );
    b.relay_join_poll_now_for_test();
    assert!(
        matches!(
            b.sync.relay.join_view(None),
            Some(super::sync::relay::JoinView::Waiting { .. })
        ),
        "not confirmed: {:?}",
        b.sync.relay.join_error
    );
    a.relay_ask_confirm_for_test(links[0].id);
    a.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    a.relay_settle_for_test();
    assert_eq!(
        a.status_text, "Added. Synthetic Mac mini receives the vault now.",
        "{}",
        a.status_text
    );
    let text = frames(&mut a);
    assert!(text.contains("Added. Synthetic Mac mini"), "{text}");
    // Only the result and Done: the used link and the wait are gone.
    for gone in [
        "Waiting for the other Mac…",
        "/link#apassy_lnk_",
        "Copy link",
        "asks to sync",
        "paste this link",
    ] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    assert!(text.contains("Done"), "{text}");
    assert!(
        a.relay_add_mac_link_for_test().is_none(),
        "the code is gone"
    );

    // "Devices…" lists both Macs.
    a.sync_open_sheet(SyncSheet::Devices { id: id.clone() }, None);
    let text = settled_frames(&mut a);
    for expected in [
        "Synthetic MacBook",
        "This Mac",
        "Synthetic Mac mini",
        "Remove",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    a.ui.sheet = None;

    // Mac B downloads the copy, and its passphrase adopts it.
    b.relay_join_poll_now_for_test();
    assert_eq!(
        b.sync.relay.join_view(None),
        Some(super::sync::relay::JoinView::Ready {
            team: "Personal".to_owned()
        }),
        "{:?}",
        b.sync.relay.join_error
    );
    let text = frames(&mut b);
    assert!(
        text.contains("Vault passphrase") && text.contains("Use this vault"),
        "{text}"
    );
    b.owner_ui.passphrase.push_str(OTHER_PASS);
    b.relay_open_vault(None);
    b.relay_settle_for_test();
    assert!(b.vault_list.registry.is_empty(), "{}", b.status_text);
    assert!(b.status_text.contains("does not open"), "{}", b.status_text);
    b.owner_ui.passphrase.push_str(PASS);
    b.relay_open_vault(None);
    b.relay_settle_for_test();
    assert!(!b.owner_ui.session.is_locked(), "{}", b.status_text);
    assert!(
        b.status_text.contains("Relay sync is on"),
        "{}",
        b.status_text
    );
    assert_eq!(names(&b), vec!["Alpha"]);
    let id_b = current_id(&b);
    let entry = b.vault_list.registry.get(&id_b).expect("entry").clone();
    assert_eq!(entry.name, "Personal");
    assert!(entry.sync_relay().is_some());
    assert!(b.sync.relay.join_view(None).is_none());

    // Both Macs sync: Sync now on B, a lock on B, and the worker of A.
    add_item(&mut b, "From B", "SYNTH-from-b");
    b.sync_now();
    b.relay_settle_for_test();
    assert_eq!(b.status_text, "Saved to the relay.");
    a.sync_now();
    a.relay_settle_for_test();
    assert!(
        a.status_text.contains("1 credential changed on this Mac"),
        "{}",
        a.status_text
    );
    add_item(&mut b, "Before lock", "SYNTH-lock");
    lock(&mut b);
    a.sync_tick_for_test(Instant::now());
    assert_eq!(names(&a), vec!["Alpha", "Before lock", "From B"]);
    assert!(matches!(
        a.sync.statuses.get(&id),
        Some(UiStatus::UpToDate(Some(_)))
    ));
}

#[test]
fn relay_statuses_read_as_in_the_adr() {
    use super::sync::relay::{tag, words};
    use crate::sync::{Receipt, RelayRefusal, SyncError};

    let now = crate::vaults::now();
    let up = UiStatus::UpToDate(Some(now));
    assert_eq!(words(&up, None), "Saved to the relay. Last sync just now.");
    let receipt = Receipt {
        device_id: 3,
        device_name: "Mac mini".to_owned(),
        version: 2,
        at: now - 90,
    };
    assert_eq!(
        words(&up, Some(&receipt)),
        "Saved to the relay. Received by Mac mini 1 minute ago."
    );
    let unnamed = Receipt {
        device_name: String::new(),
        ..receipt.clone()
    };
    assert_eq!(
        words(&up, Some(&unnamed)),
        "Saved to the relay. Received by another Mac 1 minute ago."
    );
    assert_eq!(tag(&up), ("Saved to the relay", super::kit::Tone::Good));
    let problem = |error: SyncError| UiStatus::Problem(error.to_string());
    assert_eq!(
        words(&problem(SyncError::RelayUnreachable), None),
        "Relay not reachable. Apassy syncs when it is back."
    );
    assert_eq!(
        tag(&problem(SyncError::RelayUnreachable)).0,
        "Relay not reachable"
    );
    assert_eq!(
        words(&UiStatus::Damaged, None),
        "The copy on the relay fails a check. Apassy did not use it, and does not download it again until it changes."
    );
    assert!(
        words(&problem(SyncError::RemovedFromRelay), None).starts_with(
            "Removed from the relay. This Mac keeps its vault. Turn relay sync off, then join again with a link from another Mac."
        )
    );
    assert_eq!(
        tag(&problem(SyncError::RemovedFromRelay)).0,
        "Removed from the relay"
    );
    assert!(
        words(&problem(SyncError::ForkedCopy), None)
            .starts_with("The relay served a copy that does not include this Mac's last change.")
    );
    assert_eq!(tag(&problem(SyncError::StaleCopy)).0, "Relay copy refused");
    // A relay that limits: the worker waits and tries again on its own.
    let limited = problem(SyncError::Relay(RelayRefusal::RateLimited));
    assert_eq!(tag(&limited), ("Sync pending", super::kit::Tone::Accent));
    assert_eq!(
        words(&limited, None),
        "The relay asks Apassy to wait a minute. Apassy syncs after that."
    );
    assert_eq!(
        tag(&problem(SyncError::Relay(RelayRefusal::Busy))).0,
        "Sync pending"
    );
    let hourly = problem(SyncError::Relay(RelayRefusal::TeamLimit));
    assert_eq!(tag(&hourly).0, "Sync paused");
    assert!(
        words(&hourly, None).ends_with("The changes stay on this Mac and sync later."),
        "{}",
        words(&hourly, None)
    );

    // A relay that is away: the status says so, and the folder words do not show.
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    drop(relay);
    add_item(&mut a, "Offline", "SYNTH-offline");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(
        a.sync.statuses.get(&id),
        Some(&problem(SyncError::RelayUnreachable))
    );
    a.view = OwnerView::Settings;
    let text = frames(&mut a);
    assert!(
        text.contains("Relay not reachable. Apassy syncs when it is back."),
        "{text}"
    );
    assert!(!text.contains("sync folder"), "{text}");
    // A lock with a waiting change does not stop at the relay.
    lock(&mut a);
}

/// "Turn off" on a Mac that another Mac removed says that it left the team, not that
/// it is still in it; on the last Mac whose check did not answer, the relay keeps the
/// device (409), and the text says that it was the last Mac.
#[test]
fn turn_off_of_a_removed_or_last_mac_says_what_happened() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, id_b) = join_b(&folders, &mut a, &id);
    let device_b = b
        .vault_list
        .registry
        .get(&id_b)
        .and_then(|entry| entry.sync_relay())
        .expect("relay link")
        .device_id;
    a.relay_of(&id)
        .expect("relay")
        .remove_device(crate::sync::KeySource::Memory, device_b)
        .expect("A removes B");
    // B learns it at its next sync, and then asks the relay no more.
    b.sync_now();
    b.relay_settle_for_test();
    assert!(b.relay_of(&id_b).expect("relay").is_removed());
    assert!(
        b.status_text.starts_with("Removed from the relay."),
        "{}",
        b.status_text
    );
    // "Turn off" asks the relay once more: a suspended relay refuses the same way.
    let challenges = relay.count("POST /v1/auth/challenge");
    b.relay_turn_off(&id_b, false, None).expect("off");
    b.relay_settle_for_test();
    assert_eq!(relay.count("POST /v1/auth/challenge"), challenges + 1);
    assert_eq!(relay.count("DELETE /v1/devices/"), 1, "only A's removal");
    let done = b.status_text.clone();
    assert!(done.contains("no longer in the relay team"), "{done}");
    assert!(done.contains("“Devices…” on another Mac"), "{done}");
    assert!(!done.contains("still in the relay team"), "{done}");
    assert!(!done.contains("Turn relay sync off"), "{done}");

    // A is the last Mac now; "Turn off" without the answer of its check.
    a.relay_turn_off(&id, false, None).expect("off");
    a.relay_settle_for_test();
    let done = a.status_text.clone();
    assert!(
        done.contains("was the last Mac of the relay team"),
        "{done}"
    );
    assert!(!done.contains("on another Mac"), "{done}");
    assert_eq!(relay.devices().len(), 1, "the relay keeps the last device");
}

/// A removed Mac offers only turning relay sync off: Settings has no "Sync now", "Add a
/// Mac…", or "Devices…", and a sheet that opens anyway shows why, with nothing that
/// would ask the relay again ("Check again", "New link", "Refresh").
#[test]
fn a_removed_mac_offers_only_turning_relay_sync_off() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, id_b) = join_b(&folders, &mut a, &id);
    b.view = OwnerView::Settings;
    let text = settled_frames(&mut b);
    for expected in ["Sync now", "Add a Mac…", "Devices…"] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    let device_b = b
        .vault_list
        .registry
        .get(&id_b)
        .and_then(|entry| entry.sync_relay())
        .expect("relay link")
        .device_id;
    a.relay_of(&id)
        .expect("relay")
        .remove_device(crate::sync::KeySource::Memory, device_b)
        .expect("A removes B");
    b.sync_now();
    b.relay_settle_for_test();
    assert!(b.relay_removed(&id_b));
    let text = settled_frames(&mut b);
    assert!(
        text.contains("Turn relay sync off, then join again"),
        "{text}"
    );
    for gone in ["Sync now", "Add a Mac…", "Devices…"] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    // The sync menu stays: "Off" is the way back.
    assert!(text.contains("Apassy relay"), "{text}");

    let calls = relay.log().len();
    b.sync_open_sheet(SyncSheet::AddMac { id: id_b.clone() }, None);
    let text = settled_frames(&mut b);
    assert!(text.contains("Add a Mac to “Personal”"), "{text}");
    assert!(text.contains("Removed from the relay."), "{text}");
    for gone in ["Check again", "New link", "Copy link", "/link#apassy_lnk_"] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    assert!(text.contains("Done"), "{text}");
    b.ui.sheet = None;

    b.sync_open_sheet(SyncSheet::Devices { id: id_b.clone() }, None);
    let text = settled_frames(&mut b);
    assert!(text.contains("Removed from the relay."), "{text}");
    assert!(!text.contains("Refresh"), "{text}");
    assert!(text.contains("Done"), "{text}");
    b.ui.sheet = None;
    assert_eq!(
        relay.log().len(),
        calls,
        "a removed Mac asks the relay nothing"
    );
}

#[test]
fn turning_relay_sync_off_keeps_the_copy_and_the_last_mac_can_delete_it() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    a.view = OwnerView::Settings;
    a.sync_open_sheet(SyncSheet::TurnOff { id: id.clone() }, None);
    let text = settled_frames(&mut a);
    assert!(
        text.contains("Stop syncing “Personal” through the relay?"),
        "{text}"
    );
    assert!(
        text.contains("Delete the copy on the relay"),
        "the last Mac gets the choice: {text}"
    );
    a.relay_turn_off(&id, false, None).expect("off");
    a.relay_settle_for_test();
    let done = a.status_text.clone();
    assert!(done.contains("The copy on the relay stays."), "{done}");
    assert!(
        done.contains("only the operator of the relay can delete the copy now"),
        "the last Mac says what stays: {done}"
    );
    assert_eq!(relay.version(), 1, "the relay copy stays");
    assert!(
        a.vault_list
            .registry
            .get(&id)
            .expect("entry")
            .sync
            .is_none()
    );
    let row = a
        .owner_ui
        .session
        .with_vault(|vault| vault.relay_device())
        .expect("vault")
        .expect("row");
    assert!(row.is_none(), "the device key left the vault");

    // On again with a new team, then off with "Delete the copy on the relay".
    a.relay_enable_new(&id, &relay.url, &relay.team_code(), "Synthetic MacBook")
        .expect("on again");
    a.relay_settle_for_test();
    let team = a
        .vault_list
        .registry
        .get(&id)
        .and_then(|entry| entry.sync_relay())
        .map(|link| link.team_id.clone())
        .expect("team");
    a.relay_turn_off(&id, true, None).expect("off and delete");
    a.relay_settle_for_test();
    let done = a.status_text.clone();
    assert!(done.contains("The copy on the relay is deleted."), "{done}");
    assert!(
        relay
            .log()
            .iter()
            .any(|line| line.starts_with("DELETE /v1/sync")),
        "{team}: {:?}",
        relay.log()
    );
    assert_eq!(names(&a), vec!["Alpha"], "the vault on this Mac stays");
}

/// Mac A confirms the one Mac that waits in its "Add a Mac…" sheet.
fn confirm_waiting_mac(a: &mut DesktopApp) {
    a.relay_add_mac_poll_for_test();
    let links = a.relay_add_mac_links_for_test();
    assert_eq!(links.len(), 1, "{links:?}");
    a.relay_ask_confirm_for_test(links[0].id);
    a.confirm_owner_now(crate::broker::approvals::OwnerCheck::passphrase(PASS))
        .expect("owner check");
    a.relay_settle_for_test();
}

/// A new link of Mac A for the vault `id`.
fn new_link(a: &mut DesktopApp, id: &str) -> String {
    a.sync_open_sheet(SyncSheet::AddMac { id: id.to_owned() }, None);
    let _ = settled_frames(a);
    a.relay_add_mac_link_for_test().expect("a link")
}

/// Mac B joins the vault `id` of Mac A with a link, and adopts it. Returns B and the
/// list ID of the vault on B.
fn join_b(folders: &Folders, a: &mut DesktopApp, id: &str) -> (DesktopApp, String) {
    let link = new_link(a, id);
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    b.sync.relay.source = super::sync::OpenSource::Relay;
    let _ = send_link(&mut b, &link);
    confirm_waiting_mac(a);
    b.relay_join_poll_now_for_test();
    b.owner_ui.passphrase.push_str(PASS);
    b.relay_open_vault(None);
    b.relay_settle_for_test();
    assert!(!b.owner_ui.session.is_locked(), "{}", b.status_text);
    a.ui.sheet = None;
    let id_b = current_id(&b);
    (b, id_b)
}

#[test]
fn a_mac_that_turned_relay_sync_off_joins_again_with_a_link_and_merges() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    // Mac B gets the vault through the relay.
    let (mut b, id_b) = join_b(&folders, &mut a, &id);

    // B turns relay sync off: it leaves the team, and the relay copy stays.
    b.relay_turn_off(&id_b, false, None).expect("off");
    b.relay_settle_for_test();
    let done = b.status_text.clone();
    assert!(done.contains("The copy on the relay stays."), "{done}");
    assert_eq!(relay.devices().len(), 1, "B left the team");
    add_item(&mut b, "Only on B", "SYNTH-only-b");

    // On again: "Join from another Mac" with a new link of A merges both.
    let link = new_link(&mut a, &id);
    b.sync_open_sheet(SyncSheet::RelaySetup { id: id_b.clone() }, None);
    b.sync.relay.mode = super::sync::relay::SetupMode::Join;
    let text = frames(&mut b);
    assert!(text.contains("Send link"), "{text}");
    b.sync.relay.link_input = link;
    b.relay_join_request(Some(id_b.clone()), None);
    b.relay_join_settle_for_test();
    let text = frames(&mut b);
    assert!(text.contains("Waiting for the other Mac…"), "{text}");
    confirm_waiting_mac(&mut a);
    b.relay_join_poll_now_for_test();
    assert!(b.ui.sheet.is_none(), "{:?}", b.sync.relay.join_error);
    assert!(
        b.status_text.contains("merged with the relay copy"),
        "{}",
        b.status_text
    );
    assert!(b.is_relay(&id_b));
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(names(&a), vec!["Alpha", "Only on B"]);
}

/// "Join from another Mac" for a vault of the list whose passphrase differs from the
/// relay copy's: the sheet asks for the passphrase of the copy, and the step stays on
/// the screen while the merge runs. A wrong one changes nothing and asks again; the
/// right one merges, and the vault takes the passphrase of the copy, as the other Macs
/// have it. "Cancel" in that step removes the new device.
#[test]
fn joining_a_relay_copy_under_another_passphrase_asks_for_it() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, id_b) = join_b(&folders, &mut a, &id);
    b.relay_turn_off(&id_b, false, None).expect("off");
    b.relay_settle_for_test();
    assert_eq!(relay.devices().len(), 1, "B left the team");
    b.owner_ui
        .session
        .change_passphrase(PASS, NEW_PASS, NEW_PASS)
        .expect("change");

    let link = new_link(&mut a, &id);
    b.sync_open_sheet(SyncSheet::RelaySetup { id: id_b.clone() }, None);
    b.sync.relay.mode = super::sync::relay::SetupMode::Join;
    b.sync.relay.link_input = link;
    b.relay_join_request(Some(id_b.clone()), None);
    b.relay_join_settle_for_test();
    confirm_waiting_mac(&mut a);
    b.relay_join_poll_now_for_test();
    b.relay_settle_for_test();
    let asks = Some(super::sync::relay::JoinView::Passphrase {
        team: "Personal".to_owned(),
    });
    assert_eq!(
        b.sync.relay.join_view(Some(&id_b)),
        asks,
        "{:?}",
        b.sync.relay.join_error
    );
    assert!(b.sync.relay.join_error.is_none());
    assert!(!b.is_relay(&id_b));
    assert_eq!(
        relay.devices().len(),
        2,
        "the new device waits for the step"
    );
    b.view = OwnerView::Settings;
    let text = frames(&mut b);
    for expected in [
        "uses another passphrase than this vault",
        "Passphrase of the copy",
        "takes it, as on your other Macs",
        "Merge",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }

    // A wrong passphrase changes nothing and asks again. The step stays while the
    // merge runs.
    b.relay_join_passphrase(Zeroizing::new(OTHER_PASS.to_owned()));
    assert_eq!(b.sync.relay.join_view(Some(&id_b)), asks);
    b.relay_settle_for_test();
    assert_eq!(b.sync.relay.join_view(Some(&id_b)), asks);
    let error = b.sync.relay.join_error.clone().expect("an error");
    assert!(error.contains("does not open the relay copy"), "{error}");
    assert!(!b.is_relay(&id_b));
    assert_eq!(relay.version(), 1);

    // The passphrase of the copy merges, and the vault takes it.
    add_item(&mut b, "Only on B", "SYNTH-only-b");
    b.relay_join_passphrase(Zeroizing::new(PASS.to_owned()));
    assert_eq!(b.sync.relay.join_view(Some(&id_b)), asks);
    b.relay_settle_for_test();
    assert!(b.is_relay(&id_b), "{:?}", b.sync.relay.join_error);
    assert!(b.sync.relay.join_view(Some(&id_b)).is_none());
    assert!(b.ui.sheet.is_none());
    assert!(
        b.status_text
            .contains("uses the passphrase of the relay copy now"),
        "{}",
        b.status_text
    );
    assert_eq!(relay.version(), 2);
    assert_eq!(names(&b), vec!["Alpha", "Only on B"]);
    lock(&mut b);
    unlock(&mut b, PASS);
    // Mac A syncs on with its passphrase.
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(names(&a), vec!["Alpha", "Only on B"]);

    // "Cancel" in the passphrase step removes the new device. B takes another
    // passphrase first.
    b.relay_turn_off(&id_b, false, None).expect("off");
    b.relay_settle_for_test();
    b.owner_ui
        .session
        .change_passphrase(PASS, NEW_PASS, NEW_PASS)
        .expect("change");
    let devices = relay.devices().len();
    let link = new_link(&mut a, &id);
    b.sync_open_sheet(SyncSheet::RelaySetup { id: id_b.clone() }, None);
    b.sync.relay.mode = super::sync::relay::SetupMode::Join;
    b.sync.relay.link_input = link;
    b.relay_join_request(Some(id_b.clone()), None);
    b.relay_join_settle_for_test();
    confirm_waiting_mac(&mut a);
    b.relay_join_poll_now_for_test();
    b.relay_settle_for_test();
    assert_eq!(b.sync.relay.join_view(Some(&id_b)), asks);
    assert_eq!(relay.devices().len(), devices + 1);
    b.relay_sheet_closed();
    b.relay_settle_for_test();
    assert_eq!(relay.devices().len(), devices, "the new device left again");
    assert!(!b.is_relay(&id_b));
}

/// The team code is a one-time secret: the field is masked, and its text goes after
/// each try.
#[test]
fn the_team_code_field_is_masked_and_erased_after_each_try() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, None);
    let id = current_id(&a);
    a.view = OwnerView::Settings;
    a.sync_open_sheet(SyncSheet::RelaySetup { id: id.clone() }, None);
    let ctx = egui::Context::default();
    let _ = frames_in(&ctx, &mut a, Vec::new());
    let used = format!("apassy_tcd_{}", "0".repeat(64));
    a.sync.relay.url_input = relay.url.clone();
    a.sync.relay.team_code = used.clone();
    let text = frames_in(&ctx, &mut a, Vec::new());
    assert!(text.contains("Team code"), "{text}");
    assert!(!text.contains(&used), "the code shows: {text}");
    assert!(!text.contains("apassy_tcd_0"), "the code shows: {text}");
    let enter = egui::Event::Key {
        key: egui::Key::Enter,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::NONE,
    };
    let _ = frames_in(&ctx, &mut a, vec![enter]);
    a.relay_settle_for_test();
    assert!(
        a.status_text.contains("team code is wrong"),
        "{}",
        a.status_text
    );
    assert!(a.sync.relay.team_code.is_empty(), "erased after the try");
}

/// "Remove" in "Devices…" asks first. Cancel has the focus for the keyboard, so Return
/// keeps the Mac; "Remove" in the alert removes it.
#[test]
fn removing_a_mac_asks_first_and_return_keeps_it() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (b, id_b) = join_b(&folders, &mut a, &id);
    let device_b = b
        .vault_list
        .registry
        .get(&id_b)
        .and_then(|entry| entry.sync_relay())
        .expect("relay link")
        .device_id;
    a.view = OwnerView::Settings;
    a.sync_open_sheet(SyncSheet::Devices { id: id.clone() }, None);
    let _ = settled_frames(&mut a);
    let ctx = egui::Context::default();
    super::kit::set_keyboard_mode(&ctx, true);
    let _ = frames_in(&ctx, &mut a, Vec::new());
    a.relay_ask_remove_for_test(device_b, "Synthetic Mac mini");
    let text = frames_in(&ctx, &mut a, Vec::new());
    for expected in [
        "Remove “Synthetic Mac mini” from the relay?",
        "It keeps its vault but stops syncing. To add it again you need a new link and the owner check.",
        "Cancel",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    let key = |key, modifiers| egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    };
    let _ = frames_in(
        &ctx,
        &mut a,
        vec![key(egui::Key::Enter, egui::Modifiers::NONE)],
    );
    a.relay_settle_for_test();
    assert!(!a.relay_remove_asked_for_test(), "Return pressed Cancel");
    assert_eq!(relay.devices().len(), 2, "nothing removed");
    assert!(matches!(
        a.ui.sheet,
        Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::Devices { .. })))
    ));

    // Escape closes the alert only.
    a.relay_ask_remove_for_test(device_b, "Synthetic Mac mini");
    let _ = frames_in(&ctx, &mut a, Vec::new());
    let _ = frames_in(
        &ctx,
        &mut a,
        vec![key(egui::Key::Escape, egui::Modifiers::NONE)],
    );
    assert!(!a.relay_remove_asked_for_test());
    assert_eq!(relay.devices().len(), 2);

    // Shift-Tab to "Remove", then Return: the Mac leaves the relay team.
    a.relay_ask_remove_for_test(device_b, "Synthetic Mac mini");
    let _ = frames_in(&ctx, &mut a, Vec::new());
    let _ = frames_in(
        &ctx,
        &mut a,
        vec![key(egui::Key::Tab, egui::Modifiers::SHIFT)],
    );
    let _ = frames_in(
        &ctx,
        &mut a,
        vec![key(egui::Key::Enter, egui::Modifiers::NONE)],
    );
    a.relay_settle_for_test();
    assert!(!a.relay_remove_asked_for_test());
    assert_eq!(relay.devices().len(), 1, "{}", a.status_text);
    assert!(
        a.status_text.contains("is removed from the relay"),
        "{}",
        a.status_text
    );
}

/// One frame at `time`. Returns each painted text and its position.
fn frame_texts(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    time: f64,
    events: Vec<egui::Event>,
) -> Vec<(String, Pos2)> {
    fn texts(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
        match shape {
            egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
            egui::Shape::Vec(nested) => nested.iter().for_each(|inner| texts(inner, out)),
            _ => {}
        }
    }
    let input = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
        time: Some(time),
        events,
        ..Default::default()
    };
    let output = ctx.run_ui(input, |ui| draw(app, ui));
    let mut out = Vec::new();
    for clipped in &output.shapes {
        texts(&clipped.shape, &mut out);
    }
    output.drop_without_applying_deltas();
    out
}

/// A quick click (press and release in one frame, as a tap on a trackpad) on
/// "Confirm…" opens the owner check above "Add a Mac…", also the second time, and its
/// passphrase field takes the typed passphrase.
#[test]
fn a_quick_click_on_confirm_opens_the_owner_check_on_top_each_time() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    a.view = OwnerView::Settings;
    let link = new_link(&mut a, &id);
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    b.sync.relay.source = super::sync::OpenSource::Relay;
    let _ = send_link(&mut b, &link);
    a.relay_add_mac_poll_for_test();
    let owner_check = egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new(("apassy-sheet", "owner-check")),
    );
    let ctx = egui::Context::default();
    let mut time = 0.0;
    let mut frame = |a: &mut DesktopApp, events: Vec<egui::Event>| {
        time += 0.1;
        frame_texts(&ctx, a, time, events)
    };
    let quick_click = |at: Pos2| {
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        vec![egui::Event::PointerMoved(at), button(true), button(false)]
    };
    let at = |texts: &[(String, Pos2)], needle: &str| {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("no \"{needle}\": {texts:?}"))
    };
    let key = |key| egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::NONE,
    };
    let mut texts = Vec::new();
    for _ in 0..4 {
        texts = frame(&mut a, Vec::new());
    }
    for round in 1..=2 {
        let confirm = at(&texts, "Confirm…");
        let _ = frame(&mut a, vec![egui::Event::PointerMoved(confirm)]);
        let _ = frame(&mut a, quick_click(confirm));
        for _ in 0..4 {
            texts = frame(&mut a, Vec::new());
        }
        assert!(
            a.owner.check.is_some(),
            "round {round}: the owner check is open"
        );
        assert_eq!(
            ctx.memory(|memory| memory.top_modal_layer()),
            Some(owner_check),
            "round {round}: the owner check is the top sheet"
        );
        assert!(
            ctx.text_edit_focused(),
            "round {round}: the passphrase field has the focus"
        );
        if round == 1 {
            // Escape closes the check; a click in "Add a Mac…" brings it to the front.
            let _ = frame(&mut a, vec![key(egui::Key::Escape)]);
            texts = frame(&mut a, Vec::new());
            assert!(a.owner.check.is_none());
            let title = at(&texts, "Add a Mac to “Personal”");
            let _ = frame(&mut a, vec![egui::Event::PointerMoved(title)]);
            let _ = frame(&mut a, quick_click(title));
            for _ in 0..4 {
                texts = frame(&mut a, Vec::new());
            }
        }
    }
    let _ = frame(&mut a, vec![egui::Event::Text(PASS.to_owned())]);
    let _ = frame(&mut a, vec![key(egui::Key::Enter)]);
    // The check runs on its own thread; each frame polls it.
    let start = Instant::now();
    while a.owner.check.is_some() && start.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(20));
        let _ = frame(&mut a, Vec::new());
    }
    a.relay_settle_for_test();
    assert_eq!(relay.devices().len(), 2, "{}", a.status_text);
}

/// "Remove" and "Turn off" opened with the pointer: the alert shows no focus ring, and
/// Return still presses Cancel. It never removes the Mac or turns sync off.
#[test]
fn return_on_a_relay_alert_opened_with_the_pointer_cancels() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (b, id_b) = join_b(&folders, &mut a, &id);
    let device_b = b
        .vault_list
        .registry
        .get(&id_b)
        .and_then(|entry| entry.sync_relay())
        .expect("relay link")
        .device_id;
    let enter = egui::Event::Key {
        key: egui::Key::Enter,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::NONE,
    };
    a.view = OwnerView::Settings;
    a.sync_open_sheet(SyncSheet::Devices { id: id.clone() }, None);
    let _ = settled_frames(&mut a);
    let ctx = egui::Context::default();
    let _ = frames_in(&ctx, &mut a, Vec::new());
    a.relay_ask_remove_for_test(device_b, "Synthetic Mac mini");
    let text = frames_in(&ctx, &mut a, Vec::new());
    assert!(
        text.contains("Remove “Synthetic Mac mini” from the relay?"),
        "{text}"
    );
    assert!(!super::kit::keyboard_mode(&ctx), "a pointer user");
    assert_eq!(ctx.memory(|memory| memory.focused()), None, "no focus ring");
    let _ = frames_in(&ctx, &mut a, vec![enter.clone()]);
    a.relay_settle_for_test();
    assert_eq!(relay.devices().len(), 2, "nothing removed");
    assert!(!a.relay_remove_asked_for_test(), "Return pressed Cancel");

    a.ui.sheet = None;
    a.sync_open_sheet(SyncSheet::TurnOff { id: id.clone() }, None);
    let _ = settled_frames(&mut a);
    let ctx = egui::Context::default();
    let text = frames_in(&ctx, &mut a, Vec::new());
    assert!(
        text.contains("Stop syncing “Personal” through the relay?"),
        "{text}"
    );
    assert_eq!(ctx.memory(|memory| memory.focused()), None, "no focus ring");
    let _ = frames_in(&ctx, &mut a, vec![enter]);
    a.relay_settle_for_test();
    assert!(a.is_relay(&id), "relay sync stays on: {}", a.status_text);
    assert!(a.ui.sheet.is_none(), "Return pressed Cancel");
}

/// Each relay call of the owner runs on its own thread: the window keeps drawing and
/// keeps the vault while the relay is slow, and shows what runs.
#[test]
fn relay_calls_of_the_owner_leave_the_window_responsive() {
    const SLOW: Duration = Duration::from_millis(2000);
    const QUICK: Duration = Duration::from_millis(1000);
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, None);
    add_item(&mut a, "Alpha", "SYNTH-alpha");
    let id = current_id(&a);
    a.view = OwnerView::Settings;

    // "Turn on" with a slow first upload.
    relay.delay("PUT /v1/sync/snapshot", SLOW);
    a.sync_open_sheet(SyncSheet::RelaySetup { id: id.clone() }, None);
    let started = Instant::now();
    a.relay_enable_new(&id, &relay.url, &relay.team_code(), "Synthetic MacBook")
        .expect("sent");
    let text = frames(&mut a);
    add_item(&mut a, "While it uploads", "SYNTH-busy");
    assert!(
        started.elapsed() < QUICK,
        "the window waited for the relay: {:?}",
        started.elapsed()
    );
    assert!(
        text.contains("Apassy turns relay sync on and uploads the vault…"),
        "{text}"
    );
    assert_eq!(a.relay_jobs_for_test(), 1);
    a.relay_settle_for_test();
    assert!(a.ui.sheet.is_none(), "{}", a.status_text);
    assert!(
        a.status_text.contains("syncs through the Apassy relay"),
        "{}",
        a.status_text
    );
    assert_eq!(relay.version(), 1);

    // "Sync now" with a slow relay.
    relay.delay("GET /v1/sync/head", SLOW);
    let started = Instant::now();
    a.sync_now();
    let text = frames(&mut a);
    assert!(a.owner_ui.session.with_vault(|_| ()).is_some());
    assert!(
        started.elapsed() < QUICK,
        "the window waited for the relay: {:?}",
        started.elapsed()
    );
    assert!(text.contains("Apassy syncs with the relay…"), "{text}");
    a.relay_settle_for_test();
    assert_eq!(a.status_text, "Saved to the relay.");
    assert_eq!(relay.version(), 2, "the change made during the upload");

    // "Add a Mac…" and "Devices…" with a slow relay.
    relay.delay("POST /v1/devices/links", SLOW);
    relay.delay("GET /v1/devices", SLOW);
    let started = Instant::now();
    a.sync_open_sheet(SyncSheet::AddMac { id: id.clone() }, None);
    let text = frames(&mut a);
    assert!(
        started.elapsed() < QUICK,
        "the window waited for the relay: {:?}",
        started.elapsed()
    );
    assert!(text.contains("Apassy asks the relay for a link…"), "{text}");
    a.relay_settle_for_test();
    assert!(a.relay_add_mac_link_for_test().is_some());
    a.ui.sheet = None;
    let started = Instant::now();
    a.sync_open_sheet(SyncSheet::Devices { id: id.clone() }, None);
    let text = frames(&mut a);
    assert!(
        started.elapsed() < QUICK,
        "the window waited for the relay: {:?}",
        started.elapsed()
    );
    assert!(
        text.contains("Apassy asks the relay for the Macs…"),
        "{text}"
    );
    let text = settled_frames(&mut a);
    assert!(
        text.contains("Synthetic MacBook") && text.contains("This Mac"),
        "{text}"
    );
}

/// "Cancel" on a Mac that waits for the other Mac cancels its link on the relay, also
/// at a quit; after a confirmation it removes the new device.
#[test]
fn cancel_of_a_waiting_mac_cancels_its_link_on_the_relay() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    b.sync.relay.source = super::sync::OpenSource::Relay;

    let link = new_link(&mut a, &id);
    let _ = send_link(&mut b, &link);
    assert_eq!(relay.pending_links(), 1);
    b.relay_join_cancel();
    b.relay_settle_for_test();
    assert_eq!(relay.pending_links(), 0, "the relay forgot the link");
    a.relay_add_mac_poll_for_test();
    assert!(a.relay_add_mac_links_for_test().is_empty());

    // A quit while B waits cancels the link too.
    let link = new_link(&mut a, &id);
    let _ = send_link(&mut b, &link);
    assert_eq!(relay.pending_links(), 1);
    b.relay_quit();
    assert_eq!(relay.pending_links(), 0, "the quit cancelled the link");

    // A confirmation that came first: the cancel removes the new device.
    let link = new_link(&mut a, &id);
    let _ = send_link(&mut b, &link);
    confirm_waiting_mac(&mut a);
    assert_eq!(relay.devices().len(), 2);
    b.relay_join_cancel();
    b.relay_settle_for_test();
    assert_eq!(relay.devices().len(), 1, "the new device left the team");
}

/// Picking a folder for a vault on the relay asks in the "Turn off" sheet, removes this
/// Mac from the relay team, then syncs with the folder. A locked vault says what stays.
#[test]
fn switching_a_relay_vault_to_a_folder_leaves_the_relay_team() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, id_b) = join_b(&folders, &mut a, &id);
    assert_eq!(relay.devices().len(), 2);

    b.view = OwnerView::Settings;
    b.relay_switch_to_folder(&id_b, folders.dropbox.clone(), None);
    let text = settled_frames(&mut b);
    assert!(
        text.contains("Sync “Personal” with Dropbox instead of the relay?"),
        "{text}"
    );
    assert!(text.contains("this Mac leaves the relay team"), "{text}");
    assert!(text.contains("Switch"), "{text}");
    b.relay_turn_off(&id_b, false, Some(folders.dropbox.clone()))
        .expect("switch");
    b.relay_settle_for_test();
    assert_eq!(relay.devices().len(), 1, "B left the relay team");
    let entry = b.vault_list.registry.get(&id_b).expect("entry").clone();
    assert!(entry.sync_relay().is_none());
    assert_eq!(
        entry.sync_file(),
        Some(folders.dropbox.join("Personal.apassy"))
    );
    assert!(
        b.status_text.contains("syncs with Dropbox"),
        "{}",
        b.status_text
    );
    assert!(
        b.status_text.contains("The copy on the relay stays."),
        "{}",
        b.status_text
    );
    assert!(b.ui.sheet.is_none());

    // "Turn off" of a locked vault waits for an unlock: the key of this Mac is in the
    // vault, and it leaves only with the vault unlocked.
    lock(&mut a);
    let err = a.relay_turn_off(&id, false, None).unwrap_err();
    assert!(err.contains("Open and unlock “Personal” first"), "{err}");
    assert!(a.is_relay(&id), "relay sync stays on");
    unlock(&mut a, PASS);
    let row = a
        .owner_ui
        .session
        .with_vault(|vault| vault.relay_device())
        .expect("vault")
        .expect("row");
    assert!(row.is_some(), "the device key stays in the vault");
    assert_eq!(relay.devices().len(), 1);
}

/// A damaged copy on the relay offers "Replace with this Mac's vault…" behind a sheet;
/// the replace uploads this vault as a new version.
#[test]
fn a_damaged_relay_copy_offers_replace_with_this_macs_vault() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, _) = join_b(&folders, &mut a, &id);
    add_item(&mut b, "Beta", "SYNTH-beta");
    b.sync_now();
    b.relay_settle_for_test();
    assert_eq!(relay.version(), 2);
    relay.corrupt_snapshot(2);

    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(a.sync.statuses.get(&id), Some(&UiStatus::Damaged));
    a.view = OwnerView::Settings;
    let text = frames(&mut a);
    assert!(
        text.contains("The copy of “Personal” on the relay fails a check"),
        "{text}"
    );
    assert!(text.contains("Replace with this Mac's vault…"), "{text}");

    a.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::ReplaceDamaged {
        id: id.clone(),
    })));
    let text = frames(&mut a);
    assert!(
        text.contains("Replace the damaged copy on the relay?"),
        "{text}"
    );
    a.relay_replace(&id);
    let text = frames(&mut a);
    assert!(
        text.contains("Apassy uploads the vault of this Mac to the relay…")
            || a.relay_jobs_for_test() == 0,
        "{text}"
    );
    a.relay_settle_for_test();
    assert_eq!(relay.version(), 3);
    assert!(a.ui.sheet.is_none(), "{}", a.status_text);
    assert!(a.sync.notice.is_none());
    assert!(matches!(
        a.sync.statuses.get(&id),
        Some(UiStatus::UpToDate(_))
    ));
    assert!(
        a.status_text
            .starts_with("The relay has the vault of this Mac now."),
        "{}",
        a.status_text
    );
    // B merges version 3 and keeps its own change.
    b.sync_now();
    b.relay_settle_for_test();
    assert_eq!(names(&b), vec!["Alpha", "Beta"]);
}

/// Settings reads the receipts that the other Macs send after a merge: "Received by".
#[test]
fn received_by_shows_the_receipt_of_the_other_mac() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, _) = join_b(&folders, &mut a, &id);
    add_item(&mut a, "Gamma", "SYNTH-gamma");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(relay.version(), 2);
    b.sync_now();
    b.relay_settle_for_test();
    assert_eq!(names(&b), vec!["Alpha", "Gamma"]);

    a.view = OwnerView::Settings;
    let text = settled_frames(&mut a);
    // The fake relay sends no device names; the real relay does (contract section 9).
    assert!(
        text.contains("Saved to the relay. Received by another Mac just now."),
        "{text}"
    );
}

/// A passphrase that changed on another Mac: the check with the relay copy runs on its
/// own thread, and its answer closes the sheet.
#[test]
fn a_new_passphrase_from_another_mac_on_the_relay_rekeys_off_the_window_thread() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let (mut b, id_b) = join_b(&folders, &mut a, &id);
    a.owner_ui
        .session
        .change_passphrase(PASS, NEW_PASS, NEW_PASS)
        .expect("change");
    add_item(&mut a, "After change", "SYNTH-after");
    a.sync_now();
    a.relay_settle_for_test();
    b.sync_now();
    b.relay_settle_for_test();
    assert_eq!(b.sync.statuses.get(&id_b), Some(&UiStatus::NeedsPassphrase));
    assert!(matches!(
        b.ui.sheet,
        Some(Sheet::Vault(VaultSheet::Sync(
            SyncSheet::NewPassphrase { .. }
        )))
    ));
    b.relay_take_passphrase(&id_b, Zeroizing::new(OTHER_PASS.to_owned()));
    b.relay_settle_for_test();
    assert!(b.status_text.contains("does not open"), "{}", b.status_text);
    assert!(b.ui.sheet.is_some(), "the sheet stays for another try");
    b.relay_take_passphrase(&id_b, Zeroizing::new(NEW_PASS.to_owned()));
    b.relay_settle_for_test();
    assert!(b.ui.sheet.is_none(), "{}", b.status_text);
    assert!(
        b.status_text.contains("uses the new passphrase"),
        "{}",
        b.status_text
    );
    assert_eq!(names(&b), vec!["After change", "Alpha"]);
}

/// A relay restored from a backup, with one Mac in the team: the Mac refuses the older
/// copy, Settings offers "Use the relay copy…", and the Mac syncs again with the same
/// device. Nothing is lost.
#[test]
fn a_lone_mac_after_a_relay_rollback_uses_the_relay_copy() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    add_item(&mut a, "Beta", "SYNTH-beta");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(relay.version(), 2);
    relay.roll_back_to(1);
    add_item(&mut a, "Gamma", "SYNTH-gamma");
    a.sync_now();
    a.relay_settle_for_test();
    let status = a.sync.statuses.get(&id).cloned().expect("status");
    assert!(super::sync::relay::refused_copy(&status), "{status:?}");
    a.view = OwnerView::Settings;
    let text = frames(&mut a);
    assert!(text.contains("Use the relay copy…"), "{text}");

    a.sync_open_sheet(SyncSheet::UseRelayCopy { id: id.clone() }, None);
    let text = frames(&mut a);
    assert!(text.contains("Use the copy on the relay?"), "{text}");
    a.relay_use_copy(&id);
    a.relay_settle_for_test();
    assert!(a.ui.sheet.is_none(), "{}", a.status_text);
    assert!(
        a.status_text.starts_with("Apassy merged the relay copy"),
        "{}",
        a.status_text
    );
    assert_eq!(relay.version(), 2);
    assert_eq!(relay.devices().len(), 1, "the device stays");
    assert!(matches!(
        a.sync.statuses.get(&id),
        Some(UiStatus::UpToDate(_))
    ));
    assert_eq!(names(&a), vec!["Alpha", "Beta", "Gamma"]);
}

/// A relay restored from a backup that predates a passphrase change: "Use the relay
/// copy" needs the passphrase of that copy, so the passphrase sheet opens. It asks for
/// the passphrase of the copy, not for a new one; that passphrase only opens the copy
/// for the merge, the vault keeps the passphrase of this Mac, and the result says so.
/// Nothing is lost.
#[test]
fn use_the_relay_copy_asks_for_the_passphrase_of_an_older_copy() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    a.owner_ui
        .session
        .change_passphrase(PASS, NEW_PASS, NEW_PASS)
        .expect("change");
    add_item(&mut a, "Beta", "SYNTH-beta");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(relay.version(), 2);
    relay.roll_back_to(1);
    a.sync_now();
    a.relay_settle_for_test();
    let status = a.sync.statuses.get(&id).cloned().expect("status");
    assert!(super::sync::relay::refused_copy(&status), "{status:?}");
    a.sync_open_sheet(SyncSheet::UseRelayCopy { id: id.clone() }, None);
    a.relay_use_copy(&id);
    a.relay_settle_for_test();
    assert_eq!(a.sync.statuses.get(&id), Some(&UiStatus::NeedsPassphrase));
    assert!(
        matches!(
            a.ui.sheet,
            Some(Sheet::Vault(VaultSheet::Sync(
                SyncSheet::NewPassphrase { .. }
            )))
        ),
        "{}",
        a.status_text
    );
    let text = frames(&mut a);
    assert!(text.contains("uses another passphrase"), "{text}");
    assert!(text.contains("Passphrase of the copy"), "{text}");
    assert!(text.contains("keeps its passphrase"), "{text}");
    assert!(!text.contains("changed on another Mac"), "{text}");
    a.ui.sheet = None;
    a.view = OwnerView::Settings;
    let text = frames(&mut a);
    assert!(text.contains("Type the passphrase of the copy…"), "{text}");
    assert!(
        text.contains(super::sync::relay::OLDER_COPY_WORDS),
        "{text}"
    );
    assert!(!text.contains("changed on another Mac"), "{text}");

    a.relay_take_passphrase(&id, Zeroizing::new(PASS.to_owned()));
    a.relay_settle_for_test();
    assert!(a.ui.sheet.is_none(), "{}", a.status_text);
    assert!(
        a.status_text.contains("keeps the passphrase of this Mac"),
        "{}",
        a.status_text
    );
    assert!(
        !a.status_text.contains("new passphrase"),
        "{}",
        a.status_text
    );
    assert!(matches!(
        a.sync.statuses.get(&id),
        Some(UiStatus::UpToDate(_))
    ));
    assert_eq!(relay.version(), 2);
    assert_eq!(names(&a), vec!["Alpha", "Beta"]);
    lock(&mut a);
    unlock(&mut a, NEW_PASS);
}

/// "Sync now" that a pause ends (the pause of "Turn off", or a lock) tells nothing: no
/// problem status and no "The vault is locked." while the vault is unlocked.
#[test]
fn a_sync_now_that_a_pause_ends_tells_nothing() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    add_item(&mut a, "Beta", "SYNTH-beta");
    relay.delay("PUT /v1/sync/snapshot", Duration::from_secs(3));
    let puts = relay.count("PUT /v1/sync/snapshot");
    let before = a.sync.statuses.get(&id).cloned();
    a.status_text.clear();
    a.sync_now();
    let deadline = Instant::now() + Duration::from_secs(10);
    while relay.count("PUT /v1/sync/snapshot") == puts && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    a.relay_of(&id).expect("relay").pause();
    a.relay_settle_for_test();
    assert_eq!(a.sync.statuses.get(&id).cloned(), before);
    assert!(!a.status_text.contains("locked"), "{}", a.status_text);
    assert!(!a.owner_ui.session.is_locked());
}

/// A team code that the relay refuses leaves a folder sync as it was; a good code then
/// moves the vault from the folder to the relay.
#[test]
fn a_refused_team_code_keeps_the_folder_sync() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, Some(&folders.dropbox));
    add_item(&mut a, "Alpha", "SYNTH-alpha");
    let id = current_id(&a);
    let file = Some(folders.dropbox.join("Personal.apassy"));
    assert_eq!(a.vault_list.registry.get(&id).unwrap().sync_file(), file);
    let state = a
        .vault_list
        .data_dir
        .join("sync")
        .join(format!("{id}.json"));

    let used = format!("apassy_tcd_{}", "0".repeat(64));
    a.relay_enable_new(&id, &relay.url, &used, "Synthetic MacBook")
        .expect("sent");
    a.relay_settle_for_test();
    assert!(
        a.status_text.contains("Folder sync stays on."),
        "{}",
        a.status_text
    );
    assert_eq!(a.vault_list.registry.get(&id).unwrap().sync_file(), file);
    let kept = crate::sync::read_state(&state).expect("state").expect("on");
    assert_eq!(kept.transport, crate::sync::TransportKind::Folder);

    a.relay_enable_new(&id, &relay.url, &relay.team_code(), "Synthetic MacBook")
        .expect("sent");
    a.relay_settle_for_test();
    assert!(a.is_relay(&id), "{}", a.status_text);
    let moved = crate::sync::read_state(&state).expect("state").expect("on");
    assert_eq!(moved.transport, crate::sync::TransportKind::Relay);
    let staged = a
        .vault_list
        .data_dir
        .join("sync")
        .join(format!("{id}.relay-new.json"));
    assert!(!staged.exists());
    add_item(&mut a, "Beta", "SYNTH-beta");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(a.status_text, "Saved to the relay.");
    assert_eq!(relay.version(), 2);
}

/// While relay sync turns on, the sync setting of the vault waits: a folder pick does
/// not delete the relay state that the call writes.
#[test]
fn the_sync_setting_waits_while_relay_sync_turns_on() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let mut a = folders.mac("mac-a");
    create(&mut a, "Personal", PASS, None);
    add_item(&mut a, "Alpha", "SYNTH-alpha");
    let id = current_id(&a);
    relay.delay("POST /v1/teams", Duration::from_millis(1500));
    a.relay_enable_new(&id, &relay.url, &relay.team_code(), "Synthetic MacBook")
        .expect("sent");
    let started = Instant::now();
    let refused = a.sync_enable(&id, &folders.dropbox);
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(
        refused
            .as_ref()
            .is_err_and(|text| text.contains("turning on or off")),
        "{refused:?}"
    );
    a.relay_settle_for_test();
    assert!(a.is_relay(&id), "{}", a.status_text);
    add_item(&mut a, "Beta", "SYNTH-beta");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(a.status_text, "Saved to the relay.");
}

/// A lock drops the relay key and the access token at once, without a step of the
/// worker.
#[test]
fn a_lock_drops_the_relay_key_at_once() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    a.sync_now();
    a.relay_settle_for_test();
    let sync = a.relay_of(&id).expect("relay");
    assert!(sync.has_session(), "the sync loaded the key");
    lock(&mut a);
    assert!(!sync.has_session(), "the lock dropped the key");
}

/// A new Mac whose link answer the network lost tries again with the same key: the
/// relay gives the same answer, so the code is not used up.
#[test]
fn a_lost_link_answer_does_not_use_up_the_code() {
    let folders = folders();
    let relay = fake_relay::FakeRelay::start();
    let (mut a, id) = relay_mac_a(&folders, &relay);
    let link = new_link(&mut a, &id);
    let mut b = folders.mac("mac-b");
    super::sync::begin_open(&mut b);
    b.sync.relay.source = super::sync::OpenSource::Relay;
    relay.lose_next_answers("POST /v1/devices/link", 1);
    b.sync.relay.link_input = link.clone();
    b.sync.relay.device_input = "Synthetic Mac mini".to_owned();
    b.relay_join_request(None, None);
    b.relay_join_settle_for_test();
    assert!(b.sync.relay.join_view(None).is_none());
    let error = b.sync.relay.join_error.clone().unwrap_or_default();
    assert!(error.contains("Relay not reachable"), "{error}");

    let safety = send_link(&mut b, &link);
    a.relay_add_mac_poll_for_test();
    let links = a.relay_add_mac_links_for_test();
    assert_eq!(links.len(), 1, "{links:?}");
    assert_eq!(links[0].safety.as_deref(), Some(safety.as_str()));
    confirm_waiting_mac(&mut a);
    b.relay_join_poll_now_for_test();
    assert_eq!(
        b.sync.relay.join_view(None),
        Some(super::sync::relay::JoinView::Ready {
            team: "Personal".to_owned()
        }),
        "{:?}",
        b.sync.relay.join_error
    );
}
