//! Headless tests of sync through a folder in the app (ADR 0014). Synthetic values only.
//! Temporary folders stand in for iCloud Drive and Dropbox, and each "Mac" is an app
//! with its own data directory. No test touches a real synced folder or the network.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::start::{self, Step};
use super::sync::{SyncSheet, UiStatus};
use super::vaults::VaultSheet;
use super::{Sheet, draw};
use crate::desktop::owner_store::SecretForm;
use crate::desktop::{DesktopApp, ItemDraft, OwnerView};
use crate::sync::SyncFolder;
use crate::vault::{ActivityDecision, NewActivity};

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
    let ctx = egui::Context::default();
    a.poll_sync(&ctx);
    assert!(a.sync_change_waits_for_test(), "the poll sees the change");
    assert_eq!(
        fs::read(&file).expect("file"),
        before,
        "not yet: the change settles"
    );
    // Seven seconds later the change syncs.
    a.sync_force_settled_for_test(Instant::now() - Duration::from_secs(10));
    a.poll_sync(&ctx);
    assert_ne!(fs::read(&file).expect("file"), before);

    // Mac B merges the changed file on its next look, without a lock.
    b.sync_poll_now();
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
    let ctx = egui::Context::default();
    a.poll_sync(&ctx);
    assert!(
        !a.sync_change_waits_for_test(),
        "activity is not a change to sync"
    );
    // Even a sync now writes nothing, and neither does the lock.
    a.sync_force_settled_for_test(Instant::now() - Duration::from_secs(10));
    a.poll_sync(&ctx);
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
