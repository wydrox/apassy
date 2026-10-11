//! Headless UI tests of the passkey on the credential page: the metadata, the missing key
//! controls, the removal sheet and its owner request, and the edit of a login that has a
//! passkey and no password. Synthetic data only. The keys are made in a temporary vault.

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::owner_tests::{PASS, collect, locked_app};
use super::super::{Sheet, draw};
use crate::broker::approvals::OwnerCheck;
use crate::contracts::CredentialKind;
use crate::desktop::model::ItemDraft;
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::SecretForm;
use crate::desktop::{DesktopApp, OwnerView};
use crate::vault::passkey::b64url_encode;
use crate::vault::{PasskeyCreate, PasskeyTarget};

const SIZE: Vec2 = Vec2::new(1180.0, 1600.0);
const PASSWORD: &str = "passkey-ui-password-canary";
const RP_ID: &str = "example.test";
const ACCOUNT: &str = "alice@example.test";
const DISPLAY: &str = "Alice Example";

/// One window that keeps its egui state between frames.
struct Window {
    ctx: egui::Context,
    time: f64,
    text: String,
    texts: Vec<(String, Pos2)>,
}

impl Window {
    fn new() -> Self {
        Self {
            ctx: egui::Context::default(),
            time: 0.0,
            text: String::new(),
            texts: Vec::new(),
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) {
        self.time += 0.1;
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(self.time),
            events,
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        self.text.clear();
        self.texts.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut self.text);
            positions(&clipped.shape, &mut self.texts);
        }
        output.drop_without_applying_deltas();
    }

    /// Draw frames until a new sheet is visible and the layout is stable.
    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..4 {
            self.frame(app, Vec::new());
        }
    }

    fn has(&self, needle: &str) -> bool {
        self.texts.iter().any(|(text, _)| text == needle)
    }

    fn at(&self, needle: &str) -> Pos2 {
        self.texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text))
    }

    /// Click the first painted text that is `needle`.
    fn click(&mut self, app: &mut DesktopApp, needle: &str) {
        let at = self.at(needle);
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        self.frame(app, vec![Event::PointerMoved(at)]);
        self.frame(app, vec![button(true)]);
        self.frame(app, vec![button(false)]);
        self.idle(app);
    }

    fn key(&mut self, app: &mut DesktopApp, key: Key, modifiers: Modifiers) {
        self.frame(
            app,
            vec![Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
        );
        self.idle(app);
    }
}

fn positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| positions(inner, out)),
        _ => {}
    }
}

fn unlocked_app(dir: &TempDir, name: &str) -> DesktopApp {
    let mut app = locked_app(dir, name);
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app
}

fn select(app: &mut DesktopApp, item_id: u64) {
    app.select_item(item_id.to_string());
    app.view = OwnerView::Item;
}

/// A login with a password, no passkey yet. Returns the ID and the revision.
fn login_with_password(app: &mut DesktopApp, title: &str) -> (u64, u64) {
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    let summary = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: title.to_owned(),
                kind: CredentialKind::Login,
                username: "alice".to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    (summary.id, summary.revision)
}

/// Register a passkey as the vault does. Returns the ID of the login that has it.
fn make_passkey(
    app: &mut DesktopApp,
    target: PasskeyTarget,
    user_name: &str,
    display_name: &str,
) -> u64 {
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault
                .create_passkey(PasskeyCreate {
                    rp_id: RP_ID,
                    user_handle: &[7; 16],
                    user_name,
                    user_display_name: display_name,
                    client_data_hash: &[1; 32],
                    algorithms: &[],
                    exclude: &[],
                    target,
                })
                .expect("create passkey")
                .item_id
        })
        .expect("vault")
}

/// A login that has a passkey and no password.
fn passkey_only(app: &mut DesktopApp, title: &str) -> u64 {
    make_passkey(
        app,
        PasskeyTarget::NewItem {
            title: title.to_owned(),
        },
        ACCOUNT,
        DISPLAY,
    )
}

/// A login that has a password and a passkey.
fn password_and_passkey(app: &mut DesktopApp, title: &str) -> u64 {
    let (id, revision) = login_with_password(app, title);
    make_passkey(
        app,
        PasskeyTarget::Attach {
            item_id: id,
            revision,
        },
        ACCOUNT,
        DISPLAY,
    )
}

/// The private key of the passkey, as the text that must never be on the screen.
fn key_text(app: &DesktopApp, item_id: u64) -> String {
    app.owner_ui
        .session
        .with_vault(|vault| {
            let export = vault.export_passkey(item_id).expect("export");
            b64url_encode(&export.pkcs8)
        })
        .expect("vault")
}

fn credential_id(app: &DesktopApp, item_id: u64) -> Vec<u8> {
    app.owner_ui
        .session
        .passkey_item(item_id)
        .expect("passkey item")
        .expect("the login has a passkey")
        .info
        .credential_id
}

fn has_passkey(app: &DesktopApp, item_id: u64) -> bool {
    matches!(app.owner_ui.session.passkey_item(item_id), Ok(Some(_)))
}

fn revision(app: &DesktopApp, item_id: u64) -> u64 {
    app.owner_ui
        .session
        .details(item_id)
        .expect("details")
        .revision
}

/// Pass the open owner check with the passphrase, as the owner does.
fn pass_owner_check(app: &mut DesktopApp) -> OwnerRequest {
    let request = app
        .owner
        .check
        .as_ref()
        .expect("the owner check is open")
        .request
        .clone();
    let proof = app
        .owner_gate()
        .authorize(request.action(), OwnerCheck::passphrase(PASS))
        .expect("owner check");
    app.close_owner_check(None);
    app.complete_owner_request(request.clone(), proof);
    request
}

// ---- The metadata. ----

#[test]
fn the_page_shows_the_passkey_metadata_and_no_key_control() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "metadata.db");
    let id = passkey_only(&mut app, "Example passkey");
    let key = key_text(&app, id);
    let short = super::short_credential_id(&credential_id(&app, id));
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "Passkey",
        "Website",
        RP_ID,
        "Account",
        ACCOUNT,
        "Display name",
        DISPLAY,
        "Credential ID",
        short.as_str(),
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    // The login has no password: the action deletes the whole login, and says so.
    assert!(window.has("Delete login…"), "{}", window.text);
    assert!(!window.has("Remove passkey…"), "{}", window.text);
    // No control reaches the key: the page has no secret section, no Show, no Copy, no
    // export, and no setup of the passkey.
    let details = app.owner_ui.session.details(id).expect("details");
    assert!(
        details.secret_lines.is_empty(),
        "{:?}",
        details.secret_lines
    );
    for control in ["Secret", "Show", "Hide", "Copy", "Export", "Show code"] {
        assert!(!window.has(control), "{control}: {}", window.text);
    }
    assert!(!window.text.contains(&key), "the key is on the screen");
    assert!(!window.text.contains("passkey_key"), "{}", window.text);
    // The shortcut for Show and Hide does nothing for a login without a secret value.
    window.key(
        &mut app,
        Key::H,
        Modifiers {
            command: true,
            shift: true,
            ..Modifiers::NONE
        },
    );
    assert!(app.owner.check.is_none(), "the shortcut asked for a check");
}

#[test]
fn names_from_a_page_are_cleaned_before_they_are_drawn() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "clean.db");
    let id = make_passkey(
        &mut app,
        PasskeyTarget::NewItem {
            title: "Spoof".to_owned(),
        },
        "evil\u{202e}gnp.exe\nnext line",
        &"long name ".repeat(40),
    );
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(!window.text.contains('\u{202e}'), "{}", window.text);
    assert!(window.has("evilgnp.exenext line"), "{}", window.text);
    // A long display name is cut, as in the owner check dialog.
    let cut = window
        .texts
        .iter()
        .find(|(text, _)| text.starts_with("long name"))
        .unwrap_or_else(|| panic!("no display name: {}", window.text));
    assert!(
        cut.0.ends_with('…') && cut.0.chars().count() <= 65,
        "{:?}",
        cut.0
    );
}

#[test]
fn a_login_with_a_password_offers_to_remove_only_the_passkey() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "both.db");
    let id = password_and_passkey(&mut app, "Both");
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(window.has("Remove passkey…"), "{}", window.text);
    assert!(!window.has("Delete login…"), "{}", window.text);
    assert!(window.has("Passkey"), "{}", window.text);
    // The generic Show of the password is as before, and it does not name the key.
    let details = app.owner_ui.session.details(id).expect("details");
    let names: Vec<_> = details
        .secret_lines
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    assert_eq!(names, ["password"]);
    assert!(window.has("Show"), "{}", window.text);
    assert!(!window.text.contains(PASSWORD));
    window.click(&mut app, "Show");
    let request = &app.owner.check.as_ref().expect("check").request;
    assert_eq!(*request, OwnerRequest::Reveal { item_id: id });
}

#[test]
fn a_login_without_a_passkey_has_no_passkey_section() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "plain.db");
    let (id, _) = login_with_password(&mut app, "Plain");
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    for text in [
        "Passkey",
        "Credential ID",
        "Remove passkey…",
        "Delete login…",
    ] {
        assert!(!window.has(text), "{text}: {}", window.text);
    }
}

// ---- The removal. ----

#[test]
fn removing_a_passkey_asks_the_owner_with_the_shown_revision_and_name() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "remove.db");
    let id = password_and_passkey(&mut app, "Both");
    let shown_revision = revision(&app, id);
    let before = credential_id(&app, id);
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Remove passkey…");
    // The sheet comes first. It does not ask the owner, and it changes nothing.
    assert!(window.has("Remove this passkey?"), "{}", window.text);
    assert!(
        window
            .text
            .contains("The password and the other fields stay")
    );
    assert!(!window.text.contains("whole login"), "{}", window.text);
    assert!(app.owner.check.is_none());
    assert_eq!(credential_id(&app, id), before);
    window.click(&mut app, "Remove passkey");
    assert_eq!(
        app.owner.check.as_ref().expect("check").request,
        OwnerRequest::RemovePasskey {
            item_id: id,
            revision: shown_revision,
            name: "Both".to_owned(),
            delete_login: false,
        }
    );
    // The UI changed nothing itself: the passkey waits for the owner check.
    assert!(has_passkey(&app, id));
    pass_owner_check(&mut app);
    window.idle(&mut app);
    assert!(!has_passkey(&app, id));
    let details = app.owner_ui.session.details(id).expect("the login stays");
    assert_eq!(details.name, "Both");
    assert!(details.secret_lines.iter().any(|l| l.name == "password"));
    assert!(window.has("Show"), "{}", window.text);
    assert!(!window.has("Credential ID"), "{}", window.text);
}

#[test]
fn deleting_a_login_with_only_a_passkey_warns_about_the_whole_login() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "delete.db");
    let id = passkey_only(&mut app, "Only passkey");
    let shown_revision = revision(&app, id);
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Delete login…");
    assert!(window.has("Delete this login?"), "{}", window.text);
    let text = window.text.clone();
    // The sheet names the login and says what the owner loses.
    assert!(text.contains("“Only passkey”"), "{text}");
    for expected in [
        "whole login",
        "notes",
        "tags",
        "website",
        "one-time passwords",
        "custom details",
        "agent access",
        "history",
        "other devices",
        "cannot undo",
        "add a password",
        "archive the login",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!window.has("Remove passkey"), "{text}");
    assert!(app.owner.check.is_none());
    window.click(&mut app, "Delete login");
    assert_eq!(
        app.owner.check.as_ref().expect("check").request,
        OwnerRequest::RemovePasskey {
            item_id: id,
            revision: shown_revision,
            name: "Only passkey".to_owned(),
            delete_login: true,
        }
    );
    assert!(has_passkey(&app, id), "the UI deleted before the check");
    pass_owner_check(&mut app);
    window.idle(&mut app);
    assert!(app.owner_ui.session.details(id).is_err(), "still there");
    assert_eq!(app.view, OwnerView::Vault);
}

#[test]
fn cancel_and_escape_close_the_removal_sheet_without_a_request() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "cancel.db");
    let id = passkey_only(&mut app, "Keep me");
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    for close_with_escape in [false, true] {
        window.click(&mut app, "Delete login…");
        assert!(window.has("Delete this login?"), "{}", window.text);
        if close_with_escape {
            window.key(&mut app, Key::Escape, Modifiers::NONE);
        } else {
            window.click(&mut app, "Cancel");
        }
        assert!(!window.has("Delete this login?"), "{}", window.text);
        assert!(app.owner.check.is_none());
        assert!(has_passkey(&app, id));
    }
}

#[test]
fn a_change_while_the_sheet_is_open_closes_it_and_sends_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "stale.db");
    let id = password_and_passkey(&mut app, "Both");
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Remove passkey…");
    assert!(window.has("Remove this passkey?"), "{}", window.text);
    // Another device changes the login: the revision moves.
    let details = app.owner_ui.session.details(id).expect("details");
    let mut draft = details.to_draft();
    draft.notes = "changed elsewhere".to_owned();
    app.owner_ui
        .session
        .update(id, details.revision, &draft, &SecretForm::default())
        .expect("update");
    window.idle(&mut app);
    assert!(!window.has("Remove this passkey?"), "{}", window.text);
    assert!(app.owner.check.is_none());
    assert!(has_passkey(&app, id));
    assert!(
        app.status_text.contains("The login changed"),
        "{}",
        app.status_text
    );
}

#[test]
fn the_sheet_does_not_come_back_after_the_owner_leaves_the_page() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "leave.db");
    let id = passkey_only(&mut app, "Leave");
    select(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Delete login…");
    assert!(window.has("Delete this login?"), "{}", window.text);
    app.view = OwnerView::Vault;
    window.idle(&mut app);
    select(&mut app, id);
    window.idle(&mut app);
    assert!(!window.has("Delete this login?"), "{}", window.text);
    assert!(window.has("Delete login…"), "{}", window.text);
}

// ---- The edit. ----

fn open_edit(app: &mut DesktopApp, item_id: u64) {
    let details = app.owner_ui.session.details(item_id).expect("details");
    app.edit_form = details.to_draft();
    app.owner_ui.edit_revision = details.revision;
    app.ui.sheet = Some(Sheet::EditItem);
}

#[test]
fn editing_a_login_with_only_a_passkey_keeps_the_passkey() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "edit.db");
    let id = passkey_only(&mut app, "Only passkey");
    let key = key_text(&app, id);
    let before = app
        .owner_ui
        .session
        .passkey_item(id)
        .expect("item")
        .expect("passkey");
    select(&mut app, id);
    open_edit(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    // A password is optional here, and the form says so.
    assert!(window.has("Optional"), "{}", window.text);
    assert!(!window.has("Unchanged"), "{}", window.text);
    assert!(window.text.contains("A password is optional"));
    app.edit_form.name = "Renamed passkey".to_owned();
    app.edit_form.notes = "a note".to_owned();
    window.key(&mut app, Key::S, Modifiers::COMMAND);
    assert!(app.ui.sheet.is_none(), "{}", app.status_text);
    let details = app.owner_ui.session.details(id).expect("details");
    assert_eq!(details.name, "Renamed passkey");
    assert_eq!(details.notes, "a note");
    // The key and the metadata are as they were. The title of the metadata follows the
    // login.
    let after = app
        .owner_ui
        .session
        .passkey_item(id)
        .expect("item")
        .expect("the passkey stays");
    assert!(!after.has_password);
    assert_eq!(after.info.credential_id, before.info.credential_id);
    assert_eq!(after.info.user_handle, before.info.user_handle);
    assert_eq!(after.info.rp_id, before.info.rp_id);
    assert_eq!(after.info.user_name, before.info.user_name);
    assert_eq!(after.info.user_display_name, before.info.user_display_name);
    assert_eq!(key_text(&app, id), key);
}

#[test]
fn editing_a_login_with_a_password_still_shows_the_unchanged_hint() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "edit-both.db");
    let id = password_and_passkey(&mut app, "Both");
    select(&mut app, id);
    open_edit(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(window.has("Unchanged"), "{}", window.text);
    assert!(!window.text.contains("A password is optional"));
}

#[test]
fn a_new_login_without_a_password_stays_invalid() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "new.db");
    app.add_form = ItemDraft {
        name: "No password".to_owned(),
        kind: CredentialKind::Login,
        username: "alice".to_owned(),
        ..ItemDraft::default()
    };
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
    let mut window = Window::new();
    window.idle(&mut app);
    // The add form never offers the passkey wording.
    assert!(!window.text.contains("A password is optional"));
    window.key(&mut app, Key::S, Modifiers::COMMAND);
    assert!(
        app.status_text.contains("Enter the password"),
        "{}",
        app.status_text
    );
    assert!(app.owner_ui.session.search("").expect("search").is_empty());
}

#[test]
fn a_login_with_a_password_keeps_requiring_one_when_the_passkey_is_gone() {
    // Removing the passkey from a login with a password leaves a normal login. Its edit
    // form shows the normal hint, and a blank password keeps the stored password.
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "after.db");
    let id = password_and_passkey(&mut app, "Both");
    let current = revision(&app, id);
    app.owner_ui
        .session
        .with_vault(|vault| vault.remove_passkey(id, current).expect("remove"))
        .expect("vault");
    select(&mut app, id);
    open_edit(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(window.has("Unchanged"), "{}", window.text);
    assert!(!window.text.contains("A password is optional"));
}

#[test]
fn a_passkey_without_an_account_name_can_still_be_edited() {
    // A registration can come with an empty account name. The vault accepts a login with
    // a passkey and no username, so the edit must not ask for one.
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir, "empty-name.db");
    let id = make_passkey(
        &mut app,
        PasskeyTarget::NewItem {
            title: "No account name".to_owned(),
        },
        "",
        "",
    );
    let before = credential_id(&app, id);
    select(&mut app, id);
    open_edit(&mut app, id);
    let mut window = Window::new();
    window.idle(&mut app);
    app.edit_form.notes = "a note".to_owned();
    window.key(&mut app, Key::S, Modifiers::COMMAND);
    assert!(app.ui.sheet.is_none(), "{}", app.status_text);
    assert_eq!(credential_id(&app, id), before);
    assert_eq!(
        app.owner_ui.session.details(id).expect("details").notes,
        "a note"
    );
}
