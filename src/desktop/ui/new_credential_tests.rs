//! "New Credential" (ADR 0025 §4): a paste becomes credentials in the selected folder,
//! with the variable and the declaration, and without an owner check. Synthetic values
//! only.

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::Choices;
use crate::desktop::ui::{Sheet, draw, folders};
use crate::desktop::{DesktopApp, Place};
use crate::vault::{DeclarationSource, Environment};

const PASS: &str = "new-credential-pass-ok";
const SIZE: Vec2 = Vec2::new(1180.0, 800.0);

/// A synthetic value with a provider prefix, as in `tests/detect.rs`.
fn fake(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

/// An unlocked synthetic vault. The directory must outlive the app.
fn unlocked(dir: &TempDir) -> DesktopApp {
    let mut app = DesktopApp::new();
    let path = dir.path().join("paste.db");
    app.owner_ui
        .session
        .create_file(&path, PASS)
        .expect("create");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app
}

/// One window: a context across frames, as the real window has.
struct Window {
    ctx: egui::Context,
    text: String,
    placed: Vec<(String, Pos2)>,
}

impl Window {
    fn new() -> Self {
        Self {
            ctx: egui::Context::default(),
            text: String::new(),
            placed: Vec::new(),
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<egui::Event>) {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        self.text.clear();
        self.placed.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut self.text, &mut self.placed);
        }
        output.drop_without_applying_deltas();
    }

    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..3 {
            self.frame(app, Vec::new());
        }
    }

    /// ⌘S: the default action of the sheet.
    fn command_s(&mut self, app: &mut DesktopApp) {
        self.frame(
            app,
            vec![egui::Event::Key {
                key: egui::Key::S,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::COMMAND,
            }],
        );
        self.idle(app);
    }

    /// Click the last painted text `needle` (the top layer draws last).
    fn click(&mut self, app: &mut DesktopApp, needle: &str) {
        self.idle(app);
        let at = self
            .placed
            .iter()
            .rev()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("{needle} is not on the screen: {}", self.text));
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        self.frame(app, vec![egui::Event::PointerMoved(at)]);
        self.frame(app, vec![button(true)]);
        self.frame(app, vec![button(false)]);
        self.idle(app);
    }
}

fn collect(shape: &egui::Shape, text: &mut String, placed: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(shape) => {
            text.push_str(shape.galley.text());
            text.push('\n');
            placed.push((shape.galley.text().to_owned(), shape.pos));
        }
        egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, text, placed)),
        _ => {}
    }
}

/// Open the sheet with `paste` in the field, as a paste does.
fn open_with(app: &mut DesktopApp, window: &mut Window, paste: &str) {
    app.ui.sheet = Some(Sheet::NewCredential);
    app.owner_ui.add_secrets.custom_value = paste.to_owned();
    window.idle(app);
}

/// One key: one row with the provider, the variable, and the host. Add makes the
/// credential in the folder of the sidebar, with its variable and its declaration, and
/// selects it. No owner check. The paste is erased, and no value is on the screen.
#[test]
fn a_pasted_key_goes_to_the_selected_folder_with_its_variable_and_declaration() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let work = folders::create(&mut app, None, "Work").expect("folder");
    assert_eq!(app.place, Place::Folder(Some(work.uuid.clone())));
    let key = fake("sk-ant-api03-", 40);
    let mut window = Window::new();
    open_with(&mut app, &mut window, &key);
    for expected in [
        "New Credential",
        "Anthropic API key",
        "Anthropic · ANTHROPIC_API_KEY · api.anthropic.com",
        "Work",
        "Add",
    ] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    assert!(!window.text.contains("Add 1"), "{}", window.text);
    assert!(!window.text.contains(&key), "the paste is masked");
    assert!(
        !window.text.contains("EXAMPLE0"),
        "no part of the value shows: {}",
        window.text
    );

    window.command_s(&mut app);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert!(app.owner.check.is_none(), "adding needs no owner check");
    assert!(
        app.status_text
            .starts_with("Added Anthropic API key · ANTHROPIC_API_KEY · production in Work"),
        "{}",
        app.status_text
    );
    assert!(
        app.owner_ui.add_secrets.custom_value.is_empty(),
        "the paste is erased"
    );
    let id: u64 = app
        .selected_item_id
        .as_deref()
        .and_then(|id| id.parse().ok())
        .expect("the new credential is selected");
    assert_eq!(app.place, Place::Folder(Some(work.uuid.clone())));
    let session = &app.owner_ui.session;
    let folder = session
        .with_vault(|vault| vault.item_folder(id))
        .expect("open")
        .expect("folder");
    assert_eq!(folder.as_deref(), Some(work.uuid.as_str()));
    let binding = session
        .process_binding(id)
        .expect("read")
        .expect("variable");
    assert_eq!(binding.env_name, "ANTHROPIC_API_KEY");
    let declaration = session.declaration(id).expect("read").expect("declaration");
    assert_eq!(declaration.environment, Environment::Production);
    let sources = session
        .with_vault(|vault| vault.declaration_sources(id))
        .expect("open")
        .expect("sources");
    assert_eq!(sources.environment, DeclarationSource::Default);

    // The page asks about the environment, and the value stays masked.
    window.idle(&mut app);
    assert!(
        window.text.contains("Is this a development key?"),
        "{}",
        window.text
    );
    assert!(!window.text.contains("EXAMPLE0"), "{}", window.text);
}

/// A `.env` file gives one row for each line, each with a checkbox. The owner unchecks
/// one and renames one; "Add 2" adds the two, at the top level of "All credentials".
#[test]
fn a_dotenv_paste_adds_only_the_checked_lines() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let paste = format!(
        "# synthetic .env\nRESEND_API_KEY={}\nSTRIPE_SECRET_KEY={}\nGITHUB_TOKEN={}\n",
        fake("re_", 24),
        fake("sk_test_", 24),
        fake("ghp_", 36),
    );
    let mut window = Window::new();
    open_with(&mut app, &mut window, &paste);
    assert!(window.text.contains("Add 3"), "{}", window.text);
    assert!(window.text.contains("RESEND_API_KEY"), "{}", window.text);
    assert!(
        window.text.contains("Personal"),
        "the top level: {}",
        window.text
    );

    Choices::set_kept(&window.ctx, 1, false);
    Choices::set_title(&window.ctx, 0, "Mail key");
    window.idle(&mut app);
    assert!(window.text.contains("Add 2"), "{}", window.text);

    window.command_s(&mut app);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert_eq!(app.status_text, "Added 2 credentials in Personal.");
    let items = app.owner_ui.session.search("").expect("list");
    let mut names: Vec<&str> = items.iter().map(|item| item.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["GitHub token", "Mail key"], "{names:?}");
    let selected = app.selected_item_id.clone().expect("selected");
    let mail = items
        .iter()
        .find(|item| item.name == "Mail key")
        .expect("mail");
    assert_eq!(selected, mail.id.to_string(), "the first added is selected");
    for item in &items {
        let folder = app
            .owner_ui
            .session
            .with_vault(|vault| vault.item_folder(item.id))
            .expect("open")
            .expect("folder");
        assert_eq!(folder, None, "{} is at the top level", item.name);
    }
}

/// The folder menu puts the credential in another folder than the one of the list, and
/// the list follows it. An empty paste adds nothing. Cancel erases the paste, and
/// "Fill in by hand…" leads to the add form, which also puts a credential in the folder of
/// the list.
#[test]
fn the_folder_menu_cancel_and_fill_in_by_hand() {
    use crate::contracts::CredentialKind;
    use crate::desktop::ItemDraft;

    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let home = folders::create(&mut app, None, "Home").expect("folder");
    app.place = Place::CREDENTIALS;
    let mut window = Window::new();

    open_with(&mut app, &mut window, "   ");
    window.command_s(&mut app);
    assert_eq!(app.ui.sheet, Some(Sheet::NewCredential), "nothing to add");
    assert!(app.owner_ui.session.search("").expect("list").is_empty());

    open_with(&mut app, &mut window, &fake("ghp_", 36));
    Choices::set_folder(&window.ctx, Some(home.uuid.clone()));
    window.idle(&mut app);
    assert!(window.text.contains("Home"), "{}", window.text);
    window.command_s(&mut app);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert_eq!(app.place, Place::Folder(Some(home.uuid.clone())));
    let id: u64 = app
        .selected_item_id
        .as_deref()
        .and_then(|id| id.parse().ok())
        .expect("selected");
    let folder_of = |app: &DesktopApp, id: u64| {
        app.owner_ui
            .session
            .with_vault(|vault| vault.item_folder(id))
            .expect("open")
            .expect("folder")
    };
    assert_eq!(folder_of(&app, id).as_deref(), Some(home.uuid.as_str()));

    open_with(&mut app, &mut window, &fake("ghp_", 36));
    window.click(&mut app, "Cancel");
    assert_eq!(app.ui.sheet, None);
    assert!(app.owner_ui.add_secrets.custom_value.is_empty());

    open_with(&mut app, &mut window, &fake("ghp_", 36));
    window.click(&mut app, "Fill in by hand…");
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: false }));
    assert!(app.owner_ui.add_secrets.custom_value.is_empty());

    // The add form, in the folder Home: the key lands in Home.
    app.add_form = ItemDraft {
        kind: CredentialKind::ApiKey,
        name: "Router".to_owned(),
        ..ItemDraft::default()
    };
    app.owner_ui.add_secrets.token = "synthetic-router-token".to_owned();
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
    window.command_s(&mut app);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    let router = app
        .owner_ui
        .session
        .search("Router")
        .expect("search")
        .first()
        .map(|item| item.id)
        .expect("added");
    assert_eq!(folder_of(&app, router).as_deref(), Some(home.uuid.as_str()));
}

/// The paste shows masked unless the owner edits it: each `.env` line keeps its variable
/// and the public prefix of the provider, never the value, and a comment line does not
/// show. A Stripe test key is a development key.
#[test]
fn the_paste_shows_masked_and_a_stripe_test_key_is_development() {
    use crate::vault::detect;

    let paste = format!(
        "# synthetic .env\nSTRIPE_SECRET_KEY={}\nDATABASE_PASSWORD=example-pass\nDATABASE_URL=postgres://app:EXAMPLE0@db.example.com:5432/app\n",
        fake("sk_test_", 24),
    );
    let detected = detect::detect(&paste);
    assert_eq!(
        super::masked_paste(&detected),
        "STRIPE_SECRET_KEY=sk_test_••••••••\nDATABASE_PASSWORD=••••••••\nDATABASE_URL=postgres://••••••••"
    );
    assert_eq!(super::masked_paste(&[]), "••••••••");
    assert_eq!(super::row_cap(&detected[0]), Some(("Development", false)));
    assert_eq!(super::row_line(&detected[1]), "Secret · DATABASE_PASSWORD");

    // On the screen: the masked lines, no value, and the Development cap.
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let mut window = Window::new();
    open_with(&mut app, &mut window, &paste);
    assert!(
        window.text.contains("STRIPE_SECRET_KEY=sk_test_••••••••"),
        "{}",
        window.text
    );
    assert!(window.text.contains("Development"), "{}", window.text);
    assert!(!window.text.contains("Staging"), "{}", window.text);
    for secret in ["EXAMPLE0", "example-pass", "synthetic .env"] {
        assert!(!window.text.contains(secret), "{secret}: {}", window.text);
    }
}

/// Destination survives the Paste → Login transition and a hidden saved result is revealed.
#[test]
fn paste_destination_survives_manual_login_and_reveals_the_actual_result() {
    use crate::contracts::CredentialKind;
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let a = folders::create(&mut app, None, "A").expect("A");
    let b = folders::create(&mut app, None, "B").expect("B");
    app.place = Place::Folder(Some(a.uuid));
    let mut window = Window::new();
    open_with(&mut app, &mut window, "");
    Choices::set_folder(&window.ctx, Some(b.uuid.clone()));
    window.click(&mut app, "Login");
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: true }));
    assert_eq!(app.add_form.kind, CredentialKind::Login);
    assert_eq!(app.ui.create_folder.as_deref(), Some(b.uuid.as_str()));
    app.add_form.name = "Synthetic account".to_owned();
    app.add_form.username = "owner@example.com".to_owned();
    app.add_form.website = "https://example.com/login".to_owned();
    app.owner_ui.add_secrets.password = "EXAMPLE-password".to_owned();
    app.search = "unrelated query".to_owned();
    app.ui.credential_filter = crate::desktop::ui::items::Filter::Archived;
    window.command_s(&mut app);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    let items = app.owner_ui.session.search("").expect("items");
    assert_eq!(items.len(), 1);
    let id = items[0].id;
    assert_eq!(
        app.owner_ui
            .session
            .with_vault(|v| v.item_folder(id))
            .unwrap()
            .unwrap(),
        Some(b.uuid.clone())
    );
    assert_eq!(app.place, Place::Folder(Some(b.uuid)));
    assert_eq!(app.selected_item_id, Some(id.to_string()));
    assert!(app.search.is_empty());
    assert_eq!(
        app.ui.credential_filter,
        crate::desktop::ui::items::Filter::All
    );
    assert!(window.text.contains("Synthetic account"));
    assert!(!window.text.contains("EXAMPLE-password"));
    assert!(app.owner.check.is_none());
}

#[test]
fn deleted_create_destination_retains_manual_draft_and_does_not_redirect() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let b = folders::create(&mut app, None, "B").expect("B");
    let mut window = Window::new();
    open_with(&mut app, &mut window, "");
    Choices::set_folder(&window.ctx, Some(b.uuid.clone()));
    window.click(&mut app, "Login");
    assert_eq!(app.ui.create_folder.as_deref(), Some(b.uuid.as_str()));
    app.owner_ui
        .session
        .with_vault(|v| v.delete_folder(&b.uuid))
        .unwrap()
        .unwrap();
    app.add_form.name = "Retained draft".to_owned();
    app.add_form.username = "owner@example.com".to_owned();
    app.owner_ui.add_secrets.password = "EXAMPLE-password".to_owned();
    window.command_s(&mut app);
    assert!(app.ui.sheet.is_some());
    assert_eq!(app.add_form.name, "Retained draft");
    assert_eq!(app.owner_ui.add_secrets.password, "EXAMPLE-password");
    assert!(app.owner_ui.session.search("").unwrap().is_empty());
    assert_eq!(app.ui.create_folder, Some(b.uuid));
}

#[test]
fn twenty_known_ids_move_once_and_undo_without_leaving_source() {
    use crate::desktop::model::ItemDraft;
    use crate::desktop::owner_store::SecretForm;
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let source = folders::create(&mut app, None, "Source").expect("source");
    let other = folders::create(&mut app, Some(&source.uuid), "Other").expect("other");
    let dest = folders::create(&mut app, None, "Destination").expect("dest");
    let mut originals = Vec::new();
    let mut secrets = SecretForm::default();
    secrets.token = "EXAMPLE-key".to_owned();
    for index in 0..21 {
        let original = if index == 20 {
            dest.uuid.clone()
        } else if index % 2 == 0 {
            source.uuid.clone()
        } else {
            other.uuid.clone()
        };
        let item = app
            .owner_ui
            .session
            .add_in_folder(
                &ItemDraft {
                    name: format!("Synthetic {index}"),
                    ..Default::default()
                },
                &secrets,
                Some(&original),
            )
            .expect("add");
        originals.push((item.id, original));
    }
    app.place = Place::Folder(Some(source.uuid));
    let context = app.place.clone();
    let ids: Vec<_> = originals[..20].iter().map(|(id, _)| *id).collect();
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Synthetic 0");
    let command = |key, modifiers| egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    };
    window.frame(
        &mut app,
        vec![command(egui::Key::A, egui::Modifiers::COMMAND)],
    );
    window.idle(&mut app);
    assert_eq!(app.ui.selected_items, ids.iter().copied().collect());
    window.frame(
        &mut app,
        vec![command(
            egui::Key::M,
            egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
        )],
    );
    window.idle(&mut app);
    assert_eq!(
        app.ui.sheet,
        Some(Sheet::MoveItemsToFolder {
            item_ids: ids.clone()
        })
    );
    window.click(&mut app, "Destination");
    window.click(&mut app, "Move");
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert_eq!(app.place, context);
    assert_eq!(app.ui.move_undo.len(), 20);
    for id in &ids {
        assert_eq!(
            app.owner_ui
                .session
                .with_vault(|v| v.item_folder(*id))
                .unwrap()
                .unwrap(),
            Some(dest.uuid.clone())
        );
    }
    window.click(&mut app, "Undo Move");
    assert!(app.ui.move_undo.is_empty());
    for (id, original) in originals {
        assert_eq!(
            app.owner_ui
                .session
                .with_vault(|v| v.item_folder(id))
                .unwrap()
                .unwrap(),
            Some(original)
        );
    }
    assert_eq!(app.place, context);
}

#[test]
fn field_copy_starts_a_fresh_owner_check_without_revealing_or_using_clipboard() {
    use crate::contracts::CredentialKind;
    use crate::desktop::model::ItemDraft;
    use crate::desktop::owner_check::OwnerRequest;
    use crate::desktop::owner_store::SecretForm;
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let mut secrets = SecretForm::default();
    secrets.password = "EXAMPLE-password".to_owned();
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Synthetic login".to_owned(),
                kind: CredentialKind::Login,
                username: "owner@example.com".to_owned(),
                ..Default::default()
            },
            &secrets,
        )
        .expect("login");
    let revision = app.owner_ui.session.details(item.id).unwrap().revision;
    app.select_item(item.id.to_string());
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(window.text.contains("Show"));
    assert!(window.text.contains("Copy"));
    assert!(
        app.owner_ui
            .session
            .revealed_value(item.id, "password")
            .is_none()
    );
    window.click(&mut app, "Copy");
    assert!(
        matches!(&app.owner.check.as_ref().expect("fresh check").request,
        OwnerRequest::CopyField { item_id, field, revision: submitted }
        if *item_id == item.id && field == "password" && *submitted == revision)
    );
    assert!(
        app.owner_ui
            .session
            .revealed_value(item.id, "password")
            .is_none()
    );
    assert!(!window.text.contains("EXAMPLE-password"));
}

#[test]
fn visible_folder_more_menu_moves_a_subtree_and_reveals_its_new_ancestry() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let source = folders::create(&mut app, None, "Source").expect("source");
    let child = folders::create(&mut app, Some(&source.uuid), "Child").expect("child");
    let destination = folders::create(&mut app, None, "Destination").expect("destination");
    app.place = Place::Folder(Some(source.uuid.clone()));
    let mut window = Window::new();
    window.click(&mut app, "More");
    window.click(&mut app, "Move Folder…");
    assert_eq!(
        app.ui.sheet,
        Some(Sheet::MoveFolder {
            uuid: source.uuid.clone()
        })
    );
    window.click(&mut app, "Destination");
    window.click(&mut app, "Move");
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    let tree = folders::FolderTree::load(&app);
    assert_eq!(
        tree.get(&source.uuid).unwrap().parent.as_deref(),
        Some(destination.uuid.as_str())
    );
    assert_eq!(
        tree.get(&child.uuid).unwrap().parent.as_deref(),
        Some(source.uuid.as_str())
    );
    assert!(app.ui.open_folders.contains(&destination.uuid));
    assert_eq!(app.place, Place::Folder(Some(source.uuid)));
}
