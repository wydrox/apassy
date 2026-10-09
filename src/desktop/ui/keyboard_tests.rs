//! Keyboard tests of the window: the focus follows the owner into a sheet and back,
//! Return does the default action, a destructive alert starts on Cancel, and the page
//! scrolls to the focus. Synthetic values only.

use std::collections::HashMap;

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2, accesskit};
use tempfile::TempDir;

use super::owner_tests::unlocked_app_with_item;
use super::{Sheet, draw, kit};
use crate::desktop::{DesktopApp, OwnerView};

const SIZE: Vec2 = Vec2::new(1180.0, 760.0);

/// One window with a context that keeps the focus between frames, and the AccessKit
/// names of the last frame.
struct Window {
    ctx: egui::Context,
    size: Vec2,
    time: f64,
    names: HashMap<accesskit::NodeId, String>,
    text: String,
    /// Each painted text and its position.
    texts: Vec<(String, Pos2)>,
    text_bounds: Vec<(String, Rect, Rect)>,
    focus_strokes: usize,
}

impl Window {
    fn new() -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        Self {
            ctx,
            size: SIZE,
            time: 0.0,
            names: HashMap::new(),
            text: String::new(),
            texts: Vec::new(),
            text_bounds: Vec::new(),
            focus_strokes: 0,
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) {
        // A scroll to the focus is animated. A tenth of a second per frame lets it end.
        self.time += 0.1;
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, self.size)),
            time: Some(self.time),
            events,
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        if let Some(update) = &output.platform_output.accesskit_update {
            for (id, node) in &update.nodes {
                if let Some(label) = node.label() {
                    self.names.insert(*id, label.to_owned());
                }
            }
        }
        self.text.clear();
        self.texts.clear();
        self.text_bounds.clear();
        self.focus_strokes = 0;
        for clipped in &output.shapes {
            super::owner_tests::collect(&clipped.shape, &mut self.text);
            collect_positions(&clipped.shape, &mut self.texts);
            collect_text_bounds(&clipped.shape, clipped.clip_rect, &mut self.text_bounds);
            count_focus_strokes(&clipped.shape, &mut self.focus_strokes);
        }
        output.drop_without_applying_deltas();
    }

    /// Press a key, then draw frames until the focus settles.
    fn press(&mut self, app: &mut DesktopApp, key: Key, modifiers: Modifiers) {
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
        for _ in 0..8 {
            self.frame(app, Vec::new());
        }
    }

    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..4 {
            self.frame(app, Vec::new());
        }
    }

    /// Click the first painted text that is `needle` with the pointer, then draw frames
    /// until the focus settles.
    fn click(&mut self, app: &mut DesktopApp, needle: &str) {
        let at = self
            .texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text));
        self.click_at(app, at);
    }

    fn click_at(&mut self, app: &mut DesktopApp, at: Pos2) {
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

    /// Scroll the page to its end with the mouse wheel.
    fn wheel_to_end(&mut self, app: &mut DesktopApp) {
        let at = Pos2::new(self.size.x * 0.6, self.size.y * 0.5);
        self.frame(app, vec![Event::PointerMoved(at)]);
        let wheel = Event::MouseWheel {
            unit: egui::MouseWheelUnit::Page,
            delta: Vec2::new(0.0, -10.0),
            phase: egui::TouchPhase::Move,
            modifiers: Modifiers::NONE,
        };
        self.frame(app, vec![wheel]);
        self.idle(app);
    }

    fn focused(&self) -> Option<egui::Id> {
        self.ctx.memory(|memory| memory.focused())
    }

    fn focused_name(&self) -> Option<String> {
        let id = self.focused()?;
        self.names.get(&id.accesskit_id()).cloned()
    }

    /// Press Tab until the focused control has `name`. Fails after `max` presses.
    fn tab_to(&mut self, app: &mut DesktopApp, name: &str, max: usize) {
        for _ in 0..max {
            self.press(app, Key::Tab, Modifiers::NONE);
            if self.focused_name().as_deref() == Some(name) {
                return;
            }
        }
        panic!(
            "Tab did not reach \"{name}\". Last focus: {:?}",
            self.focused_name()
        );
    }

    /// Press Tab until a text field has the focus. Fails after `max` presses.
    fn tab_to_text_field(&mut self, app: &mut DesktopApp, max: usize) {
        for _ in 0..max {
            self.press(app, Key::Tab, Modifiers::NONE);
            if self.ctx.text_edit_focused() {
                return;
            }
        }
        panic!("Tab did not reach a text field");
    }

    /// The layer of the focused control.
    fn focused_layer(&self) -> Option<egui::LayerId> {
        let id = self.focused()?;
        self.ctx.read_response(id).map(|response| response.layer_id)
    }

    fn focused_rect(&self) -> Option<Rect> {
        let id = self.focused()?;
        self.ctx.read_response(id).map(|response| response.rect)
    }

    /// The rightmost exact text match separates the Back control from the sidebar.
    fn visible_text_rect(&self, needle: &str) -> Rect {
        let (_, rect, clip) = self
            .text_bounds
            .iter()
            .filter(|(text, _, _)| text == needle)
            .max_by(|(_, a, _), (_, b, _)| a.left().total_cmp(&b.left()))
            .unwrap_or_else(|| panic!("\"{needle}\" is not painted: {}", self.text));
        let screen = Rect::from_min_size(Pos2::ZERO, self.size);
        assert!(
            screen.contains_rect(*rect),
            "{needle} is outside the window: {rect:?}"
        );
        assert!(
            clip.contains_rect(*rect),
            "{needle} is clipped: {rect:?}, {clip:?}"
        );
        *rect
    }
}

/// The top of the first painted text that is `needle`. egui does not paint a label
/// that is scrolled out of view.
fn text_top(window: &Window, needle: &str) -> Option<f32> {
    window
        .texts
        .iter()
        .find(|(text, _)| text == needle)
        .map(|(_, pos)| pos.y)
}

fn collect_positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested
            .iter()
            .for_each(|inner| collect_positions(inner, out)),
        _ => {}
    }
}

fn collect_text_bounds(shape: &egui::Shape, clip: Rect, out: &mut Vec<(String, Rect, Rect)>) {
    match shape {
        egui::Shape::Text(text) => out.push((
            text.galley.text().to_owned(),
            Rect::from_min_size(text.pos, text.galley.size()),
            clip,
        )),
        egui::Shape::Vec(nested) => nested
            .iter()
            .for_each(|inner| collect_text_bounds(inner, clip, out)),
        _ => {}
    }
}

fn count_focus_strokes(shape: &egui::Shape, count: &mut usize) {
    match shape {
        egui::Shape::Rect(rect) if rect.stroke == kit::FOCUS_STROKE => *count += 1,
        egui::Shape::Vec(nested) => nested
            .iter()
            .for_each(|inner| count_focus_strokes(inner, count)),
        _ => {}
    }
}

fn open_item(dir: &TempDir) -> (DesktopApp, u64) {
    let (mut app, id) = unlocked_app_with_item(dir);
    app.select_item(id.to_string());
    app.view = OwnerView::Item;
    (app, id)
}

fn add_long_credential(app: &mut DesktopApp, name: &str) -> u64 {
    let notes = (0..80)
        .map(|index| format!("Synthetic note {index:02}: Check the test account before use."))
        .collect::<Vec<_>>()
        .join("\n");
    let details = (0..10)
        .map(|index| crate::desktop::model::DetailDraft {
            label: format!("Test field {index}"),
            value: format!("synthetic-value-{index}"),
            ..Default::default()
        })
        .collect();
    let mut secrets = crate::desktop::owner_store::SecretForm::default();
    secrets.token = "synthetic-header-test-token".to_owned();
    app.owner_ui
        .session
        .add(
            &crate::desktop::ItemDraft {
                name: name.to_owned(),
                notes,
                details,
                ..Default::default()
            },
            &secrets,
        )
        .expect("add synthetic credential")
        .id
}

#[test]
fn credential_header_stays_visible_after_body_scroll_and_back_returns_to_list() {
    for size in [SIZE, Vec2::new(900.0, 600.0)] {
        let dir = TempDir::new().expect("temp dir");
        let (mut app, _) = unlocked_app_with_item(&dir);
        let name = "Long synthetic credential for the fixed header";
        let id = add_long_credential(&mut app, name);
        app.select_item(id.to_string());
        let mut window = Window::new();
        window.size = size;
        window.idle(&mut app);
        let header = ["Credentials", name, "Edit"].map(|label| window.visible_text_rect(label));
        assert!(header[0].left() > 216.0, "Credentials is the Back control");
        assert!(header.iter().all(|rect| rect.top() >= kit::TITLE_BAR));
        let secret_top = text_top(&window, "Secret").expect("the body starts at Secret");
        assert!(text_top(&window, "More actions").is_none());

        window.wheel_to_end(&mut app);
        assert!(
            text_top(&window, "Secret").is_none_or(|top| top < secret_top - 100.0),
            "the wheel must move the body at {size:?}"
        );
        window.visible_text_rect("More actions");
        for (label, before) in ["Credentials", name, "Edit"].into_iter().zip(header) {
            let after = window.visible_text_rect(label);
            assert_eq!(
                before, after,
                "{label} moved after the body scrolled at {size:?}"
            );
        }
        let back = window.visible_text_rect("Credentials");
        window.click_at(&mut app, back.center());
        assert_eq!(
            app.view,
            OwnerView::Vault,
            "Back returns to the credential list"
        );
    }
}

#[test]
fn a_different_credential_starts_with_its_body_at_the_top() {
    for size in [SIZE, Vec2::new(900.0, 600.0)] {
        let dir = TempDir::new().expect("temp dir");
        let (mut app, _) = unlocked_app_with_item(&dir);
        let first = add_long_credential(&mut app, "First synthetic credential");
        let second = add_long_credential(&mut app, "Second synthetic credential");
        app.select_item(first.to_string());
        let mut window = Window::new();
        window.size = size;
        window.idle(&mut app);
        let first_top = text_top(&window, "Secret").expect("the first body starts at Secret");
        window.wheel_to_end(&mut app);
        assert!(
            text_top(&window, "Secret").is_none(),
            "the first body scrolled"
        );
        window.visible_text_rect("More actions");

        app.select_item(second.to_string());
        window.idle(&mut app);
        window.visible_text_rect("Second synthetic credential");
        let second_top = text_top(&window, "Secret").expect("the second body starts at Secret");
        assert!(
            (first_top - second_top).abs() < 1.0,
            "the new item inherited a scroll offset"
        );
        assert!(text_top(&window, "More actions").is_none());
    }
}

#[test]
fn return_in_the_locked_passphrase_field_unlocks() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.lock_vault(None);
    let mut window = Window::new();
    window.idle(&mut app);
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD))
    );
    window.frame(
        &mut app,
        vec![Event::Text(super::owner_tests::PASS.to_owned())],
    );
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(
        !app.owner_ui.session.is_locked(),
        "Return unlocks the vault"
    );
    assert!(
        app.owner_ui.passphrase.is_empty(),
        "unlock clears the typed passphrase"
    );
}

#[test]
fn a_missing_new_vault_name_takes_the_focus_without_losing_passphrases() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    // Add an entry to disable the first-vault fallback name.
    app.vault_list
        .registry
        .add("Test", &dir.path().join("named.db"), 0)
        .expect("registry entry");
    app.lock_vault(None);
    app.ui.start = super::start::Step::Create;
    let mut window = Window::new();
    window.idle(&mut app);
    window.tab_to(&mut app, "Create vault", 30);
    app.owner_ui.passphrase = super::owner_tests::PASS.to_owned();
    app.owner_ui.passphrase_confirm = super::owner_tests::PASS.to_owned();
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.status_text, "Type a name for the vault.");
    assert!(
        window.ctx.text_edit_focused(),
        "the missing Name field has the focus"
    );
    window.frame(&mut app, vec![Event::Text("Keyboard vault".to_owned())]);
    assert_eq!(app.vault_list.name_input, "Keyboard vault");
    assert_eq!(app.owner_ui.passphrase, super::owner_tests::PASS);
    assert_eq!(app.owner_ui.passphrase_confirm, super::owner_tests::PASS);
}

#[test]
fn a_dirty_edit_requires_confirmation_and_restores_focus() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, id) = open_item(&dir);
    let saved = app
        .owner_ui
        .session
        .details(id)
        .expect("details")
        .to_draft();
    let mut window = Window::new();
    window.idle(&mut app);
    window.tab_to(&mut app, "Edit", 40);
    let edit_button = window.focused();
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    let name_field = window.focused();
    window.frame(&mut app, vec![Event::Text(" unsaved".to_owned())]);
    window
        .ctx
        .memory_mut(|memory| memory.request_focus(super::secret_field_id("edit-token")));
    window.idle(&mut app);
    let secret_field = window.focused();
    assert_ne!(secret_field, name_field);
    window.frame(&mut app, vec![Event::Text("synthetic-secret".to_owned())]);
    let draft = app.edit_form.clone();
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(app.ui.discard_item_changes);
    assert_eq!(app.ui.sheet, Some(Sheet::EditItem));
    assert!(window.text.contains("Discard changes?"));
    assert_eq!(window.focused_name().as_deref(), Some("Keep editing"));
    window.press(&mut app, Key::S, Modifiers::COMMAND);
    assert!(
        app.ui.discard_item_changes,
        "Save does not bypass the alert"
    );
    assert_eq!(
        app.owner_ui
            .session
            .details(id)
            .expect("stored details")
            .to_draft(),
        saved
    );
    // Return on the safe default keeps the form and all typed data.
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(!app.ui.discard_item_changes);
    assert_eq!(app.edit_form, draft);
    assert_eq!(app.owner_ui.edit_secrets.token, "synthetic-secret");
    assert_eq!(window.focused(), secret_field);
    // Escape on the alert also keeps the form.
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(!app.ui.discard_item_changes);
    assert_eq!(window.focused(), secret_field);
    // Explicit discard closes the form and erases typed secrets.
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    window.tab_to(&mut app, "Discard", 5);
    window.press(&mut app, Key::Space, Modifiers::NONE);
    assert_eq!(app.ui.sheet, None);
    assert!(!app.ui.discard_item_changes);
    assert!(app.owner_ui.edit_secrets.is_blank());
    assert_eq!(
        app.owner_ui
            .session
            .details(id)
            .expect("stored details")
            .to_draft(),
        saved
    );
    assert_eq!(window.focused(), edit_button);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    window
        .ctx
        .memory_mut(|memory| memory.request_focus(super::secret_field_id("edit-token")));
    window.idle(&mut app);
    window.press(&mut app, Key::Z, Modifiers::COMMAND);
    assert!(
        app.owner_ui.edit_secrets.is_blank(),
        "Undo does not restore the discarded secret"
    );
}

#[test]
fn a_new_credential_secret_requires_discard_confirmation() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.press(&mut app, Key::N, Modifiers::COMMAND);
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: false }));
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: true }));
    let name_field = window.focused();
    app.owner_ui.add_secrets.token = "synthetic-new-secret".to_owned();
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(app.ui.discard_item_changes);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.owner_ui.add_secrets.token, "synthetic-new-secret");
    assert_eq!(window.focused(), name_field);
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    window.tab_to(&mut app, "Discard", 5);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, None);
    assert!(app.owner_ui.add_secrets.is_blank());
}

#[test]
fn change_kind_keeps_typed_data_until_the_owner_confirms_discard() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.press(&mut app, Key::N, Modifiers::COMMAND);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    window.frame(&mut app, vec![Event::Text("Unsaved credential".to_owned())]);
    window
        .ctx
        .memory_mut(|memory| memory.request_focus(super::secret_field_id("add-token")));
    window.idle(&mut app);
    window.frame(
        &mut app,
        vec![Event::Text("synthetic-kind-secret".to_owned())],
    );
    let draft = app.add_form.clone();
    window.tab_to(&mut app, "Change kind", 30);
    let change_button = window.focused();
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(app.ui.discard_item_changes);
    assert!(app.ui.discard_item_kind_change);
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: true }));
    assert_eq!(window.focused_name().as_deref(), Some("Keep editing"));
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(!app.ui.discard_item_changes);
    assert!(!app.ui.discard_item_kind_change);
    assert_eq!(app.add_form, draft);
    assert_eq!(app.owner_ui.add_secrets.token, "synthetic-kind-secret");
    assert_eq!(window.focused(), change_button);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    window.tab_to(&mut app, "Discard", 5);
    window.press(&mut app, Key::Space, Modifiers::NONE);
    assert!(!app.ui.discard_item_changes);
    assert!(!app.ui.discard_item_kind_change);
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: false }));
    assert_eq!(app.add_form, crate::desktop::ItemDraft::default());
    assert!(app.owner_ui.add_secrets.is_blank());
    // The selector remains open. A new form must not recover the removed secret.
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: true }));
    window
        .ctx
        .memory_mut(|memory| memory.request_focus(super::secret_field_id("add-token")));
    window.idle(&mut app);
    window.press(&mut app, Key::Z, Modifiers::COMMAND);
    assert!(app.owner_ui.add_secrets.is_blank());
    // No confirmation is needed if the form contains no data.
    window.tab_to(&mut app, "Change kind", 30);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: false }));
    assert!(!app.ui.discard_item_changes);
}

/// A sheet opened with Return takes the focus, Escape closes it, and the focus goes
/// back to the button that opened it. The focus ring is the solid 2-point accent.
#[test]
fn a_sheet_takes_the_focus_and_gives_it_back() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = open_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);

    window.tab_to(&mut app, "Edit", 40);
    assert!(
        window.focus_strokes > 0,
        "the focused button has the focus ring"
    );
    let edit = window.focused();

    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, Some(Sheet::EditItem));
    let layer = window
        .focused_layer()
        .expect("a control in the sheet has the focus");
    assert_eq!(
        layer.order,
        egui::Order::Foreground,
        "the focus is in the sheet"
    );
    assert!(
        window.ctx.text_edit_focused(),
        "the first control is the Name field"
    );

    window.press(&mut app, Key::Escape, Modifiers::NONE);
    assert_eq!(app.ui.sheet, None);
    assert_eq!(window.focused(), edit, "the focus is back on Edit");

    // Return in the Name field saves and closes the sheet. The focus also comes back
    // after a sheet closes with its own action.
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, Some(Sheet::EditItem));
    window.frame(&mut app, vec![Event::Text(" 2".to_owned())]);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, None, "Return saved");
    assert!(
        app.owner_ui
            .session
            .search("")
            .unwrap()
            .iter()
            .any(|item| item.name.ends_with(" 2")),
        "the new name is stored"
    );
    assert_eq!(
        window.focused(),
        edit,
        "the focus is back on Edit after Save"
    );
}

/// Return in a single-line field does the default action of the sheet. Tab and the
/// arrow keys stay in the sheet.
#[test]
fn return_in_a_field_does_the_default_action() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.view = OwnerView::Agents;
    let mut window = Window::new();
    window.idle(&mut app);
    // A key press puts the window in keyboard mode, as a real key does.
    window.press(&mut app, Key::Tab, Modifiers::NONE);
    app.ui.sheet = Some(Sheet::RegisterAgent);
    window.idle(&mut app);
    let in_sheet = window.focused_layer().expect("focus");
    assert_eq!(in_sheet.order, egui::Order::Foreground);

    // Up and Down do not leave the sheet.
    window.press(&mut app, Key::ArrowDown, Modifiers::NONE);
    window.press(&mut app, Key::ArrowUp, Modifiers::NONE);
    assert_eq!(window.focused_layer(), Some(in_sheet));

    // The name field is the first control. Type and press Return.
    assert!(
        window.ctx.text_edit_focused(),
        "the name field has the focus"
    );
    window.frame(&mut app, vec![Event::Text("Keyboard agent".to_owned())]);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    let agents = app.owner_ui.session.agents().expect("agents");
    assert_eq!(agents.len(), 1, "Return registered the agent");
    assert_eq!(agents[0].name, "Keyboard agent");
}

/// A destructive alert starts on Cancel. Return or Space cancels, never deletes.
#[test]
fn a_delete_alert_starts_on_cancel() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, id) = open_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "More actions");
    window.tab_to(&mut app, "Delete credential…", 60);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(app.pending_delete, "the alert is open");
    assert_eq!(window.focused_name().as_deref(), Some("Cancel"));
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(!app.pending_delete, "Return pressed Cancel");
    assert!(app.owner_ui.session.details(id).is_ok_and(|d| !d.hidden));
    assert_eq!(window.focused_name().as_deref(), Some("Delete credential…"));
}

/// A destructive alert opened with the pointer shows no focus ring. Return or Space
/// still presses Cancel: the key never reaches Delete, the first control of the alert.
#[test]
fn return_on_a_delete_alert_opened_with_the_pointer_cancels() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, id) = open_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "More actions");
    for key in [Key::Enter, Key::Space] {
        window.wheel_to_end(&mut app);
        window.click(&mut app, "Delete credential…");
        assert!(app.pending_delete, "the alert is open");
        assert!(!kit::keyboard_mode(&window.ctx), "a pointer user");
        assert_ne!(
            window.focused_layer().map(|layer| layer.order),
            Some(egui::Order::Foreground),
            "no control of the alert has the focus"
        );
        window.press(&mut app, key, Modifiers::NONE);
        assert!(!app.pending_delete, "{key:?} pressed Cancel");
        assert!(
            app.owner_ui.session.details(id).is_ok_and(|d| !d.hidden),
            "{key:?} kept the credential"
        );
    }
}

/// "Discard changes?" opened with the pointer: Return keeps editing and the typed text.
#[test]
fn return_on_a_discard_alert_opened_with_the_pointer_keeps_editing() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = open_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Edit");
    assert_eq!(app.ui.sheet, Some(Sheet::EditItem));
    window.frame(&mut app, vec![Event::Text(" unsaved".to_owned())]);
    let draft = app.edit_form.clone();
    window.click(&mut app, "Cancel");
    assert!(app.ui.discard_item_changes, "the alert is open");
    assert!(window.text.contains("Discard changes?"));
    assert!(!kit::keyboard_mode(&window.ctx), "a pointer user");
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(!app.ui.discard_item_changes, "Return pressed Keep editing");
    assert_eq!(app.ui.sheet, Some(Sheet::EditItem), "the form stays");
    assert_eq!(app.edit_form, draft, "the typed text stays");
}

/// The arrow keys change a segmented picker and keep the focus on it.
#[test]
fn arrows_change_a_picker_without_moving_the_focus() {
    let ctx = egui::Context::default();
    let mut value = 0u8;
    let mut other = 0u8;
    let frame = |value: &mut u8, other: &mut u8, events: Vec<Event>| {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| {
            ui.horizontal(|ui| {
                kit::segmented(ui, "first", value, &[(0, "One"), (1, "Two"), (2, "Three")]);
                kit::segmented(ui, "second", other, &[(0, "A"), (1, "B")]);
            });
        });
        output.drop_without_applying_deltas();
    };
    let key = |key| Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Modifiers::NONE,
    };
    let tab = key(Key::Tab);
    let right = key(Key::ArrowRight);
    frame(&mut value, &mut other, Vec::new());
    frame(&mut value, &mut other, vec![tab]);
    frame(&mut value, &mut other, Vec::new());
    let focused = ctx.memory(|memory| memory.focused());
    assert!(focused.is_some());
    for _ in 0..2 {
        frame(&mut value, &mut other, vec![right.clone()]);
        frame(&mut value, &mut other, Vec::new());
    }
    assert_eq!(value, 2);
    assert_eq!(other, 0, "the second picker did not change");
    assert_eq!(
        ctx.memory(|memory| memory.focused()),
        focused,
        "the focus stayed on the first picker"
    );
}

/// ⌘1 to ⌘4 and ⌘, switch the view, ⌘[ goes back, and ⌘L locks.
#[test]
fn shortcuts_switch_views_go_back_and_lock() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = open_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.press(&mut app, Key::OpenBracket, Modifiers::COMMAND);
    assert_eq!(app.view, OwnerView::Vault, "⌘[ goes back to the list");
    for (key, view) in [
        (Key::Num2, OwnerView::Agents),
        (Key::Num3, OwnerView::Activity),
        (Key::Num4, OwnerView::Learning),
        (Key::Comma, OwnerView::Settings),
        (Key::Num1, OwnerView::Vault),
    ] {
        window.press(&mut app, key, Modifiers::COMMAND);
        assert_eq!(app.view, view);
        assert!(
            window.focused().is_some(),
            "the page took the focus for {view:?}"
        );
    }
    window.press(&mut app, Key::L, Modifiers::COMMAND);
    assert!(app.owner_ui.session.is_locked(), "⌘L locks");
}

/// Tab through Settings > Agents, which is longer than the window: the page scrolls, so
/// each focused control is on screen. Page Down scrolls Settings > About without a focus.
#[test]
fn the_page_scrolls_to_the_focus_and_with_page_keys() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::open_settings(&mut app, super::SettingsTab::Agents);
    let mut window = Window::new();
    window.idle(&mut app);
    let screen = Rect::from_min_size(Pos2::ZERO, SIZE);
    let mut below_the_fold = 0;
    for _ in 0..40 {
        window.press(&mut app, Key::Tab, Modifiers::NONE);
        if let Some(rect) = window.focused_rect() {
            assert!(
                screen.contains_rect(rect),
                "{:?} at {rect:?} is off screen",
                window.focused_name()
            );
            if rect.bottom() > SIZE.y / 2.0 {
                below_the_fold += 1;
            }
        }
    }
    assert!(
        below_the_fold > 0,
        "the walk reached the lower part of the page"
    );

    // Page Down and Home with no focus in a field.
    let mut fresh = Window::new();
    let second = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&second);
    super::open_settings(&mut app, super::SettingsTab::About);
    fresh.idle(&mut app);
    let top = text_top(&fresh, "Updates").expect("the top of Settings shows");
    assert_eq!(
        text_top(&fresh, "Contract"),
        None,
        "the bottom is out of view"
    );
    fresh.press(&mut app, Key::PageDown, Modifiers::NONE);
    let after = text_top(&fresh, "Updates");
    assert!(
        after.is_none_or(|after| after < top - SIZE.y / 2.0),
        "Page Down scrolled: {top} -> {after:?}"
    );
    fresh.press(&mut app, Key::PageUp, Modifiers::NONE);
    let back = text_top(&fresh, "Updates").expect("Page Up came back");
    assert!((back - top).abs() < 2.0, "{top} -> {back}");
    fresh.press(&mut app, Key::End, Modifiers::NONE);
    assert!(
        text_top(&fresh, "Contract").is_some(),
        "End shows the bottom"
    );
    assert_eq!(text_top(&fresh, "Updates"), None);
    fresh.press(&mut app, Key::Home, Modifiers::NONE);
    let home = text_top(&fresh, "Updates").expect("Home scrolled back up");
    assert!((home - top).abs() < 2.0, "{top} -> {home}");
}

/// Escape closes an error message when no sheet is open.
#[test]
fn escape_closes_an_error_message() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let mut window = Window::new();
    app.set_err("Synthetic error for the keyboard test.");
    window.idle(&mut app);
    assert!(window.text.contains("Synthetic error"));
    window.press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(!window.text.contains("Synthetic error"), "{}", window.text);
}

/// A menu picker: Space opens it, Tab moves through the options, Return chooses one,
/// the menu closes, and the focus goes back to the menu button.
#[test]
fn a_menu_choice_with_the_keyboard_closes_the_menu() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.view = OwnerView::Vault;
    let mut window = Window::new();
    window.idle(&mut app);
    // The toolbar draws from left to right: the search field, then the filter menu.
    for _ in 0..30 {
        window.press(&mut app, Key::Tab, Modifiers::NONE);
        if window.ctx.text_edit_focused() {
            break;
        }
    }
    assert!(
        window.ctx.text_edit_focused(),
        "Tab reaches the search field"
    );
    window.press(&mut app, Key::Tab, Modifiers::NONE);
    let button = window.focused().expect("the filter menu has the focus");
    let before = app.ui.credential_filter;
    window.press(&mut app, Key::Space, Modifiers::NONE);
    assert!(
        egui::Popup::is_any_open(&window.ctx),
        "Space opens the menu"
    );
    window.tab_to(&mut app, "Needs setup", 12);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(
        !egui::Popup::is_any_open(&window.ctx),
        "the choice closed the menu"
    );
    assert_ne!(app.ui.credential_filter, before, "the filter changed");
    assert_eq!(
        window.focused(),
        Some(button),
        "the focus is back on the menu"
    );
}

/// A control that goes away after a key press does not drop the focus to nothing:
/// the first control of the page takes it, so the next Tab does not start again at
/// the sidebar.
#[test]
fn the_focus_survives_a_control_that_goes_away() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = open_item(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "More actions");
    window.tab_to(&mut app, "Archive credential…", 60);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, Some(Sheet::ArchiveItem));
    // The archive sheet: Return archives (no button had to be clicked).
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.sheet, None, "the item is archived");
    window.idle(&mut app);
    // The "Archive credential…" row is gone. The focus is on the page, not lost.
    let layer = window.focused_layer().expect("a control has the focus");
    assert_eq!(layer.order, egui::Order::Background);
    assert_ne!(
        window.focused_name().as_deref(),
        Some("Archive credential…")
    );
}

#[test]
fn a_sheet_opened_with_the_pointer_focuses_its_first_text_field() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.view = OwnerView::Agents;
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(
        !kit::keyboard_mode(&window.ctx),
        "the test starts as a pointer user"
    );
    app.ui.sheet = Some(Sheet::RegisterAgent);
    window.idle(&mut app);
    assert!(
        window.ctx.text_edit_focused(),
        "the Name field of the new sheet takes the focus"
    );
    window.frame(&mut app, vec![Event::Text("Pointer agent".to_owned())]);
    assert_eq!(app.owner_ui.new_agent_name, "Pointer agent");

    // After the pick of a kind, the Name field of the credential form takes the focus.
    app.ui.sheet = None;
    window.idle(&mut app);
    app.view = OwnerView::Vault;
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
    app.ui.focus_form_name = true;
    window.idle(&mut app);
    window.frame(&mut app, vec![Event::Text("Pointer key".to_owned())]);
    assert_eq!(app.add_form.name, "Pointer key");
}

#[test]
fn return_moves_through_the_new_vault_fields_and_creates_the_vault() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    let mut window = Window::new();
    window.idle(&mut app);
    window.tab_to(&mut app, "Create my first vault", 15);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.start, super::start::Step::Create);
    assert!(
        window.ctx.text_edit_focused(),
        "the Name field has the focus"
    );
    window.frame(&mut app, vec![Event::Text("Keyboard vault".to_owned())]);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD)),
        "Return in Name goes on to Passphrase, not to {:?}",
        window.focused_name()
    );
    window.frame(
        &mut app,
        vec![Event::Text(super::owner_tests::PASS.to_owned())],
    );
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_REPEAT_FIELD)),
        "Return in Passphrase goes on to Repeat"
    );
    window.frame(
        &mut app,
        vec![Event::Text(super::owner_tests::PASS.to_owned())],
    );
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(
        !app.owner_ui.session.is_locked(),
        "Return in Repeat creates and opens the vault: {}",
        app.status_text
    );
    assert_eq!(app.current_vault_name().as_deref(), Some("Keyboard vault"));
}

#[test]
fn control_command_s_hides_and_shows_the_sidebar() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.view = OwnerView::Vault;
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(window.text.contains("Learning"), "{}", window.text);
    // The open vault has a name for VoiceOver, with where it lives.
    assert!(
        window
            .names
            .values()
            .any(|name| name.starts_with("Vault ") && name.ends_with("On this Mac")),
        "{:?}",
        window.names.values().collect::<Vec<_>>()
    );
    window.press(&mut app, Key::S, Modifiers::COMMAND | Modifiers::CTRL);
    assert!(app.ui.sidebar_hidden);
    assert!(!window.text.contains("Learning"), "{}", window.text);
    // The shortcuts of the views still work without the sidebar.
    window.press(&mut app, Key::Num2, Modifiers::COMMAND);
    assert_eq!(app.view, OwnerView::Agents);
    window.press(&mut app, Key::S, Modifiers::COMMAND | Modifiers::CTRL);
    assert!(!app.ui.sidebar_hidden);
    assert!(window.text.contains("Learning"), "{}", window.text);
}

#[test]
fn a_full_path_typed_by_hand_keeps_the_focus_until_return() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    app.sync.offered = true;
    super::sync::begin_open(&mut app);
    app.ui.set_expanded("sync-open-details", true);
    let mut window = Window::new();
    window.idle(&mut app);
    // The path field: the only single-line field on the screen before a pick.
    let field = window
        .ctx
        .memory(|memory| memory.focused())
        .filter(|_| window.ctx.text_edit_focused());
    if field.is_none() {
        window.tab_to_text_field(&mut app, 30);
    }
    // A keyboard sends a key and its text for each character.
    for ch in "/tmp/Team.apassy".chars() {
        window.frame(
            &mut app,
            vec![
                Event::Key {
                    key: Key::A,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Modifiers::NONE,
                },
                Event::Text(ch.to_string()),
            ],
        );
    }
    window.idle(&mut app);
    assert_eq!(
        app.sync.open_path, "/tmp/Team.apassy",
        "each character goes into the path field"
    );
    assert!(
        app.owner_ui.passphrase.is_empty(),
        "no character went into the passphrase field"
    );
    // Return picks the file; then the passphrase field takes the focus.
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(
        app.sync.open_pick.as_deref(),
        Some(std::path::Path::new("/tmp/Team.apassy"))
    );
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD))
    );
}

#[test]
fn a_vault_file_picked_with_the_pointer_gives_the_focus_to_the_passphrase() {
    let dir = TempDir::new().expect("temp dir");
    let folder = dir.path().join("Mobile Documents").join("Apassy");
    std::fs::create_dir_all(&folder).expect("synced folder");
    let file = folder.join("Team.apassy");
    std::fs::write(&file, b"synthetic synced vault").expect("vault file");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    app.sync.offered = true;
    app.sync.folders = vec![crate::sync::SyncFolder {
        label: "iCloud Drive".to_owned(),
        path: folder,
    }];
    super::sync::begin_open(&mut app);
    let mut window = Window::new();
    window.idle(&mut app);
    // A click on the file in the list, as a pointer user picks it.
    window.click(&mut app, "Team.apassy");
    assert_eq!(app.sync.open_pick.as_deref(), Some(file.as_path()));
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD)),
        "the passphrase field takes the focus after the pick, so the owner can type at once"
    );
}

#[test]
fn a_click_on_apassy_relay_gives_the_focus_to_the_link_field() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    app.sync.offered = true;
    super::sync::begin_open(&mut app);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Apassy relay");
    assert!(window.ctx.text_edit_focused(), "a text field has the focus");
    // What the owner pastes goes into the link field.
    let link = "https://relay.example.test/link#apassy_lnk_synthetic";
    window.frame(&mut app, vec![Event::Text(link.to_owned())]);
    window.idle(&mut app);
    assert_eq!(app.sync.relay.link_input.as_str(), link);
}

#[test]
fn a_click_on_create_my_first_vault_gives_the_focus_to_the_name() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    app.sync.offered = true;
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Create my first vault");
    assert_eq!(app.ui.start, super::start::Step::Create);
    assert!(
        window.ctx.text_edit_focused(),
        "the name field has the focus"
    );
    window.frame(&mut app, vec![Event::Text("Work".to_owned())]);
    window.idle(&mut app);
    assert_eq!(app.vault_list.name_input, "Work");
}

#[test]
fn welcome_choices_and_second_mac_passphrase_work_with_the_keyboard() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    app.sync.offered = true;
    let mut window = Window::new();
    window.idle(&mut app);
    window.tab_to(&mut app, "Create my first vault", 15);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.start, super::start::Step::Create);
    window.tab_to(&mut app, "Back", 20);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    window.tab_to(&mut app, "Use a vault from another Mac", 20);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.start, super::start::Step::OpenSynced);
    let file = dir.path().join("Team.apassy");
    app.sync_select_open_file(file.clone(), false, Some(&window.ctx));
    window.idle(&mut app);
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD))
    );
    window.frame(
        &mut app,
        vec![Event::Text("synthetic-passphrase".to_owned())],
    );
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(
        app.status_text.contains("cannot find") || app.status_text.contains("could not open"),
        "Return attempted to open the missing vault"
    );
    assert!(
        app.owner_ui.passphrase.is_empty(),
        "the failed open erases the passphrase"
    );
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD)),
        "the failed open returns the focus to the passphrase field"
    );
    assert_eq!(app.sync.open_pick, Some(file));
    assert_eq!(app.vault_list.name_input, "Team");
    window.tab_to(&mut app, "Retry", 20);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.vault_list.name_input, "Team");
    window.tab_to(&mut app, "Back", 20);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.start, super::start::Step::Home);
    window.tab_to(&mut app, "Open a local vault file…", 20);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert_eq!(app.ui.start, super::start::Step::Open);
}

#[test]
fn wrong_synced_passphrase_shows_clear_error_and_allows_keyboard_retry() {
    let dir = TempDir::new().expect("synthetic Macs");
    let source_path = dir.path().join("source.db");
    let folder = dir.path().join("Shared");
    let mut source =
        crate::vault::Vault::create(&source_path, super::owner_tests::PASS).expect("source vault");
    source
        .unlock(super::owner_tests::PASS)
        .expect("unlock source");
    let sync = crate::sync::FolderSync::new(crate::sync::SyncConfig::in_data_dir(
        &dir.path().join("mac-a"),
        &source_path,
        &folder,
        "mac-a-state",
    ));
    let report = sync.enable(&mut source, "Team").expect("synced source");
    let file = folder.join(report.file_name);
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("mac-b"), true);
    app.sync.offered = true;
    super::sync::begin_open(&mut app);
    app.sync_select_open_file(file.clone(), false, None);
    app.vault_list.name_input = "Team on this Mac".to_owned();
    let mut window = Window::new();
    window.idle(&mut app);
    window.press(&mut app, Key::Tab, Modifiers::NONE);
    // The selector can also be operated with the pointer before the owner types.
    window.ctx.memory_mut(|memory| {
        memory.request_focus(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD))
    });
    window.idle(&mut app);
    window.frame(
        &mut app,
        vec![Event::Text("synthetic-wrong-passphrase".to_owned())],
    );
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(
        window
            .text
            .contains("The passphrase does not open this synced vault"),
        "{}",
        window.text
    );
    assert!(
        !window
            .text
            .contains("could not read the synced file or folder"),
        "{}",
        window.text
    );
    assert_eq!(
        window.focused(),
        Some(super::secret_field_id(super::VAULT_PASSPHRASE_FIELD))
    );
    assert!(app.owner_ui.passphrase.is_empty());
    assert_eq!(app.sync.open_pick, Some(file));
    assert_eq!(app.vault_list.name_input, "Team on this Mac");
    assert!(app.vault_list.registry.is_empty());
    window.frame(
        &mut app,
        vec![Event::Text(super::owner_tests::PASS.to_owned())],
    );
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(!app.owner_ui.session.is_locked(), "{}", app.status_text);
    assert_eq!(
        app.current_vault_name().as_deref(),
        Some("Team on this Mac")
    );
}
