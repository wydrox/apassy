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
    time: f64,
    names: HashMap<accesskit::NodeId, String>,
    text: String,
    /// Each painted text and its position.
    texts: Vec<(String, Pos2)>,
    focus_strokes: usize,
}

impl Window {
    fn new() -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        Self {
            ctx,
            time: 0.0,
            names: HashMap::new(),
            text: String::new(),
            texts: Vec::new(),
            focus_strokes: 0,
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) {
        // A scroll to the focus is animated. A tenth of a second per frame lets it end.
        self.time += 0.1;
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
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
        self.focus_strokes = 0;
        for clipped in &output.shapes {
            super::owner_tests::collect(&clipped.shape, &mut self.text);
            collect_positions(&clipped.shape, &mut self.texts);
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

    /// The layer of the focused control.
    fn focused_layer(&self) -> Option<egui::LayerId> {
        let id = self.focused()?;
        self.ctx.read_response(id).map(|response| response.layer_id)
    }

    fn focused_rect(&self) -> Option<Rect> {
        let id = self.focused()?;
        self.ctx.read_response(id).map(|response| response.rect)
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
    window.tab_to(&mut app, "Delete credential…", 60);
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(app.pending_delete, "the alert is open");
    assert_eq!(window.focused_name().as_deref(), Some("Cancel"));
    window.press(&mut app, Key::Enter, Modifiers::NONE);
    assert!(!app.pending_delete, "Return pressed Cancel");
    assert!(app.owner_ui.session.details(id).is_ok_and(|d| !d.hidden));
    assert_eq!(window.focused_name().as_deref(), Some("Delete credential…"));
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

/// Tab through the long Settings page: the page scrolls, so each focused control is on
/// screen. Page Down scrolls without a focus.
#[test]
fn the_page_scrolls_to_the_focus_and_with_page_keys() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.view = OwnerView::Settings;
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
    app.view = OwnerView::Settings;
    fresh.idle(&mut app);
    let top = text_top(&fresh, "Lock now").expect("the top of Settings shows");
    assert_eq!(text_top(&fresh, "About"), None, "the bottom is out of view");
    fresh.press(&mut app, Key::PageDown, Modifiers::NONE);
    let after = text_top(&fresh, "Lock now");
    assert!(
        after.is_none_or(|after| after < top - SIZE.y / 2.0),
        "Page Down scrolled: {top} -> {after:?}"
    );
    fresh.press(&mut app, Key::PageUp, Modifiers::NONE);
    let back = text_top(&fresh, "Lock now").expect("Page Up came back");
    assert!((back - top).abs() < 2.0, "{top} -> {back}");
    fresh.press(&mut app, Key::End, Modifiers::NONE);
    assert!(text_top(&fresh, "About").is_some(), "End shows the bottom");
    assert_eq!(text_top(&fresh, "Lock now"), None);
    fresh.press(&mut app, Key::Home, Modifiers::NONE);
    let home = text_top(&fresh, "Lock now").expect("Home scrolled back up");
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
