//! Native main-process menus. AppKit stays inside muda's safe API; command
//! delivery is only a request, revalidated against the current vault and UI.

use super::{DesktopApp, Place, ui};
use eframe::egui;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Command {
    NewCredential,
    NewFolder,
    MoveItems,
    RenameFolder,
    MoveFolder,
    DeleteFolder,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    SelectAll,
}

/// No secret values: an event is bound to its displayed session, selection,
/// navigation and focus. Even a lock/unlock of the same vault changes the epoch.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Context {
    pub epoch: Option<[u8; 32]>,
    pub path: Option<std::path::PathBuf>,
    pub place: Place,
    pub selected: Vec<u64>,
    pub detail: Option<String>,
    pub search: String,
    pub filter: u8,
    pub search_all: bool,
    pub sheet: Option<ui::Sheet>,
    pub focus: Option<egui::Id>,
    pub text: bool,
    pub library: bool,
    pub blocked: bool,
    pub owner_busy: bool,
    pub owner_identity: Option<u64>,
    pub owner_text_input: bool,
    pub folder_exists: bool,
    pub selection_exists: bool,
    pub undo: Vec<crate::vault::ItemFolderMove>,
}

impl Context {
    pub fn allows(&self, command: Command) -> bool {
        let text = self.text && self.focus.is_some() && !self.owner_busy;
        let organize = self.epoch.is_some() && !self.blocked;
        let personal = matches!(self.place, Place::Folder(_));
        match command {
            Command::Cut | Command::Copy => text,
            Command::Paste | Command::Redo => text || self.owner_text_input,
            Command::SelectAll => text || self.owner_text_input || (organize && self.library),
            Command::Undo => {
                text || self.owner_text_input || (organize && personal && !self.undo.is_empty())
            }
            Command::NewCredential => organize,
            Command::NewFolder => {
                organize && personal && (self.place == Place::CREDENTIALS || self.folder_exists)
            }
            Command::MoveItems => organize && personal && !self.text && self.selection_exists,
            Command::RenameFolder | Command::MoveFolder | Command::DeleteFolder => {
                organize && personal && self.folder_exists
            }
        }
    }
}

pub(super) struct Request {
    pub command: Command,
    pub context: Context,
}

/// Shared by the real menu receiver and guard tests. Disabled menu items are
/// presentation only; stale or no-longer-authorized requests do nothing.
pub(super) fn dispatch(app: &mut DesktopApp, ctx: &egui::Context, request: Request) {
    // A pointer press or focus navigation waiting in this frame can change the
    // receiving widget after this check. Drop the request instead of retargeting it.
    if ctx.input(|input| {
        input.events.iter().any(|event| {
            matches!(
                event,
                egui::Event::PointerButton { pressed: true, .. }
                    | egui::Event::Key {
                        key: egui::Key::Tab | egui::Key::Escape,
                        pressed: true,
                        ..
                    }
                    | egui::Event::WindowFocused(false)
            )
        })
    }) {
        return;
    }
    let current = ui::native_menu_context(app, ctx);
    if current != request.context || !current.allows(request.command) {
        return;
    }
    ui::native_menu_command(app, ctx, request.command, current.text);
}

#[cfg(target_os = "macos")]
pub(super) use platform::NativeMenu;

#[cfg(target_os = "macos")]
pub(super) fn process(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(menu) = app.native_menu.take() else {
        return;
    };
    while let Ok(request) = menu.receiver.try_recv() {
        dispatch(app, ctx, request);
    }
    app.native_menu = Some(menu);
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use muda::accelerator::{Accelerator, Code, Modifiers};
    use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem as Standard, Submenu};
    use std::sync::{Arc, Mutex, mpsc};

    pub(in crate::desktop) struct NativeMenu {
        // Retain the installed NSApp menu for the lifetime of the app.
        _menu: Menu,
        items: Vec<(Command, MenuItem)>,
        state: Arc<Mutex<Option<Context>>>,
        pub(super) receiver: mpsc::Receiver<Request>,
    }

    impl NativeMenu {
        pub(in crate::desktop) fn install(ctx: &egui::Context) -> Self {
            let menu = Menu::new();
            let app = Submenu::new("Apassy", true);
            app.append_items(&[
                &Standard::about(Some("About Apassy"), None),
                &Standard::separator(),
                &Standard::services(None),
                &Standard::separator(),
                &Standard::hide(Some("Hide Apassy")),
                &Standard::hide_others(None),
                &Standard::show_all(None),
                &Standard::separator(),
                &Standard::quit(Some("Quit Apassy")),
            ])
            .expect("valid standard app menu");
            let file = Submenu::new("File", true);
            let edit = Submenu::new("Edit", true);
            let item = Submenu::new("Item", true);
            let folder = Submenu::new("Folder", true);
            let window = Submenu::new("Window", true);
            window
                .append_items(&[
                    &Standard::minimize(None),
                    &Standard::zoom(None),
                    &Standard::bring_all_to_front(None),
                ])
                .expect("valid Window menu");
            let mut items = Vec::new();
            let mut add = |menu: &Submenu, command, label, key: Option<Code>, shift| {
                let accelerator = key.map(|code| {
                    Accelerator::new(
                        if shift {
                            Modifiers::META | Modifiers::SHIFT
                        } else {
                            Modifiers::META
                        },
                        code,
                    )
                });
                let entry = MenuItem::new(label, false, accelerator);
                menu.append(&entry).expect("valid menu command");
                items.push((command, entry));
            };
            add(
                &file,
                Command::NewCredential,
                "New Credential…",
                Some(Code::KeyN),
                false,
            );
            add(&file, Command::NewFolder, "New Folder…", None, false);
            add(&edit, Command::Undo, "Undo", Some(Code::KeyZ), false);
            add(&edit, Command::Redo, "Redo", Some(Code::KeyZ), true);
            edit.append(&Standard::separator())
                .expect("valid separator");
            add(&edit, Command::Cut, "Cut", Some(Code::KeyX), false);
            add(&edit, Command::Copy, "Copy", Some(Code::KeyC), false);
            add(&edit, Command::Paste, "Paste", Some(Code::KeyV), false);
            add(
                &edit,
                Command::SelectAll,
                "Select All",
                Some(Code::KeyA),
                false,
            );
            add(
                &item,
                Command::MoveItems,
                "Move to Folder…",
                Some(Code::KeyM),
                true,
            );
            add(&folder, Command::RenameFolder, "Rename…", None, false);
            add(&folder, Command::MoveFolder, "Move Folder…", None, false);
            add(&folder, Command::DeleteFolder, "Delete…", None, false);
            file.append_items(&[&Standard::separator(), &Standard::close_window(None)])
                .expect("valid File menu");
            menu.append_items(&[&app, &file, &edit, &item, &folder, &window])
                .expect("valid menu bar");
            menu.init_for_nsapp();
            window.set_as_windows_menu_for_nsapp();
            let state: Arc<Mutex<Option<Context>>> = Arc::new(Mutex::new(None));
            let event_state = state.clone();
            let (sender, receiver) = mpsc::sync_channel(32);
            let ids: Vec<_> = items
                .iter()
                .map(|(command, item)| (item.id().clone(), *command))
                .collect();
            let ctx = ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let Some((_, command)) = ids.iter().find(|(id, _)| *id == event.id) else {
                    return;
                };
                if let Some(context) = event_state.lock().ok().and_then(|state| state.clone())
                    && context.allows(*command)
                {
                    let _ = sender.try_send(Request {
                        command: *command,
                        context,
                    });
                    ctx.request_repaint();
                }
            }));
            Self {
                _menu: menu,
                items,
                state,
                receiver,
            }
        }

        pub(in crate::desktop) fn refresh(&mut self, state: Context) {
            for (command, item) in &self.items {
                item.set_enabled(state.allows(*command));
                if *command == Command::Undo {
                    item.set_text(if state.text || state.undo.is_empty() {
                        "Undo"
                    } else {
                        "Undo Move"
                    });
                }
            }
            if let Ok(mut displayed) = self.state.lock() {
                *displayed = Some(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::{ItemDraft, owner_store::SecretForm};

    fn fixture() -> (tempfile::TempDir, DesktopApp, u64, String) {
        let dir = tempfile::tempdir().unwrap();
        let mut app = DesktopApp::new();
        app.owner_ui
            .session
            .create_file(&dir.path().join("menu.db"), "native-menu-test-pass")
            .unwrap();
        app.owner_ui
            .session
            .unlock("native-menu-test-pass")
            .unwrap();
        let mut secrets = SecretForm::default();
        secrets.token = "synthetic-menu-token".into();
        let item = app
            .owner_ui
            .session
            .add(
                &ItemDraft {
                    name: "Synthetic menu credential".into(),
                    ..Default::default()
                },
                &secrets,
            )
            .unwrap();
        let folder = app
            .owner_ui
            .session
            .with_vault(|vault| vault.create_folder(None, "Destination"))
            .unwrap()
            .unwrap();
        app.selected_item_id = Some(item.id.to_string());
        (dir, app, item.id, folder.uuid)
    }

    fn request(app: &DesktopApp, ctx: &egui::Context, command: Command) -> Request {
        Request {
            command,
            context: ui::native_menu_context(app, ctx),
        }
    }

    #[test]
    fn menu_opens_existing_move_and_folder_confirmation_without_mutating_vault() {
        let (_dir, mut app, id, folder) = fixture();
        let ctx = egui::Context::default();
        let move_request = request(&app, &ctx, Command::MoveItems);
        dispatch(&mut app, &ctx, move_request);
        assert_eq!(
            app.ui.sheet,
            Some(ui::Sheet::MoveItemsToFolder { item_ids: vec![id] })
        );
        app.ui.sheet = None;
        app.place = Place::Folder(Some(folder.clone()));
        for (command, expected) in [
            (
                Command::RenameFolder,
                ui::Sheet::RenameFolder {
                    uuid: folder.clone(),
                },
            ),
            (
                Command::MoveFolder,
                ui::Sheet::MoveFolder {
                    uuid: folder.clone(),
                },
            ),
            (
                Command::DeleteFolder,
                ui::Sheet::DeleteFolder {
                    uuid: folder.clone(),
                },
            ),
        ] {
            let queued = request(&app, &ctx, command);
            dispatch(&mut app, &ctx, queued);
            assert_eq!(app.ui.sheet, Some(expected));
            app.ui.sheet = None;
        }
        assert!(
            app.owner_ui
                .session
                .with_vault(|v| v.folders())
                .unwrap()
                .unwrap()
                .iter()
                .any(|f| f.uuid == folder)
        );
        assert!(app.owner_ui.session.details(id).is_ok());
    }

    #[test]
    fn queued_command_is_rejected_after_lock_unlock_or_selection_change() {
        let (_dir, mut app, _id, _folder) = fixture();
        let ctx = egui::Context::default();
        let queued = request(&app, &ctx, Command::NewCredential);
        app.owner_ui.session.lock().unwrap();
        app.owner_ui
            .session
            .unlock("native-menu-test-pass")
            .unwrap();
        dispatch(&mut app, &ctx, queued);
        assert!(app.ui.sheet.is_none());
        let queued = request(&app, &ctx, Command::MoveItems);
        app.selected_item_id = None;
        dispatch(&mut app, &ctx, queued);
        assert!(app.ui.sheet.is_none());
    }

    #[test]
    fn queued_command_does_not_replace_a_modal_or_accept_a_deleted_folder() {
        let (_dir, mut app, _id, folder) = fixture();
        let ctx = egui::Context::default();
        let queued = request(&app, &ctx, Command::NewFolder);
        app.ui.sheet = Some(ui::Sheet::NewCredential);
        dispatch(&mut app, &ctx, queued);
        assert_eq!(app.ui.sheet, Some(ui::Sheet::NewCredential));
        app.ui.sheet = None;
        app.place = Place::Folder(Some(folder.clone()));
        let queued = request(&app, &ctx, Command::RenameFolder);
        app.owner_ui
            .session
            .with_vault(|v| v.delete_folder(&folder))
            .unwrap()
            .unwrap();
        dispatch(&mut app, &ctx, queued);
        assert!(app.ui.sheet.is_none());
    }

    #[test]
    fn native_undo_restores_actual_move_and_text_undo_never_undoes_the_move() {
        let (_dir, mut app, id, folder) = fixture();
        let ctx = egui::Context::default();
        app.ui.move_undo = app
            .owner_ui
            .session
            .move_items_to_folder(&[id], Some(&folder))
            .unwrap();
        let mut text = "Editable text".to_owned();
        let text_id = egui::Id::new("native-menu-test-text");
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.add(egui::TextEdit::singleline(&mut text).id(text_id))
                .request_focus();
        });
        output.drop_without_applying_deltas();
        assert!(ctx.text_edit_focused());
        let queued = request(&app, &ctx, Command::Undo);
        dispatch(&mut app, &ctx, queued);
        assert!(!app.ui.move_undo.is_empty());
        assert!(ctx.input(|i| i.events.iter().any(|event| matches!(
            event,
            egui::Event::Key {
                key: egui::Key::Z,
                ..
            }
        ))));
        ctx.memory_mut(|memory| memory.surrender_focus(text_id));
        let queued = request(&app, &ctx, Command::Undo);
        dispatch(&mut app, &ctx, queued);
        assert!(app.ui.move_undo.is_empty());
        assert!(
            !app.owner_ui
                .session
                .with_vault(|v| v.items_in_folder(Some(&folder), false))
                .unwrap()
                .unwrap()
                .contains(&id)
        );
    }

    #[test]
    fn native_copy_without_text_focus_never_requests_secret_reveal() {
        let (_dir, mut app, _id, _folder) = fixture();
        let ctx = egui::Context::default();
        let queued = request(&app, &ctx, Command::Copy);
        dispatch(&mut app, &ctx, queued);
        assert!(app.owner.check.is_none());
        assert!(ctx.input(|input| input.events.is_empty()));
    }

    #[test]
    fn select_all_requires_the_same_focused_library_row_or_a_text_editor() {
        let (_dir, mut app, _id, _folder) = fixture();
        let ctx = egui::Context::default();
        let row = egui::Id::new("native-library-row");
        app.ui.native_library_focus = Some(row);
        ctx.memory_mut(|memory| memory.request_focus(row));
        let queued = request(&app, &ctx, Command::SelectAll);
        ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("different-control")));
        dispatch(&mut app, &ctx, queued);
        assert!(ctx.input(|input| input.events.is_empty()));
        assert!(app.ui.selected_items.is_empty());
    }

    fn text_frame(
        app: &mut DesktopApp,
        ctx: &egui::Context,
        text: &mut String,
        password: bool,
        command: Option<Command>,
        time: f64,
    ) -> Vec<String> {
        let output = ctx.run_ui(
            egui::RawInput {
                time: Some(time),
                ..Default::default()
            },
            |ui| {
                if let Some(command) = command {
                    let queued = request(app, ctx, command);
                    dispatch(app, ctx, queued);
                }
                ui.add(
                    egui::TextEdit::singleline(text)
                        .id(egui::Id::new("menu-text-editor"))
                        .password(password),
                )
                .request_focus();
            },
        );
        let copies = output
            .platform_output
            .commands
            .iter()
            .filter_map(|command| match command {
                egui::OutputCommand::CopyText(text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        // Inspect output only: these tests never apply clipboard commands.
        output.drop_without_applying_deltas();
        copies
    }

    #[test]
    fn native_edit_commands_reach_the_text_editor_and_preserve_its_undo_redo() {
        let (_dir, mut app, id, folder) = fixture();
        app.ui.move_undo = app
            .owner_ui
            .session
            .move_items_to_folder(&[id], Some(&folder))
            .unwrap();
        let ctx = egui::Context::default();
        let mut text = "Synthetic editable text".to_owned();
        text_frame(&mut app, &ctx, &mut text, false, None, 0.0);
        text_frame(&mut app, &ctx, &mut text, false, None, 2.0);
        text_frame(
            &mut app,
            &ctx,
            &mut text,
            false,
            Some(Command::SelectAll),
            4.0,
        );
        let copied = text_frame(&mut app, &ctx, &mut text, false, Some(Command::Copy), 6.0);
        assert_eq!(copied, vec!["Synthetic editable text"]);
        let cut = text_frame(&mut app, &ctx, &mut text, false, Some(Command::Cut), 8.0);
        assert_eq!(cut, vec!["Synthetic editable text"]);
        assert!(text.is_empty());
        text_frame(&mut app, &ctx, &mut text, false, Some(Command::Undo), 10.0);
        assert_eq!(text, "Synthetic editable text");
        text_frame(&mut app, &ctx, &mut text, false, Some(Command::Redo), 12.0);
        assert!(text.is_empty());
        assert!(
            !app.ui.move_undo.is_empty(),
            "text undo must not change vault organization"
        );
        assert!(app.owner.check.is_none());
    }

    #[test]
    fn native_password_copy_emits_no_clipboard_output() {
        let (_dir, mut app, _id, _folder) = fixture();
        let ctx = egui::Context::default();
        let mut text = "synthetic-password-canary".to_owned();
        text_frame(&mut app, &ctx, &mut text, true, None, 0.0);
        text_frame(
            &mut app,
            &ctx,
            &mut text,
            true,
            Some(Command::SelectAll),
            2.0,
        );
        assert!(text_frame(&mut app, &ctx, &mut text, true, Some(Command::Copy), 4.0).is_empty());
        assert_eq!(text, "synthetic-password-canary");
        assert!(app.owner.check.is_none());
    }

    #[test]
    fn queued_action_is_rejected_when_an_owner_check_opens() {
        let (_dir, mut app, id, _folder) = fixture();
        let ctx = egui::Context::default();
        let queued = request(&app, &ctx, Command::MoveItems);
        app.ask_owner(
            crate::desktop::owner_check::OwnerRequest::Reveal { item_id: id },
            None,
        );
        dispatch(&mut app, &ctx, queued);
        assert!(app.ui.sheet.is_none());
        assert!(app.owner.check.is_some());
    }

    #[test]
    fn owner_passphrase_allows_input_but_rejects_paste_queued_for_previous_dialog() {
        let (_dir, mut app, id, _folder) = fixture();
        let ctx = egui::Context::default();
        let owner_request = crate::desktop::owner_check::OwnerRequest::Reveal { item_id: id };
        app.ask_owner(owner_request.clone(), None);
        let field = egui::Id::new(("apassy-secret-field", ui::OWNER_CHECK_FIELD));
        let mut text = "synthetic-passphrase".to_owned();
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut text)
                    .password(true)
                    .id(field),
            )
            .request_focus();
        });
        output.drop_without_applying_deltas();
        let state = ui::native_menu_context(&app, &ctx);
        for command in [
            Command::Paste,
            Command::SelectAll,
            Command::Undo,
            Command::Redo,
        ] {
            assert!(state.allows(command));
        }
        for command in [
            Command::Copy,
            Command::Cut,
            Command::MoveItems,
            Command::NewFolder,
        ] {
            assert!(!state.allows(command));
        }
        let stale_paste = request(&app, &ctx, Command::Paste);
        // The same request and field ID still represent a different confirmation.
        app.ask_owner(owner_request, None);
        assert_ne!(
            state.owner_identity,
            ui::native_menu_context(&app, &ctx).owner_identity
        );
        dispatch(&mut app, &ctx, stale_paste);
        assert!(ctx.input(|input| input.events.is_empty()));
        let select = request(&app, &ctx, Command::SelectAll);
        dispatch(&mut app, &ctx, select);
        assert!(ctx.input(|input| input.events.iter().any(|event| matches!(
            event,
            egui::Event::Key {
                key: egui::Key::A,
                ..
            }
        ))));
        assert!(app.owner.check.is_some());
    }
}
