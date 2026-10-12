//! Folders of the personal vault (ADR 0026 §5): the tree that the sidebar and the
//! list read, and the sheets New Folder, Rename, Delete, and Move to Folder.
//!
//! The sheets change the vault through the folders API (`src/vault/folders.rs`). A
//! folder change needs no owner check: it changes no access. Moving a credential
//! changes nothing else, and deleting a folder moves its credentials to the parent: it
//! never deletes a credential.

use std::collections::{BTreeMap, BTreeSet};

use eframe::egui::{self, Label};

use super::kit::{self, Font, Icon, Style};
use super::{Sheet, close_sheet, save_pressed};
use crate::desktop::{DesktopApp, Place};
use crate::vault::{Folder, MAX_FOLDER_DEPTH, MAX_FOLDER_NAME_BYTES, VaultError, VaultErrorKind};

/// The folders of the open vault and the folder of each credential, read once for a
/// frame.
#[derive(Debug, Default, Clone)]
pub(crate) struct FolderTree {
    /// Depth first; each level by position, name, and UUID.
    pub(crate) folders: Vec<Folder>,
    /// The folder of each credential in a folder.
    pub(crate) item_folder: BTreeMap<u64, String>,
}

impl FolderTree {
    /// Read the tree. A locked vault or an error gives an empty tree: the list then
    /// shows every credential at the top level.
    pub(crate) fn load(app: &DesktopApp) -> Self {
        app.owner_ui
            .session
            .with_vault(|vault| -> Result<Self, VaultError> {
                let folders = vault.folders()?;
                let mut item_folder = BTreeMap::new();
                for folder in &folders {
                    for item in vault.items_in_folder(Some(&folder.uuid), false)? {
                        item_folder.insert(item, folder.uuid.clone());
                    }
                }
                Ok(Self {
                    folders,
                    item_folder,
                })
            })
            .and_then(Result::ok)
            .unwrap_or_default()
    }

    pub(crate) fn get(&self, uuid: &str) -> Option<&Folder> {
        self.folders.iter().find(|folder| folder.uuid == uuid)
    }

    pub(crate) fn name(&self, uuid: &str) -> Option<String> {
        self.get(uuid).map(|folder| folder.name.clone())
    }

    /// The folders right under `parent`.
    pub(crate) fn children<'a>(
        &'a self,
        parent: Option<&'a str>,
    ) -> impl Iterator<Item = &'a Folder> + 'a {
        self.folders
            .iter()
            .filter(move |folder| folder.parent.as_deref() == parent)
    }

    pub(crate) fn has_children(&self, uuid: &str) -> bool {
        self.children(Some(uuid)).next().is_some()
    }

    /// The names from the top level to `uuid`.
    pub(crate) fn path(&self, uuid: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = self.get(uuid);
        while let Some(folder) = at {
            names.push(folder.name.clone());
            if names.len() > MAX_FOLDER_DEPTH * 4 {
                break;
            }
            at = folder.parent.as_deref().and_then(|parent| self.get(parent));
        }
        names.reverse();
        names
    }

    /// "Work › Acme", or "Personal" for the top level.
    pub(crate) fn path_label(&self, uuid: Option<&str>) -> String {
        match uuid {
            Some(uuid) if self.get(uuid).is_some() => self.path(uuid).join(" › "),
            _ => "Personal".to_owned(),
        }
    }

    /// The level of a folder: 0 at the top level.
    pub(crate) fn level(&self, uuid: &str) -> usize {
        self.path(uuid).len().saturating_sub(1)
    }

    /// The folder and its subfolders.
    pub(crate) fn subtree(&self, uuid: &str) -> BTreeSet<String> {
        let mut found = BTreeSet::from([uuid.to_owned()]);
        loop {
            let more: Vec<String> = self
                .folders
                .iter()
                .filter(|folder| {
                    folder
                        .parent
                        .as_ref()
                        .is_some_and(|parent| found.contains(parent))
                        && !found.contains(&folder.uuid)
                })
                .map(|folder| folder.uuid.clone())
                .collect();
            if more.is_empty() {
                return found;
            }
            found.extend(more);
        }
    }

    /// The folder of a credential, `None` at the top level.
    pub(crate) fn folder_of(&self, item_id: u64) -> Option<&str> {
        self.item_folder.get(&item_id).map(String::as_str)
    }

    /// The credential is in `place`: every credential for "All credentials", the
    /// credentials of the folder and its subfolders for a folder.
    pub(crate) fn contains(&self, place: &Place, item_id: u64) -> bool {
        match place {
            Place::Folder(None) => true,
            Place::Folder(Some(uuid)) => self
                .folder_of(item_id)
                .is_some_and(|folder| self.subtree(uuid).contains(folder)),
            _ => false,
        }
    }
}

/// What the owner reads when a folder change fails.
fn folder_error(error: &VaultError) -> String {
    match error.kind() {
        VaultErrorKind::AlreadyExists => "A folder with this name is already there.".to_owned(),
        VaultErrorKind::InvalidInput => format!(
            "Type a name of at most {MAX_FOLDER_NAME_BYTES} bytes, without control characters. Folders nest at most {MAX_FOLDER_DEPTH} levels deep."
        ),
        VaultErrorKind::NotFound => {
            "The folder is gone. Another Mac may have deleted it.".to_owned()
        }
        _ => format!("The folder did not change: {error}."),
    }
}

/// Open "New Folder" in `parent`.
pub(super) fn open_new(app: &mut DesktopApp, parent: Option<String>) {
    app.ui.folder_name.clear();
    app.ui.sheet = Some(Sheet::NewFolder { parent });
}

/// Open "Rename Folder" with the current name.
pub(super) fn open_rename(app: &mut DesktopApp, uuid: &str) {
    app.ui.folder_name = FolderTree::load(app).name(uuid).unwrap_or_default();
    app.ui.sheet = Some(Sheet::RenameFolder {
        uuid: uuid.to_owned(),
    });
}

pub(super) fn open_delete(app: &mut DesktopApp, uuid: &str) {
    app.ui.sheet = Some(Sheet::DeleteFolder {
        uuid: uuid.to_owned(),
    });
}

/// Open "Move to Folder" with the folder of the credential selected.
pub(super) fn open_move(app: &mut DesktopApp, item_id: u64) {
    app.ui.move_target = FolderTree::load(app).folder_of(item_id).map(str::to_owned);
    app.ui.sheet = Some(Sheet::MoveToFolder { item_id });
}

/// Make a folder. On success the sidebar opens its parent and selects it.
pub(crate) fn create(app: &mut DesktopApp, parent: Option<&str>, name: &str) -> Option<Folder> {
    let result = app
        .owner_ui
        .session
        .with_vault(|vault| vault.create_folder(parent, name.trim()));
    match result {
        Some(Ok(folder)) => {
            if let Some(parent) = parent {
                app.ui.open_folders.insert(parent.to_owned());
            }
            app.place = Place::Folder(Some(folder.uuid.clone()));
            app.selected_item_id = None;
            app.set_ok(format!("The folder “{}” is made.", folder.name));
            Some(folder)
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            None
        }
        None => {
            app.set_err("No vault is open.");
            None
        }
    }
}

pub(crate) fn rename(app: &mut DesktopApp, uuid: &str, name: &str) -> bool {
    match app
        .owner_ui
        .session
        .with_vault(|vault| vault.rename_folder(uuid, name.trim()))
    {
        Some(Ok(())) => {
            app.set_ok(format!("The folder is now “{}”.", name.trim()));
            true
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            false
        }
        None => false,
    }
}

/// Delete a folder. Its credentials and subfolders go to its parent. A list that showed
/// the folder shows its parent.
pub(crate) fn delete(app: &mut DesktopApp, uuid: &str) -> bool {
    let tree = FolderTree::load(app);
    let parent = tree.get(uuid).and_then(|folder| folder.parent.clone());
    let name = tree.name(uuid).unwrap_or_default();
    match app
        .owner_ui
        .session
        .with_vault(|vault| vault.delete_folder(uuid))
    {
        Some(Ok(moved)) => {
            if let Place::Folder(Some(shown)) = &app.place
                && tree.subtree(uuid).contains(shown)
            {
                app.place = Place::Folder(parent.clone());
            }
            app.ui.open_folders.remove(uuid);
            let place = tree.path_label(parent.as_deref());
            app.set_ok(match moved {
                0 => format!("The folder “{name}” is deleted."),
                1 => format!("The folder “{name}” is deleted. Its credential is in {place}."),
                _ => format!(
                    "The folder “{name}” is deleted. Its {moved} credentials are in {place}."
                ),
            });
            true
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            false
        }
        None => false,
    }
}

/// Put a credential in `folder` (`None`: the top level). Sharing, rules, and history
/// stay.
pub(crate) fn move_item(app: &mut DesktopApp, item_id: u64, folder: Option<&str>) -> bool {
    match app
        .owner_ui
        .session
        .with_vault(|vault| vault.set_item_folder(item_id, folder))
    {
        Some(Ok(())) => {
            let place = FolderTree::load(app).path_label(folder);
            // The list follows the credential, so it stays selected and in view.
            if let Place::Folder(Some(_)) = &app.place {
                app.place = Place::Folder(folder.map(str::to_owned));
            }
            app.set_ok(format!("Moved to {place}."));
            true
        }
        Some(Err(error)) => {
            app.set_err(folder_error(&error));
            false
        }
        None => false,
    }
}

/// The name field of New Folder and Rename.
fn name_field(app: &mut DesktopApp, ui: &mut egui::Ui) -> egui::Response {
    let response = kit::text_input(ui, &mut app.ui.folder_name, "folder-name", "Name");
    ui.ctx()
        .accesskit_node_builder(response.id, |node| node.set_label("Folder name"));
    response
}

/// "New Folder". Returns true on Escape.
pub(super) fn new_folder_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    parent: Option<&str>,
) -> bool {
    let tree = FolderTree::load(app);
    let place = tree.path_label(parent);
    let mut create_now = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "new-folder", 400.0, |ui| {
        kit::sheet_title(ui, "New Folder", Some(&format!("In {place}.")));
        name_field(app, ui);
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let ready = !app.ui.folder_name.trim().is_empty();
                create_now = ui
                    .add_enabled_ui(ready, |ui| kit::button(ui, "Create", Style::Prominent))
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if save_pressed(app, ctx) && !app.ui.folder_name.trim().is_empty() {
        create_now = true;
    }
    if create_now {
        let name = app.ui.folder_name.clone();
        if create(app, parent, &name).is_some() {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Rename Folder". Returns true on Escape.
pub(super) fn rename_sheet(app: &mut DesktopApp, ctx: &egui::Context, uuid: &str) -> bool {
    let Some(old) = FolderTree::load(app).name(uuid) else {
        close_sheet(app, ctx);
        return false;
    };
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "rename-folder", 400.0, |ui| {
        kit::sheet_title(ui, &format!("Rename “{old}”"), None);
        name_field(app, ui);
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let ready = !app.ui.folder_name.trim().is_empty();
                save = ui
                    .add_enabled_ui(ready, |ui| kit::button(ui, "Rename", Style::Prominent))
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if save_pressed(app, ctx) && !app.ui.folder_name.trim().is_empty() {
        save = true;
    }
    if save {
        let name = app.ui.folder_name.clone();
        if rename(app, uuid, &name) {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Delete Folder": an alert. Return and Space press Cancel. Returns true on Escape.
pub(super) fn delete_sheet(app: &mut DesktopApp, ctx: &egui::Context, uuid: &str) -> bool {
    let tree = FolderTree::load(app);
    let Some(folder) = tree.get(uuid).cloned() else {
        close_sheet(app, ctx);
        return false;
    };
    let parent = tree.path_label(folder.parent.as_deref());
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "delete-folder", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Delete “{}”?", folder.name),
            Some(&format!(
                "Its credentials and subfolders move to {parent}. No credential is deleted."
            )),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Delete", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if confirm {
        if delete(app, uuid) {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Move to Folder": the top level and each folder, indented by level. Returns true on
/// Escape.
pub(super) fn move_sheet(app: &mut DesktopApp, ctx: &egui::Context, item_id: u64) -> bool {
    let Ok(details) = app.owner_ui.session.details(item_id) else {
        close_sheet(app, ctx);
        return false;
    };
    let tree = FolderTree::load(app);
    let current = tree.folder_of(item_id).map(str::to_owned);
    let mut choice = app.ui.move_target.clone();
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "move-to-folder", 440.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Move “{}”", details.name),
            Some("Sharing, rules, and history do not change."),
        );
        kit::sheet_body(ui, |ui| {
            kit::section(ui, None, None, |s| {
                let options = std::iter::once((None, "Personal".to_owned(), 0)).chain(
                    tree.folders.iter().map(|folder| {
                        (
                            Some(folder.uuid.clone()),
                            folder.name.clone(),
                            tree.level(&folder.uuid) + 1,
                        )
                    }),
                );
                for (uuid, name, level) in options {
                    let selected = choice == uuid;
                    let response = s.clickable_row(&name, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_space(14.0 * level as f32);
                            kit::paint_icon_in(ui, Icon::Folder, 15.0, kit::ACCENT);
                            ui.add(
                                Label::new(kit::text(&name, Font::Body).color(kit::LABEL))
                                    .truncate(),
                            );
                            if selected {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| kit::paint_icon_in(ui, Icon::Check, 13.0, kit::ACCENT),
                                );
                            }
                        });
                    });
                    ui_selected(&response, selected);
                    if response.clicked() {
                        choice = uuid;
                    }
                }
            });
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Move", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    app.ui.move_target = choice.clone();
    if save_pressed(app, ctx) {
        confirm = true;
    }
    if confirm {
        // The same folder changes nothing.
        if choice == current || move_item(app, item_id, choice.as_deref()) {
            close_sheet(app, ctx);
        }
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// A row of a choice says to VoiceOver that it is the selected one.
fn ui_selected(response: &egui::Response, selected: bool) {
    response
        .ctx
        .accesskit_node_builder(response.id, |node| node.set_selected(selected));
}
