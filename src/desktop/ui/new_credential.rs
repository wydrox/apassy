//! "New Credential" (ADR 0025 §4, ADR 0026 §4): "+" in a list and ⌘N open it.
//!
//! The owner pastes a key, a `KEY=value` line, a `.env` file, a database URL, or an
//! `otpauth://` link. [`detect`] finds each credential on this Mac, and the sheet shows
//! one row for each: the provider tile, the title (the owner can change it), the
//! provider, the variable, the host, and the environment that a signal found. A paste
//! with several credentials has a checkbox on each row. "Add" saves the checked ones in
//! one transaction, in the folder of the menu (the folder that the sidebar shows), with
//! the variable and the declaration. No owner check: a new credential moves no
//! authority, and the bouncer decides each use of it.
//!
//! The paste is a secret. It lives in the secret buffer of the add form, so a lock
//! erases it, and its field has a global ID, so a close forgets its undo history.
//! "More kinds…" leads to the add form with its kinds (a login, an SSH key) for a
//! credential that a paste does not fit.

use eframe::egui::{self, Label, RichText, TextEdit};

use super::folders::FolderTree;
use super::kit::{self, Font, Style, Tone};
use super::{SECRET_VALUE_CAPACITY, close_sheet, forget_secret_field, save_pressed};
use crate::desktop::{DesktopApp, Place};
use crate::vault::detect::{self, Detected, Source};
use crate::vault::{Environment, providers};

/// The note when a paste has no credential.
const NOTHING_FOUND: &str = "Apassy found no credential in the text. Paste a secret, a KEY=value line, a .env file, a URL with a password, or an otpauth:// link.";

/// The salt of the paste field. It is the custom value field of the add form: both use
/// the secret buffer `add_secrets.custom_value`, and a lock erases both.
pub(super) const PASTE_FIELD: &str = "add-custom";

/// What the owner chose for the rows of a paste. It has no secret value.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct Choices {
    /// The place that the sheet opened in. Another place starts new choices.
    place: Option<Place>,
    /// The folder for the new credentials. `None`: the top level.
    pub(super) folder: Option<String>,
    /// For each row of the detection, by [`row_key`]: the title and whether it is added.
    rows: Vec<(String, String, bool)>,
}

impl Choices {
    fn id() -> egui::Id {
        egui::Id::new("apassy-new-credential")
    }

    pub(super) fn load(ctx: &egui::Context) -> Self {
        ctx.data(|data| data.get_temp::<Self>(Self::id()))
            .unwrap_or_default()
    }

    fn store(self, ctx: &egui::Context) {
        ctx.data_mut(|data| data.insert_temp(Self::id(), self));
    }

    /// Follow a new detection: a row that was there keeps its title and its checkbox.
    fn follow(&mut self, detected: &[Detected]) {
        let old = std::mem::take(&mut self.rows);
        self.rows = detected
            .iter()
            .map(|found| {
                let key = row_key(found);
                old.iter()
                    .find(|(old_key, _, _)| *old_key == key)
                    .cloned()
                    .unwrap_or_else(|| (key, found.title.clone(), true))
            })
            .collect();
    }

    /// The detected credentials that the owner keeps, with the typed titles.
    pub(super) fn kept(&self, mut detected: Vec<Detected>) -> Vec<Detected> {
        let mut kept = Vec::new();
        for (found, (_, title, keep)) in detected.drain(..).zip(&self.rows) {
            if !keep {
                continue;
            }
            let mut found = found;
            if !title.trim().is_empty() {
                found.title = title.trim().to_owned();
            }
            kept.push(found);
        }
        kept
    }

    /// Set the title of row `index`, as the field of the row does.
    #[cfg(test)]
    pub(super) fn set_title(ctx: &egui::Context, index: usize, title: &str) {
        let mut choices = Self::load(ctx);
        if let Some(row) = choices.rows.get_mut(index) {
            row.1 = title.to_owned();
        }
        choices.store(ctx);
    }

    /// Check or uncheck row `index`, as its checkbox does.
    #[cfg(test)]
    pub(super) fn set_kept(ctx: &egui::Context, index: usize, keep: bool) {
        let mut choices = Self::load(ctx);
        if let Some(row) = choices.rows.get_mut(index) {
            row.2 = keep;
        }
        choices.store(ctx);
    }

    /// Choose the folder, as the Folder menu does.
    #[cfg(test)]
    pub(super) fn set_folder(ctx: &egui::Context, folder: Option<String>) {
        let mut choices = Self::load(ctx);
        choices.folder = folder;
        choices.store(ctx);
    }
}

/// The identity of a detected row across frames: its line, its variable, and its
/// detected title. It has no secret value.
fn row_key(found: &Detected) -> String {
    format!(
        "{}|{}|{}",
        found.line.unwrap_or(0),
        found.env_name.as_deref().unwrap_or_default(),
        found.title
    )
}

/// The provider label of a detected credential, or its kind.
fn provider_label(found: &Detected) -> String {
    found
        .provider
        .as_deref()
        .and_then(providers::find)
        .map_or_else(|| found.kind.label().to_owned(), |p| p.label.clone())
}

/// "Stripe · STRIPE_SECRET_KEY · api.stripe.com".
pub(super) fn row_line(found: &Detected) -> String {
    let mut parts = vec![provider_label(found)];
    if let Some(variable) = &found.env_name {
        parts.push(variable.clone());
    }
    if let Some(host) = found.hosts.first() {
        parts.push(host.clone());
    }
    parts.join(" · ")
}

/// The cap of a row: the environment that a signal found. A default shows none: the
/// bouncer treats it as production until the owner answers.
pub(super) fn row_cap(found: &Detected) -> Option<(&'static str, bool)> {
    if found.sources.environment != Source::Signal {
        return None;
    }
    match found.environment {
        Environment::Production => Some(("Production", true)),
        Environment::Development | Environment::Local => Some(("Development", false)),
        Environment::Staging => Some(("Staging", false)),
    }
}

/// Erase the paste and forget the choices and the undo history of the field. Each way
/// out of the sheet calls it.
pub(super) fn forget(app: &mut DesktopApp, ctx: &egui::Context) {
    use zeroize::Zeroize;
    app.owner_ui.add_secrets.custom_value.zeroize();
    forget_secret_field(ctx, PASTE_FIELD);
    ctx.data_mut(|data| data.remove::<Choices>(Choices::id()));
}

/// The sheet. Returns true on Escape.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let tree = FolderTree::load(app);
    let mut choices = Choices::load(ctx);
    if choices.place.as_ref() != Some(&app.place) {
        choices = Choices {
            place: Some(app.place.clone()),
            folder: tree.folder_of_place(&app.place),
            rows: Vec::new(),
        };
    }
    // A folder that another Mac deleted gives way to the top level.
    if choices
        .folder
        .as_deref()
        .is_some_and(|uuid| tree.get(uuid).is_none())
    {
        choices.folder = None;
    }
    let detected = detect::detect(&app.owner_ui.add_secrets.custom_value);
    choices.follow(&detected);
    let kept = choices.rows.iter().filter(|(_, _, keep)| *keep).count();
    let typed = !app.owner_ui.add_secrets.custom_value.trim().is_empty();
    let folder_choices = tree.choices();
    let folder_label = tree.path_label(choices.folder.as_deref());

    let mut add = false;
    let mut cancel = false;
    let mut more_kinds = false;
    let response = kit::sheet(ctx, "new-credential", 540.0, |ui| {
        kit::sheet_title(
            ui,
            "New Credential",
            Some("Paste a key, a .env file, a database URL, or an otpauth:// link."),
        );
        kit::sheet_body(ui, |ui| {
            paste_field(ui, &mut app.owner_ui.add_secrets.custom_value);
            if typed && detected.is_empty() {
                ui.add_space(6.0);
                kit::tone_note(ui, NOTHING_FOUND, Tone::Warning);
            }
            if !detected.is_empty() {
                ui.add_space(12.0);
                rows(ui, &detected, &mut choices);
                kit::note(
                    ui,
                    "Everything else is set automatically. Apassy found it on this Mac and sent nothing.",
                );
            }
            ui.add_space(6.0);
            more_kinds = kit::small_button(ui, "More kinds…", Style::Link)
                .on_hover_text("A login, an SSH key, or another kind, field by field")
                .clicked();
        });
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |ui| {
                ui.label(kit::text("Folder", Font::Body).color(kit::LABEL));
                let mut folder = choices.folder.clone();
                let menu = kit::picker(
                    ui,
                    "new-credential-folder",
                    &mut folder,
                    &folder_choices,
                    folder_label.as_str(),
                    170.0,
                );
                ui.ctx().accesskit_node_builder(menu.id, |node| {
                    node.set_label(format!("Folder, {folder_label}"));
                });
                choices.folder = folder;
            },
            |ui| {
                let label = if kept > 1 {
                    format!("Add {kept}")
                } else {
                    "Add".to_owned()
                };
                add = ui
                    .add_enabled_ui(kept > 0, |ui| kit::button(ui, &label, Style::Prominent))
                    .inner
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    let ready = kept > 0;
    choices.store(ctx);
    if ready && !add && save_pressed(app, ctx) {
        add = true;
    }
    if add {
        add_kept(app, ctx, detected);
    } else if more_kinds {
        forget(app, ctx);
        super::items::open_add(app);
    } else if cancel {
        forget(app, ctx);
        close_sheet(app, ctx);
    }
    if response.escape {
        forget(app, ctx);
    }
    response.escape
}

/// The multi-line paste field. It is masked: the rows below say what Apassy found.
fn paste_field(ui: &mut egui::Ui, value: &mut String) {
    super::presize(value, SECRET_VALUE_CAPACITY);
    let response = ui.add(
        TextEdit::multiline(value)
            .password(true)
            .id(super::secret_field_id(PASTE_FIELD))
            .char_limit(SECRET_VALUE_CAPACITY / 4)
            .font(egui::TextStyle::Monospace)
            .hint_text(kit::text("⌘V", Font::Mono).color(kit::TERTIARY))
            .margin(kit::FIELD_MARGIN)
            .desired_rows(4)
            .desired_width(f32::INFINITY),
    );
    ui.ctx().accesskit_node_builder(response.id, |node| {
        node.set_label("Paste a credential");
    });
    // The owner pastes at once, also after a click on "+".
    kit::claim_first_field(&response);
}

/// One row for each detected credential.
fn rows(ui: &mut egui::Ui, detected: &[Detected], choices: &mut Choices) {
    let several = detected.len() > 1;
    kit::section(ui, None, None, |s| {
        for (index, found) in detected.iter().enumerate() {
            let Some((_, title, keep)) = choices.rows.get_mut(index) else {
                continue;
            };
            s.row(|ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    if several {
                        let check = ui.checkbox(keep, "");
                        let name = format!("Add {}", found.title);
                        ui.ctx()
                            .accesskit_node_builder(check.id, |node| node.set_label(name));
                    }
                    let tile = super::credential_tile(found.kind, &provider_label(found), title);
                    kit::tile(ui, &tile, 32.0);
                    let cap = row_cap(found);
                    let cap_width = if cap.is_some() { 96.0 } else { 0.0 };
                    ui.vertical(|ui| {
                        ui.set_width((ui.available_width() - cap_width).max(80.0));
                        ui.spacing_mut().item_spacing.y = 2.0;
                        let field = ui.add(
                            TextEdit::singleline(title)
                                .id_salt(("new-credential-title", index))
                                .margin(egui::Margin::symmetric(4, 2))
                                .desired_width(f32::INFINITY),
                        );
                        ui.ctx().accesskit_node_builder(field.id, |node| {
                            node.set_label(format!("Title of the credential on row {}", index + 1));
                        });
                        ui.add(
                            Label::new(
                                RichText::new(row_line(found))
                                    .font(egui::FontId::monospace(11.5))
                                    .color(kit::SECONDARY),
                            )
                            .truncate(),
                        );
                    });
                    if let Some((label, red)) = cap {
                        kit::cap(ui, label, red);
                    }
                });
            });
        }
    });
}

/// Add the kept rows in the chosen folder, select the new credential (the first of
/// several), and say what was added.
fn add_kept(app: &mut DesktopApp, ctx: &egui::Context, detected: Vec<Detected>) {
    let choices = Choices::load(ctx);
    let kept = choices.kept(detected);
    if kept.is_empty() {
        return;
    }
    let folder = choices.folder.clone();
    let result = app
        .owner_ui
        .session
        .add_detected_items(&kept, folder.as_deref());
    drop(kept);
    let added = match result {
        Ok(added) => added,
        Err(err) => {
            app.set_err(err.message);
            return;
        }
    };
    let lines = app
        .owner_ui
        .session
        .added_credentials(&added)
        .unwrap_or_default();
    forget(app, ctx);
    close_sheet(app, ctx);
    app.place = Place::Folder(folder.clone());
    if let Some(first) = added.first() {
        app.select_item(first.id.to_string());
    }
    let place = FolderTree::load(app).path_label(folder.as_deref());
    match lines.as_slice() {
        [one] => app.set_ok(format!("Added {} in {place}.", one.line())),
        _ => app.set_ok(format!("Added {} credentials in {place}.", added.len())),
    }
}

#[cfg(test)]
#[path = "new_credential_tests.rs"]
mod tests;
