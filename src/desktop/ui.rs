//! Drawing code for the desktop shell. Keep state changes in [`super::DesktopApp`].

use eframe::egui::{
    self, Color32, ComboBox, CornerRadius, FontId, Frame, Margin, RichText, ScrollArea, Stroke,
    TextEdit, Theme, ThemePreference, Vec2,
};

use crate::contracts::{CredentialKind, Decision};
use crate::desktop::model::{
    AMBIGUOUS_SAMPLE_TEXT, CONFLICTING_SAMPLE_TEXT, DEMO_BANNER, ExtraField, INTERPRETER_ID,
    SAMPLE_RULE_TEXT, UNSUPPORTED_SAMPLE_TEXT,
};
use crate::desktop::{DesktopApp, OwnerView, StatusKind};

const INK: Color32 = Color32::from_rgb(28, 25, 20);
const INK_MUTED: Color32 = Color32::from_rgb(83, 77, 68);
const BG: Color32 = Color32::from_rgb(243, 239, 230);
const BG_ELEV: Color32 = Color32::from_rgb(255, 253, 248);
const LINE: Color32 = Color32::from_rgb(215, 208, 195);
const FIELD_BG: Color32 = Color32::WHITE;
const FIELD_LINE: Color32 = Color32::from_rgb(160, 150, 132);
const ACCENT: Color32 = Color32::from_rgb(33, 90, 120);
const ACCENT_INK: Color32 = Color32::from_rgb(247, 251, 255);
const ACCENT_WEAK: Color32 = Color32::from_rgb(228, 238, 243);
const SIDEBAR: Color32 = Color32::from_rgb(36, 50, 60);
const SIDEBAR_INK: Color32 = Color32::from_rgb(244, 239, 230);
const SIDEBAR_MUTED: Color32 = Color32::from_rgb(201, 194, 180);
const SIDEBAR_CURRENT: Color32 = Color32::from_rgb(49, 88, 108);
const BANNER_BG: Color32 = Color32::from_rgb(239, 228, 196);
const BANNER_INK: Color32 = Color32::from_rgb(63, 52, 20);
const ALLOW: Color32 = Color32::from_rgb(33, 88, 69);
const ASK: Color32 = Color32::from_rgb(122, 78, 16);
const DENY: Color32 = Color32::from_rgb(138, 36, 48);

pub(crate) fn apply_style(ctx: &egui::Context) {
    ctx.options_mut(|options| {
        options.theme_preference = ThemePreference::Light;
    });
    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = BG;
    visuals.window_fill = BG_ELEV;
    visuals.warn_fg_color = ASK;
    visuals.error_fg_color = DENY;
    // Text fields need a visible edge on the light cards.
    visuals.text_edit_bg_color = Some(FIELD_BG);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, FIELD_LINE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    ctx.set_visuals_of(Theme::Light, visuals);
}

pub(crate) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    {
        let spacing = ui.spacing_mut();
        spacing.item_spacing = Vec2::new(10.0, 8.0);
        spacing.button_padding = Vec2::new(12.0, 8.0);
        spacing.interact_size.y = 32.0;
    }

    egui::Panel::top("demo_banner")
        .resizable(false)
        .exact_size(96.0)
        .show_separator_line(false)
        .frame(banner_frame())
        .show(ui, |ui| draw_banner(app, ui));

    egui::Panel::left("owner_sidebar")
        .resizable(false)
        .exact_size(248.0)
        .show_separator_line(false)
        .frame(sidebar_frame())
        .show(ui, |ui| draw_sidebar(app, ui));

    egui::CentralPanel::default()
        .frame(content_frame())
        .show(ui, |ui| draw_content(app, ui));
}

fn banner_frame() -> Frame {
    Frame::NONE
        .fill(BANNER_BG)
        .inner_margin(Margin::symmetric(16, 12))
        .stroke(Stroke::new(0.0, BANNER_BG))
}

fn sidebar_frame() -> Frame {
    Frame::NONE
        .fill(SIDEBAR)
        .inner_margin(Margin::symmetric(16, 16))
}

fn content_frame() -> Frame {
    Frame::NONE.fill(BG).inner_margin(Margin::symmetric(18, 16))
}

fn card_frame() -> Frame {
    Frame::NONE
        .fill(BG_ELEV)
        .inner_margin(Margin::symmetric(14, 12))
        .corner_radius(CornerRadius::same(8))
        .stroke(Stroke::new(1.0, LINE))
}

fn draw_banner(app: &DesktopApp, ui: &mut egui::Ui) {
    ui.colored_label(
        BANNER_INK,
        RichText::new("Demo data only").size(12.0).strong(),
    );
    ui.colored_label(BANNER_INK, RichText::new(DEMO_BANNER).size(16.0).strong());
    ui.colored_label(BANNER_INK, banner_status(app));
}

#[cfg(not(feature = "vault"))]
fn banner_status(app: &DesktopApp) -> String {
    let status = app.model.foundation_status();
    format!(
        "Storage is {storage}. The model is {model}. Isolation is {isolation}. Encryption is {encryption}.",
        storage = status.storage,
        model = status.model,
        isolation = status.isolation,
        encryption = status.encryption,
    )
}

#[cfg(feature = "vault")]
fn banner_status(app: &DesktopApp) -> String {
    let status = app.model.foundation_status();
    format!(
        "{VAULT_STORAGE_SENTENCE} Rules, agents, and activity stay demo fixtures. The model is {model}. Isolation is {isolation}.",
        model = status.model,
        isolation = status.isolation,
    )
}

/// Storage and persistence lines for the sidebar.
#[cfg(not(feature = "vault"))]
fn sidebar_storage(app: &DesktopApp) -> (String, &'static str) {
    let status = app.model.foundation_status();
    (format!("Storage: {}", status.storage), status.persistence)
}

#[cfg(feature = "vault")]
fn sidebar_storage(_app: &DesktopApp) -> (String, &'static str) {
    (
        "Storage: encrypted vault file".to_owned(),
        "Rules, agents, and activity: in memory only.",
    )
}

#[cfg(feature = "vault")]
const VAULT_STORAGE_SENTENCE: &str =
    "Vault items are in an experimental encrypted file on disk. Do not store real credentials.";

fn draw_sidebar(app: &mut DesktopApp, ui: &mut egui::Ui) {
    ui.label(
        RichText::new("Apassy")
            .size(22.0)
            .color(SIDEBAR_INK)
            .strong(),
    );
    ui.label(
        RichText::new("Owner desktop. Demo data only.")
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
    ui.add_space(8.0);

    for view in OwnerView::ALL {
        let selected = app.view == view;
        let fill = if selected {
            SIDEBAR_CURRENT
        } else {
            Color32::TRANSPARENT
        };
        let button = egui::Button::new(RichText::new(view.label()).color(SIDEBAR_INK))
            .fill(fill)
            .stroke(Stroke::new(
                1.0,
                Color32::from_rgba_unmultiplied(244, 239, 230, 40),
            ))
            .min_size(Vec2::new(ui.available_width(), 34.0));
        if ui.add(button).clicked() {
            app.view = view;
        }
    }

    ui.add_space(12.0);
    draw_lock_controls(app, ui);
    if secondary_sidebar_button(ui, "Reset demo").clicked() {
        app.reset_demo();
    }

    ui.add_space(16.0);
    let status = app.model.foundation_status();
    ui.label(
        RichText::new("Foundation status")
            .color(SIDEBAR_INK)
            .strong(),
    );
    let (storage_line, persistence_line) = sidebar_storage(app);
    ui.label(RichText::new(storage_line).size(13.0).color(SIDEBAR_MUTED));
    ui.label(
        RichText::new(format!("Model: {}", status.model))
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
    ui.label(
        RichText::new(format!("Isolation: {}", status.isolation))
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
    ui.label(
        RichText::new(persistence_line)
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
    ui.label(
        RichText::new(format!("Contract version {}", status.contract_version))
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
}

fn draw_content(app: &mut DesktopApp, ui: &mut egui::Ui) {
    draw_status(app, ui);
    ui.add_space(8.0);
    ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| match app.view {
            OwnerView::Vault => draw_vault(app, ui),
            OwnerView::Item => draw_item(app, ui),
            OwnerView::Rules => draw_rules(app, ui),
            OwnerView::Agents => draw_agents(app, ui),
            OwnerView::Activity => draw_activity(app, ui),
        });
}

fn draw_status(app: &DesktopApp, ui: &mut egui::Ui) {
    let (fill, stroke) = match app.status_kind {
        StatusKind::Neutral => (ACCENT_WEAK, Color32::from_rgb(197, 214, 223)),
        StatusKind::Ok => (
            Color32::from_rgb(231, 242, 234),
            Color32::from_rgb(197, 217, 204),
        ),
        StatusKind::Error => (
            Color32::from_rgb(248, 232, 234),
            Color32::from_rgb(227, 192, 197),
        ),
    };
    Frame::NONE
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .inner_margin(Margin::symmetric(12, 10))
        .corner_radius(CornerRadius::same(6))
        .show(ui, |ui| {
            ui.label(RichText::new(&app.status_text).color(INK));
        });
}

#[cfg(not(feature = "vault"))]
fn draw_lock_controls(app: &mut DesktopApp, ui: &mut egui::Ui) {
    ui.label(
        RichText::new(app.model.lock_state_label())
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
    ui.add_space(6.0);

    let locked = app.model.is_locked();
    ui.add_enabled_ui(!locked, |ui| {
        if accent_button(ui, "Lock vault").clicked() {
            let result = app.model.lock();
            if app
                .apply(result, "The vault is locked. Item details are hidden.")
                .is_some()
            {
                app.pending_delete = false;
            }
        }
    });
    ui.add_enabled_ui(locked, |ui| {
        if secondary_sidebar_button(ui, "Open vault").clicked() {
            let result = app.model.unlock();
            let _ = app.apply(
                result,
                "The vault is open. This control is not owner authentication.",
            );
        }
    });
}

#[cfg(feature = "vault")]
fn draw_lock_controls(app: &mut DesktopApp, ui: &mut egui::Ui) {
    ui.label(
        RichText::new(app.owner_ui.session.lock_label())
            .size(13.0)
            .color(SIDEBAR_MUTED),
    );
    ui.add_space(6.0);
    let unlocked = app.owner_ui.session.has_file() && !app.owner_ui.session.is_locked();
    ui.add_enabled_ui(unlocked, |ui| {
        if accent_button(ui, "Lock vault").clicked() {
            let result = app.owner_ui.session.lock();
            if app
                .apply(result, "The vault is locked. Item details are hidden.")
                .is_some()
            {
                app.pending_delete = false;
            }
        }
    });
}

#[cfg(feature = "vault")]
fn draw_vault(app: &mut DesktopApp, ui: &mut egui::Ui) {
    draw_owner_vault(app, ui);
}

#[cfg(not(feature = "vault"))]
fn draw_vault(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Vault");
    ui.label(
        RichText::new("The vault lists five credential categories. This desktop assigns a fixed synthetic value. Real secrets are not valid input.")
            .color(INK_MUTED),
    );
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        let label = ui.label("Search items");
        let edit = ui.add(
            TextEdit::singleline(&mut app.search)
                .desired_width(280.0)
                .hint_text("Name, project, service, or notes"),
        );
        edit.labelled_by(label.id);
        if ui.button("Search").clicked() {
            let count = app.model.list_items(&app.search).len();
            let noun = if count == 1 {
                "item matches"
            } else {
                "items match"
            };
            app.set_ok(format!("The search is complete. {count} {noun}."));
        }
        if ui.button("Clear").clicked() {
            app.search.clear();
            app.set_ok("Search is cleared.");
        }
    });

    ui.add_space(8.0);
    let items = app.model.list_items(&app.search);
    for kind in CredentialKind::ALL {
        card_frame().show(ui, |ui| {
            ui.label(RichText::new(kind.label()).size(16.0).strong().color(INK));
            let group: Vec<_> = items
                .iter()
                .filter(|item| item.kind == kind)
                .cloned()
                .collect();
            if group.is_empty() {
                ui.label(RichText::new("No items in this category.").color(INK_MUTED));
            } else {
                for item in group {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&item.name).strong().color(INK));
                            ui.label(
                                RichText::new(meta_line(&item.project, &item.service))
                                    .color(INK_MUTED),
                            );
                        });
                        if ui.button("Open item").clicked() {
                            app.select_item(item.id.clone());
                        }
                    });
                }
            }
        });
        ui.add_space(8.0);
    }

    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Add item").size(16.0).strong().color(INK));
        ui.label(
            RichText::new("The form stores labels only. The model creates the synthetic value.")
                .color(INK_MUTED),
        );
        item_form(ui, &mut app.add_form, true);
        ui.add_enabled_ui(!app.model.is_locked(), |ui| {
            if accent_button(ui, "Add item").clicked() {
                match app.model.create_item(app.add_form.clone()) {
                    Ok(item) => {
                        app.set_ok(format!("The desktop added {}.", item.name));
                        app.add_form = Default::default();
                        app.select_item(item.id);
                    }
                    Err(err) => app.set_err(err.message),
                }
            }
        });
        if app.model.is_locked() {
            ui.label(
                RichText::new("The vault is locked. Open the vault to add an item.")
                    .color(INK_MUTED),
            );
        }
    });
}

#[cfg(feature = "vault")]
fn draw_item(app: &mut DesktopApp, ui: &mut egui::Ui) {
    draw_owner_item(app, ui);
}

#[cfg(not(feature = "vault"))]
fn draw_item(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Item details");
    ui.label(
        RichText::new(
            "Values stay hidden until a demo reveal. Copy does not write to the clipboard.",
        )
        .color(INK_MUTED),
    );
    ui.add_space(8.0);

    let Some(id) = app.selected_item_id.clone() else {
        ui.label(RichText::new("Select an item in the vault.").color(INK_MUTED));
        return;
    };
    let details = match app.model.item_details(&id) {
        Ok(details) => details,
        Err(err) => {
            ui.label(RichText::new(err.message).color(DENY));
            return;
        }
    };

    card_frame().show(ui, |ui| {
        ui.label(RichText::new(&details.name).size(18.0).strong().color(INK));
        ui.label(RichText::new(details.kind.label()).color(INK_MUTED));
        if details.hidden {
            ui.label(RichText::new(&details.message).color(ASK));
            return;
        }
        ui.label(RichText::new(details.agent_use_label).color(INK_MUTED));
        ui.add_space(6.0);
        Frame::NONE
            .fill(Color32::from_rgb(247, 244, 236))
            .inner_margin(Margin::symmetric(10, 8))
            .corner_radius(CornerRadius::same(6))
            .show(ui, |ui| {
                ui.label(RichText::new("Synthetic value").color(INK_MUTED));
                let value = if details.revealed {
                    RichText::new(&details.display_value).monospace().color(INK)
                } else {
                    RichText::new(&details.display_value)
                        .monospace()
                        .color(INK_MUTED)
                };
                ui.label(value);
                if details.revealed {
                    ui.label(RichText::new(details.reveal_warning).color(ASK));
                }
                ui.label(RichText::new(details.copy_warning).color(INK_MUTED));
            });
        ui.horizontal(|ui| {
            let reveal_label = if details.revealed {
                "Hide demo value"
            } else {
                "Show demo value"
            };
            if ui.button(reveal_label).clicked() {
                if details.revealed {
                    let result = app.model.hide_item(&id);
                    let _ = app.apply(result, "The demo value is hidden.");
                } else {
                    match app.model.reveal_item(&id) {
                        Ok(revealed) => app.set_ok(revealed.reveal_warning),
                        Err(err) => app.set_err(err.message),
                    }
                }
            }
            ui.add_enabled_ui(details.revealed, |ui| {
                if ui.button("Copy (demo)").clicked() {
                    match app.model.demo_copy_item(&id) {
                        Ok(copy) => app.set_ok(copy.warning),
                        Err(err) => app.set_err(err.message),
                    }
                }
            });
        });
        property_grid(
            ui,
            "item-meta",
            &[
                ("Project", empty_as_none(&details.project)),
                ("Service", empty_as_none(&details.service)),
                ("Username", empty_as_none(&details.username)),
                ("Host", empty_as_none(&details.host)),
                ("Database", empty_as_none(&details.database_name)),
                ("Field name", empty_as_none(&details.field_name)),
                ("Public label", empty_as_none(&details.public_label)),
                ("Notes", empty_as_none(&details.notes)),
                ("Revision", details.revision.to_string()),
            ],
        );
    });

    if details.hidden {
        return;
    }

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Edit item").size(16.0).strong().color(INK));
        item_form(ui, &mut app.edit_form, false);
        if accent_button(ui, "Save item").clicked() {
            let result = app.model.update_item(&id, app.edit_form.clone());
            if app.apply(result, "The item was updated.").is_some() {
                app.pending_delete = false;
            }
        }
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Delete item").size(16.0).strong().color(INK));
        ui.label(RichText::new("Delete removes the item from this demo memory.").color(INK_MUTED));
        if app.pending_delete {
            ui.horizontal(|ui| {
                if danger_button(ui, "Confirm delete").clicked() {
                    let result = app.model.delete_item(&id);
                    if app.apply(result, "The item was deleted.").is_some() {
                        app.selected_item_id = None;
                        app.pending_delete = false;
                        app.view = OwnerView::Vault;
                    }
                }
                if ui.button("Cancel").clicked() {
                    app.pending_delete = false;
                    app.set_ok("Delete is canceled.");
                }
            });
        } else if danger_button(ui, "Delete item").clicked() {
            app.pending_delete = true;
        }
    });
}

#[cfg(feature = "vault")]
fn draw_owner_vault(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Vault");
    ui.label(
        RichText::new(
            "Create or open an encrypted vault file, then unlock it with its passphrase. Do not store real credentials. Rules, agents, and activity on the other screens stay demo fixtures.",
        )
        .color(INK_MUTED),
    );
    ui.add_space(8.0);

    if app.owner_ui.session.is_locked() {
        draw_vault_file_card(app, ui);
        ui.add_space(8.0);
        draw_backup_card(app, ui);
    } else {
        // When the vault is unlocked, the items come first. The file controls fold below them.
        draw_owner_items(app, ui);
        ui.add_space(8.0);
        egui::CollapsingHeader::new(RichText::new("Vault file and backup").strong().color(INK))
            .id_salt("vault-file-and-backup")
            .default_open(false)
            .show(ui, |ui| {
                draw_vault_file_card(app, ui);
                ui.add_space(8.0);
                draw_backup_card(app, ui);
            });
        return;
    }

    draw_owner_items(app, ui);
}

#[cfg(feature = "vault")]
fn draw_vault_file_card(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use std::path::Path;

    use super::owner_store::Ephemeral;

    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Vault file").size(16.0).strong().color(INK));
        let location = app
            .owner_ui
            .session
            .location()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "No vault file is open.".to_owned());
        ui.label(RichText::new(location).color(INK_MUTED));
        ui.label(RichText::new(app.owner_ui.session.lock_label()).color(INK_MUTED));
        labeled_text(ui, "vault-create-path", "New file path", &mut app.owner_ui.create_path);
        labeled_text(ui, "vault-open-path", "Existing file path", &mut app.owner_ui.open_path);
        password_line(ui, "vault-passphrase", "Passphrase", &mut app.owner_ui.passphrase);
        ui.label(
            RichText::new("The passphrase field is cleared after create, unlock, or restore. It is not written into the item list.")
                .color(INK_MUTED),
        );
        ui.horizontal_wrapped(|ui| {
            if accent_button(ui, "Create vault file").clicked() {
                let path = app.owner_ui.create_path.clone();
                let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
                let result = app
                    .owner_ui
                    .session
                    .create_file(Path::new(&path), passphrase.expose());
                drop(passphrase);
                if app
                    .apply(result, "The vault file is created and locked.")
                    .is_some()
                {
                    app.selected_item_id = None;
                    app.pending_delete = false;
                }
            }
            if ui.button("Open vault file").clicked() {
                let path = app.owner_ui.open_path.clone();
                let result = app.owner_ui.session.open_file(Path::new(&path));
                if app
                    .apply(result, "The vault file is open and locked.")
                    .is_some()
                {
                    app.selected_item_id = None;
                    app.pending_delete = false;
                }
            }
            let can_unlock = app.owner_ui.session.has_file() && app.owner_ui.session.is_locked();
            ui.add_enabled_ui(can_unlock, |ui| {
                if ui.button("Unlock vault").clicked() {
                    let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
                    let result = app.owner_ui.session.unlock(passphrase.expose());
                    drop(passphrase);
                    let _ = app.apply(
                        result,
                        "The vault file is unlocked in this process. This is not an authenticated owner channel.",
                    );
                }
            });
        });
    });
}

#[cfg(feature = "vault")]
fn draw_backup_card(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use std::path::Path;

    use super::owner_store::Ephemeral;

    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("Backup and restore")
                .size(16.0)
                .strong()
                .color(INK),
        );
        ui.label(
            RichText::new(
                "Backup locks the open vault. Restore opens the restored file in the locked state.",
            )
            .color(INK_MUTED),
        );
        labeled_text(
            ui,
            "vault-backup-path",
            "Backup path",
            &mut app.owner_ui.backup_path,
        );
        labeled_text(
            ui,
            "vault-restore-source",
            "Backup to restore",
            &mut app.owner_ui.restore_source,
        );
        labeled_text(
            ui,
            "vault-restore-dest",
            "Restored file path",
            &mut app.owner_ui.restore_dest,
        );
        ui.horizontal_wrapped(|ui| {
            if ui.button("Back up vault").clicked() {
                let path = app.owner_ui.backup_path.clone();
                let result = app.owner_ui.session.backup(Path::new(&path));
                if app
                    .apply(result, "The backup is written. The vault is locked.")
                    .is_some()
                {
                    app.pending_delete = false;
                }
            }
            if ui.button("Restore vault").clicked() {
                let source = app.owner_ui.restore_source.clone();
                let dest = app.owner_ui.restore_dest.clone();
                let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
                let result = app.owner_ui.session.restore(
                    Path::new(&source),
                    Path::new(&dest),
                    passphrase.expose(),
                );
                drop(passphrase);
                if app
                    .apply(result, "The restored vault is open and locked.")
                    .is_some()
                {
                    app.selected_item_id = None;
                    app.pending_delete = false;
                }
            }
        });
    });
}

#[cfg(feature = "vault")]
fn draw_owner_items(app: &mut DesktopApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        let label = ui.label("Search items");
        let edit = ui.add(
            TextEdit::singleline(&mut app.search)
                .desired_width(280.0)
                .hint_text("Name, project, service, or notes"),
        );
        edit.labelled_by(label.id);
        if ui.button("Search").clicked() {
            match app.owner_ui.session.search(&app.search) {
                Ok(items) => {
                    let count = items.len();
                    let noun = if count == 1 {
                        "item matches"
                    } else {
                        "items match"
                    };
                    app.set_ok(format!("The search is complete. {count} {noun}."));
                }
                Err(err) => app.set_err(err.message),
            }
        }
        if ui.button("Clear").clicked() {
            app.search.clear();
            app.set_ok("Search is cleared.");
        }
    });

    ui.add_space(8.0);
    let items = if app.owner_ui.session.is_locked() {
        Vec::new()
    } else {
        app.owner_ui.session.search(&app.search).unwrap_or_default()
    };
    if app.owner_ui.session.is_locked() {
        ui.label(RichText::new("Unlock the vault file to list items.").color(INK_MUTED));
    }
    for kind in CredentialKind::ALL {
        card_frame().show(ui, |ui| {
            ui.label(RichText::new(kind.label()).size(16.0).strong().color(INK));
            let group: Vec<_> = items
                .iter()
                .filter(|item| item.kind == kind)
                .cloned()
                .collect();
            if group.is_empty() {
                ui.label(RichText::new("No items in this category.").color(INK_MUTED));
            } else {
                for item in group {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&item.name).strong().color(INK));
                            ui.label(
                                RichText::new(meta_line(&item.project, &item.service))
                                    .color(INK_MUTED),
                            );
                        });
                        if ui.button("Open item").clicked() {
                            app.select_item(item.id.to_string());
                        }
                    });
                }
            }
        });
        ui.add_space(8.0);
    }

    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Add item").size(16.0).strong().color(INK));
        ui.label(
            RichText::new(
                "Secret fields stay out of search, status text, and the demo activity log.",
            )
            .color(INK_MUTED),
        );
        let kind_before = app.add_form.kind;
        item_form(ui, &mut app.add_form, true);
        if app.add_form.kind != kind_before {
            app.owner_ui.add_secrets.clear();
        }
        secret_inputs(ui, "add", app.add_form.kind, &mut app.owner_ui.add_secrets);
        ui.add_enabled_ui(!app.owner_ui.session.is_locked(), |ui| {
            if accent_button(ui, "Add item").clicked() {
                let draft = app.add_form.clone();
                let secrets = app.owner_ui.add_secrets.clone();
                match app.owner_ui.session.add(&draft, &secrets) {
                    Ok(item) => {
                        app.owner_ui.add_secrets.clear();
                        app.add_form = Default::default();
                        app.set_ok(format!("The vault stored {}.", item.name));
                        app.select_item(item.id.to_string());
                    }
                    Err(err) => app.set_err(err.message),
                }
            }
        });
        if app.owner_ui.session.is_locked() {
            ui.label(
                RichText::new("The vault is locked. Unlock it to add an item.").color(INK_MUTED),
            );
        }
    });
}

#[cfg(feature = "vault")]
fn draw_owner_item(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Item details");
    ui.label(
        RichText::new(
            "Values stay hidden until you reveal them. This desktop does not write to the clipboard.",
        )
        .color(INK_MUTED),
    );
    ui.add_space(8.0);

    if !app.owner_ui.session.has_file() {
        ui.label(
            RichText::new(
                "No vault file is open. Create or open a vault file before selecting an item.",
            )
            .color(INK_MUTED),
        );
        return;
    }
    let Some(id_text) = app.selected_item_id.clone() else {
        ui.label(RichText::new("Select an item in the vault.").color(INK_MUTED));
        return;
    };
    let Ok(id) = id_text.parse::<u64>() else {
        ui.label(RichText::new("Select an item in the vault.").color(INK_MUTED));
        return;
    };
    let details = match app.owner_ui.session.details(id) {
        Ok(details) => details,
        Err(err) => {
            ui.label(RichText::new(err.message).color(DENY));
            return;
        }
    };

    card_frame().show(ui, |ui| {
        if details.hidden {
            ui.label(RichText::new(&details.message).color(ASK));
            return;
        }
        ui.label(RichText::new(&details.name).size(18.0).strong().color(INK));
        ui.label(RichText::new(details.kind.label()).color(INK_MUTED));
        ui.label(RichText::new(details.agent_use_label()).color(INK_MUTED));
        ui.add_space(6.0);
        Frame::NONE
            .fill(Color32::from_rgb(247, 244, 236))
            .inner_margin(Margin::symmetric(10, 8))
            .corner_radius(CornerRadius::same(6))
            .show(ui, |ui| {
                ui.label(RichText::new("Stored secrets").color(INK_MUTED));
                for line in &details.secret_lines {
                    ui.label(RichText::new(&line.name).color(INK_MUTED));
                    let value = if line.revealed {
                        RichText::new(&line.display).monospace().color(INK)
                    } else {
                        RichText::new(&line.display).monospace().color(INK_MUTED)
                    };
                    ui.label(value);
                }
                if details.any_revealed() {
                    ui.label(RichText::new(details.reveal_warning()).color(ASK));
                }
                ui.label(
                    RichText::new(
                        "A copy would leave Apassy control. This desktop does not write to the clipboard.",
                    )
                    .color(INK_MUTED),
                );
            });
        ui.horizontal(|ui| {
            let reveal_label = if details.any_revealed() {
                "Hide values"
            } else {
                "Reveal values"
            };
            if ui.button(reveal_label).clicked() {
                if details.any_revealed() {
                    let result = app.owner_ui.session.hide(id);
                    let _ = app.apply(result, "The values are hidden.");
                } else {
                    match app.owner_ui.session.reveal(id) {
                        Ok(_) => app.set_ok(details.reveal_warning()),
                        Err(err) => app.set_err(err.message),
                    }
                }
            }
        });
        property_grid(
            ui,
            "item-meta",
            &[
                ("Project", empty_as_none(&details.project)),
                ("Service", empty_as_none(&details.service)),
                ("Username", empty_as_none(&details.username)),
                ("Host", empty_as_none(&details.host)),
                ("Database", empty_as_none(&details.database_name)),
                ("Field name", empty_as_none(&details.field_name)),
                ("Public label", empty_as_none(&details.public_label)),
                ("Notes", empty_as_none(&details.notes)),
                ("Revision", details.revision.to_string()),
            ],
        );
    });

    if details.hidden {
        return;
    }

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Edit item").size(16.0).strong().color(INK));
        ui.label(RichText::new("Leave a secret blank to keep the stored value.").color(INK_MUTED));
        item_form(ui, &mut app.edit_form, false);
        secret_inputs(
            ui,
            "edit",
            app.edit_form.kind,
            &mut app.owner_ui.edit_secrets,
        );
        if accent_button(ui, "Save item").clicked() {
            let draft = app.edit_form.clone();
            let secrets = app.owner_ui.edit_secrets.clone();
            let revision = app.owner_ui.edit_revision;
            let unchanged = app
                .owner_ui
                .session
                .is_unchanged(id, &draft, &secrets)
                .unwrap_or(false);
            if unchanged {
                app.set_ok("There are no changes to save.");
            } else {
                match app.owner_ui.session.update(id, revision, &draft, &secrets) {
                    Ok(summary) => {
                        app.owner_ui.edit_secrets.clear();
                        app.owner_ui.edit_revision = summary.revision;
                        app.pending_delete = false;
                        app.set_ok("The item was updated.");
                    }
                    Err(err) => app.set_err(err.message),
                }
            }
        }
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Delete item").size(16.0).strong().color(INK));
        ui.label(RichText::new("Delete removes the item from the vault file.").color(INK_MUTED));
        if app.pending_delete {
            ui.horizontal(|ui| {
                if danger_button(ui, "Confirm delete").clicked() {
                    let revision = app.owner_ui.edit_revision;
                    let result = app.owner_ui.session.delete(id, revision);
                    if app.apply(result, "The item was deleted.").is_some() {
                        app.selected_item_id = None;
                        app.pending_delete = false;
                        app.view = OwnerView::Vault;
                    }
                }
                if ui.button("Cancel").clicked() {
                    app.pending_delete = false;
                    app.set_ok("Delete is canceled.");
                }
            });
        } else if danger_button(ui, "Delete item").clicked() {
            app.pending_delete = true;
        }
    });
}

#[cfg(feature = "vault")]
fn secret_inputs(
    ui: &mut egui::Ui,
    salt: &str,
    kind: CredentialKind,
    secrets: &mut super::owner_store::SecretForm,
) {
    match kind {
        CredentialKind::ApiKey => {
            password_line(ui, &format!("{salt}-token"), "Token", &mut secrets.token);
        }
        CredentialKind::Login => {
            password_line(
                ui,
                &format!("{salt}-password"),
                "Password",
                &mut secrets.password,
            );
        }
        CredentialKind::SshKey => {
            password_line(
                ui,
                &format!("{salt}-private"),
                "Private key",
                &mut secrets.private_key,
            );
            password_line(
                ui,
                &format!("{salt}-phrase"),
                "Key passphrase",
                &mut secrets.key_passphrase,
            );
        }
        CredentialKind::Database => {
            password_line(
                ui,
                &format!("{salt}-password"),
                "Password",
                &mut secrets.password,
            );
        }
        CredentialKind::Custom => {
            password_line(
                ui,
                &format!("{salt}-custom"),
                "Secret value",
                &mut secrets.custom_value,
            );
        }
    }
}

#[cfg(feature = "vault")]
fn password_line(ui: &mut egui::Ui, salt: &str, caption: &str, value: &mut String) {
    let label = ui.label(caption);
    let edit = ui.add(
        TextEdit::singleline(value)
            .password(true)
            .id_salt(salt)
            .desired_width(320.0),
    );
    edit.labelled_by(label.id);
}

fn draw_rules(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Rules");
    ui.label(
        RichText::new(
            "The editor accepts ordinary language. This desktop uses a deterministic fixture interpreter. It does not call a language model.",
        )
        .color(INK_MUTED),
    );
    ui.label(
        RichText::new(format!(
            "Interpreter {INTERPRETER_ID}. This is a fixture interpreter. It is not live natural-language support."
        ))
        .color(ASK),
    );
    ui.add_space(8.0);

    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("Supported sample")
                .size(16.0)
                .strong()
                .color(INK),
        );
        ui.label(
            RichText::new("The interpreter matches this exact sample. Other text is refused.")
                .color(INK_MUTED),
        );
        quote(ui, SAMPLE_RULE_TEXT);
        ui.horizontal_wrapped(|ui| {
            if ui.button("Fill supported sample").clicked() {
                app.rule_text = SAMPLE_RULE_TEXT.to_owned();
                app.set_ok("The sample text is in the editor. Review the rule next.");
            }
            if ui.button("Fill ambiguous sample").clicked() {
                app.rule_text = AMBIGUOUS_SAMPLE_TEXT.to_owned();
                app.set_ok("The sample text is in the editor. Review the rule next.");
            }
            if ui.button("Fill conflicting sample").clicked() {
                app.rule_text = CONFLICTING_SAMPLE_TEXT.to_owned();
                app.set_ok("The sample text is in the editor. Review the rule next.");
            }
            if ui.button("Fill unsupported sample").clicked() {
                app.rule_text = UNSUPPORTED_SAMPLE_TEXT.to_owned();
                app.set_ok("The sample text is in the editor. Review the rule next.");
            }
        });
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        let label = ui.label("Rule text");
        let edit = ui.add(
            TextEdit::multiline(&mut app.rule_text)
                .desired_width(f32::INFINITY)
                .desired_rows(6),
        );
        edit.labelled_by(label.id);
        ui.horizontal_wrapped(|ui| {
            if accent_button(ui, "Review rule").clicked() {
                match app.model.interpret_rule(&app.rule_text) {
                    Ok(draft) if draft.status == crate::desktop::DraftStatus::ReadyForReview => {
                        app.set_ok("The fixture interpreter produced a reviewable sample draft.");
                    }
                    Ok(_) => app.set_err(
                        "The fixture interpreter refused this text. See questions and issues.",
                    ),
                    Err(err) => app.set_err(err.message),
                }
            }
            let can_confirm = app.model.rule_draft().is_some_and(|draft| {
                draft.status == crate::desktop::DraftStatus::ReadyForReview && !draft.confirmed
            });
            ui.add_enabled_ui(can_confirm, |ui| {
                if ui.button("Confirm interpretation").clicked() {
                    let result = app.model.confirm_rule();
                    let _ = app.apply(result, "The owner demo confirmation is recorded.");
                }
            });
            let can_activate = app.model.rule_draft().is_some_and(|draft| {
                draft.status == crate::desktop::DraftStatus::ReadyForReview && draft.confirmed
            });
            ui.add_enabled_ui(can_activate, |ui| {
                if accent_button(ui, "Activate rule").clicked() {
                    let result = app.model.activate_rule();
                    let _ = app.apply(result, "The sample rule is active in this desktop demo.");
                }
            });
        });
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("Clause review")
                .size(16.0)
                .strong()
                .color(INK),
        );
        match app.model.rule_draft() {
            None => {
                ui.label(
                    RichText::new("A review shows clauses, questions, and examples.")
                        .color(INK_MUTED),
                );
            }
            Some(draft) => {
                ui.label(format!(
                    "{}. Interpreter: {}.",
                    draft.status.label(),
                    draft.interpreter
                ));
                ui.label(RichText::new("Original text").strong());
                quote(ui, &draft.original_text);
                ui.label(RichText::new("Clauses").strong());
                if draft.clauses.is_empty() {
                    ui.label(
                        RichText::new("No clauses. The interpreter did not invent a parse.")
                            .color(INK_MUTED),
                    );
                } else {
                    for clause in &draft.clauses {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(clause.kind_label)
                                    .small()
                                    .strong()
                                    .color(ACCENT),
                            );
                            ui.vertical(|ui| {
                                ui.label(&clause.text);
                                ui.label(RichText::new(&clause.meaning).color(INK_MUTED));
                            });
                        });
                    }
                }
                ui.label(RichText::new("Questions and issues").strong());
                if draft.questions.is_empty() && draft.issues.is_empty() {
                    ui.label(RichText::new("No open questions.").color(INK_MUTED));
                } else {
                    for question in &draft.questions {
                        ui.label(format!("• {question}"));
                    }
                    for issue in &draft.issues {
                        ui.label(format!("• {}", issue.message));
                    }
                }
                ui.label(RichText::new("Examples").strong());
                if let Some(examples) = &draft.examples {
                    property_grid(
                        ui,
                        "draft-examples",
                        &[
                            ("Permit", examples.allow.clone()),
                            ("Wait", examples.ask.clone()),
                            ("Deny", examples.deny.clone()),
                        ],
                    );
                } else {
                    ui.label(RichText::new("No examples for this text.").color(INK_MUTED));
                }
            }
        }
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Active rule").size(16.0).strong().color(INK));
        match app.model.active_rule() {
            None => ui.label(RichText::new("No active rule.").color(INK_MUTED)),
            Some(rule) => {
                ui.label(RichText::new(rule.status).color(decision_color_from_status(rule.status)));
                property_grid(
                    ui,
                    "active-rule",
                    &[
                        ("Agent", rule.agent_name.clone()),
                        ("Item", rule.item_name.clone()),
                        ("Destination", rule.destination.to_owned()),
                        ("Denied", rule.denied_destinations.join(", ")),
                        ("Operation", rule.operation.to_owned()),
                        (
                            "Expiry",
                            format!("{} ({})", rule.expiry_iso, rule.time_zone),
                        ),
                        (
                            "Uses",
                            format!("{} of {}", rule.use_count, rule.usage_limit),
                        ),
                        ("Interpreter", rule.interpreter.to_owned()),
                        ("Version", rule.version.to_string()),
                    ],
                );
                quote(ui, &rule.original_text);
                ui.label(RichText::new(rule.interpreter).color(INK_MUTED))
            }
        };
    });
}

fn draw_agents(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Agents");
    ui.label(
        RichText::new(
            "You can connect a synthetic catalog agent. Revoke stops future sample use. This is not a verified isolation boundary.",
        )
        .color(INK_MUTED),
    );
    ui.add_space(8.0);
    let agents = app.model.catalog_agents();
    for agent in agents {
        card_frame().show(ui, |ui| {
            ui.label(RichText::new(&agent.name).size(16.0).strong().color(INK));
            ui.label(&agent.summary);
            ui.label(RichText::new(format!("Status: {}", agent.status_label)).color(INK_MUTED));
            if agent.connected {
                if danger_button(ui, "Revoke agent").clicked() {
                    let message = format!("{} is revoked.", agent.name);
                    let result = app.model.revoke_agent(&agent.id);
                    let _ = app.apply(result, &message);
                }
            } else if accent_button(ui, "Connect agent").clicked() {
                let message = format!("{} is connected.", agent.name);
                let result = app.model.connect_agent(&agent.id);
                let _ = app.apply(result, &message);
            }
        });
        ui.add_space(8.0);
    }
}

fn draw_activity(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Activity and approvals");
    ui.label(
        RichText::new(
            "A demo request can be sent from this view. A normal grant is permitted. An unclear task waits. Production is denied and cannot be approved.",
        )
        .color(INK_MUTED),
    );
    ui.label(
        RichText::new("This is a fixture risk simulation. It is not a verified bouncer.")
            .color(ASK),
    );
    ui.add_space(8.0);

    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Demo request").size(16.0).strong().color(INK));
        ComboBox::new("demo_scenario", "Request")
            .selected_text(app.scenario.label())
            .show_ui(ui, |ui| {
                for scenario in crate::desktop::DemoScenario::ALL {
                    ui.selectable_value(&mut app.scenario, scenario, scenario.label());
                }
            });
        if accent_button(ui, "Send request").clicked() {
            match app.model.simulate(app.scenario) {
                Ok(request) => {
                    if request.decision == Decision::Deny {
                        app.set_err(request.message);
                    } else {
                        app.set_ok(request.message);
                    }
                }
                Err(err) => app.set_err(err.message),
            }
        }
        ui.label(RichText::new(app.model.notification_health().label).color(INK_MUTED));
        ui.horizontal(|ui| {
            if ui.button("Set notification to failed").clicked() {
                let result = app.model.set_notification_healthy(false);
                let _ = app.apply(
                    result,
                    "Notification delivery will fail. Waiting requests stay in the inbox.",
                );
            }
            if ui.button("Set notification to healthy").clicked() {
                let result = app.model.set_notification_healthy(true);
                let _ = app.apply(result, "The demo notification channel is healthy.");
            }
        });
        ui.label(
            RichText::new("The inbox is in memory. This desktop does not claim durability.")
                .color(INK_MUTED),
        );
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("Inbox and alerts")
                .size(16.0)
                .strong()
                .color(INK),
        );
        let alerts: Vec<_> = app.model.list_alerts().into_iter().cloned().collect();
        if alerts.is_empty() {
            ui.label(RichText::new("No alerts.").color(INK_MUTED));
        }
        for alert in alerts {
            let request = app
                .model
                .list_requests()
                .iter()
                .find(|request| request.id == alert.request_id)
                .cloned();
            Frame::NONE
                .stroke(Stroke::new(1.0, LINE))
                .inner_margin(Margin::symmetric(10, 8))
                .corner_radius(CornerRadius::same(6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let current = request
                            .as_ref()
                            .map(|r| r.decision)
                            .unwrap_or(alert.decision);
                        decision_pill(ui, current);
                        ui.label(RichText::new(&alert.title).strong());
                    });
                    if let Some(request) = &request
                        && request.initial_decision != request.decision
                    {
                        ui.label(
                            RichText::new(format!(
                                "First decision: {}",
                                first_decision_label(request.initial_decision)
                            ))
                            .color(INK_MUTED),
                        );
                    }
                    ui.label(&alert.message);
                    ui.label(
                        RichText::new(format!(
                            "{} · {} · {} · {} · delivery {}",
                            alert.agent_name,
                            alert.item_name,
                            alert.destination,
                            alert.operation,
                            alert.delivery_status
                        ))
                        .color(INK_MUTED),
                    );
                    ui.horizontal_wrapped(|ui| {
                        if let Some(request) = &request
                            && request.status == crate::desktop::RequestStatus::Pending
                            && request.approvable
                        {
                            if ui.button("Approve once").clicked() {
                                let result = app.model.approve_once(&request.id, None);
                                let _ = app.apply(result, "The request was approved once.");
                            }
                            if ui.button("Deny request").clicked() {
                                let result = app.model.deny_request(&request.id);
                                let _ = app.apply(result, "The request was denied.");
                            }
                        }
                        let connected = app
                            .model
                            .list_agents()
                            .iter()
                            .any(|agent| agent.id == alert.agent_id && agent.connected);
                        if connected && danger_button(ui, "Revoke agent").clicked() {
                            let message = format!("{} is revoked.", alert.agent_name);
                            let result = app.model.revoke_agent(&alert.agent_id);
                            let _ = app.apply(result, &message);
                        }
                    });
                });
            ui.add_space(6.0);
        }
    });

    ui.add_space(8.0);
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("History").size(16.0).strong().color(INK));
        let events: Vec<_> = app.model.list_activity().into_iter().cloned().collect();
        if events.is_empty() {
            ui.label(RichText::new("No history.").color(INK_MUTED));
        }
        for event in events {
            ui.label(&event.message);
            ui.label(RichText::new(format!("{} · {}", event.at_iso, event.kind)).color(INK_MUTED));
            ui.add_space(4.0);
        }
    });
}

fn item_form(ui: &mut egui::Ui, form: &mut crate::desktop::ItemDraft, kind_editable: bool) {
    labeled_text(ui, "add-name", "Name", &mut form.name);
    if kind_editable {
        ComboBox::new("add-kind", "Category")
            .selected_text(form.kind.label())
            .show_ui(ui, |ui| {
                for kind in CredentialKind::ALL {
                    ui.selectable_value(&mut form.kind, kind, kind.label());
                }
            });
    } else {
        ui.label(format!("Category: {}", form.kind.label()));
    }
    labeled_text(ui, "add-service", "Service", &mut form.service);
    labeled_text(ui, "add-project", "Project", &mut form.project);
    for field in crate::desktop::model::DesktopModel::extra_fields(form.kind) {
        match field {
            ExtraField::Username => {
                labeled_text(ui, "add-username", field.label(), &mut form.username)
            }
            ExtraField::Host => labeled_text(ui, "add-host", field.label(), &mut form.host),
            ExtraField::DatabaseName => {
                labeled_text(ui, "add-database", field.label(), &mut form.database_name)
            }
            ExtraField::FieldName => {
                labeled_text(ui, "add-field", field.label(), &mut form.field_name)
            }
            ExtraField::PublicLabel => {
                labeled_text(ui, "add-public", field.label(), &mut form.public_label)
            }
        }
    }
    let label = ui.label("Notes");
    let edit = ui.add(
        TextEdit::multiline(&mut form.notes)
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    );
    edit.labelled_by(label.id);
}

fn labeled_text(ui: &mut egui::Ui, id: &str, caption: &str, value: &mut String) {
    let label = ui.label(caption);
    let edit = ui.add(TextEdit::singleline(value).id_salt(id).desired_width(320.0));
    edit.labelled_by(label.id);
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(22.0)
            .strong()
            .color(INK)
            .font(FontId::proportional(22.0)),
    );
}

fn quote(ui: &mut egui::Ui, text: &str) {
    Frame::NONE
        .fill(Color32::from_rgb(247, 244, 236))
        .inner_margin(Margin::symmetric(10, 8))
        .stroke(Stroke::new(3.0, ACCENT))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(INK));
        });
}

fn property_grid(ui: &mut egui::Ui, id: &str, rows: &[(&str, String)]) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            for (term, value) in rows {
                ui.label(RichText::new(*term).color(INK_MUTED).strong());
                ui.label(RichText::new(value).color(INK));
                ui.end_row();
            }
        });
}

fn meta_line(project: &str, service: &str) -> String {
    match (project.is_empty(), service.is_empty()) {
        (true, true) => "No project or service label".to_owned(),
        (false, true) => project.to_owned(),
        (true, false) => service.to_owned(),
        (false, false) => format!("{project} · {service}"),
    }
}

fn empty_as_none(value: &str) -> String {
    if value.is_empty() {
        "None".to_owned()
    } else {
        value.to_owned()
    }
}

fn accent_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(ACCENT_INK))
            .fill(ACCENT)
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

fn secondary_sidebar_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(SIDEBAR_INK))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(
                1.0,
                Color32::from_rgba_unmultiplied(244, 239, 230, 90),
            ))
            .min_size(Vec2::new(ui.available_width(), 32.0)),
    )
}

fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(Color32::from_rgb(255, 248, 247)))
            .fill(DENY)
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

fn first_decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "Permit",
        Decision::RequireApproval => "Wait",
        Decision::Deny => "Deny",
    }
}

fn decision_pill(ui: &mut egui::Ui, decision: Decision) {
    let text = first_decision_label(decision);
    let color = match decision {
        Decision::Allow => ALLOW,
        Decision::RequireApproval => ASK,
        Decision::Deny => DENY,
    };
    ui.label(RichText::new(text).strong().color(color));
}

fn decision_color_from_status(status: &str) -> Color32 {
    match status {
        "active" | "completed" => ALLOW,
        "pending" => ASK,
        _ => DENY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "vault"))]
    use crate::desktop::model::MASKED_VALUE;
    use crate::desktop::model::{
        DEMO_BANNER, REPORTING_AGENT_ID, REPORTING_ITEM_ID, SAMPLE_RULE_TEXT,
    };
    use crate::desktop::{DemoScenario, DesktopApp, OwnerView};
    use eframe::egui::{self, Pos2, RawInput, Rect, Shape, Vec2};

    const DEFAULT_SIZE: Vec2 = Vec2::new(1280.0, 840.0);
    const MIN_SIZE: Vec2 = Vec2::new(960.0, 640.0);
    const TALL_SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

    fn heading_for(view: OwnerView) -> &'static str {
        match view {
            OwnerView::Vault => "Vault",
            OwnerView::Item => "Item details",
            OwnerView::Rules => "Rules",
            OwnerView::Agents => "Agents",
            OwnerView::Activity => "Activity and approvals",
        }
    }

    fn collect_shape_text(shape: &Shape, out: &mut String) {
        match shape {
            Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            Shape::Vec(nested) => {
                for inner in nested {
                    collect_shape_text(inner, out);
                }
            }
            _ => {}
        }
    }

    fn collect_frame_text(output: &egui::FullOutput) -> String {
        let mut out = String::new();
        for clipped in &output.shapes {
            collect_shape_text(&clipped.shape, &mut out);
        }
        out
    }

    fn draw_frames(app: &mut DesktopApp, size: Vec2, frames: u32) -> (String, usize) {
        let ctx = egui::Context::default();
        let mut text = String::new();
        let mut shape_count = 0;
        for _ in 0..frames {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| draw(app, ui));
            shape_count = output.shapes.len();
            text = collect_frame_text(&output);
            output.drop_without_applying_deltas();
        }
        (text, shape_count)
    }

    fn unlocked_app_with_item() -> DesktopApp {
        let mut app = DesktopApp::new();
        app.model
            .unlock()
            .expect("open vault is not authentication");
        app.select_item(REPORTING_ITEM_ID.to_owned());
        app
    }

    fn assert_demo_shell(text: &str, shape_count: usize, heading: &str) {
        assert!(
            shape_count > 0,
            "the pass must paint shapes; this is not pixel-level QA"
        );
        assert!(
            text.contains(DEMO_BANNER),
            "missing demo warning in {heading}: {text}"
        );
        assert!(text.contains(heading), "missing heading {heading}: {text}");
        #[cfg(not(feature = "vault"))]
        assert!(
            text.contains("Storage is not connected"),
            "storage must stay not connected: {text}"
        );
        #[cfg(feature = "vault")]
        {
            assert!(
                text.contains(VAULT_STORAGE_SENTENCE),
                "the vault build must name the encrypted file: {text}"
            );
            assert!(
                !text.contains("Encryption is not present"),
                "the vault build must not deny encryption: {text}"
            );
        }
        assert!(
            text.contains("The model is unverified"),
            "the model must stay unverified: {text}"
        );
        assert!(
            text.contains("Isolation is unverified"),
            "isolation must stay unverified: {text}"
        );
        assert!(
            !text.contains("SYNTH-"),
            "masked demo must not show a synthetic value: {text}"
        );
        assert!(
            !text.contains("NOT-A-SECRET"),
            "masked demo must not show a synthetic value: {text}"
        );
    }

    #[test]
    fn locked_state_draws_warning_and_hides_item_details() {
        let mut app = DesktopApp::new();
        assert!(app.model.is_locked());
        let (text, shape_count) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert_demo_shell(&text, shape_count, "Vault");
        assert!(
            text.contains("The vault is locked"),
            "locked label missing: {text}"
        );
        #[cfg(feature = "vault")]
        {
            assert!(
                text.contains("Create vault file"),
                "vault file controls missing: {text}"
            );
            assert!(
                text.contains("No vault file is open"),
                "missing empty vault state: {text}"
            );
            assert!(
                !text.contains("Project A reporting service"),
                "demo items must stay off the vault view: {text}"
            );
        }
        assert!(
            text.contains("Open vault is not owner authentication")
                || text.contains("Item details are hidden"),
            "lock copy missing: {text}"
        );
    }

    #[test]
    fn five_owner_views_draw_at_default_and_minimum_sizes() {
        for size in [DEFAULT_SIZE, MIN_SIZE] {
            for view in OwnerView::ALL {
                let mut app = unlocked_app_with_item();
                app.view = view;
                let (text, shape_count) = draw_frames(&mut app, size, 3);
                assert_demo_shell(&text, shape_count, heading_for(view));
                if view == OwnerView::Item {
                    #[cfg(not(feature = "vault"))]
                    {
                        assert!(
                            text.contains(MASKED_VALUE),
                            "item details must stay masked at {size:?}: {text}"
                        );
                        assert!(
                            text.contains("Project A reporting service"),
                            "selected item missing at {size:?}: {text}"
                        );
                    }
                    #[cfg(feature = "vault")]
                    {
                        assert!(
                            text.contains("No vault file is open"),
                            "vault item view must wait for a file at {size:?}: {text}"
                        );
                        assert!(
                            !text.contains("Project A reporting service"),
                            "demo items must stay off the vault item view at {size:?}: {text}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn activity_history_after_approve_once_draws_on_a_tall_frame() {
        let mut app = unlocked_app_with_item();
        app.model
            .connect_agent(REPORTING_AGENT_ID)
            .expect("connect reporting agent");
        app.model
            .interpret_rule(SAMPLE_RULE_TEXT)
            .expect("review supported sample");
        app.model.confirm_rule().expect("confirm sample");
        app.model.activate_rule().expect("activate sample");
        let waiting = app
            .model
            .simulate(DemoScenario::Uncertain)
            .expect("uncertain fixture path");
        app.model
            .approve_once(&waiting.id, None)
            .expect("approve once");
        app.view = OwnerView::Activity;

        let (compact, compact_shapes) = draw_frames(&mut app, MIN_SIZE, 3);
        assert_demo_shell(&compact, compact_shapes, heading_for(OwnerView::Activity));
        assert!(
            compact.contains("This is a fixture risk simulation"),
            "fixture risk label missing: {compact}"
        );

        let (tall, tall_shapes) = draw_frames(&mut app, TALL_SIZE, 3);
        assert_demo_shell(&tall, tall_shapes, heading_for(OwnerView::Activity));
        assert!(
            tall.contains("Permitted request"),
            "current completion title missing on the tall frame: {tall}"
        );
        assert!(
            tall.contains("The owner approved this exact request once"),
            "current approval message missing on the tall frame: {tall}"
        );
        assert!(
            tall.contains("First decision: Wait"),
            "first wait label missing on the tall frame: {tall}"
        );
        assert!(
            !tall.contains("Approve once"),
            "completed use must not show Approve once: {tall}"
        );
        assert!(
            tall.contains("History"),
            "history heading missing on the tall frame: {tall}"
        );
        assert!(
            tall.contains("The request waits for an owner decision"),
            "original wait must stay in history: {tall}"
        );
    }
}
