//! The start screens: welcome, create, open, restore, and unlock. They fill the window
//! while no vault file is open or the vault is locked.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Align, Frame, Id, Key, Label, Rect, Vec2};

use super::kit::{self, Font, Icon, Style, Tone};
use super::{
    PASSPHRASE_CAPACITY, VAULT_PASSPHRASE_FIELD, VAULT_REPEAT_FIELD, default_vault_path,
    forget_secret_field, secure_input,
};
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::unlock::UnlockMethod;
use crate::desktop::{DesktopApp, OwnerView};

/// Width of the start column.
const WIDTH: f32 = 400.0;

/// The step of the start screens. `Home` is the welcome screen without a file, and the
/// unlock screen with a locked file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Step {
    #[default]
    Home,
    Create,
    Open,
    Restore,
}

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    egui::CentralPanel::default()
        .frame(Frame::NONE.fill(kit::WINDOW))
        .show(ui, |ui| {
            let full = ui.max_rect();
            kit::window_drag_region(
                ui,
                Rect::from_min_size(full.min, Vec2::new(full.width(), kit::TITLE_BAR)),
            );
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| centered(ui, |ui| screen(app, ui)));
        });
}

/// A column of `WIDTH`, centered in the window. The height of the last frame gives the
/// top space.
fn centered(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    let id = Id::new("apassy-start-height");
    let last: f32 = ui.ctx().data(|data| data.get_temp(id)).unwrap_or(420.0);
    let top = ((ui.available_height() - last) / 2.0).max(kit::TITLE_BAR + 24.0);
    ui.add_space(top);
    let side = ((ui.available_width() - WIDTH) / 2.0).max(24.0);
    let height = ui
        .horizontal(|ui| {
            ui.add_space(side);
            ui.vertical(|ui| {
                ui.set_width(WIDTH);
                add(ui);
            })
            .response
            .rect
            .height()
        })
        .inner;
    ui.ctx().data_mut(|data| data.insert_temp(id, height));
    ui.add_space(32.0);
}

fn screen(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let has_file = app.owner_ui.session.has_file();
    match app.ui.start {
        Step::Home if has_file => unlock(app, ui),
        Step::Home => welcome(app, ui),
        Step::Create => create(app, ui),
        Step::Open => open(app, ui),
        Step::Restore => restore(app, ui),
    }
}

/// The app mark: a key on an accent tile.
fn mark(ui: &mut egui::Ui, icon: Icon, color: egui::Color32) {
    ui.vertical_centered(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(64.0), egui::Sense::hover());
        ui.painter().rect_filled(
            rect.translate(Vec2::new(0.0, 2.0)),
            16,
            egui::Color32::from_black_alpha(22),
        );
        ui.painter().rect_filled(rect, 16, color);
        kit::paint_icon(ui.painter(), rect.shrink(17.0), icon, egui::Color32::WHITE);
    });
    ui.add_space(14.0);
}

fn title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.vertical_centered(|ui| {
        ui.label(kit::text(title, Font::LargeTitle).color(kit::LABEL));
        ui.add_space(4.0);
        ui.add(
            Label::new(kit::text(subtitle, Font::Body).color(kit::SECONDARY))
                .wrap()
                .halign(Align::Center),
        );
    });
    ui.add_space(24.0);
}

fn back(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::back_link(ui, "Back") {
        app.ui.start = Step::Home;
    }
    ui.add_space(8.0);
}

fn welcome(app: &mut DesktopApp, ui: &mut egui::Ui) {
    mark(ui, Icon::Key, kit::ACCENT);
    title(
        ui,
        "Welcome to Apassy",
        "Credentials for you and your agents. Your secrets stay in one encrypted file on this Mac. Agents use them through Apassy and never see the values.",
    );
    if kit::wide_button(ui, "Create a new vault", Style::Prominent).clicked() {
        app.ui.start = Step::Create;
    }
    ui.add_space(8.0);
    if kit::wide_button(ui, "Open an existing vault", Style::Bordered).clicked() {
        app.ui.start = Step::Open;
    }
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        if kit::small_button(ui, "Restore from a backup…", Style::Link).clicked() {
            app.ui.start = Step::Restore;
        }
    });
}

/// Fill an empty path field with the default location.
fn prefill(path: &mut String, default: &Path) {
    if path.trim().is_empty() {
        *path = default.display().to_string();
    }
}

fn create(app: &mut DesktopApp, ui: &mut egui::Ui) {
    back(app, ui);
    ui.label(kit::text("Create your vault", Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "Choose a passphrase that you can remember. Apassy cannot recover a lost passphrase, and the data is then gone.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    prefill(&mut app.owner_ui.create_path, &default_vault_path());
    let ctx = ui.ctx().clone();
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some("12 or more characters. A sentence of several words is strong and easy to remember."),
        |s| {
            s.field("Passphrase", |ui| {
                secure_input(
                    ui,
                    VAULT_PASSPHRASE_FIELD,
                    &mut app.owner_ui.passphrase,
                    PASSPHRASE_CAPACITY,
                    "Required",
                )
            });
            let repeat = s.field("Repeat", |ui| {
                secure_input(
                    ui,
                    VAULT_REPEAT_FIELD,
                    &mut app.owner_ui.passphrase_confirm,
                    PASSPHRASE_CAPACITY,
                    "Type it again",
                )
            });
            submit = enter_pressed(&repeat);
        },
    );
    let mut open = app.ui.is_expanded("start-location");
    if kit::disclosure(ui, &mut open, "Location").changed() {
        app.ui.set_expanded("start-location", open);
    }
    if open {
        ui.add_space(4.0);
        kit::section(
            ui,
            None,
            Some("The default folder is closed to agents by the Apassy sandbox profile."),
            |s| {
                s.field("File", |ui| {
                    kit::text_input(ui, &mut app.owner_ui.create_path, "vault-create-path", "")
                });
            },
        );
    } else {
        ui.add_space(14.0);
    }
    if kit::wide_button(ui, "Create vault", Style::Prominent).clicked() || submit {
        create_vault(app, &ctx);
    }
}

/// Create the vault file and unlock it with the same passphrase. The passphrase fields
/// and their undo history are erased first (key-memory review F1, F3).
pub(super) fn create_vault(app: &mut DesktopApp, ctx: &egui::Context) {
    let path = PathBuf::from(app.owner_ui.create_path.trim());
    let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
    let repeat = Ephemeral::take(&mut app.owner_ui.passphrase_confirm);
    forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
    forget_secret_field(ctx, VAULT_REPEAT_FIELD);
    if passphrase.expose() != repeat.expose() {
        app.set_err("The two passphrases are different. Type the same passphrase two times.");
        return;
    }
    drop(repeat);
    if let Err(message) = ensure_private_folder(&path) {
        app.set_err(message);
        return;
    }
    let created = app.owner_ui.session.create_file(&path, passphrase.expose());
    if app.apply(created, "The vault is created.").is_none() {
        return;
    }
    let unlocked = app.owner_ui.session.unlock(passphrase.expose());
    drop(passphrase);
    app.selected_item_id = None;
    app.pending_delete = false;
    app.end_waiting_runs();
    app.refresh_unlock_setting(Some(ctx));
    app.ui.start = Step::Home;
    app.view = OwnerView::Vault;
    let _ = app.apply(
        unlocked,
        "Your vault is ready. Add your first credential, then make a backup in Settings.",
    );
}

/// Create a missing parent folder with mode 0700. The broker does not start in a data
/// folder with a wider mode.
fn ensure_private_folder(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;

    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|err| {
            format!(
                "Apassy cannot create the folder {}: {err}",
                parent.display()
            )
        })
}

fn open(app: &mut DesktopApp, ui: &mut egui::Ui) {
    back(app, ui);
    ui.label(kit::text("Open a vault", Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "Type the location of an Apassy vault file. You unlock it on the next screen.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    prefill(&mut app.owner_ui.open_path, &default_vault_path());
    let mut submit = false;
    kit::section(ui, None, None, |s| {
        let field = s.field("File", |ui| {
            kit::text_input(ui, &mut app.owner_ui.open_path, "vault-open-path", "")
        });
        submit = enter_pressed(&field);
    });
    if kit::wide_button(ui, "Open", Style::Prominent).clicked() || submit {
        let ctx = ui.ctx().clone();
        let path = PathBuf::from(app.owner_ui.open_path.trim());
        let result = app.owner_ui.session.open_file(&path);
        if app
            .apply(result, "The vault file is open. Unlock it.")
            .is_some()
        {
            app.selected_item_id = None;
            app.pending_delete = false;
            app.end_waiting_runs();
            app.refresh_unlock_setting(Some(&ctx));
            app.ui.start = Step::Home;
        }
    }
}

fn restore(app: &mut DesktopApp, ui: &mut egui::Ui) {
    back(app, ui);
    ui.label(kit::text("Restore from a backup", Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "Apassy copies the backup to a new vault file and opens it locked. Agents are revoked, and each credential waits for your review before agents can use it.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    let ctx = ui.ctx().clone();
    if restore_form(app, ui) {
        restore_now(app, &ctx);
    }
    if kit::wide_button(ui, "Restore", Style::Prominent).clicked() {
        restore_now(app, &ctx);
    }
}

/// The restore fields. Returns true when the owner presses Enter in the passphrase.
pub(super) fn restore_form(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    let default = default_vault_path();
    let dest = if default.exists() {
        default.with_file_name("vault-restored.db")
    } else {
        default
    };
    prefill(&mut app.owner_ui.restore_dest, &dest);
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some(
            "The passphrase is the one of the backup. Touch ID unlock stays off for the restored file.",
        ),
        |s| {
            s.field("Backup file", |ui| {
                kit::text_input(
                    ui,
                    &mut app.owner_ui.restore_source,
                    "vault-restore-source",
                    "/Volumes/Backup/apassy.backup",
                )
            });
            s.field("New vault file", |ui| {
                kit::text_input(ui, &mut app.owner_ui.restore_dest, "vault-restore-dest", "")
            });
            let field = s.field("Passphrase", |ui| {
                secure_input(
                    ui,
                    VAULT_PASSPHRASE_FIELD,
                    &mut app.owner_ui.passphrase,
                    PASSPHRASE_CAPACITY,
                    "Passphrase of the backup",
                )
            });
            submit = enter_pressed(&field);
        },
    );
    submit
}

/// Restore needs the typed passphrase. Touch ID never supplies it (A2).
pub(super) fn restore_now(app: &mut DesktopApp, ctx: &egui::Context) {
    let source = PathBuf::from(app.owner_ui.restore_source.trim());
    let dest = PathBuf::from(app.owner_ui.restore_dest.trim());
    if let Err(message) = ensure_private_folder(&dest) {
        app.set_err(message);
        return;
    }
    let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
    forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
    let result = app
        .owner_ui
        .session
        .restore(&source, &dest, passphrase.expose());
    drop(passphrase);
    if app
        .apply(
            result,
            "The backup is restored. Unlock the vault, then review each credential.",
        )
        .is_some()
    {
        app.selected_item_id = None;
        app.pending_delete = false;
        app.end_waiting_runs();
        app.refresh_unlock_setting(Some(ctx));
        app.ui.start = Step::Home;
        app.view = OwnerView::Vault;
    }
}

fn unlock(app: &mut DesktopApp, ui: &mut egui::Ui) {
    mark(ui, Icon::Lock, egui::Color32::from_rgb(99, 99, 104));
    let file = app
        .owner_ui
        .session
        .location()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    title(
        ui,
        "Apassy is locked",
        "Type your passphrase to unlock the vault.",
    );
    draw_unlock_card(app, ui);
    ui.add_space(14.0);
    ui.vertical_centered(|ui| {
        ui.add(
            Label::new(kit::text(file, Font::Footnote).color(kit::SECONDARY))
                .truncate()
                .halign(Align::Center),
        );
        ui.horizontal(|ui| {
            // Center the two links.
            let width = 260.0;
            ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
            if kit::small_button(ui, "Open another vault…", Style::Link).clicked() {
                app.ui.start = Step::Open;
            }
            if kit::small_button(ui, "Restore…", Style::Link).clicked() {
                app.ui.start = Step::Restore;
            }
        });
    });
}

/// The passphrase field, Unlock, and Touch ID when it is set up. The field takes the
/// focus when nothing else has it.
pub(super) fn draw_unlock_card(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    let mut submit = false;
    kit::section(ui, None, None, |s| {
        let field = s.field("Passphrase", |ui| {
            secure_input(
                ui,
                VAULT_PASSPHRASE_FIELD,
                &mut app.owner_ui.passphrase,
                PASSPHRASE_CAPACITY,
                "Required",
            )
        });
        if ctx.memory(|memory| memory.focused().is_none()) && app.owner.check.is_none() {
            field.request_focus();
        }
        submit = enter_pressed(&field);
    });
    if kit::wide_button(ui, "Unlock", Style::Prominent).clicked() || submit {
        unlock_with_passphrase(app, &ctx);
    }
    touch_id_unlock(app, ui);
}

/// Unlock with the typed passphrase. The field and its undo history are erased first
/// (key-memory review F1, F3).
pub(crate) fn unlock_with_passphrase(app: &mut DesktopApp, ctx: &egui::Context) {
    let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
    forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
    let result = app.owner_ui.session.unlock(passphrase.expose());
    drop(passphrase);
    if result.is_ok() {
        app.view = OwnerView::Vault;
    }
    let _ = app.apply(result, "The vault is unlocked.");
}

/// Touch ID unlock (goal items A2, A3). It shows only when it is set up for this file.
fn touch_id_unlock(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let unlock = &app.owner.unlock;
    if unlock.reading.is_some() {
        ui.add_space(8.0);
        kit::note(ui, "Apassy is checking the Touch ID unlock setting.");
        return;
    }
    let Some(setting) = unlock.setting.clone() else {
        return;
    };
    let touch_id = setting.method == UnlockMethod::TouchId;
    if touch_id {
        ui.add_space(8.0);
        if unlock.unlocking.is_some() {
            kit::tone_note(
                ui,
                "Waiting for Touch ID. Touch the sensor, or cancel the macOS prompt.",
                Tone::Warning,
            );
        } else if kit::wide_button(ui, "Unlock with Touch ID", Style::Bordered).clicked() {
            let ctx = ui.ctx().clone();
            app.start_touch_id_unlock(&ctx);
        }
    }
    if let Some(note) = &setting.note
        && touch_id
    {
        ui.add_space(6.0);
        kit::tone_note(ui, note, Tone::Warning);
    }
}

fn enter_pressed(field: &egui::Response) -> bool {
    field.lost_focus() && field.ctx.input(|input| input.key_pressed(Key::Enter))
}
