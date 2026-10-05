//! The start screens: welcome, create, open, restore, and unlock. They fill the window
//! while no vault file is open or the vault is locked. Create, Open, and Restore add
//! the vault to the vault list with a name (ADR 0013).

use std::path::{Path, PathBuf};

use eframe::egui::{self, Align, Frame, Id, Key, Label, Rect, Vec2};

use super::kit::{self, Font, Icon, Style, Tone};
use super::{
    PASSPHRASE_CAPACITY, VAULT_PASSPHRASE_FIELD, VAULT_REPEAT_FIELD, default_vault_path, files,
    forget_secret_field, secure_input, vaults,
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
    /// Open a synced vault (ADR 0014).
    OpenSynced,
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
                .show(ui, |ui| {
                    super::focus::page_start(&mut app.ui.focus, &ui.ctx().clone());
                    centered(ui, |ui| screen(app, ui));
                    kit::follow_focus(ui);
                    kit::keyboard_scroll(ui);
                });
        });
}

/// The first field of a step takes the focus once, after [`go`].
fn first_field(app: &mut DesktopApp, field: &egui::Response) {
    if std::mem::take(&mut app.ui.focus_start_field) && kit::keyboard_mode(&field.ctx) {
        field.request_focus();
    }
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
        Step::OpenSynced => super::sync::open_screen(app, ui),
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
        go(app, Step::Home);
    }
    ui.add_space(8.0);
}

fn welcome(app: &mut DesktopApp, ui: &mut egui::Ui) {
    mark(ui, Icon::Key, kit::ACCENT);
    title(
        ui,
        "Welcome to Apassy",
        "Credentials for you and your agents. Each vault is one encrypted file on this Mac. Agents use the secrets through Apassy and never see the values.",
    );
    vaults::start_notices(app, ui);
    vaults::welcome_list(app, ui);
    if kit::wide_button(ui, "Create my first vault", Style::Prominent).clicked() {
        go(app, Step::Create);
    }
    if app.sync.offered {
        ui.add_space(8.0);
        if kit::wide_button(ui, "Use a vault from another Mac", Style::Bordered).clicked() {
            super::sync::begin_open(app);
        }
    }
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        if kit::small_button(ui, "Open a local vault file…", Style::Link).clicked() {
            go(app, Step::Open);
        }
    });
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        if kit::small_button(ui, "Restore from a backup…", Style::Link).clicked() {
            go(app, Step::Restore);
        }
    });
}

/// Go to a start step with an empty name field.
/// Go to a step. Its first field takes the focus (for a keyboard user).
fn go(app: &mut DesktopApp, step: Step) {
    app.vault_list.name_input.clear();
    app.ui.start = step;
    app.ui.focus_start_field = step != Step::Home;
    if step == Step::Home {
        app.ui.focus.focus_page_start();
    }
}

/// Fill an empty path field with the default location.
fn prefill(path: &mut String, default: &Path) {
    if path.trim().is_empty() {
        *path = default.display().to_string();
    }
}

fn create(app: &mut DesktopApp, ui: &mut egui::Ui) {
    back(app, ui);
    let first = app.vault_list.registry.is_empty();
    let heading = if first {
        "Create your vault"
    } else {
        "Create a new vault"
    };
    ui.label(kit::text(heading, Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "Each vault has its own passphrase, agents, and rules. Choose a passphrase that you can remember. Apassy cannot recover a lost passphrase, and the data is then gone.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    let ctx = ui.ctx().clone();
    let mut submit = false;
    let name_hint = app.create_fallback_name().unwrap_or("For example Work");
    kit::section(
        ui,
        None,
        Some("12 or more characters. A sentence of several words is strong and easy to remember."),
        |s| {
            let name = vaults::name_field(app, s, "vault-create-name", name_hint);
            if std::mem::take(&mut app.ui.focus_start_field) && kit::keyboard_mode(&ctx) {
                name.request_focus();
            }
            // Return in a field goes on to the next one.
            if enter_pressed(&name) {
                ctx.memory_mut(|memory| {
                    memory.request_focus(super::secret_field_id(VAULT_PASSPHRASE_FIELD));
                });
            }
            let first = s.field("Passphrase", |ui| {
                secure_input(
                    ui,
                    VAULT_PASSPHRASE_FIELD,
                    &mut app.owner_ui.passphrase,
                    PASSPHRASE_CAPACITY,
                    "Required",
                )
            });
            if enter_pressed(&first) {
                ctx.memory_mut(|memory| {
                    memory.request_focus(super::secret_field_id(VAULT_REPEAT_FIELD));
                });
            }
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
    super::sync::create_option(app, ui);
    let mut open = app.ui.is_expanded("start-location");
    if kit::disclosure(ui, &mut open, "Location").changed() {
        app.ui.set_expanded("start-location", open);
    }
    if open {
        ui.add_space(4.0);
        let name = match app.vault_list.name_input.trim() {
            "" => app.create_fallback_name().unwrap_or("vault").to_owned(),
            typed => typed.to_owned(),
        };
        let default = app
            .vault_list
            .registry
            .new_vault_path(&app.vault_list.data_dir, &name)
            .display()
            .to_string();
        kit::section(
            ui,
            None,
            Some("Leave the field empty to use the Apassy data folder."),
            |s| {
                s.field("File", |ui| {
                    files::path_input(
                        ui,
                        &mut app.files,
                        &mut app.owner_ui.create_path,
                        "vault-create-path",
                        &default,
                        files::DialogKind::SaveVault,
                    )
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

/// Create the vault file, add it to the vault list, and unlock it with the same
/// passphrase. A wrong name or file keeps the typed passphrases. Then the passphrase
/// fields and their undo history are erased (key-memory review F1, F3).
pub(super) fn create_vault(app: &mut DesktopApp, ctx: &egui::Context) {
    let fallback = app.create_fallback_name();
    let (name, path) = match app.new_vault_target(&app.owner_ui.create_path, fallback) {
        Ok(target) => target,
        Err(message) => {
            if app.vault_list.name_input.trim().is_empty() && fallback.is_none() {
                // Keep the typed passphrases and return to the missing field.
                app.ui.focus_start_field = true;
                ctx.request_repaint();
            }
            app.set_err(message);
            return;
        }
    };
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
    app.reset_vault_state(Some(ctx));
    app.end_waiting_runs();
    app.list_open_vault(&name, Some(ctx));
    app.ui.start = Step::Home;
    app.view = OwnerView::Vault;
    drop(passphrase);
    // The Sync choice of the Create screen.
    let synced = if unlocked.is_ok() {
        super::sync::after_create(app)
    } else {
        Ok(None)
    };
    let ready = format!(
        "Your vault is ready. Add your first credential, then make a backup in Settings.{}",
        synced
            .as_ref()
            .ok()
            .and_then(|line| line.as_deref())
            .unwrap_or("")
    );
    let _ = app.apply(unlocked, &ready);
    if let Err(message) = synced {
        app.set_err(message);
    }
}

/// Create a missing parent folder with mode 0700. The broker does not start in a data
/// folder with a wider mode.
pub(super) fn ensure_private_folder(path: &Path) -> Result<(), String> {
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
        "Type the location of an Apassy vault file. Apassy adds it to your vaults. You unlock it on the next screen.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    if app.vault_list.registry.is_empty() {
        prefill(&mut app.owner_ui.open_path, &default_vault_path());
    }
    let name_hint = match app.owner_ui.open_path.trim() {
        "" => "From the file name".to_owned(),
        path => crate::vaults::name_from_path(Path::new(path)),
    };
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some("A file in your vaults opens as it is. A new file gets the name."),
        |s| {
            let field = s.field("File", |ui| {
                files::path_input(
                    ui,
                    &mut app.files,
                    &mut app.owner_ui.open_path,
                    "vault-open-path",
                    "/Volumes/Work/work.db",
                    files::DialogKind::OpenVault,
                )
            });
            first_field(app, &field);
            submit = enter_pressed(&field);
            let name = vaults::name_field(app, s, "vault-open-name", &name_hint);
            submit |= enter_pressed(&name);
        },
    );
    if kit::wide_button(ui, "Open", Style::Prominent).clicked() || submit {
        let ctx = ui.ctx().clone();
        let typed = app.owner_ui.open_path.clone();
        app.open_vault_file(&typed, Some(&ctx));
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
    let (name_hint, dest_hint) = match app.new_vault_target(
        &app.owner_ui.restore_dest,
        Some(&restore_fallback_name(app)),
    ) {
        Ok((name, path)) => (name, path.display().to_string()),
        Err(_) => (restore_fallback_name(app), String::new()),
    };
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some(
            "The passphrase is the one of the backup. The restored vault is a new vault in your list. Leave the file empty for the default folder. Touch ID unlock stays off for the restored file.",
        ),
        |s| {
            let source = s.field("Backup file", |ui| {
                files::path_input(
                    ui,
                    &mut app.files,
                    &mut app.owner_ui.restore_source,
                    "vault-restore-source",
                    "/Volumes/Backup/apassy.backup",
                    files::DialogKind::OpenBackup,
                )
            });
            first_field(app, &source);
            vaults::name_field(app, s, "vault-restore-name", &name_hint);
            s.field("New vault file", |ui| {
                files::path_input(
                    ui,
                    &mut app.files,
                    &mut app.owner_ui.restore_dest,
                    "vault-restore-dest",
                    &dest_hint,
                    files::DialogKind::SaveVault,
                )
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

/// The name of a restored vault when the owner types none: from the typed file name,
/// else "Restored".
fn restore_fallback_name(app: &DesktopApp) -> String {
    match app.owner_ui.restore_dest.trim() {
        "" => "Restored".to_owned(),
        dest => crate::vaults::name_from_path(Path::new(dest)),
    }
}

/// Restore needs the typed passphrase. Touch ID never supplies it (A2). The restored
/// file is a new vault in the list (ADR 0013). A vault that was open and unlocked ends
/// its waiting runs, as at a switch.
pub(super) fn restore_now(app: &mut DesktopApp, ctx: &egui::Context) {
    let source = PathBuf::from(app.owner_ui.restore_source.trim());
    let fallback = restore_fallback_name(app);
    let (name, dest) = match app.new_vault_target(&app.owner_ui.restore_dest, Some(&fallback)) {
        Ok(target) => target,
        Err(message) => {
            app.set_err(message);
            return;
        }
    };
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
        app.reset_vault_state(Some(ctx));
        app.end_waiting_runs();
        app.list_open_vault(&name, Some(ctx));
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
    let subtitle = match app.current_vault_name() {
        Some(name) => format!("Type the passphrase of “{name}” to unlock it."),
        None => "Type your passphrase to unlock the vault.".to_owned(),
    };
    title(ui, "Apassy is locked", &subtitle);
    vaults::start_notices(app, ui);
    super::sync::unlock_notices(app, ui);
    vaults::unlock_picker(app, ui);
    draw_unlock_card(app, ui);
    ui.add_space(14.0);
    ui.vertical_centered(|ui| {
        ui.add(
            Label::new(kit::text(file, Font::Footnote).color(kit::SECONDARY))
                .truncate()
                .halign(Align::Center),
        );
        ui.horizontal(|ui| {
            // Center the three links.
            let width = 300.0;
            ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
            if kit::small_button(ui, "New vault…", Style::Link).clicked() {
                go(app, Step::Create);
            }
            if kit::small_button(ui, "Open vault file…", Style::Link).clicked() {
                go(app, Step::Open);
            }
            if kit::small_button(ui, "Restore…", Style::Link).clicked() {
                go(app, Step::Restore);
            }
        });
    });
    super::sync::start_link(app, ui);
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
        // Check Return before restoring focus. A single-line TextEdit surrenders
        // focus on Return; requesting it again would hide that submit event.
        submit = enter_pressed(&field);
        if !submit && ctx.memory(|memory| memory.focused().is_none()) && app.owner.check.is_none() {
            field.request_focus();
        }
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
    // Sync before the owner sees the list (ADR 0014). A sync problem does not stop the
    // unlock.
    let loaded = if result.is_ok() {
        app.view = OwnerView::Vault;
        app.sync_after_unlock()
    } else {
        None
    };
    let ok = match loaded {
        Some(line) => format!("The vault is unlocked. {line}"),
        None => "The vault is unlocked.".to_owned(),
    };
    let _ = app.apply(result, &ok);
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
