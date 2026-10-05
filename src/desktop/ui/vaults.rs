//! Several vaults, one open at a time (ADR 0013): the vault list in the app, the
//! switch, the switcher at the top of the sidebar, the vault picker of the start
//! screens, and Settings > Vaults.
//!
//! A switch locks the open vault first. Each run that waits in it ends with
//! [`ENDED_BY_SWITCH`]. Then every piece of state of that vault goes: typed secrets,
//! forms, the selection, revealed values, the owner check, a Touch ID unlock that is
//! still running, inbox marks, and the learning view. The new file opens locked, so
//! the unlock screen shows.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Align, Label};

use super::kit::{self, Font, Icon, Style, Tone};
use super::start::Step;
use super::{Sheet, close_sheet};
use crate::desktop::owner_store::ENDED_BY_SWITCH;
use crate::desktop::{DesktopApp, ItemDraft, OwnerView};
use crate::vaults::{self, LEGACY_VAULT_NAME, Registry, VaultEntry};

/// The vault list in the app.
pub(crate) struct VaultListState {
    /// The data directory: the list file and the default folder of new vaults.
    pub(crate) data_dir: PathBuf,
    /// Write each change to `<data dir>/vaults.json`. The window turns it on. Tests
    /// and `DesktopApp::new` keep the list in memory.
    pub(crate) persist: bool,
    pub(crate) registry: Registry,
    /// The entry of the open vault file.
    pub(crate) current: Option<String>,
    /// A listed vault whose file is missing. The start screen and a sheet offer to
    /// remove it from the list.
    pub(crate) missing: Option<String>,
    /// A note about the list, for example after a damaged list. It stays until the
    /// owner closes it.
    pub(crate) note: Option<String>,
    /// The name field of Create, Open, Restore, and Rename.
    pub(crate) name_input: String,
}

impl Default for VaultListState {
    fn default() -> Self {
        Self {
            data_dir: crate::paths::data_dir(),
            persist: false,
            registry: Registry::new(),
            current: None,
            missing: None,
            note: None,
            name_input: String::new(),
        }
    }
}

/// A sheet of the vault list. [`Sheet::Vault`] holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VaultSheet {
    Rename {
        id: String,
    },
    Remove {
        id: String,
    },
    /// The file of a listed vault is missing.
    Missing {
        id: String,
    },
    /// Sync: a folder, a new passphrase, off, or the replacement of a damaged copy
    /// (ADR 0014).
    Sync(super::sync::SyncSheet),
}

/// Text for a listed vault whose file is missing.
fn missing_text(entry: &VaultEntry) -> String {
    format!(
        "Apassy cannot find the file of “{}” at {}. Move the file back, or remove the vault from the list. Apassy does not delete a file.",
        entry.name,
        entry.path.display()
    )
}

impl DesktopApp {
    /// Read the vault list of `data_dir`. A damaged list moves aside and a new one
    /// takes its place; the note says so. It never blocks the start.
    pub(crate) fn load_vault_list(&mut self, data_dir: PathBuf, persist: bool) {
        let mut loaded = Registry::load(&data_dir);
        // A rebuilt list lost the sync setting of each vault. Link it again where the
        // state file proves the vault (ADR 0014).
        if let Some(note) = loaded.note.take() {
            let line = super::sync::relink_states(&data_dir, &mut loaded.registry);
            if line.is_some() && persist {
                let _ = loaded.registry.save(&data_dir);
            }
            loaded.note = Some(match line {
                Some(line) => format!("{note} {line}"),
                None => note,
            });
        }
        // The window uses the synced folders of the owner. A unit test never does: it
        // sets temporary folders.
        if persist && !cfg!(test) {
            self.sync_detect_folders();
        }
        self.vault_list = VaultListState {
            data_dir,
            persist,
            registry: loaded.registry,
            note: loaded.note.clone(),
            ..VaultListState::default()
        };
        if let Some(note) = loaded.note {
            self.set_note(note);
        }
    }

    /// Open the vault that the owner used last, locked. The window then starts on the
    /// unlock screen. A missing file shows on the start screen.
    pub(crate) fn open_last_vault(&mut self, ctx: Option<&egui::Context>) {
        let Some(entry) = self.vault_list.registry.last_used().cloned() else {
            return;
        };
        if !entry.path.is_file() {
            self.vault_list.missing = Some(entry.id);
            return;
        }
        match self.owner_ui.session.open_file(&entry.path) {
            Ok(()) => self.vault_opened(&entry.id, ctx),
            Err(err) => self.set_err(format!(
                "Apassy cannot open “{}”. {}",
                entry.name, err.message
            )),
        }
    }

    /// The list entry of the open vault file.
    pub(crate) fn current_vault(&self) -> Option<&VaultEntry> {
        if !self.owner_ui.session.has_file() {
            return None;
        }
        let id = self.vault_list.current.as_deref()?;
        self.vault_list.registry.get(id)
    }

    /// The name of the open vault, or the name of its file.
    pub(crate) fn current_vault_name(&self) -> Option<String> {
        self.current_vault()
            .map(|entry| entry.name.clone())
            .or_else(|| self.owner_ui.session.location().map(vaults::name_from_path))
    }

    /// Switch to the listed vault `id` (ADR 0013). The open vault locks, and its runs
    /// that wait end. The chosen file opens locked. A missing file changes nothing.
    pub(crate) fn switch_vault(&mut self, id: &str, ctx: Option<&egui::Context>) {
        let Some(entry) = self.vault_list.registry.get(id).cloned() else {
            self.set_err("This vault is not in the list any more.");
            return;
        };
        if self.vault_list.current.as_deref() == Some(id) && self.owner_ui.session.has_file() {
            self.ui.start = Step::Home;
            return;
        }
        if !entry.path.is_file() {
            self.vault_list.missing = Some(entry.id.clone());
            if !self.owner_ui.session.is_locked() {
                self.ui.sheet = Some(Sheet::Vault(VaultSheet::Missing {
                    id: entry.id.clone(),
                }));
            }
            self.set_err(missing_text(&entry));
            return;
        }
        self.leave_vault(ctx);
        match self.owner_ui.session.open_file(&entry.path) {
            Ok(()) => {
                self.vault_opened(&entry.id, ctx);
                self.set_ok(format!("“{}” is open. Unlock it.", entry.name));
            }
            Err(err) => self.set_err(format!(
                "Apassy cannot open “{}”. {}",
                entry.name, err.message
            )),
        }
    }

    /// Lock the open vault to leave it (ADR 0013). Each run that waits ends with
    /// [`ENDED_BY_SWITCH`], and each piece of state of the vault goes.
    pub(crate) fn leave_vault(&mut self, ctx: Option<&egui::Context>) {
        let approvals = self.approvals();
        let _ = self
            .owner_ui
            .session
            .lock_ending_runs(approvals.as_deref(), ENDED_BY_SWITCH);
        self.end_waiting_runs();
        self.reset_vault_state(ctx);
    }

    /// Leave the open vault for the Create or the Open screen. "Back" there shows the
    /// unlock screen of the vault that the owner left.
    pub(crate) fn leave_vault_for(&mut self, step: Step, ctx: Option<&egui::Context>) {
        self.leave_vault(ctx);
        self.ui.start = step;
    }

    /// Forget each piece of state of the vault that was open: typed secrets and their
    /// undo history, forms, the selection, the navigation, the owner check, a Touch ID
    /// unlock or change that still runs, inbox marks, the learning view, and a parsed
    /// 1Password export. A training stops: it reads and writes the vault that was open.
    pub(crate) fn reset_vault_state(&mut self, ctx: Option<&egui::Context>) {
        self.ui.discard_item_changes = false;
        self.ui.discard_item_kind_change = false;
        self.files.forget();
        self.erase_typed_secrets(ctx);
        self.view = OwnerView::Vault;
        self.selected_item_id = None;
        self.search.clear();
        self.add_form = ItemDraft::default();
        self.edit_form = ItemDraft::default();
        self.pending_delete = false;

        let ui = &mut self.ui;
        ui.sheet = None;
        ui.close_after_check = None;
        ui.start = Step::Home;
        ui.activity_tab = Default::default();
        ui.credential_filter = Default::default();
        ui.focus_search = false;
        ui.grant = Default::default();

        let fields = &mut self.owner_ui;
        fields.edit_revision = 0;
        fields.connector_url.clear();
        fields.new_agent_name.clear();
        fields.fresh_token = None;
        fields.token_lifetime_input.clear();
        fields.selected_agent = None;
        fields.env_name_input.clear();
        fields.env_field_input.clear();
        fields.env_placeholder_input = false;
        fields.env_hosts_input.clear();
        fields.declaration_form = Default::default();
        fields.exec_dir_inputs.clear();
        fields.rule_inputs.clear();
        fields.signaled_runs.clear();
        fields.backup_path.clear();
        fields.restore_source.clear();
        fields.restore_dest.clear();
        fields.create_path.clear();

        // A Touch ID key of the old file must not reach the new one.
        self.owner.unlock.unlocking = None;
        self.owner.unlock.changing = None;
        self.owner.acknowledged.clear();
        if let Some(center) = &self.owner.notifications {
            center.forget_activity();
        }
        self.learning.stop_training();
        self.learning = Default::default();
        // A parsed 1Password export belongs to the import into the vault that was open.
        self.import.forget();
        self.vault_list.name_input.clear();
        // No sync into the synced file of the vault that was open.
        self.sync_forget_open_vault(ctx);
    }

    /// The open file is the vault `id`. It becomes the last used vault, and the Touch
    /// ID setting of its file loads.
    fn vault_opened(&mut self, id: &str, ctx: Option<&egui::Context>) {
        let list = &mut self.vault_list;
        let _ = list.registry.mark_opened(id, vaults::now());
        list.current = Some(id.to_owned());
        if list.missing.as_deref() == Some(id) {
            list.missing = None;
        }
        if let Some(path) = self.owner_ui.session.location() {
            self.owner_ui.open_path = path.display().to_string();
        }
        self.save_vault_list();
        self.refresh_unlock_setting(ctx);
        self.sync_track_open_vault();
    }

    /// Add the open vault file to the list as `name`, or find it there, and make it the
    /// open vault.
    pub(crate) fn list_open_vault(&mut self, name: &str, ctx: Option<&egui::Context>) {
        let Some(path) = self.owner_ui.session.vault_path() else {
            return;
        };
        let registry = &mut self.vault_list.registry;
        let id = match registry.find_path(&path) {
            Some(entry) => entry.id.clone(),
            None => match registry.add(name, &path, vaults::now()) {
                Ok(id) => id,
                Err(err) => {
                    self.vault_list.current = None;
                    self.set_err(format!(
                        "The vault is open, but it is not in the vault list: {err}"
                    ));
                    self.refresh_unlock_setting(ctx);
                    return;
                }
            },
        };
        self.vault_opened(&id, ctx);
    }

    /// Write the list when the window keeps it. A failure shows as an error.
    pub(crate) fn save_vault_list(&mut self) -> bool {
        if !self.vault_list.persist {
            return true;
        }
        match self.vault_list.registry.save(&self.vault_list.data_dir) {
            Ok(()) => true,
            Err(err) => {
                self.set_err(format!("Apassy could not save the vault list: {err}."));
                false
            }
        }
    }

    /// The name and the file of a new vault from the Create or the Restore fields. An
    /// empty file field gives `<data dir>/vaults/<name>.db`. An empty name takes
    /// `fallback`, made unique; without a fallback it is an error.
    pub(crate) fn new_vault_target(
        &self,
        typed_path: &str,
        fallback: Option<&str>,
    ) -> Result<(String, PathBuf), String> {
        let list = &self.vault_list;
        let name = match (list.name_input.trim(), fallback) {
            ("", Some(fallback)) => list.registry.free_name(fallback),
            ("", None) => return Err("Type a name for the vault.".to_owned()),
            (typed, _) => typed.to_owned(),
        };
        let path = match typed_path.trim() {
            "" => list.registry.new_vault_path(&list.data_dir, &name),
            typed => std::path::absolute(typed)
                .map_err(|_| "Type the absolute path of the vault file.".to_owned())?,
        };
        let name = list
            .registry
            .check_new(&name, &path)
            .map_err(|err| err.to_string())?;
        Ok((name, path))
    }

    /// The name of the first vault when the owner types none.
    pub(crate) fn create_fallback_name(&self) -> Option<&'static str> {
        self.vault_list
            .registry
            .is_empty()
            .then_some(LEGACY_VAULT_NAME)
    }

    /// Open the vault file at `typed` (ADR 0013). A listed file is a switch. A new
    /// file comes into the list with the typed name, or a name from its file name.
    pub(crate) fn open_vault_file(&mut self, typed: &str, ctx: Option<&egui::Context>) {
        let typed = typed.trim();
        if typed.is_empty() {
            self.set_err("Type the path of the vault file.");
            return;
        }
        let path = std::path::absolute(typed).unwrap_or_else(|_| PathBuf::from(typed));
        if let Some(id) = self
            .vault_list
            .registry
            .find_path(&path)
            .map(|entry| entry.id.clone())
        {
            self.switch_vault(&id, ctx);
            return;
        }
        let list = &self.vault_list;
        let name = match list.name_input.trim() {
            "" => list.registry.free_name(&vaults::name_from_path(&path)),
            typed => typed.to_owned(),
        };
        let name = match list.registry.check_new(&name, &path) {
            Ok(name) => name,
            Err(err) => {
                self.set_err(err.to_string());
                return;
            }
        };
        let result = self.owner_ui.session.open_file(&path);
        if self
            .apply(result, "The vault file is open. Unlock it.")
            .is_none()
        {
            return;
        }
        self.reset_vault_state(ctx);
        self.end_waiting_runs();
        self.list_open_vault(&name, ctx);
    }

    /// Rename the vault `id` with the text of the name field.
    pub(crate) fn rename_vault(&mut self, id: &str) -> bool {
        let name = self.vault_list.name_input.clone();
        match self.vault_list.registry.rename(id, &name) {
            Ok(()) => {
                if self.save_vault_list() {
                    self.set_ok(format!("The vault is now “{}”.", name.trim()));
                }
                self.vault_list.name_input.clear();
                true
            }
            Err(err) => {
                self.set_err(err.to_string());
                false
            }
        }
    }

    /// Take the vault `id` out of the list. The file stays. The open vault stays in
    /// the list.
    pub(crate) fn remove_vault(&mut self, id: &str) -> bool {
        if self.vault_list.current.as_deref() == Some(id) && self.owner_ui.session.has_file() {
            self.set_err(
                "The open vault stays in the list. Open another vault first, then remove this one.",
            );
            return false;
        }
        // Sync of the vault stops; its synced file stays (ADR 0014).
        let synced = self.sync_on_remove(id).unwrap_or_default();
        match self.vault_list.registry.remove(id) {
            Ok(entry) => {
                if self.vault_list.missing.as_deref() == Some(id) {
                    self.vault_list.missing = None;
                }
                if self.save_vault_list() {
                    self.set_ok(format!(
                        "“{}” is not in the list now. The file stays at {}.{synced}",
                        entry.name,
                        entry.path.display()
                    ));
                }
                true
            }
            Err(err) => {
                self.set_err(err.to_string());
                false
            }
        }
    }
}

/// Is the file of `entry` there?
fn file_present(entry: &VaultEntry) -> bool {
    entry.path.is_file()
}

/// The path of `path` for a subtitle.
fn shown_path(path: &Path) -> String {
    path.display().to_string()
}

// ---- Drawing. ----

enum Pick {
    Switch(String),
    Leave(Step),
}

/// The switcher at the top of the sidebar: the name of the open vault. Its menu has
/// the other vaults, "New vault…", and "Open vault file…".
pub(super) fn sidebar_switcher(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let current = app.vault_list.current.clone();
    let name = app
        .current_vault_name()
        .unwrap_or_else(|| "Vault".to_owned());
    let mut pick = None;
    let width = ui.available_width();
    kit::menu("vault-switcher", kit::medium(name, Font::Body), width)
        .show_ui(ui, |ui| {
            let others: Vec<(String, String)> = app
                .vault_list
                .registry
                .entries()
                .iter()
                .filter(|entry| Some(&entry.id) != current.as_ref())
                .map(|entry| (entry.id.clone(), entry.name.clone()))
                .collect();
            for (id, name) in &others {
                if ui.selectable_label(false, name).clicked() {
                    pick = Some(Pick::Switch(id.clone()));
                }
            }
            if !others.is_empty() {
                ui.separator();
            }
            if ui.selectable_label(false, "New vault…").clicked() {
                pick = Some(Pick::Leave(Step::Create));
            }
            if ui.selectable_label(false, "Open vault file…").clicked() {
                pick = Some(Pick::Leave(Step::Open));
            }
        })
        .response
        .on_hover_text("Switch vaults. The open vault locks first.");
    ui.add_space(8.0);
    let ctx = ui.ctx().clone();
    match pick {
        Some(Pick::Switch(id)) => app.switch_vault(&id, Some(&ctx)),
        Some(Pick::Leave(step)) => app.leave_vault_for(step, Some(&ctx)),
        None => {}
    }
}

/// The vault picker of the unlock screen, when the list has another vault.
pub(super) fn unlock_picker(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if app.vault_list.registry.entries().len() < 2 {
        return;
    }
    let current = app.vault_list.current.clone();
    let name = app
        .current_vault_name()
        .unwrap_or_else(|| "Vault".to_owned());
    let mut pick = None;
    ui.vertical_centered(|ui| {
        kit::menu("unlock-vault", kit::medium(name, Font::Body), 240.0)
            .show_ui(ui, |ui| {
                for entry in app.vault_list.registry.entries() {
                    let selected = Some(&entry.id) == current.as_ref();
                    if ui.selectable_label(selected, &entry.name).clicked() && !selected {
                        pick = Some(entry.id.clone());
                    }
                }
            })
            .response
            .on_hover_text("Unlock another vault");
    });
    ui.add_space(12.0);
    if let Some(id) = pick {
        let ctx = ui.ctx().clone();
        app.switch_vault(&id, Some(&ctx));
    }
}

/// The note about the list and the missing vault, on a start screen.
pub(super) fn start_notices(app: &mut DesktopApp, ui: &mut egui::Ui) {
    list_note(app, ui);
    let Some(entry) = app
        .vault_list
        .missing
        .as_deref()
        .and_then(|id| app.vault_list.registry.get(id))
        .cloned()
    else {
        return;
    };
    let mut remove = false;
    let mut again = false;
    kit::notice(
        ui,
        Tone::Warning,
        &format!("The file of “{}” is missing", entry.name),
        Some(&missing_text(&entry)),
        |ui| {
            ui.horizontal(|ui| {
                remove = kit::small_button(ui, "Remove from list", Style::Bordered).clicked();
                again = kit::small_button(ui, "Try again", Style::Link).clicked();
            });
        },
    );
    let ctx = ui.ctx().clone();
    if remove {
        app.remove_vault(&entry.id);
    } else if again {
        app.switch_vault(&entry.id, Some(&ctx));
    }
}

/// The note about a damaged list. "Close" hides it.
fn list_note(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(note) = app.vault_list.note.clone() else {
        return;
    };
    let mut close = false;
    kit::notice(ui, Tone::Warning, "The vault list", Some(&note), |ui| {
        close = kit::small_button(ui, "Close", Style::Link).clicked();
    });
    if close {
        app.vault_list.note = None;
    }
}

/// The listed vaults on the welcome screen, when no file is open.
pub(super) fn welcome_list(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if app.vault_list.registry.is_empty() {
        return;
    }
    let mut pick = None;
    kit::section(ui, Some("Your vaults"), None, |s| {
        for entry in app.vault_list.registry.entries() {
            let present = file_present(entry);
            let subtitle = if present {
                shown_path(&entry.path)
            } else {
                format!("The file is missing: {}", shown_path(&entry.path))
            };
            let detail = (!present)
                .then(|| kit::text("Missing", Font::Footnote).color(Tone::Warning.text()));
            let gray = egui::Color32::from_rgb(99, 99, 104);
            if s.nav(
                Some((Icon::Lock, gray)),
                &entry.name,
                Some(&subtitle),
                detail,
            )
            .clicked()
            {
                pick = Some(entry.id.clone());
            }
        }
    });
    if let Some(id) = pick {
        let ctx = ui.ctx().clone();
        app.switch_vault(&id, Some(&ctx));
    }
}

/// The name field of Create, Open, and Restore.
pub(super) fn name_field(
    app: &mut DesktopApp,
    s: &mut kit::Section<'_>,
    salt: &str,
    placeholder: &str,
) -> egui::Response {
    s.field("Name", |ui| {
        kit::text_input(ui, &mut app.vault_list.name_input, salt, placeholder)
    })
}

/// Settings > Vaults: each vault with its file, "Rename…", and "Remove from list…".
pub(super) fn settings_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    list_note(app, ui);
    let current = app.vault_list.current.clone();
    let mut open = None;
    let mut sheet = None;
    let mut leave = None;
    kit::section(
        ui,
        Some("Vaults"),
        Some(
            "Each vault is its own encrypted file with its own passphrase, agents, grants, and rules. One vault is open at a time. A switch locks the open vault and ends the runs that wait for you. \"Remove from list\" never deletes a file.",
        ),
        |s| {
            for entry in app.vault_list.registry.entries() {
                let is_open = Some(&entry.id) == current.as_ref();
                let present = file_present(entry);
                s.row(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(kit::medium(&entry.name, Font::Body).color(kit::LABEL));
                        if is_open {
                            kit::tag(ui, "Open", Tone::Good);
                        } else if !present {
                            kit::tag(ui, "File missing", Tone::Warning);
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if !is_open
                                && kit::small_button(ui, "Remove from list…", Style::Link).clicked()
                            {
                                sheet = Some(VaultSheet::Remove {
                                    id: entry.id.clone(),
                                });
                            }
                            if kit::small_button(ui, "Rename…", Style::Link).clicked() {
                                sheet = Some(VaultSheet::Rename {
                                    id: entry.id.clone(),
                                });
                            }
                            if !is_open
                                && present
                                && kit::small_button(ui, "Open", Style::Bordered).clicked()
                            {
                                open = Some(entry.id.clone());
                            }
                        });
                    });
                    ui.add(
                        Label::new(
                            kit::text(shown_path(&entry.path), Font::MonoSmall)
                                .color(kit::SECONDARY),
                        )
                        .truncate(),
                    );
                });
            }
            if s.clickable_row("New vault…", |ui| {
                ui.label(kit::text("New vault…", Font::Body).color(kit::ACCENT_TEXT));
            })
            .clicked()
            {
                leave = Some(Step::Create);
            }
            if s.clickable_row("Open vault file…", |ui| {
                ui.label(kit::text("Open vault file…", Font::Body).color(kit::ACCENT_TEXT));
            })
            .clicked()
            {
                leave = Some(Step::Open);
            }
        },
    );
    let ctx = ui.ctx().clone();
    if let Some(id) = open {
        app.switch_vault(&id, Some(&ctx));
    } else if let Some(step) = leave {
        app.leave_vault_for(step, Some(&ctx));
    } else if let Some(sheet) = sheet {
        if let VaultSheet::Rename { id } = &sheet {
            app.vault_list.name_input = app
                .vault_list
                .registry
                .get(id)
                .map(|entry| entry.name.clone())
                .unwrap_or_default();
        }
        app.ui.sheet = Some(Sheet::Vault(sheet));
    }
    super::sync::settings_section(app, ui);
}

/// A sheet of the vault list. Returns true when the owner pressed Escape.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &VaultSheet) -> bool {
    let id = match sheet {
        VaultSheet::Rename { id } | VaultSheet::Remove { id } | VaultSheet::Missing { id } => id,
        VaultSheet::Sync(sheet) => return super::sync::sheet(app, ctx, sheet),
    };
    let Some(entry) = app.vault_list.registry.get(id).cloned() else {
        close_sheet(app, ctx);
        return false;
    };
    match sheet {
        VaultSheet::Rename { .. } => rename_sheet(app, ctx, &entry),
        VaultSheet::Remove { .. } => remove_sheet(app, ctx, &entry, false),
        VaultSheet::Missing { .. } => remove_sheet(app, ctx, &entry, true),
        VaultSheet::Sync(_) => false,
    }
}

fn rename_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "rename-vault", 460.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Rename “{}”", entry.name),
            Some("The name shows in the sidebar and on the unlock screen. The file does not move."),
        );
        kit::section(
            ui,
            None,
            Some("1 to 40 characters. Each vault has its own name."),
            |s| {
                let field = s.field("Name", |ui| {
                    kit::text_input(ui, &mut app.vault_list.name_input, "vault-rename", "")
                });
                save = field.lost_focus() && ctx.input(|input| input.key_pressed(egui::Key::Enter));
            },
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                save |= kit::button(ui, "Save", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    save |= super::save_pressed(app, ctx);
    if save && app.rename_vault(&entry.id) {
        app.ui.sheet = None;
    }
    if cancel || response.escape {
        app.vault_list.name_input.clear();
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

fn remove_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    missing: bool,
) -> bool {
    let mut remove = false;
    let mut cancel = false;
    let (title, text) = if missing {
        (
            format!("The file of “{}” is missing", entry.name),
            missing_text(entry),
        )
    } else {
        (
            format!("Remove “{}” from the list?", entry.name),
            format!(
                "The file stays at {}. Apassy does not delete it. You can open it again with “Open vault file…”. A vault file outside the Apassy data folder is then not closed to agents that start later: move it into a safe place, or delete it yourself.{}",
                entry.path.display(),
                if entry.sync_state().is_some() {
                    " Sync of this vault stops. Its synced copy stays in its folder."
                } else {
                    ""
                }
            ),
        )
    };
    let response = kit::sheet(ctx, "remove-vault", 480.0, |ui| {
        kit::sheet_title(ui, &title, Some(&text));
        kit::sheet_buttons(
            ui,
            |ui| {
                remove = kit::button(ui, "Remove from list", Style::Destructive).clicked();
            },
            |ui| {
                let label = if missing { "Close" } else { "Cancel" };
                cancel = kit::button(ui, label, Style::Bordered).clicked();
            },
        );
    });
    if remove && app.remove_vault(&entry.id) {
        app.ui.sheet = None;
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}
