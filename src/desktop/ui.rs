//! Drawing code for the desktop shell. Keep state changes in [`super::DesktopApp`].
//!
//! The look follows SwiftUI on macOS: a sidebar, large page titles, grouped form
//! sections, sheets for changes, and a toast for results. [`kit`] has the tokens and
//! the controls. Each screen shows the common path first and folds the rest away.

#[cfg(feature = "vault")]
mod activity;
#[cfg(feature = "vault")]
mod agent_setup;
#[cfg(feature = "vault")]
mod agents;
#[cfg(feature = "vault")]
mod browser_settings;
#[cfg(all(test, feature = "vault"))]
mod browser_tests;
#[cfg(all(test, feature = "vault"))]
mod cli_tests;
#[cfg(feature = "vault")]
mod cli_tools;
#[cfg(feature = "vault")]
mod companion;
#[cfg(all(test, feature = "vault"))]
mod companion_tests;
#[cfg(not(feature = "vault"))]
mod demo;
#[cfg(feature = "vault")]
pub(crate) mod files;
mod focus;
/// The steps from a new vault to the first agent request.
#[cfg(feature = "vault")]
mod get_started;
#[cfg(feature = "vault")]
pub(crate) mod import;
#[cfg(feature = "vault")]
mod items;
#[cfg(all(test, feature = "vault"))]
mod keyboard_tests;
pub(crate) mod kit;
#[cfg(feature = "vault")]
mod owner_check_view;
#[cfg(all(test, feature = "vault"))]
mod owner_tests;
#[cfg(feature = "vault")]
mod settings;
mod shell;
#[cfg(feature = "vault")]
mod start;
/// Sync of the vaults through a folder (ADR 0014).
#[cfg(feature = "vault")]
pub(crate) mod sync;
#[cfg(all(test, feature = "vault"))]
mod sync_tests;
#[cfg(feature = "vault")]
mod timeline;
#[cfg(feature = "vault")]
mod updates;
#[cfg(all(test, feature = "vault"))]
mod vault_tests;
/// Several vaults, one open at a time (ADR 0013).
#[cfg(feature = "vault")]
pub(crate) mod vaults;

use std::collections::BTreeSet;

use eframe::egui;
#[cfg(feature = "vault")]
use eframe::egui::TextEdit;

use crate::desktop::{DesktopApp, StatusKind};

pub(crate) use kit::WINDOW as WINDOW_COLOR;
#[cfg(feature = "vault")]
pub(crate) use settings::{SettingsTab, open as open_settings};

/// Byte capacity of a passphrase field. A field holds at most `MAX_PASSPHRASE_BYTES`
/// characters, and a character has at most 4 bytes, so typing never moves the text
/// (key-memory review F4).
#[cfg(feature = "vault")]
pub(crate) const PASSPHRASE_CAPACITY: usize = 4 * crate::vault::MAX_PASSPHRASE_BYTES;
/// Byte capacity of an item secret field, with the same rule. The vault takes at most
/// 65536 bytes in a field value (`MAX_FIELD_VALUE_BYTES` in `src/vault/types.rs`).
#[cfg(feature = "vault")]
const SECRET_VALUE_CAPACITY: usize = 4 * 65_536;
/// The passphrase field of the start screens (create, unlock, restore).
#[cfg(feature = "vault")]
const VAULT_PASSPHRASE_FIELD: &str = "vault-passphrase";
/// The second passphrase field when the owner creates a vault.
#[cfg(feature = "vault")]
const VAULT_REPEAT_FIELD: &str = "vault-passphrase-repeat";
/// The passphrase field of the owner check.
#[cfg(feature = "vault")]
pub(crate) const OWNER_CHECK_FIELD: &str = "owner-check-passphrase";
/// The passphrase field of the Touch ID setup.
#[cfg(feature = "vault")]
pub(crate) const TOUCH_ID_SETUP_FIELD: &str = "touch-id-setup-passphrase";
/// The fields of the passphrase change sheet.
#[cfg(feature = "vault")]
const CHANGE_FIELDS: [&str; 3] = ["passphrase-current", "passphrase-new", "passphrase-repeat"];
/// Every passphrase field.
#[cfg(feature = "vault")]
const PASSPHRASE_FIELDS: [&str; 7] = [
    VAULT_PASSPHRASE_FIELD,
    VAULT_REPEAT_FIELD,
    CHANGE_FIELDS[0],
    CHANGE_FIELDS[1],
    CHANGE_FIELDS[2],
    OWNER_CHECK_FIELD,
    TOUCH_ID_SETUP_FIELD,
];
/// The item forms that have secret fields.
#[cfg(feature = "vault")]
const SECRET_FORMS: [&str; 2] = ["add", "edit"];
/// The secret fields of an item form. They match [`super::owner_store::SecretForm::fields_mut`].
#[cfg(feature = "vault")]
const SECRET_FORM_FIELDS: [&str; 5] = ["token", "password", "private", "phrase", "custom"];

/// A global widget ID for a secret field, so the app can clear its undo history from
/// any place.
#[cfg(feature = "vault")]
fn secret_field_id(salt: &str) -> egui::Id {
    egui::Id::new(("apassy-secret-field", salt))
}

/// Forget the undo history of one secret field (key-memory review F1). Without this,
/// Cmd+Z in the field brings back the text after the app took it.
#[cfg(feature = "vault")]
pub(crate) fn forget_secret_field(ctx: &egui::Context, salt: &str) {
    let id = secret_field_id(salt);
    if let Some(mut state) = TextEdit::load_state(ctx, id) {
        state.clear_undoer();
        TextEdit::store_state(ctx, id, state);
    }
}

/// Forget the undo history of each field in an item secret form, with the hidden
/// custom details.
#[cfg(feature = "vault")]
fn forget_secret_form(ctx: &egui::Context, form: &str) {
    for field in SECRET_FORM_FIELDS {
        forget_secret_field(ctx, &format!("{form}-{field}"));
    }
    for index in 0..super::owner_store::MAX_DETAILS {
        forget_secret_field(ctx, &format!("{form}-detail-{index}"));
    }
}

/// Forget the undo history of every passphrase and secret field. The app calls this on
/// lock.
#[cfg(feature = "vault")]
pub(crate) fn forget_all_secret_fields(ctx: &egui::Context) {
    for salt in PASSPHRASE_FIELDS {
        forget_secret_field(ctx, salt);
    }
    for form in SECRET_FORMS {
        forget_secret_form(ctx, form);
    }
}

/// Give `value` its full capacity before typing starts (key-memory review F4). A
/// field with text moves once. The old buffer is erased.
#[cfg(feature = "vault")]
fn presize(value: &mut String, capacity: usize) {
    use zeroize::Zeroize;

    if value.capacity() >= capacity {
        return;
    }
    let mut sized = String::with_capacity(capacity);
    sized.push_str(value);
    value.zeroize();
    *value = sized;
}

/// A masked field for a passphrase or a secret. `capacity` is the byte capacity. The
/// field takes at most `capacity / 4` characters, so the text never grows past the
/// buffer (key-memory review F4). The widget ID is global ([`secret_field_id`]), so
/// the app can clear the undo history (F1).
#[cfg(feature = "vault")]
fn secure_input(
    ui: &mut egui::Ui,
    salt: &str,
    value: &mut String,
    capacity: usize,
    placeholder: &str,
) -> egui::Response {
    presize(value, capacity);
    let response = ui.add(
        TextEdit::singleline(value)
            .password(true)
            .id(secret_field_id(salt))
            .char_limit(capacity / 4)
            .hint_text(kit::text(placeholder, kit::Font::Body).color(kit::TERTIARY))
            .margin(kit::FIELD_MARGIN)
            .desired_width(f32::INFINITY),
    );
    kit::claim_first_field(&response);
    response
}

/// The vault file of Apassy 0.2. The agent profile denies this directory (isolation,
/// §1). New vaults go to `vaults/` in the same directory (ADR 0013).
#[cfg(feature = "vault")]
pub(crate) fn default_vault_path() -> std::path::PathBuf {
    crate::vaults::legacy_vault_path(&crate::paths::data_dir())
}

/// Navigation and sheet state of the drawing code. It holds no secret text: typed
/// secrets live in [`super::owner_store::OwnerUiState`], which erases them.
#[derive(Default)]
pub(crate) struct UiState {
    /// The sheet over the window, if any.
    pub(crate) sheet: Option<Sheet>,
    /// The sheet closes when the owner check for its action ends with success. The
    /// value is the status sequence number at the time of the request.
    #[cfg(feature = "vault")]
    pub(crate) close_after_check: Option<u64>,
    /// The status message on screen and the time it first showed.
    toast_shown: Option<(u64, f64)>,
    /// The status message that the owner closed.
    toast_closed: u64,
    /// Keyboard focus across sheets and pages.
    pub(crate) focus: focus::FocusState,
    /// Open disclosure groups.
    #[cfg_attr(not(feature = "vault"), allow(dead_code))]
    expanded: BTreeSet<String>,
    /// The step of the start screens.
    #[cfg(feature = "vault")]
    pub(crate) start: start::Step,
    /// The tab of the Activity view.
    #[cfg(feature = "vault")]
    pub(crate) activity_tab: activity::Tab,
    /// The owner hid the sidebar (⌃⌘S or the title bar button). `ui.json` keeps it
    /// across restarts.
    pub(crate) sidebar_hidden: bool,
    /// The list IDs of the vaults where the owner hid the "Get started" list. `ui.json`
    /// keeps them across restarts.
    #[cfg(feature = "vault")]
    get_started_hidden: BTreeSet<String>,
    /// `ui.json`. Only the window sets it, so a test never writes the real folder.
    #[cfg(feature = "vault")]
    prefs_path: Option<std::path::PathBuf>,
    /// The tab of the Settings view.
    #[cfg(feature = "vault")]
    pub(crate) settings_tab: settings::SettingsTab,
    /// The filter of the credential list.
    #[cfg(feature = "vault")]
    pub(crate) credential_filter: items::Filter,
    /// The order of the credential list.
    #[cfg(feature = "vault")]
    pub(crate) credential_sort: items::Sort,
    /// ⌘F: the search field takes the focus in the next frame.
    #[cfg(feature = "vault")]
    pub(crate) focus_search: bool,
    /// The Name field of the add form takes the focus in the next frame, after the
    /// owner picked a kind with the keyboard.
    #[cfg(feature = "vault")]
    pub(crate) focus_form_name: bool,
    #[cfg(feature = "vault")]
    pub(crate) discard_item_changes: bool,
    #[cfg(feature = "vault")]
    pub(crate) discard_item_kind_change: bool,
    #[cfg(feature = "vault")]
    pub(crate) setup_host: usize,
    #[cfg(feature = "vault")]
    agent_setup: agent_setup::SetupState,
    /// The newly adopted vault whose local agent setup is still offered.
    #[cfg(feature = "vault")]
    pub(crate) setup_vault: Option<String>,
    /// The first field of a start screen takes the focus, after a step change.
    #[cfg(feature = "vault")]
    pub(crate) focus_start_field: bool,
    /// The form of a grant for several credentials or of an access request.
    #[cfg(feature = "vault")]
    pub(crate) grant: agents::GrantForm,
}

#[cfg_attr(not(feature = "vault"), allow(dead_code))]
impl UiState {
    pub(crate) fn is_expanded(&self, key: &str) -> bool {
        self.expanded.contains(key)
    }

    pub(crate) fn set_expanded(&mut self, key: &str, open: bool) {
        if open {
            self.expanded.insert(key.to_owned());
        } else {
            self.expanded.remove(key);
        }
    }

    /// Read `ui.json` in `data_dir`, and keep its path for the next saves. A missing or
    /// broken file gives the defaults.
    #[cfg(feature = "vault")]
    pub(crate) fn load_prefs(&mut self, data_dir: std::path::PathBuf) {
        let path = crate::desktop::ui_prefs::UiPrefs::path(&data_dir);
        let prefs = crate::desktop::ui_prefs::UiPrefs::load(&path);
        self.sidebar_hidden = prefs.sidebar_hidden;
        self.get_started_hidden = prefs.get_started_hidden;
        self.prefs_path = Some(path);
    }

    /// Write `ui.json` when the window loaded it. A failed write is not an error for the
    /// owner: the setting then lasts until the quit.
    fn save_prefs(&self) {
        #[cfg(feature = "vault")]
        if let Some(path) = &self.prefs_path {
            let prefs = crate::desktop::ui_prefs::UiPrefs {
                sidebar_hidden: self.sidebar_hidden,
                get_started_hidden: self.get_started_hidden.clone(),
            };
            let _ = prefs.save(path);
        }
    }

    /// Hide or show the sidebar, and keep the choice.
    pub(crate) fn toggle_sidebar(&mut self) {
        self.sidebar_hidden = !self.sidebar_hidden;
        self.save_prefs();
    }
}

/// A sheet over the window. Item sheets act on the selected item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Sheet {
    /// Add a credential. The first step picks the kind.
    AddItem {
        kind_chosen: bool,
    },
    EditItem,
    #[cfg(feature = "vault")]
    Declaration,
    #[cfg(feature = "vault")]
    Variable,
    #[cfg(feature = "vault")]
    Connector,
    #[cfg(feature = "vault")]
    RegisterAgent,
    /// Archive the selected item.
    #[cfg(feature = "vault")]
    ArchiveItem,
    #[cfg(feature = "vault")]
    RevokeAgent {
        agent_id: u64,
        name: String,
    },
    #[cfg(feature = "vault")]
    ProcessAccess {
        agent_id: u64,
        item_id: u64,
        mode: crate::vault::ExecMode,
        any_folder: bool,
    },
    /// Give one agent access to several credentials (ADR 0012).
    #[cfg(feature = "vault")]
    GrantMany {
        agent_id: u64,
    },
    /// Decide an access request of an agent (ADR 0012).
    #[cfg(feature = "vault")]
    AccessRequest {
        request_id: u64,
    },
    /// Review one waiting run.
    #[cfg(feature = "vault")]
    Approval(u64),
    #[cfg(feature = "vault")]
    ChangePassphrase,
    #[cfg(feature = "vault")]
    Backup,
    #[cfg(feature = "vault")]
    Restore,
    /// Rename a vault, remove it from the list, or a missing vault file (ADR 0013).
    #[cfg(feature = "vault")]
    Vault(vaults::VaultSheet),
    /// Import from 1Password.
    #[cfg(feature = "vault")]
    Import,
    /// Remove every paired iPhone and make a new certificate (ADR 0020).
    #[cfg(feature = "vault")]
    ResetCompanion,
}

pub(crate) fn apply_style(ctx: &egui::Context) {
    kit::apply_theme(ctx);
}

pub(crate) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    focus::begin_frame(&mut app.ui.focus, &ctx);
    #[cfg(feature = "vault")]
    {
        app.poll_owner_flows(&ctx);
        app.poll_sync(&ctx);
        if let Some(id) = app.sync.adopted_vault.take() {
            app.ui.setup_vault = Some(id);
        }
        if app.ui.setup_vault.as_ref() != app.vault_list.current.as_ref() {
            app.ui.setup_vault = None;
        }
        close_sheet_after_check(app);
        let session = &app.owner_ui.session;
        if !session.has_file() || session.is_locked() {
            // A lock also hides a token that the owner did not dismiss.
            app.owner_ui.fresh_token = None;
            app.ui.agent_setup = Default::default();
            app.ui.sheet = None;
            app.import.forget();
            start::draw(app, ui);
        } else {
            shell::draw(app, ui);
        }
    }
    #[cfg(not(feature = "vault"))]
    shell::draw(app, ui);
    draw_toast(app, &ctx);
    #[cfg(feature = "vault")]
    owner_check_view::draw(app, &ctx);
    focus::end_frame(&mut app.ui.focus, &ctx);
}

/// Close the sheet. Typed secrets of its form and their undo history are erased.
pub(crate) fn close_sheet(app: &mut DesktopApp, ctx: &egui::Context) {
    let _ = ctx;
    #[cfg(feature = "vault")]
    {
        app.ui.discard_item_changes = false;
        app.ui.discard_item_kind_change = false;
        app.files.forget();
    }
    #[cfg(feature = "vault")]
    match app.ui.sheet.take() {
        Some(Sheet::AddItem { .. }) => {
            app.owner_ui.add_secrets.clear();
            forget_secret_form(ctx, "add");
        }
        Some(Sheet::EditItem) => {
            app.owner_ui.edit_secrets.clear();
            forget_secret_form(ctx, "edit");
        }
        Some(Sheet::ChangePassphrase) => {
            use zeroize::Zeroize;
            app.owner_ui.passphrase_current.zeroize();
            app.owner_ui.passphrase_new.zeroize();
            app.owner_ui.passphrase_repeat.zeroize();
            for field in CHANGE_FIELDS {
                forget_secret_field(ctx, field);
            }
        }
        Some(Sheet::Restore) => {
            use zeroize::Zeroize;
            app.owner_ui.passphrase.zeroize();
            forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
        }
        Some(Sheet::Import) => app.import.forget(),
        _ => {}
    }
    #[cfg(not(feature = "vault"))]
    {
        app.ui.sheet = None;
    }
}

/// ⌘S in a sheet. It does nothing while the owner check is over the sheet.
pub(crate) fn save_pressed(app: &DesktopApp, ctx: &egui::Context) -> bool {
    #[cfg(feature = "vault")]
    if app.owner.check.is_some() {
        return false;
    }
    let _ = app;
    kit::save_shortcut(ctx)
}

/// Ask for the owner check from a sheet. The sheet closes when the action succeeds, and
/// stays open after a cancel or an error.
#[cfg(feature = "vault")]
pub(crate) fn ask_owner_from_sheet(
    app: &mut DesktopApp,
    request: crate::desktop::owner_check::OwnerRequest,
    ctx: &egui::Context,
) {
    app.ui.close_after_check = Some(app.status_seq);
    app.ask_owner(request, Some(ctx));
}

#[cfg(feature = "vault")]
fn close_sheet_after_check(app: &mut DesktopApp) {
    let Some(seq) = app.ui.close_after_check else {
        return;
    };
    if app.owner.check.is_some() {
        return;
    }
    app.ui.close_after_check = None;
    if app.status_seq > seq && app.status_kind == StatusKind::Ok {
        app.ui.sheet = None;
    }
}

/// How long a result stays on screen. An error stays until the owner closes it.
const TOAST_SECONDS: f64 = 4.5;
const TOAST_FADE: f64 = 0.35;

fn draw_toast(app: &mut DesktopApp, ctx: &egui::Context) {
    if app.status_text.is_empty() || app.ui.toast_closed == app.status_seq {
        return;
    }
    let now = ctx.input(|input| input.time);
    let shown_at = match app.ui.toast_shown {
        Some((seq, at)) if seq == app.status_seq => at,
        _ => {
            app.ui.toast_shown = Some((app.status_seq, now));
            now
        }
    };
    let error = app.status_kind == StatusKind::Error;
    let age = now - shown_at;
    let opacity = if error || age <= TOAST_SECONDS {
        1.0
    } else if age <= TOAST_SECONDS + TOAST_FADE {
        (1.0 - (age - TOAST_SECONDS) / TOAST_FADE) as f32
    } else {
        return;
    };
    if !error {
        let wait = if age < TOAST_SECONDS {
            TOAST_SECONDS - age
        } else {
            0.016
        };
        ctx.request_repaint_after(std::time::Duration::from_secs_f64(wait));
    }
    let tone = match app.status_kind {
        StatusKind::Ok => kit::Tone::Good,
        StatusKind::Error => kit::Tone::Critical,
        StatusKind::Neutral => kit::Tone::Accent,
    };
    // Escape closes an error message when no sheet or menu is open.
    let escape = error
        && ctx.memory(|memory| memory.top_modal_layer()).is_none()
        && !egui::Popup::is_any_open(ctx)
        && ctx.input(|input| input.key_pressed(egui::Key::Escape));
    if kit::toast(ctx, &app.status_text, tone, opacity, error) || escape {
        app.ui.toast_closed = app.status_seq;
    }
}

/// "project · service", or nothing.
pub(super) fn meta_line(project: &str, service: &str) -> String {
    match (project.is_empty(), service.is_empty()) {
        (true, true) => String::new(),
        (false, true) => project.to_owned(),
        (true, false) => service.to_owned(),
        (false, false) => format!("{project} · {service}"),
    }
}

/// The icon and the tile color of a credential kind.
pub(super) fn kind_icon(kind: crate::contracts::CredentialKind) -> (kit::Icon, egui::Color32) {
    use crate::contracts::CredentialKind;
    match kind {
        CredentialKind::ApiKey => (kit::Icon::Key, egui::Color32::from_rgb(255, 149, 0)),
        CredentialKind::Login => (kit::Icon::Person, kit::ACCENT),
        CredentialKind::SshKey => (kit::Icon::Terminal, egui::Color32::from_rgb(88, 86, 214)),
        CredentialKind::Database => (kit::Icon::Database, egui::Color32::from_rgb(52, 170, 90)),
        CredentialKind::Custom => (kit::Icon::Asterisk, egui::Color32::from_rgb(142, 142, 147)),
    }
}

/// The plural section title of a credential kind.
pub(super) fn kind_plural(kind: crate::contracts::CredentialKind) -> &'static str {
    use crate::contracts::CredentialKind;
    match kind {
        CredentialKind::ApiKey => "API keys",
        CredentialKind::Login => "Logins",
        CredentialKind::SshKey => "SSH keys",
        CredentialKind::Database => "Databases",
        CredentialKind::Custom => "Custom secrets",
    }
}

/// One line about a credential kind, for the add sheet.
#[cfg(feature = "vault")]
pub(super) fn kind_blurb(kind: crate::contracts::CredentialKind) -> &'static str {
    use crate::contracts::CredentialKind;
    match kind {
        CredentialKind::ApiKey => "A token for an HTTP API",
        CredentialKind::Login => "A username and a password",
        CredentialKind::SshKey => "A private key for SSH or Git",
        CredentialKind::Database => "Host, database, user, password",
        CredentialKind::Custom => "Any other secret value",
    }
}

/// The label of an extra item field in the forms.
pub(super) fn extra_label(field: crate::desktop::ExtraField) -> &'static str {
    match field {
        crate::desktop::ExtraField::PublicLabel => "Public key",
        other => other.label(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "vault")]
    use crate::broker::approvals::{OwnerAction, OwnerCheck};
    use crate::desktop::OwnerView;
    use crate::desktop::model::MASKED_VALUE;
    #[cfg(not(feature = "vault"))]
    use crate::desktop::model::REPORTING_ITEM_ID;
    #[cfg(feature = "vault")]
    use crate::desktop::owner_check::OwnerRequest;
    use eframe::egui::{Pos2, RawInput, Rect, Shape, Vec2};

    const DEFAULT_SIZE: Vec2 = Vec2::new(1180.0, 800.0);
    const MIN_SIZE: Vec2 = Vec2::new(900.0, 600.0);
    const TALL_SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

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

    /// Draw `frames` frames at `time` and return the text and the shape count of the
    /// last one. A new sheet is invisible in its first frame, while egui measures it.
    fn draw_at(app: &mut DesktopApp, size: Vec2, frames: u32, time: f64) -> (String, usize) {
        let ctx = egui::Context::default();
        let mut text = String::new();
        let mut shape_count = 0;
        for _ in 0..frames {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
                time: Some(time),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| draw(app, ui));
            shape_count = output.shapes.len();
            text.clear();
            for clipped in &output.shapes {
                collect_shape_text(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        (text, shape_count)
    }

    fn draw_frames(app: &mut DesktopApp, size: Vec2, frames: u32) -> (String, usize) {
        draw_at(app, size, frames, 0.0)
    }

    /// No view shows a synthetic or a stored secret value while it is masked.
    fn assert_masked(text: &str) {
        for canary in ["SYNTH-", "NOT-A-SECRET", "ui-draw-token-canary"] {
            assert!(!text.contains(canary), "a masked value is visible: {text}");
        }
    }

    #[cfg(feature = "vault")]
    const UI_PASS: &str = "ui-draw-pass-ok";
    #[cfg(feature = "vault")]
    const UI_TOKEN: &str = "ui-draw-token-canary";

    /// An unlocked synthetic vault file in the app. The directory must outlive the app.
    #[cfg(feature = "vault")]
    fn app_with_vault(dir: &tempfile::TempDir) -> DesktopApp {
        let mut app = DesktopApp::new();
        let path = dir.path().join("ui.db");
        app.owner_ui
            .session
            .create_file(&path, UI_PASS)
            .expect("create");
        app.owner_ui.session.unlock(UI_PASS).expect("unlock");
        app
    }

    /// An unlocked vault with one API key, selected.
    #[cfg(feature = "vault")]
    fn app_with_item(dir: &tempfile::TempDir) -> (DesktopApp, u64) {
        use crate::desktop::owner_store::SecretForm;

        let mut app = app_with_vault(dir);
        let mut secrets = SecretForm::default();
        secrets.token = UI_TOKEN.to_owned();
        let item = app
            .owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: "Drawn key".to_owned(),
                    project: "ui".to_owned(),
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add");
        app.select_item(item.id.to_string());
        (app, item.id)
    }

    #[cfg(feature = "vault")]
    #[test]
    fn adoption_next_steps_belong_only_to_the_adopted_unlocked_vault() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        app.vault_list.current = Some("adopted-test-vault".to_owned());
        app.sync.adopted_vault = app.vault_list.current.clone();
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(text.contains("Use this vault on this Mac"), "{text}");
        assert!(app.sync.adopted_vault.is_none());
        app.owner_ui.session.lock().expect("lock");
        let (locked, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(!locked.contains("Use this vault on this Mac"), "{locked}");
        app.owner_ui.session.unlock(UI_PASS).expect("unlock");
        app.vault_list.current = Some("another-vault".to_owned());
        let (other, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(app.ui.setup_vault.is_none());
        assert!(!other.contains("Use this vault on this Mac"), "{other}");
    }

    /// A proof after a passed passphrase check (goal item A4).
    #[cfg(feature = "vault")]
    fn owner_ok(
        app: &DesktopApp,
        action: crate::broker::approvals::OwnerAction,
    ) -> crate::broker::approvals::OwnerProof {
        app.owner_gate()
            .authorize(action, OwnerCheck::passphrase(UI_PASS))
            .expect("owner check")
    }

    #[cfg(feature = "vault")]
    #[test]
    fn start_screen_without_a_file_offers_create_and_open() {
        let mut app = DesktopApp::new();
        app.sync.offered = true;
        let (text, shape_count) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(shape_count > 0);
        for expected in [
            "Welcome to Apassy",
            "Create my first vault",
            "Use a vault from another Mac",
            "Open a local vault file",
            "Restore from a backup",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(
            !text.contains("Learning"),
            "no sidebar before a vault: {text}"
        );

        app.ui.start = start::Step::Create;
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(text.contains("Create your vault"), "{text}");
        assert!(
            text.contains("Repeat"),
            "the passphrase is typed two times: {text}"
        );
        assert!(
            text.contains("Apassy cannot recover a lost passphrase"),
            "{text}"
        );
    }

    /// The two create fields must match. Both fields are empty after the try.
    #[cfg(feature = "vault")]
    #[test]
    fn create_needs_the_same_passphrase_two_times() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = DesktopApp::new();
        let ctx = egui::Context::default();
        app.owner_ui.create_path = dir
            .path()
            .join("new")
            .join("vault.db")
            .display()
            .to_string();
        app.owner_ui.passphrase.push_str("ui-create-pass-1");
        app.owner_ui.passphrase_confirm.push_str("ui-create-pass-2");
        start::create_vault(&mut app, &ctx);
        assert!(!app.owner_ui.session.has_file(), "no file after a mismatch");
        assert!(app.status_text.contains("different"), "{}", app.status_text);
        assert!(app.owner_ui.passphrase.is_empty());
        assert!(app.owner_ui.passphrase_confirm.is_empty());

        app.owner_ui.passphrase.push_str("ui-create-pass-1");
        app.owner_ui.passphrase_confirm.push_str("ui-create-pass-1");
        start::create_vault(&mut app, &ctx);
        assert!(app.owner_ui.session.has_file());
        assert!(
            !app.owner_ui.session.is_locked(),
            "create unlocks the new vault"
        );
        assert!(app.owner_ui.passphrase.is_empty());
        assert!(app.owner_ui.passphrase_confirm.is_empty());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("new"))
            .expect("folder")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "a new data folder is private");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn locked_file_shows_the_unlock_screen_only() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, _) = app_with_item(&dir);
        app.owner_ui.session.lock().expect("lock");
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(text.contains("Apassy is locked"), "{text}");
        assert!(text.contains("Unlock"), "{text}");
        assert!(!text.contains("Drawn key"), "items stay hidden: {text}");
        assert_masked(&text);
    }

    #[cfg(not(feature = "vault"))]
    #[test]
    fn demo_starts_locked_and_says_demo() {
        let mut app = DesktopApp::new();
        assert!(app.model.is_locked());
        let (text, shape_count) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(shape_count > 0);
        assert!(text.contains(crate::desktop::DEMO_BANNER), "{text}");
        assert!(text.contains("Demo data only"), "{text}");
        assert!(text.contains("The demo vault is locked"), "{text}");
        assert!(text.contains("Open vault"), "{text}");
    }

    /// The heading of each view.
    fn heading_for(view: OwnerView) -> &'static str {
        match view {
            #[cfg(feature = "vault")]
            OwnerView::Item => "Drawn key",
            #[cfg(not(feature = "vault"))]
            OwnerView::Item => "Project A reporting service",
            other => other.label(),
        }
    }

    #[test]
    fn every_view_draws_at_default_and_minimum_sizes() {
        for size in [DEFAULT_SIZE, MIN_SIZE] {
            for view in OwnerView::ALL {
                #[cfg(feature = "vault")]
                let dir = tempfile::TempDir::new().expect("temp dir");
                #[cfg(feature = "vault")]
                let mut app = app_with_item(&dir).0;
                #[cfg(not(feature = "vault"))]
                let mut app = {
                    let mut app = DesktopApp::new();
                    app.model
                        .unlock()
                        .expect("open vault is not authentication");
                    app.select_item(REPORTING_ITEM_ID.to_owned());
                    app
                };
                app.view = view;
                let (text, shape_count) = draw_frames(&mut app, size, 3);
                assert!(shape_count > 0, "{view:?} paints nothing");
                let heading = heading_for(view);
                assert!(
                    text.contains(heading),
                    "missing {heading} at {size:?}: {text}"
                );
                assert_masked(&text);
                if view == OwnerView::Item {
                    assert!(text.contains(MASKED_VALUE), "masked value missing: {text}");
                }
            }
        }
    }

    /// Goal item P1: the agent page shows the expiry and rotation. Settings shows the
    /// lifetime. Rotation waits for the owner check (A4), then shows the token once.
    #[cfg(feature = "vault")]
    #[test]
    fn agent_page_shows_token_expiry_and_rotation() {
        use crate::desktop::owner_store::FreshToken;

        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let (agent, _token) = app
            .owner_ui
            .session
            .register_agent("UI agent")
            .expect("register");
        app.view = OwnerView::Agents;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("UI agent"), "{text}");
        assert!(text.contains("Active"), "{text}");
        app.owner_ui.selected_agent = Some(agent.id);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Expires"), "{text}");
        assert!(
            text.contains(&crate::vault::format_utc(agent.token_expires_at)),
            "{text}"
        );
        assert!(text.contains("Rotate token"), "{text}");
        assert!(
            text.contains("Token lifetime: 30 days after issue."),
            "{text}"
        );

        open_settings(&mut app, SettingsTab::Agents);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Token lifetime"), "{text}");
        assert!(text.contains("Current lifetime: 30 days."), "{text}");

        app.view = OwnerView::Agents;
        app.ask_owner(
            OwnerRequest::RotateToken {
                agent_id: agent.id,
                agent_name: agent.name.clone(),
            },
            None,
        );
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Confirm that it is you"), "{text}");
        assert!(
            app.owner_ui.fresh_token.is_none(),
            "no rotation before the check"
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        let shown = app
            .owner_ui
            .fresh_token
            .as_ref()
            .map(|fresh: &FreshToken| fresh.token.expose().to_owned())
            .expect("rotated");
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("The old token does not work"), "{text}");
        assert!(text.contains("Connect Claude Code"), "{text}");
        assert!(text.contains("Advanced setup"), "{text}");
        assert!(!text.contains(&shown), "the token is hidden by default");
        app.ui.agent_setup.advanced = true;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains(&shown), "Advanced setup shows the new token");

        // A lock hides the token for good.
        app.lock_vault(None);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(app.owner_ui.fresh_token.is_none());
        assert!(!text.contains(&shown));
    }

    /// Goal item V5: the passphrase sheet asks for the current passphrase and for the
    /// new passphrase two times.
    #[cfg(feature = "vault")]
    #[test]
    fn passphrase_sheet_asks_for_the_new_passphrase_two_times() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        app.view = OwnerView::Settings;
        app.ui.sheet = Some(Sheet::ChangePassphrase);
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        for label in [
            "Change passphrase",
            "Current passphrase",
            "New passphrase",
            "Repeat the new one",
            "Old backups still need the old passphrase",
        ] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
        let err = app
            .owner_ui
            .session
            .change_passphrase(UI_PASS, "ui-new-pass-ok-1", "ui-new-pass-ok-2")
            .expect_err("different repeat");
        assert!(err.message.contains("different"), "{}", err.message);
        assert!(!app.owner_ui.session.is_locked());
        app.owner_ui.session.lock().expect("lock");
        app.owner_ui
            .session
            .unlock(UI_PASS)
            .expect("the old passphrase works");
    }

    /// Goal item V4: after a restore, the list shows the items to review, and the item
    /// page has the review notice with "Confirm settings".
    #[cfg(feature = "vault")]
    #[test]
    fn restored_item_shows_the_review_and_confirm_action() {
        use crate::desktop::owner_store::{DeclarationForm, SecretForm};

        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let mut secrets = SecretForm::default();
        secrets.token = UI_TOKEN.to_owned();
        let item = app
            .owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: "Restored key".to_owned(),
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add");
        let form = DeclarationForm {
            project: "ui".to_owned(),
            ..DeclarationForm::default()
        };
        let proof = owner_ok(&app, OwnerAction::ChangeItemRules { item_id: item.id });
        app.owner_ui
            .session
            .set_declaration(item.id, &form, proof)
            .expect("declaration");
        let backup = dir.path().join("ui.backup");
        app.owner_ui.session.backup(&backup).expect("backup");
        app.owner_ui
            .session
            .restore(&backup, &dir.path().join("ui-restored.db"), UI_PASS)
            .expect("restore");
        app.owner_ui.session.unlock(UI_PASS).expect("unlock");

        app.view = OwnerView::Vault;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Review after restore"), "{text}");
        assert!(text.contains("Restored key"), "{text}");
        assert!(text.contains("Needs review"), "{text}");

        app.select_item(item.id.to_string());
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Confirm settings"), "{text}");
        assert!(text.contains("production, high risk"), "{text}");
        assert_masked(&text);

        // The confirmation waits for the owner check (goal item A4).
        app.ask_owner(OwnerRequest::ConfirmReview { item_id: item.id }, None);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Confirm that it is you"), "{text}");
        assert!(text.contains("Confirm settings"), "{text}");
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(!text.contains("Confirm settings"), "{text}");
    }

    /// Goal item B4: a new item gets a suggested declaration. The sheet shows a hint
    /// only for a changed value, and the reasons on request. The save waits for the
    /// owner check, and the sheet then shows the acceptance share.
    #[cfg(feature = "vault")]
    #[test]
    fn declaration_sheet_shows_the_suggestion_and_the_acceptance_share() {
        use crate::desktop::owner_store::SecretForm;
        use crate::vault::{Environment, RiskLevel};

        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let secret = format!("sk_live_{}", "EXAMPLE0".repeat(3));
        let mut secrets = SecretForm::default();
        secrets.token.clone_from(&secret);
        let item = app
            .owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: "Payments".to_owned(),
                    project: "shop".to_owned(),
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add");
        app.select_item(item.id.to_string());
        app.ui
            .set_expanded(&format!("credential-access-{}", item.id), true);
        let form = &app.owner_ui.declaration_form;
        assert!(!form.stored);
        assert_eq!(form.provider.as_deref(), Some("stripe"));
        assert_eq!(
            form.project, "shop",
            "the project of the item fills the form"
        );
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Declaration"), "{text}");
        assert!(
            text.contains("Not set"),
            "the item page says it is not set: {text}"
        );

        app.ui.sheet = Some(Sheet::Declaration);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Apassy suggests the values below"), "{text}");
        assert!(
            text.contains("Known hosts of Stripe: api.stripe.com"),
            "{text}"
        );
        assert!(
            text.contains("No suggested declaration is saved yet"),
            "{text}"
        );
        assert!(text.contains("Why these values?"), "{text}");
        assert!(
            !text.contains("You changed it."),
            "no hint for accepted values: {text}"
        );
        assert!(!text.contains(&secret), "the value stays hidden");

        let reason = app
            .owner_ui
            .declaration_form
            .suggestion
            .as_ref()
            .map(|suggestion| suggestion.provider_reason.clone())
            .expect("suggestion");
        assert!(!text.contains(&reason), "the reasons start folded");
        app.ui.set_expanded(items_why_key(), true);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains(&reason), "{text}");

        // The owner lowers the risk. The save waits for the owner check (goal item A4).
        app.owner_ui.declaration_form.risk = RiskLevel::Medium;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(
            text.contains("Apassy suggested high. You changed it."),
            "{text}"
        );
        let form = app.owner_ui.declaration_form.clone();
        app.ask_owner(
            OwnerRequest::SaveDeclaration {
                item_id: item.id,
                form,
            },
            None,
        );
        assert!(
            app.owner_ui
                .session
                .declaration(item.id)
                .expect("read")
                .is_none()
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        let stored = app
            .owner_ui
            .session
            .declaration(item.id)
            .expect("read")
            .expect("saved");
        assert_eq!(stored.environment, Environment::Production);
        assert_eq!(stored.risk, RiskLevel::Medium);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(
            text.contains("Suggested declarations saved without a change: 0 of 1 (0%). Changed fields: risk 1."),
            "{text}"
        );
        // The stored declaration fills the form again, with the provider.
        app.select_item(item.id.to_string());
        assert!(app.owner_ui.declaration_form.stored);
        assert_eq!(
            app.owner_ui.declaration_form.provider.as_deref(),
            Some("stripe")
        );
    }

    #[cfg(feature = "vault")]
    fn items_why_key() -> &'static str {
        "declaration-why"
    }

    /// The add sheet asks for the kind first, then for the name and the secret.
    #[cfg(feature = "vault")]
    #[test]
    fn add_sheet_picks_a_kind_then_asks_for_the_secret() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        // A new vault shows the steps; their first one adds a credential.
        assert!(text.contains("Get started · 0 of 5"), "{text}");
        app.ui.sheet = Some(Sheet::AddItem { kind_chosen: false });
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        for kind in [
            "Add a credential",
            "API key",
            "Login",
            "SSH key",
            "Database",
            "Custom",
        ] {
            assert!(text.contains(kind), "missing {kind}: {text}");
        }
        assert!(!text.contains("Token"), "no fields before the kind: {text}");
        app.add_form.kind = crate::contracts::CredentialKind::Database;
        app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        for field in [
            "New database login",
            "Name",
            "Host",
            "Database name",
            "Password",
            "Where it is used",
        ] {
            assert!(text.contains(field), "missing {field}: {text}");
        }
    }

    /// Closing a sheet erases the secrets typed in it (key-memory review F3).
    #[cfg(feature = "vault")]
    #[test]
    fn closing_a_sheet_erases_its_typed_secrets() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, _) = app_with_item(&dir);
        let ctx = egui::Context::default();
        app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
        app.owner_ui.add_secrets.token.push_str(UI_TOKEN);
        close_sheet(&mut app, &ctx);
        assert!(app.ui.sheet.is_none());
        assert!(app.owner_ui.add_secrets.is_blank());

        app.ui.sheet = Some(Sheet::EditItem);
        app.owner_ui.edit_secrets.token.push_str(UI_TOKEN);
        close_sheet(&mut app, &ctx);
        assert!(app.owner_ui.edit_secrets.is_blank());

        app.ui.sheet = Some(Sheet::ChangePassphrase);
        app.owner_ui.passphrase_current.push_str(UI_PASS);
        app.owner_ui.passphrase_new.push_str(UI_PASS);
        app.owner_ui.passphrase_repeat.push_str(UI_PASS);
        close_sheet(&mut app, &ctx);
        assert!(app.owner_ui.passphrase_current.is_empty());
        assert!(app.owner_ui.passphrase_new.is_empty());
        assert!(app.owner_ui.passphrase_repeat.is_empty());

        app.ui.sheet = Some(Sheet::Restore);
        app.owner_ui.passphrase.push_str(UI_PASS);
        close_sheet(&mut app, &ctx);
        assert!(app.owner_ui.passphrase.is_empty());
    }

    /// A sheet closes after its owner check succeeds, and stays after a cancel.
    #[cfg(feature = "vault")]
    #[test]
    fn a_sheet_closes_only_after_a_successful_owner_check() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, item_id) = app_with_item(&dir);
        let ctx = egui::Context::default();
        app.ui.sheet = Some(Sheet::Declaration);
        let form = app.owner_ui.declaration_form.clone();
        let request = OwnerRequest::SaveDeclaration { item_id, form };

        ask_owner_from_sheet(&mut app, request.clone(), &ctx);
        app.close_owner_check(Some(&ctx));
        app.set_note("The owner check is cancelled. Apassy did nothing.");
        draw_frames(&mut app, DEFAULT_SIZE, 1);
        assert_eq!(
            app.ui.sheet,
            Some(Sheet::Declaration),
            "a cancel keeps the sheet"
        );

        ask_owner_from_sheet(&mut app, request, &ctx);
        assert!(
            app.confirm_owner_now(OwnerCheck::passphrase("ui-draw-pass-no"))
                .is_err()
        );
        draw_frames(&mut app, DEFAULT_SIZE, 1);
        assert_eq!(
            app.ui.sheet,
            Some(Sheet::Declaration),
            "a failed check keeps it"
        );

        let form = app.owner_ui.declaration_form.clone();
        ask_owner_from_sheet(
            &mut app,
            OwnerRequest::SaveDeclaration { item_id, form },
            &ctx,
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        draw_frames(&mut app, DEFAULT_SIZE, 1);
        assert_eq!(app.ui.sheet, None, "success closes the sheet");
        assert!(
            app.owner_ui
                .session
                .declaration(item_id)
                .expect("read")
                .is_some()
        );
    }

    /// ADR 0011: the variable sheet offers a placeholder with hosts. The owner check
    /// saves the mode, and the credential page shows it.
    #[cfg(feature = "vault")]
    #[test]
    fn the_variable_sheet_saves_a_placeholder_with_its_hosts() {
        use crate::vault::EnvDelivery;

        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, item_id) = app_with_item(&dir);
        let ctx = egui::Context::default();
        items::prepare_sheet(&mut app, item_id, &Sheet::Variable);
        app.ui.sheet = Some(Sheet::Variable);
        // The item has no provider, so a new variable starts with the real value.
        assert!(!app.owner_ui.env_placeholder_input);
        app.owner_ui.env_placeholder_input = true;
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 2);
        for expected in [
            "What the program gets",
            "Placeholder",
            "Real value",
            "Hosts",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert_masked(&text);

        let hosts = items::host_list("API.example.com, api.other.example:8443\nAPI.example.com");
        assert_eq!(
            hosts,
            vec![
                "api.example.com".to_owned(),
                "api.other.example:8443".to_owned(),
                "api.example.com".to_owned()
            ]
        );
        ask_owner_from_sheet(
            &mut app,
            OwnerRequest::SaveVariable {
                item_id,
                env_name: "DRAWN_KEY".to_owned(),
                field: "token".to_owned(),
                delivery: EnvDelivery::Placeholder(hosts),
            },
            &ctx,
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        let binding = app
            .owner_ui
            .session
            .env_binding(item_id)
            .expect("read")
            .expect("binding");
        assert_eq!(
            binding.delivery,
            EnvDelivery::Placeholder(vec![
                "api.example.com".to_owned(),
                "api.other.example:8443".to_owned()
            ])
        );
        app.ui.sheet = None;
        app.select_item(item_id.to_string());
        app.ui
            .set_expanded(&format!("credential-access-{}", item_id), true);
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 2);
        assert!(text.contains("DRAWN_KEY · placeholder"), "{text}");
        items::prepare_sheet(&mut app, item_id, &Sheet::Variable);
        assert!(app.owner_ui.env_placeholder_input);
        assert_eq!(
            app.owner_ui.env_hosts_input,
            "api.example.com, api.other.example:8443"
        );

        // A value that is too short for a placeholder is refused.
        let mut secrets = crate::desktop::owner_store::SecretForm::default();
        secrets.token = "short-1".to_owned();
        let short = app
            .owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: "Short key".to_owned(),
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add");
        let proof = owner_ok(
            &app,
            crate::broker::approvals::OwnerAction::ChangeItemRules { item_id: short.id },
        );
        let refused = app.owner_ui.session.set_env_binding(
            short.id,
            "SHORT_KEY",
            "token",
            &EnvDelivery::Placeholder(vec!["api.example.com".to_owned()]),
            proof,
        );
        assert!(
            refused.is_err_and(|err| err.message.contains("too short")),
            "a short value"
        );
    }

    /// ADR 0012: "see all" waits for the owner check, several credentials get access with
    /// one check, and an access request shows in Activity until a grant answers it.
    #[cfg(feature = "vault")]
    #[test]
    fn access_model_screens_wait_for_the_owner_check() {
        use crate::broker::approvals::OwnerAction;
        use crate::desktop::owner_store::SecretForm;
        use crate::vault::{EnvDelivery, ExecMode, GrantPlace, RequestState};

        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, first) = app_with_item(&dir);
        let ctx = egui::Context::default();
        let mut secrets = SecretForm::default();
        secrets.token = "ui-second-token-canary".to_owned();
        let second = app
            .owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: "Second key".to_owned(),
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add")
            .id;
        for (item_id, name) in [(first, "FIRST_KEY"), (second, "SECOND_KEY")] {
            let proof = owner_ok(&app, OwnerAction::ChangeItemRules { item_id });
            app.owner_ui
                .session
                .set_env_binding(item_id, name, "token", &EnvDelivery::Value, proof)
                .expect("variable");
        }
        let (agent, _token) = app
            .owner_ui
            .session
            .register_agent("Finder")
            .expect("register");
        app.view = OwnerView::Agents;
        app.owner_ui.selected_agent = Some(agent.id);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        for expected in [
            "What it can see",
            "All credentials, without values",
            "Give access to several credentials",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }

        app.ask_owner(
            OwnerRequest::ShowAllCredentials {
                agent_id: agent.id,
                agent_name: agent.name.clone(),
            },
            None,
        );
        assert!(!app.owner_ui.session.agent_sees_all(agent.id).expect("read"));
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        assert!(app.owner_ui.session.agent_sees_all(agent.id).expect("read"));

        // Two credentials in any folder with one check. They hold the real value, so
        // the sheet says that each run waits.
        app.ui.grant = agents::GrantForm {
            selection: [first, second].into_iter().collect(),
            any_folder: true,
            ..agents::GrantForm::default()
        };
        app.ui.sheet = Some(Sheet::GrantMany { agent_id: agent.id });
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 2);
        for expected in [
            "Give Finder access",
            "Give access to 2 credentials",
            "Any folder",
            "you approve each run with it",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        ask_owner_from_sheet(
            &mut app,
            OwnerRequest::GrantMany {
                agent_id: agent.id,
                item_ids: vec![first, second],
                place: GrantPlace::AnyFolder,
                mode: ExecMode::Ask,
            },
            &ctx,
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        draw_frames(&mut app, TALL_SIZE, 1);
        assert_eq!(app.ui.sheet, None, "the sheet closes after the check");
        let grants = app.owner_ui.session.exec_grants(agent.id).expect("grants");
        assert_eq!(grants.len(), 2);
        assert!(
            grants
                .iter()
                .all(|grant| grant.place == GrantPlace::AnyFolder)
        );

        // An access request of the agent shows in Activity.
        app.owner_ui
            .session
            .remove_exec_grant(agent.id, second)
            .expect("remove");
        let request_id = {
            let shared = app.owner_ui.session.shared_vault();
            let mut guard = shared.lock().expect("vault");
            guard
                .as_mut()
                .expect("open")
                .request_access(agent.id, second, "Run the second job.", "")
                .expect("request")
                .0
        };
        app.view = OwnerView::Activity;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Access requests"), "{text}");
        assert!(text.contains("Finder asks for Second key"), "{text}");
        assert!(text.contains("Run the second job."), "{text}");
        assert!(!text.contains("ui-second-token-canary"));

        app.ui.grant = agents::GrantForm {
            any_folder: true,
            ..agents::GrantForm::default()
        };
        app.ui.sheet = Some(Sheet::AccessRequest { request_id });
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 2);
        assert!(text.contains("Give access"), "{text}");
        ask_owner_from_sheet(
            &mut app,
            OwnerRequest::GrantRequest {
                request_id,
                agent_id: agent.id,
                item_id: second,
                agent_name: agent.name.clone(),
                item_name: "Second key".to_owned(),
                place: GrantPlace::AnyFolder,
                mode: ExecMode::Ask,
            },
            &ctx,
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        let requests = app.owner_ui.session.access_requests(false).expect("read");
        assert_eq!(requests[0].state, RequestState::Granted);
        assert_eq!(
            app.owner_ui
                .session
                .exec_grants(agent.id)
                .expect("grants")
                .len(),
            2
        );

        // Turning "see all" off needs no check.
        app.owner_ui
            .session
            .set_agent_sees_all(agent.id, false, None)
            .expect("off");
        assert!(!app.owner_ui.session.agent_sees_all(agent.id).expect("read"));
    }

    /// A lock leaves the main window, closes every sheet, and hides a fresh token.
    #[cfg(feature = "vault")]
    #[test]
    fn a_lock_closes_sheets_and_shows_the_unlock_screen() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, _) = app_with_item(&dir);
        app.ui.sheet = Some(Sheet::EditItem);
        let ctx = egui::Context::default();
        app.lock_vault(Some(&ctx));
        let (text, _) = draw_frames(&mut app, DEFAULT_SIZE, 3);
        assert!(app.ui.sheet.is_none());
        assert!(text.contains("Apassy is locked"), "{text}");
        assert!(!text.contains("Edit credential"), "{text}");
    }

    /// A result fades after a few seconds. An error stays until the owner closes it.
    #[test]
    fn a_result_fades_and_an_error_stays() {
        let mut app = DesktopApp::new();
        app.set_ok("Synthetic result message.");
        let (text, _) = draw_at(&mut app, DEFAULT_SIZE, 3, 100.0);
        assert!(text.contains("Synthetic result message."), "{text}");
        let (text, _) = draw_at(&mut app, DEFAULT_SIZE, 3, 110.0);
        assert!(!text.contains("Synthetic result message."), "{text}");

        app.set_err("Synthetic error message.");
        let (text, _) = draw_at(&mut app, DEFAULT_SIZE, 3, 200.0);
        assert!(text.contains("Synthetic error message."), "{text}");
        let (text, _) = draw_at(&mut app, DEFAULT_SIZE, 3, 400.0);
        assert!(text.contains("Synthetic error message."), "{text}");
    }

    #[cfg(not(feature = "vault"))]
    #[test]
    fn activity_history_after_approve_once_draws_on_a_tall_frame() {
        use crate::desktop::DemoScenario;
        use crate::desktop::model::{REPORTING_AGENT_ID, SAMPLE_RULE_TEXT};

        let mut app = DesktopApp::new();
        app.model
            .unlock()
            .expect("open vault is not authentication");
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

        let (compact, _) = draw_frames(&mut app, MIN_SIZE, 3);
        assert!(
            compact.contains("This is a fixture risk simulation"),
            "fixture risk label missing: {compact}"
        );
        let (tall, _) = draw_frames(&mut app, TALL_SIZE, 3);
        for expected in [
            "Permitted request",
            "The owner approved this exact request once",
            "First decision: Wait",
            "History",
            "The request waits for an owner decision",
        ] {
            assert!(tall.contains(expected), "missing {expected}: {tall}");
        }
        assert!(
            !tall.contains("Approve once"),
            "completed use must not show Approve once: {tall}"
        );
    }

    /// Draw one frame with `events`, then two frames without, so a new sheet shows.
    #[cfg(feature = "vault")]
    fn draw_events(app: &mut DesktopApp, events: Vec<egui::Event>) -> String {
        let ctx = egui::Context::default();
        let mut text = String::new();
        for events in [events, Vec::new(), Vec::new()] {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, TALL_SIZE)),
                events,
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| draw(app, ui));
            text.clear();
            for clipped in &output.shapes {
                collect_shape_text(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        text
    }

    #[cfg(feature = "vault")]
    fn key(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    #[cfg(feature = "vault")]
    fn add_named(app: &mut DesktopApp, name: &str, kind: crate::contracts::CredentialKind) -> u64 {
        use crate::desktop::owner_store::SecretForm;

        let mut secrets = SecretForm::default();
        secrets.token = UI_TOKEN.to_owned();
        secrets.password = UI_TOKEN.to_owned();
        app.owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: name.to_owned(),
                    kind,
                    username: "ui-user".to_owned(),
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add")
            .id
    }

    /// The list hides an archived credential until a search or the "Archived" filter.
    /// A filter by kind and the recency orders work.
    #[cfg(feature = "vault")]
    #[test]
    fn the_list_sorts_filters_and_hides_archived_credentials() {
        use crate::contracts::CredentialKind;

        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let alpha = add_named(&mut app, "Alpha key", CredentialKind::ApiKey);
        add_named(&mut app, "Beta login", CredentialKind::Login);
        let gamma = add_named(&mut app, "Gamma key", CredentialKind::ApiKey);
        app.owner_ui.session.archive(gamma).expect("archive");
        app.view = OwnerView::Vault;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(
            text.contains("Alpha key") && text.contains("Beta login"),
            "{text}"
        );
        assert!(!text.contains("Gamma key"), "{text}");
        assert!(text.contains("1 archived credential is hidden."), "{text}");

        app.search = "gamma".to_owned();
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(
            text.contains("Gamma key") && text.contains("Archived"),
            "{text}"
        );
        assert!(!text.contains("Alpha key"), "{text}");

        app.search.clear();
        app.ui.credential_filter = items::Filter::Archived;
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(
            text.contains("Gamma key") && !text.contains("Alpha key"),
            "{text}"
        );

        app.ui.credential_filter = items::Filter::Kind(CredentialKind::Login);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(
            text.contains("Beta login") && !text.contains("Alpha key"),
            "{text}"
        );

        // The newest change goes first.
        app.ui.credential_filter = items::Filter::All;
        app.ui.credential_sort = items::Sort::Changed;
        let details = app.owner_ui.session.details(alpha).expect("details");
        let mut draft = details.to_draft();
        draft.notes = "changed".to_owned();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        app.owner_ui
            .session
            .update(alpha, details.revision, &draft, &Default::default())
            .expect("update");
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        let first = text.find("Alpha key").expect("alpha");
        let second = text.find("Beta login").expect("beta");
        assert!(first < second, "{text}");
        assert!(text.contains("Recently changed"), "{text}");
        assert!(text.contains("Changed just now"), "{text}");
    }

    /// The page of a credential shows custom details (hidden ones masked), the history,
    /// and the agent requests.
    #[cfg(feature = "vault")]
    #[test]
    fn the_credential_page_shows_details_history_and_requests() {
        use crate::desktop::model::DetailDraft;
        use crate::desktop::owner_store::SecretForm;

        const HIDDEN: &str = "ui-hidden-detail-canary";
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let mut secrets = SecretForm::default();
        secrets.token = UI_TOKEN.to_owned();
        secrets.details[1] = HIDDEN.to_owned();
        let item = app
            .owner_ui
            .session
            .add(
                &crate::desktop::ItemDraft {
                    name: "Detailed key".to_owned(),
                    details: vec![
                        DetailDraft {
                            label: "Account ID".to_owned(),
                            value: "acct_ui".to_owned(),
                            ..DetailDraft::default()
                        },
                        DetailDraft {
                            label: "Recovery code".to_owned(),
                            hidden: true,
                            ..DetailDraft::default()
                        },
                    ],
                    ..crate::desktop::ItemDraft::default()
                },
                &secrets,
            )
            .expect("add");
        app.select_item(item.id.to_string());
        app.ui
            .set_expanded(&format!("credential-history-{}", item.id), true);
        app.ui
            .set_expanded(&format!("credential-actions-{}", item.id), true);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        for expected in [
            "Account ID",
            "acct_ui",
            "Recovery code",
            "Add custom detail",
            "History",
            "Added",
            "Agent requests",
            "No agent asked for this credential yet.",
            "Archive credential…",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(!text.contains(HIDDEN), "a hidden detail is masked");
        assert_masked(&text);

        let proof = owner_ok(&app, OwnerAction::Reveal { item_id: item.id });
        app.owner_ui.session.reveal(item.id, proof).expect("reveal");
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains(HIDDEN), "{text}");
        assert!(text.contains("You showed the secret"), "{text}");

        // "Add custom detail" opens the edit sheet with a new row.
        app.ui.sheet = None;
        app.owner_ui.session.hide(item.id).expect("hide");
        let details = app.owner_ui.session.details(item.id).expect("details");
        app.edit_form = details.to_draft();
        app.edit_form.details.push(DetailDraft::default());
        app.ui.sheet = Some(Sheet::EditItem);
        let (text, _) = draw_frames(&mut app, TALL_SIZE, 3);
        assert!(text.contains("Custom details"), "{text}");
        assert!(
            text.contains("Unchanged"),
            "a stored hidden value stays: {text}"
        );
        assert!(!text.contains(HIDDEN), "{text}");
    }

    /// The archive sheet archives at once. The page then offers the way back, which
    /// needs the owner check.
    #[cfg(feature = "vault")]
    #[test]
    fn archive_from_the_page_and_back_with_the_owner_check() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, item_id) = app_with_item(&dir);
        app.ui.sheet = Some(Sheet::ArchiveItem);
        let text = draw_events(&mut app, Vec::new());
        assert!(text.contains("Archive “Drawn key”?"), "{text}");
        // ⌘S takes the default action of the sheet.
        draw_events(&mut app, vec![key(egui::Key::S, egui::Modifiers::COMMAND)]);
        assert!(app.owner_ui.session.is_archived(item_id).expect("state"));
        assert!(app.ui.sheet.is_none());
        let text = draw_events(&mut app, Vec::new());
        assert!(text.contains("Restore from archive"), "{text}");
        app.ask_owner(
            OwnerRequest::Unarchive {
                item_id,
                name: "Drawn key".to_owned(),
            },
            None,
        );
        let text = draw_events(&mut app, Vec::new());
        assert!(
            text.contains("Bring \"Drawn key\" back from the archive"),
            "{text}"
        );
        app.confirm_owner_now(OwnerCheck::passphrase(UI_PASS))
            .expect("owner check");
        assert!(!app.owner_ui.session.is_archived(item_id).expect("state"));
    }

    /// ⌘N opens the add sheet, ⌘F goes to the search, ⌘⇧H asks to show the values, and
    /// ⌘S saves the edit sheet.
    #[cfg(feature = "vault")]
    #[test]
    fn keyboard_shortcuts_open_save_and_show() {
        use egui::{Key, Modifiers};

        let dir = tempfile::TempDir::new().expect("temp dir");
        let (mut app, item_id) = app_with_item(&dir);
        draw_events(
            &mut app,
            vec![key(Key::H, Modifiers::COMMAND | Modifiers::SHIFT)],
        );
        let check = app.owner.check.as_ref().expect("the owner check opens");
        assert!(matches!(check.request, OwnerRequest::Reveal { item_id: id } if id == item_id));
        app.close_owner_check(None);

        draw_events(&mut app, vec![key(Key::F, Modifiers::COMMAND)]);
        assert_eq!(app.view, OwnerView::Vault);
        draw_events(&mut app, vec![key(Key::N, Modifiers::COMMAND)]);
        assert_eq!(app.ui.sheet, Some(Sheet::AddItem { kind_chosen: false }));
        app.ui.sheet = None;

        app.select_item(item_id.to_string());
        let details = app.owner_ui.session.details(item_id).expect("details");
        app.edit_form = details.to_draft();
        app.edit_form.name = "Renamed by shortcut".to_owned();
        app.owner_ui.edit_revision = details.revision;
        app.ui.sheet = Some(Sheet::EditItem);
        draw_events(&mut app, Vec::new());
        draw_events(&mut app, vec![key(Key::S, Modifiers::COMMAND)]);
        assert!(app.ui.sheet.is_none(), "the sheet closes after the save");
        assert_eq!(
            app.owner_ui.session.details(item_id).expect("details").name,
            "Renamed by shortcut"
        );
        let history = app
            .owner_ui
            .session
            .item_events(item_id, 5)
            .expect("history");
        assert_eq!(history[0].kind, crate::vault::ItemEventKind::Edited);
    }

    /// A segmented picker is one Tab stop. Space selects the next option, and the arrow
    /// keys move left and right.
    #[cfg(feature = "vault")]
    #[test]
    fn tab_focuses_a_picker_and_space_cycles_its_options() {
        use egui::{Key, Modifiers};

        let ctx = egui::Context::default();
        let mut value = 0u8;
        let frame = |value: &mut u8, events: Vec<egui::Event>| {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, DEFAULT_SIZE)),
                events,
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| {
                kit::segmented(ui, "picker", value, &[(0, "One"), (1, "Two"), (2, "Three")]);
            });
            output.drop_without_applying_deltas();
        };
        frame(&mut value, Vec::new());
        frame(&mut value, vec![key(Key::Tab, Modifiers::NONE)]);
        frame(&mut value, Vec::new());
        frame(&mut value, vec![key(Key::Space, Modifiers::NONE)]);
        assert_eq!(value, 1, "Space selects the next option");
        frame(&mut value, vec![key(Key::ArrowRight, Modifiers::NONE)]);
        assert_eq!(value, 2);
        frame(&mut value, vec![key(Key::Space, Modifiers::NONE)]);
        assert_eq!(value, 0, "Space wraps around");
        frame(&mut value, vec![key(Key::ArrowLeft, Modifiers::NONE)]);
        assert_eq!(value, 0, "the first option stays at the left end");
    }
}
