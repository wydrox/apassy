//! Native eframe/egui owner shell for the Apassy desktop foundation.
//!
//! This module is a demo UI. It is not a secure vault, authenticated owner
//! channel, or verified isolation boundary.

/// The browser socket (ADR 0021).
#[cfg(feature = "vault")]
pub(crate) mod browser;
/// The copy of a one-time code and its clear.
#[cfg(feature = "vault")]
pub(crate) mod clipboard;
#[cfg(feature = "vault")]
mod companion;
#[cfg(feature = "vault")]
pub mod inbox;
#[cfg(feature = "vault")]
mod learning_ui;
pub mod model;
#[cfg(feature = "vault")]
pub mod notify;
/// Tests of the guarded show and copy of one-time codes.
#[cfg(all(test, feature = "vault"))]
mod otp_guard_tests;
#[cfg(feature = "vault")]
pub mod owner_check;
#[cfg(feature = "vault")]
pub(crate) mod owner_cli;
#[cfg(feature = "vault")]
pub(crate) mod owner_socket;
#[cfg(feature = "vault")]
pub mod owner_store;
/// Tests of the browser passkeys, the browser one-time codes, and the macOS passkey sheet.
#[cfg(all(test, feature = "vault"))]
mod passkey_controller_tests;
/// Passkeys for the macOS passkey sheet, through the signed credential bridge.
#[cfg(feature = "vault")]
pub(crate) mod passkey_socket;
/// Folder sync in the background (ADR 0014).
#[cfg(feature = "vault")]
pub(crate) mod sync_worker;
mod ui;
/// The view settings that survive a restart: `ui.json`.
#[cfg(feature = "vault")]
pub(crate) mod ui_prefs;
#[cfg(feature = "vault")]
pub mod unlock;
/// Automatic updates of the macOS app (ADR 0015).
#[cfg(feature = "vault")]
pub(crate) mod update;

use eframe::egui;

pub use model::{
    ActiveRule, ActivityEvent, AgentRecord, Clause, CopyDemo, DEMO_BANNER, DemoAlert, DemoRequest,
    DemoScenario, DesktopModel, DetailDraft, DraftStatus, ExtraField, FoundationStatus,
    INTERPRETER_ID, ItemDetails, ItemDraft, ItemSummary, MASKED_VALUE, ModelError, ModelResult,
    OTHER_AGENT_ID, REPORTING_AGENT_ID, REPORTING_ITEM_ID, RequestStatus, SAMPLE_RULE_TEXT,
};

/// Owner views in the desktop shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerView {
    /// The list of credentials.
    Vault,
    /// One credential.
    Item,
    /// The fixture rule interpreter of the demo build.
    #[cfg(not(feature = "vault"))]
    Rules,
    Agents,
    Activity,
    /// Ask rate, automatic decisions, patterns, and calibration (ADR 0009, goal item B10).
    #[cfg(feature = "vault")]
    Learning,
    /// Vault file, passphrase, backup, notifications, and the broker.
    #[cfg(feature = "vault")]
    Settings,
}

impl OwnerView {
    #[cfg(feature = "vault")]
    pub const ALL: [Self; 6] = [
        Self::Vault,
        Self::Item,
        Self::Agents,
        Self::Activity,
        Self::Learning,
        Self::Settings,
    ];
    #[cfg(not(feature = "vault"))]
    pub const ALL: [Self; 5] = [
        Self::Vault,
        Self::Item,
        Self::Rules,
        Self::Agents,
        Self::Activity,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Vault => "Credentials",
            Self::Item => "Credential",
            #[cfg(not(feature = "vault"))]
            Self::Rules => "Rules",
            Self::Agents => "Agents",
            Self::Activity => "Activity",
            #[cfg(feature = "vault")]
            Self::Learning => "Learning",
            #[cfg(feature = "vault")]
            Self::Settings => "Settings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusKind {
    /// Information, for example a cancelled owner check.
    Neutral,
    Ok,
    Error,
}

/// Native desktop app. Drawing code lives in [`ui`]. Tests use [`DesktopModel`].
pub struct DesktopApp {
    pub(crate) model: DesktopModel,
    pub(crate) view: OwnerView,
    pub(crate) selected_item_id: Option<String>,
    pub(crate) search: String,
    pub(crate) status_text: String,
    pub(crate) status_kind: StatusKind,
    /// Grows with each status message. The toast shows each message once.
    pub(crate) status_seq: u64,
    /// Navigation and sheet state of the drawing code.
    pub(crate) ui: ui::UiState,
    pub(crate) add_form: ItemDraft,
    pub(crate) edit_form: ItemDraft,
    pub(crate) pending_delete: bool,
    /// The rule editor text of the demo build.
    #[cfg(not(feature = "vault"))]
    pub(crate) rule_text: String,
    /// The demo request of the demo build.
    #[cfg(not(feature = "vault"))]
    pub(crate) scenario: DemoScenario,
    #[cfg(feature = "vault")]
    pub(crate) owner_ui: owner_store::OwnerUiState,
    /// The local agent broker. It runs only with a native window.
    #[cfg(feature = "vault")]
    pub(crate) broker: BrokerState,
    /// Owner checks, Touch ID unlock, notifications, and the inbox (goal items A2 to
    /// A4, N1 to N4).
    #[cfg(feature = "vault")]
    pub(crate) owner: owner_check::OwnerFlows,
    /// Learning view state (goal item B10).
    #[cfg(feature = "vault")]
    pub(crate) learning: learning_ui::LearningUiState,
    /// The list of vaults (ADR 0013).
    #[cfg(feature = "vault")]
    pub(crate) vault_list: ui::vaults::VaultListState,
    /// Import from 1Password. It holds the parsed export until the import, a cancel, or
    /// a lock.
    #[cfg(feature = "vault")]
    pub(crate) import: ui::import::ImportState,
    #[cfg(feature = "vault")]
    pub(crate) files: ui::files::FilePickerState,
    /// Update checks, downloads, and the installer (ADR 0015). Idle until the window
    /// starts it.
    #[cfg(feature = "vault")]
    pub(crate) updates: update::Updater,
    /// Sync of the vaults through a folder (ADR 0014).
    #[cfg(feature = "vault")]
    pub(crate) sync: ui::sync::SyncUiState,
    /// The owner socket and the command-line sessions (ADR 0017).
    #[cfg(feature = "vault")]
    pub(crate) cli: owner_cli::CliHost,
    /// The browser socket and the fill on its way to the extension (ADR 0021).
    #[cfg(feature = "vault")]
    pub(crate) browser: browser::BrowserHost,
    /// The credential bridge of the macOS passkey sheet. Idle until the window finds it.
    #[cfg(feature = "vault")]
    pub(crate) platform: passkey_socket::PlatformHost,
    /// The iPhone listener and the pairing state of Settings > iPhone companion (ADR 0020).
    #[cfg(feature = "vault")]
    pub(crate) companion: companion::CompanionFlows,
    /// The bouncer model server of Settings > Agents. Only the window starts it, so
    /// tests start nothing.
    #[cfg(feature = "vault")]
    pub(crate) model_server: Option<std::sync::Arc<crate::broker::model_server::ModelServer>>,
    styled: bool,
}

/// Broker state for the Agents view.
#[cfg(feature = "vault")]
#[derive(Debug, Default)]
pub(crate) enum BrokerState {
    /// Tests and the smoke test do not start the broker.
    #[default]
    NotStarted,
    Running(crate::broker::BrokerHandle),
    Failed(String),
}

impl Default for DesktopApp {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopApp {
    /// Create the demo app in memory. This does not open a window.
    pub fn new() -> Self {
        Self {
            model: DesktopModel::new(),
            view: OwnerView::Vault,
            selected_item_id: None,
            search: String::new(),
            status_text: String::new(),
            status_kind: StatusKind::Neutral,
            status_seq: 0,
            ui: ui::UiState::default(),
            add_form: ItemDraft::default(),
            edit_form: ItemDraft::default(),
            pending_delete: false,
            #[cfg(not(feature = "vault"))]
            rule_text: String::new(),
            #[cfg(not(feature = "vault"))]
            scenario: DemoScenario::Normal,
            #[cfg(feature = "vault")]
            owner_ui: owner_store::OwnerUiState::default(),
            #[cfg(feature = "vault")]
            broker: BrokerState::NotStarted,
            #[cfg(feature = "vault")]
            owner: owner_check::OwnerFlows::default(),
            #[cfg(feature = "vault")]
            learning: learning_ui::LearningUiState::default(),
            #[cfg(feature = "vault")]
            vault_list: ui::vaults::VaultListState::default(),
            #[cfg(feature = "vault")]
            import: ui::import::ImportState::default(),
            #[cfg(feature = "vault")]
            files: Default::default(),
            #[cfg(feature = "vault")]
            updates: update::Updater::idle(),
            #[cfg(feature = "vault")]
            sync: ui::sync::SyncUiState::default(),
            #[cfg(feature = "vault")]
            cli: owner_cli::CliHost::default(),
            #[cfg(feature = "vault")]
            browser: browser::BrowserHost::default(),
            #[cfg(feature = "vault")]
            platform: passkey_socket::PlatformHost::default(),
            #[cfg(feature = "vault")]
            companion: companion::CompanionFlows::default(),
            #[cfg(feature = "vault")]
            model_server: None,
            styled: false,
        }
    }

    pub fn from_creation_context(cc: &eframe::CreationContext<'_>) -> Self {
        ui::apply_style(&cc.egui_ctx);
        let mut app = Self::new();
        app.styled = true;
        #[cfg(feature = "vault")]
        {
            // `bouncer.json`: the broker uses its address, and in "With Apassy" the
            // model server starts now.
            app.model_server = Some(crate::broker::model_server::ModelServer::start_default());
            app.start_broker(&crate::agent::client::default_socket_path());
            // The notification center sets the notifier of the approval queue. It
            // wakes its watcher and repaints the window when a run starts to wait.
            app.start_native(&cc.egui_ctx);
            // The last used vault opens locked, so the window starts on the unlock
            // screen (ADR 0013).
            app.load_vault_list(crate::paths::data_dir(), true);
            app.ui.load_prefs(crate::paths::data_dir());
            app.open_last_vault(Some(&cc.egui_ctx));
            // Folder sync runs on its own thread, also while the window is hidden.
            app.start_sync_worker(&cc.egui_ctx);
            app.start_updates(&cc.egui_ctx);
            app.start_cli(&crate::owner::client::default_socket_path(), &cc.egui_ctx);
            app.start_browser(&crate::browser::wire::default_socket_path(), &cc.egui_ctx);
            // The bridge starts with each unlocked vault session.
            app.find_credential_bridge();
        }
        app
    }

    /// Start the agent broker on `socket`. It shares the owner vault slot.
    #[cfg(feature = "vault")]
    pub fn start_broker(&mut self, socket: &std::path::Path) {
        let vault = self.owner_ui.session.shared_vault();
        let started = match &self.model_server {
            Some(server) => crate::broker::start_with_model_server(vault, socket, server),
            None => crate::broker::start(vault, socket),
        };
        self.broker = match started {
            Ok(handle) => BrokerState::Running(handle),
            Err(err) => BrokerState::Failed(format!(
                "The agent broker did not start at {}: {err}",
                socket.display()
            )),
        };
    }

    /// End every agent run that waits for the owner (goal item V3), and stop the iPhone
    /// listener. Call it after a lock, backup, restore, open, or passphrase change. The
    /// broker also ends such a run when it sees the vault epoch change. This call makes
    /// the card go away at once. The listener starts again for the new vault session, in
    /// the next frame, when the setting is on and the vault is unlocked.
    #[cfg(feature = "vault")]
    pub(crate) fn end_waiting_runs(&mut self) {
        if let BrokerState::Running(handle) = &self.broker {
            handle.approvals().invalidate_all();
        }
        self.stop_companion();
    }

    pub fn model(&self) -> &DesktopModel {
        &self.model
    }

    pub fn view(&self) -> OwnerView {
        self.view
    }

    pub(crate) fn set_ok(&mut self, message: impl Into<String>) {
        self.set_status(message.into(), StatusKind::Ok);
    }

    pub(crate) fn set_err(&mut self, message: impl Into<String>) {
        self.set_status(message.into(), StatusKind::Error);
    }

    /// A message that is neither a result nor an error, for example a cancel.
    pub(crate) fn set_note(&mut self, message: impl Into<String>) {
        self.set_status(message.into(), StatusKind::Neutral);
    }

    fn set_status(&mut self, message: String, kind: StatusKind) {
        self.status_text = message;
        self.status_kind = kind;
        self.status_seq += 1;
    }

    pub(crate) fn apply<T>(&mut self, result: ModelResult<T>, ok: &str) -> Option<T> {
        match result {
            Ok(value) => {
                self.set_ok(ok);
                Some(value)
            }
            Err(err) => {
                self.set_err(err.message);
                None
            }
        }
    }

    #[cfg(not(feature = "vault"))]
    pub(crate) fn select_item(&mut self, id: String) {
        self.selected_item_id = Some(id.clone());
        self.pending_delete = false;
        self.ui.sheet = None;
        if let Ok(details) = self.model.item_details(&id)
            && !details.hidden
        {
            self.edit_form = draft_from_details(&details);
        }
        self.view = OwnerView::Item;
    }

    #[cfg(feature = "vault")]
    pub(crate) fn select_item(&mut self, id: String) {
        self.pending_delete = false;
        self.ui.sheet = None;
        self.view = OwnerView::Item;
        self.owner_ui.edit_secrets.clear();
        if let Ok(parsed) = id.parse::<u64>()
            && let Ok(details) = self.owner_ui.session.details(parsed)
            && !details.hidden
        {
            self.edit_form = details.to_draft();
            self.owner_ui.edit_revision = details.revision;
            let binding = self.owner_ui.session.env_binding(parsed).ok().flatten();
            self.owner_ui.env_name_input = binding
                .as_ref()
                .map(|binding| binding.env_name.clone())
                .unwrap_or_default();
            self.owner_ui.env_placeholder_input = matches!(
                binding.as_ref().map(|binding| &binding.delivery),
                Some(crate::vault::EnvDelivery::Placeholder(_))
            );
            self.owner_ui.env_field_input =
                binding.map(|binding| binding.field).unwrap_or_default();
            // The stored declaration, or the suggestion from the item (goal item B4).
            self.owner_ui.declaration_form = self
                .owner_ui
                .session
                .declaration_form(parsed)
                .unwrap_or_default();
            self.owner_ui.connector_url = self
                .owner_ui
                .session
                .connector(parsed)
                .ok()
                .flatten()
                .map(|destination| destination.base_url)
                .unwrap_or_default();
        }
        self.selected_item_id = Some(id);
    }

    #[cfg(not(feature = "vault"))]
    pub(crate) fn reset_demo(&mut self) {
        let result = self.model.reset();
        if self
            .apply(
                result,
                "Fixture data is loaded again. Earlier demo state is gone.",
            )
            .is_some()
        {
            self.view = OwnerView::Vault;
            self.selected_item_id = None;
            self.search.clear();
            self.add_form = ItemDraft::default();
            self.edit_form = ItemDraft::default();
            self.pending_delete = false;
            self.rule_text.clear();
            self.scenario = DemoScenario::Normal;
            self.ui.sheet = None;
        }
    }
}

impl eframe::App for DesktopApp {
    fn persist_egui_memory(&self) -> bool {
        false
    }

    /// Waiting runs end and stay in the inbox. The vault locks. Typed secrets are
    /// erased (goal items V3, N3; key-memory review F3). Then a ready update installs
    /// when automatic install is on (ADR 0015).
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        #[cfg(feature = "vault")]
        {
            // A Mac that joins through the relay cancels its link or its device.
            self.relay_quit();
            // No background sync after this: the lock in `shut_down` syncs last.
            self.stop_sync_worker();
            self.shut_down();
            // A model server that Apassy started stops with the app.
            if let Some(server) = &self.model_server {
                server.shutdown();
            }
            self.finish_updates();
        }
    }

    /// eframe calls this each frame, and also while the window is hidden or minimized.
    /// So the command line gets its answer without a visible window.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(feature = "vault")]
        {
            self.poll_cli(ctx);
            self.poll_browser(ctx);
            self.poll_platform(ctx);
        }
        #[cfg(not(feature = "vault"))]
        let _ = ctx;
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        ui::WINDOW_COLOR.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.styled {
            ui::apply_style(ui.ctx());
            self.styled = true;
        }
        ui::draw(self, ui);
    }
}

/// Native window options. Persistence is off. The title bar is transparent, and the
/// sidebar runs under it, as in a SwiftUI `NavigationSplitView`. The empty icon keeps
/// the icon of the bundle (`packaging/AppIcon.icns`) in the Dock: without it, eframe
/// replaces the Dock icon with the egui logo at start.
pub fn native_options() -> eframe::NativeOptions {
    let mut native_options = eframe::NativeOptions::default();
    native_options.viewport = native_options
        .viewport
        .with_icon(egui::IconData::default())
        .with_inner_size(egui::Vec2::new(1180.0, 800.0))
        .with_min_inner_size(egui::Vec2::new(900.0, 600.0))
        .with_title("Apassy")
        .with_fullsize_content_view(true)
        .with_titlebar_shown(false)
        .with_title_shown(false);
    native_options.persist_window = false;
    native_options.centered = true;
    native_options
}

/// Open the native desktop window.
pub fn run() -> eframe::Result {
    eframe::run_native(
        "apassy",
        native_options(),
        Box::new(|cc| Ok(Box::new(DesktopApp::from_creation_context(cc)))),
    )
}

/// Exercise the desktop model without a window. This is not a graphical test.
pub fn smoke_test() -> Result<(), String> {
    use crate::contracts::{CredentialKind, Decision};

    let mut app = DesktopApp::new();
    if !app.model.is_locked() {
        return Err("the demo must start locked".to_owned());
    }
    let status = app.model.foundation_status();
    if status.banner != DEMO_BANNER {
        return Err("the demo banner is missing".to_owned());
    }
    if status.storage != "not connected"
        || status.model != "unverified"
        || status.isolation != "unverified"
    {
        return Err("foundation status must stay unverified".to_owned());
    }
    app.model.unlock().map_err(|err| err.message)?;
    if app.model.is_locked() {
        return Err("open vault failed".to_owned());
    }

    for kind in CredentialKind::ALL {
        let created = app
            .model
            .create_item(ItemDraft {
                name: format!("Smoke {}", kind.label()),
                kind,
                ..ItemDraft::default()
            })
            .map_err(|err| err.message)?;
        if created.kind != kind {
            return Err("create did not keep the category".to_owned());
        }
        if app.model.list_items(&created.name).len() != 1 {
            return Err("search missed a created item".to_owned());
        }
        app.model
            .update_item(
                &created.id,
                ItemDraft {
                    name: format!("Smoke {} 2", kind.label()),
                    kind,
                    ..ItemDraft::default()
                },
            )
            .map_err(|err| err.message)?;
        app.model
            .delete_item(&created.id)
            .map_err(|err| err.message)?;
    }

    let details = app
        .model
        .item_details(REPORTING_ITEM_ID)
        .map_err(|err| err.message)?;
    if details.revealed || details.display_value != MASKED_VALUE {
        return Err("values must stay masked until reveal".to_owned());
    }
    let revealed = app
        .model
        .reveal_item(REPORTING_ITEM_ID)
        .map_err(|err| err.message)?;
    if !revealed.revealed {
        return Err("demo reveal failed".to_owned());
    }
    let copy = app
        .model
        .demo_copy_item(REPORTING_ITEM_ID)
        .map_err(|err| err.message)?;
    if copy.wrote_clipboard {
        return Err("the desktop must not write the clipboard".to_owned());
    }

    app.model
        .connect_agent(REPORTING_AGENT_ID)
        .map_err(|err| err.message)?;
    let draft = app
        .model
        .interpret_rule(SAMPLE_RULE_TEXT)
        .map_err(|err| err.message)?;
    if draft.status != DraftStatus::ReadyForReview {
        return Err("supported sample must be ready for review".to_owned());
    }
    app.model.confirm_rule().map_err(|err| err.message)?;
    app.model.activate_rule().map_err(|err| err.message)?;

    let refused = app
        .model
        .interpret_rule(model::UNSUPPORTED_SAMPLE_TEXT)
        .map_err(|err| err.message)?;
    if refused.status != DraftStatus::Blocked {
        return Err("unsupported prose must be refused".to_owned());
    }

    let allow = app
        .model
        .simulate(DemoScenario::Normal)
        .map_err(|err| err.message)?;
    if allow.decision != Decision::Allow || !allow.executed {
        return Err("normal fixture path must permit without extra approval".to_owned());
    }
    let ask = app
        .model
        .simulate(DemoScenario::Uncertain)
        .map_err(|err| err.message)?;
    if ask.decision != Decision::RequireApproval || ask.executed {
        return Err("uncertain fixture path must wait".to_owned());
    }
    app.model
        .approve_once(&ask.id, None)
        .map_err(|err| err.message)?;
    let deny = app
        .model
        .simulate(DemoScenario::Production)
        .map_err(|err| err.message)?;
    if deny.decision != Decision::Deny || deny.approvable {
        return Err("production fixture path must deny".to_owned());
    }

    let waiting = app
        .model
        .simulate(DemoScenario::Uncertain)
        .map_err(|err| err.message)?;
    app.model
        .revoke_agent(REPORTING_AGENT_ID)
        .map_err(|err| err.message)?;
    let revoked = app
        .model
        .list_requests()
        .iter()
        .find(|request| request.id == waiting.id)
        .ok_or_else(|| "waiting request missing after revoke".to_owned())?;
    if revoked.status != RequestStatus::Invalidated {
        return Err("revoke must invalidate waiting requests".to_owned());
    }

    app.model
        .connect_agent(REPORTING_AGENT_ID)
        .map_err(|err| err.message)?;
    let _ = app.model.interpret_rule(SAMPLE_RULE_TEXT);
    let _ = app.model.confirm_rule();
    let _ = app.model.activate_rule();
    let pending = app
        .model
        .simulate(DemoScenario::Uncertain)
        .map_err(|err| err.message)?;
    app.model.lock().map_err(|err| err.message)?;
    match app.model.approve_once(&pending.id, None) {
        Err(err) if err.code == "vault_locked" => {}
        other => {
            return Err(format!("lock must invalidate approval, got {other:?}"));
        }
    }
    #[cfg(feature = "vault")]
    owner_store::smoke_roundtrip()?;
    Ok(())
}

#[cfg(not(feature = "vault"))]
fn draft_from_details(details: &ItemDetails) -> ItemDraft {
    ItemDraft {
        name: details.name.clone(),
        kind: details.kind,
        service: details.service.clone(),
        project: details.project.clone(),
        notes: details.notes.clone(),
        username: details.username.clone(),
        website: String::new(),
        host: details.host.clone(),
        database_name: details.database_name.clone(),
        field_name: details.field_name.clone(),
        public_label: details.public_label.clone(),
        details: Vec::new(),
    }
}
