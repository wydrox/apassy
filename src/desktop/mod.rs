//! Native eframe/egui owner shell for the Apassy desktop foundation.
//!
//! This module is a demo UI. It is not a secure vault, authenticated owner
//! channel, or verified isolation boundary.

pub mod model;
#[cfg(feature = "vault")]
pub mod owner_store;
mod ui;

use eframe::egui;

pub use model::{
    ActiveRule, ActivityEvent, AgentRecord, Clause, CopyDemo, DEMO_BANNER, DemoAlert, DemoRequest,
    DemoScenario, DesktopModel, DraftStatus, ExtraField, FoundationStatus, INTERPRETER_ID,
    ItemDetails, ItemDraft, ItemSummary, MASKED_VALUE, ModelError, ModelResult, OTHER_AGENT_ID,
    REPORTING_AGENT_ID, REPORTING_ITEM_ID, RequestStatus, SAMPLE_RULE_TEXT,
};

/// Five owner views in the desktop shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerView {
    Vault,
    Item,
    Rules,
    Agents,
    Activity,
}

impl OwnerView {
    pub const ALL: [Self; 5] = [
        Self::Vault,
        Self::Item,
        Self::Rules,
        Self::Agents,
        Self::Activity,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Vault => "Vault",
            Self::Item => "Item details",
            Self::Rules => "Rules",
            Self::Agents => "Agents",
            Self::Activity => "Activity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusKind {
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
    pub(crate) add_form: ItemDraft,
    pub(crate) edit_form: ItemDraft,
    pub(crate) pending_delete: bool,
    pub(crate) rule_text: String,
    pub(crate) scenario: DemoScenario,
    #[cfg(feature = "vault")]
    pub(crate) owner_ui: owner_store::OwnerUiState,
    /// The local agent broker. It runs only with a native window.
    #[cfg(feature = "vault")]
    pub(crate) broker: BrokerState,
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
            status_text: initial_status(),
            status_kind: StatusKind::Neutral,
            add_form: ItemDraft::default(),
            edit_form: ItemDraft::default(),
            pending_delete: false,
            rule_text: String::new(),
            scenario: DemoScenario::Normal,
            #[cfg(feature = "vault")]
            owner_ui: owner_store::OwnerUiState::default(),
            #[cfg(feature = "vault")]
            broker: BrokerState::NotStarted,
            styled: false,
        }
    }

    pub fn from_creation_context(cc: &eframe::CreationContext<'_>) -> Self {
        ui::apply_style(&cc.egui_ctx);
        let mut app = Self::new();
        app.styled = true;
        #[cfg(feature = "vault")]
        {
            app.start_broker(&crate::agent::client::default_socket_path());
            if let BrokerState::Running(handle) = &app.broker {
                let ctx = cc.egui_ctx.clone();
                handle
                    .approvals()
                    .set_notifier(move || ctx.request_repaint());
            }
        }
        app
    }

    /// Start the agent broker on `socket`. It shares the owner vault slot.
    #[cfg(feature = "vault")]
    pub fn start_broker(&mut self, socket: &std::path::Path) {
        self.broker = match crate::broker::start(self.owner_ui.session.shared_vault(), socket) {
            Ok(handle) => BrokerState::Running(handle),
            Err(err) => BrokerState::Failed(format!(
                "The agent broker did not start at {}: {err}",
                socket.display()
            )),
        };
    }

    pub fn model(&self) -> &DesktopModel {
        &self.model
    }

    pub fn view(&self) -> OwnerView {
        self.view
    }

    pub(crate) fn set_ok(&mut self, message: impl Into<String>) {
        self.status_text = message.into();
        self.status_kind = StatusKind::Ok;
    }

    pub(crate) fn set_err(&mut self, message: impl Into<String>) {
        self.status_text = message.into();
        self.status_kind = StatusKind::Error;
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
            self.owner_ui.env_field_input =
                binding.map(|binding| binding.field).unwrap_or_default();
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
        }
    }
}

impl eframe::App for DesktopApp {
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Color32::from_rgb(243, 239, 230).to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.styled {
            ui::apply_style(ui.ctx());
            self.styled = true;
        }
        ui::draw(self, ui);
    }
}

/// Native window options. Persistence is off.
pub fn native_options() -> eframe::NativeOptions {
    let mut native_options = eframe::NativeOptions::default();
    native_options.viewport.inner_size = Some(egui::Vec2::new(1280.0, 840.0));
    native_options.viewport.min_inner_size = Some(egui::Vec2::new(960.0, 640.0));
    native_options.viewport.title = Some("Apassy".to_owned());
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

fn initial_status() -> String {
    #[cfg(feature = "vault")]
    {
        format!(
            "{DEMO_BANNER} The vault is locked. No vault file is open. Item details are hidden."
        )
    }
    #[cfg(not(feature = "vault"))]
    {
        format!("{DEMO_BANNER} The vault starts locked. Open vault is not authentication.")
    }
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
        host: details.host.clone(),
        database_name: details.database_name.clone(),
        field_name: details.field_name.clone(),
        public_label: details.public_label.clone(),
    }
}
