//! In-memory demo model for the Apassy desktop foundation.
//!
//! This module is not a vault, policy engine, or bouncer. It holds fixture
//! data for a visual owner shell. Values are synthetic. State is not durable.

use std::collections::HashSet;

use crate::contracts::{CONTRACT_VERSION, CredentialKind, Decision};

pub const DEMO_BANNER: &str = "Demo data only. Not a secure vault.";
pub const INTERPRETER_ID: &str = "fixture-interpreter-v1";
pub const MASKED_VALUE: &str = "••••••••";
pub const REPORTING_AGENT_ID: &str = "reporting-agent";
pub const OTHER_AGENT_ID: &str = "other-agent";
pub const REPORTING_ITEM_ID: &str = "item-reporting-api";
pub const SAMPLE_DESTINATION: &str = "staging";
pub const DENIED_DESTINATION: &str = "production";
pub const SAMPLE_OPERATION: &str = "read_report";
pub const SAMPLE_EXPIRY_ISO: &str = "2026-09-18T23:59:59-04:00";
pub const SAMPLE_TIME_ZONE: &str = "America/New_York";
pub const SAMPLE_USAGE_LIMIT: u32 = 3;
pub const DEFAULT_NOW_ISO: &str = "2026-09-16T16:00:00.000Z";
pub const AFTER_EXPIRY_ISO: &str = "2026-09-19T04:00:00.000Z";
pub const POLICY_SCHEMA: &str = "desktop-demo-policy-v1";

pub const SAMPLE_RULE_TEXT: &str = "My reporting agent can use this credential for Project A, against staging, until Friday. Never use it for production. Ask me if the request does not fit the task.";
pub const AMBIGUOUS_SAMPLE_TEXT: &str = "Let the agent use the credential until Friday.";
pub const CONFLICTING_SAMPLE_TEXT: &str = "My reporting agent can use this credential for Project A against staging and production. Never use it for production.";
pub const UNSUPPORTED_SAMPLE_TEXT: &str =
    "My reporting agent can run any SQL on any database and send the password to the agent.";

const DEFAULT_NOW_MS: i64 = 0;
const SAMPLE_EXPIRY_MS: i64 = 215_999_000;
const AFTER_EXPIRY_MS: i64 = 216_000_000;

const REVEAL_WARNING: &str = "This is a demo reveal. There is no authenticated owner check.";
const COPY_WARNING: &str =
    "A copy takes the value outside Apassy control. This desktop does not write to the clipboard.";

/// Result of a demo model action.
pub type ModelResult<T> = Result<T, ModelError>;

/// Failure from a demo model action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError {
    pub code: &'static str,
    pub message: String,
}

/// Honest status of this desktop foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationStatus {
    pub banner: &'static str,
    pub storage: &'static str,
    pub model: &'static str,
    pub isolation: &'static str,
    pub persistence: &'static str,
    pub encryption: &'static str,
    pub interpreter: &'static str,
    pub contract_version: u32,
}

/// Label fields for a vault item. There is no secret input field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemDraft {
    pub name: String,
    pub kind: CredentialKind,
    pub service: String,
    pub project: String,
    pub notes: String,
    pub username: String,
    pub host: String,
    pub database_name: String,
    pub field_name: String,
    pub public_label: String,
}

impl Default for ItemDraft {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: CredentialKind::ApiKey,
            service: String::new(),
            project: String::new(),
            notes: String::new(),
            username: String::new(),
            host: String::new(),
            database_name: String::new(),
            field_name: String::new(),
            public_label: String::new(),
        }
    }
}

/// Public item row. This type does not include a synthetic value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: String,
    pub name: String,
    pub kind: CredentialKind,
    pub service: String,
    pub project: String,
    pub notes: String,
    pub username: String,
    pub host: String,
    pub database_name: String,
    pub field_name: String,
    pub public_label: String,
    pub revision: u32,
    pub agent_use_label: &'static str,
}

/// Item detail for the owner view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemDetails {
    pub id: String,
    pub name: String,
    pub kind: CredentialKind,
    pub service: String,
    pub project: String,
    pub notes: String,
    pub username: String,
    pub host: String,
    pub database_name: String,
    pub field_name: String,
    pub public_label: String,
    pub revision: u32,
    pub agent_use_label: &'static str,
    pub hidden: bool,
    pub revealed: bool,
    pub synthetic_value: Option<String>,
    pub masked_value: &'static str,
    pub display_value: String,
    pub reveal_warning: &'static str,
    pub copy_warning: &'static str,
    pub message: String,
}

/// Demo copy result. The desktop never writes the clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyDemo {
    pub wrote_clipboard: bool,
    pub warning: &'static str,
}

/// Catalog or connected agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub connected: bool,
    pub generation: u32,
    pub status_label: &'static str,
}

/// Fixture interpreter draft. This is not live language support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDraft {
    pub id: String,
    pub original_text: String,
    pub interpreter: &'static str,
    pub status: DraftStatus,
    pub reason_code: &'static str,
    pub confirmed: bool,
    pub can_activate: bool,
    pub clauses: Vec<Clause>,
    pub issues: Vec<Issue>,
    pub questions: Vec<String>,
    pub examples: Option<Examples>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftStatus {
    ReadyForReview,
    NeedsClarification,
    Blocked,
}

impl DraftStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadyForReview => "Ready for review",
            Self::NeedsClarification => "Needs clarification",
            Self::Blocked => "Blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub text: String,
    pub kind_label: &'static str,
    pub meaning: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Examples {
    pub allow: String,
    pub ask: String,
    pub deny: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRule {
    pub id: String,
    pub status: &'static str,
    pub original_text: String,
    pub interpreter: &'static str,
    pub schema: &'static str,
    pub version: u32,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_generation: u32,
    pub item_id: String,
    pub item_name: String,
    pub item_revision: u32,
    pub destination: &'static str,
    pub denied_destinations: Vec<&'static str>,
    pub operation: &'static str,
    pub expiry_iso: &'static str,
    pub time_zone: &'static str,
    pub usage_limit: u32,
    pub use_count: u32,
    pub remaining_uses: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoScenario {
    Normal,
    Uncertain,
    Production,
}

impl DemoScenario {
    pub const ALL: [Self; 3] = [Self::Normal, Self::Uncertain, Self::Production];

    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal staging report",
            Self::Uncertain => "Uncertain task on staging",
            Self::Production => "Production report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Completed,
    Pending,
    Denied,
    Invalidated,
}

impl RequestStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Pending => "pending",
            Self::Denied => "denied",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoRequest {
    pub id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub item_id: String,
    pub item_name: String,
    pub item_revision: Option<u32>,
    pub destination: String,
    pub operation: String,
    pub purpose: String,
    pub decision: Decision,
    pub initial_decision: Decision,
    pub reason_code: &'static str,
    pub initial_reason_code: &'static str,
    pub status: RequestStatus,
    pub message: String,
    pub approvable: bool,
    pub executed: bool,
    pub approval_consumed: bool,
    pub digest: String,
    pub delivery_status: &'static str,
    pub epoch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoAlert {
    pub id: String,
    pub request_id: String,
    pub title: String,
    pub message: String,
    pub decision: Decision,
    pub status: RequestStatus,
    pub agent_id: String,
    pub agent_name: String,
    pub item_name: String,
    pub destination: String,
    pub operation: String,
    pub delivery_status: &'static str,
    pub delivery_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEvent {
    pub id: String,
    pub at_iso: String,
    pub kind: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationHealth {
    pub healthy: bool,
    pub label: &'static str,
}

struct Item {
    id: String,
    name: String,
    kind: CredentialKind,
    service: String,
    project: String,
    notes: String,
    username: String,
    host: String,
    database_name: String,
    field_name: String,
    public_label: String,
    revision: u32,
    synthetic_value: String,
}

struct Agent {
    id: String,
    name: String,
    summary: String,
    connected: bool,
    generation: u32,
}

struct LiveRule {
    public: ActiveRule,
    expiry_ms: i64,
}

/// Concise in-memory owner demo. This is not a security backend.
pub struct DesktopModel {
    locked: bool,
    epoch: u32,
    now_ms: i64,
    now_iso: String,
    items: Vec<Item>,
    revealed: HashSet<String>,
    agents: Vec<Agent>,
    draft: Option<RuleDraft>,
    active_rule: Option<LiveRule>,
    requests: Vec<DemoRequest>,
    alerts: Vec<DemoAlert>,
    activity: Vec<ActivityEvent>,
    notification_healthy: bool,
    issued_secrets: HashSet<String>,
    seq_item: u32,
    seq_request: u32,
    seq_alert: u32,
    seq_event: u32,
    seq_draft: u32,
}

impl Default for DesktopModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopModel {
    /// Create the demo in the locked view. Open vault is not authentication.
    pub fn new() -> Self {
        let mut model = Self {
            locked: true,
            epoch: 1,
            now_ms: DEFAULT_NOW_MS,
            now_iso: DEFAULT_NOW_ISO.to_owned(),
            items: Vec::new(),
            revealed: HashSet::new(),
            agents: Vec::new(),
            draft: None,
            active_rule: None,
            requests: Vec::new(),
            alerts: Vec::new(),
            activity: Vec::new(),
            notification_healthy: true,
            issued_secrets: HashSet::new(),
            seq_item: 1,
            seq_request: 1,
            seq_alert: 1,
            seq_event: 1,
            seq_draft: 1,
        };
        model.load_fixtures();
        model
    }

    pub fn foundation_status(&self) -> FoundationStatus {
        FoundationStatus {
            banner: DEMO_BANNER,
            storage: "not connected",
            model: "unverified",
            isolation: "unverified",
            persistence: "in-memory only. Not durable.",
            encryption: "not present",
            interpreter: INTERPRETER_ID,
            contract_version: CONTRACT_VERSION,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn now_iso(&self) -> &str {
        &self.now_iso
    }

    pub fn lock_state_label(&self) -> &'static str {
        if self.locked {
            "The vault is locked. Item details are hidden. Pending demo authority is not valid."
        } else {
            "The vault is open. Open vault is not owner authentication."
        }
    }

    pub fn reset(&mut self) -> ModelResult<()> {
        self.load_fixtures();
        self.record(
            "reset",
            "The demo loaded fixture data again. Earlier demo state is gone.",
        );
        Ok(())
    }

    pub fn lock(&mut self) -> ModelResult<()> {
        self.locked = true;
        self.epoch = self.epoch.saturating_add(1);
        self.revealed.clear();
        self.invalidate_pending(
            "vault_locked",
            "The vault lock made pending demo authority invalid.",
        );
        self.record(
            "lock",
            "The vault is locked. Item details are hidden. Pending demo authority is not valid.",
        );
        Ok(())
    }

    pub fn unlock(&mut self) -> ModelResult<()> {
        self.locked = false;
        self.record(
            "unlock",
            "The vault is open. This control is not owner authentication.",
        );
        Ok(())
    }

    pub fn list_items(&self, query: &str) -> Vec<ItemSummary> {
        let needle = query.trim().to_lowercase();
        self.items
            .iter()
            .filter(|item| item_matches(item, &needle))
            .map(public_item)
            .collect()
    }

    pub fn item_details(&self, id: &str) -> ModelResult<ItemDetails> {
        let item = self
            .find_item(id)
            .ok_or_else(|| fail("not_found", "The item is not in the vault."))?;
        if self.locked {
            return Ok(ItemDetails {
                id: item.id.clone(),
                name: item.name.clone(),
                kind: item.kind,
                service: item.service.clone(),
                project: item.project.clone(),
                notes: String::new(),
                username: String::new(),
                host: String::new(),
                database_name: String::new(),
                field_name: String::new(),
                public_label: String::new(),
                revision: item.revision,
                agent_use_label: agent_use_label(item.kind),
                hidden: true,
                revealed: false,
                synthetic_value: None,
                masked_value: MASKED_VALUE,
                display_value: MASKED_VALUE.to_owned(),
                reveal_warning: REVEAL_WARNING,
                copy_warning: COPY_WARNING,
                message: "The vault is locked. Item details are hidden.".to_owned(),
            });
        }
        let revealed = self.revealed.contains(&item.id);
        Ok(details_from_item(item, revealed))
    }

    pub fn create_item(&mut self, draft: ItemDraft) -> ModelResult<ItemSummary> {
        self.require_open()?;
        let fields = checked_fields(draft, true)?;
        if fields.name.is_empty() {
            return Err(fail("invalid_name", "The item name is required."));
        }
        let id = format!("item-{}", self.seq_item);
        self.seq_item += 1;
        let item = build_item(id, &fields, 1);
        self.issued_secrets.insert(item.synthetic_value.clone());
        let summary = public_item(&item);
        let message = format!("The desktop added {}.", item.name);
        self.items.push(item);
        self.record("item_create", &message);
        Ok(summary)
    }

    pub fn update_item(&mut self, id: &str, draft: ItemDraft) -> ModelResult<ItemSummary> {
        self.require_open()?;
        let fields = checked_fields(draft, false)?;
        let item = self
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| fail("not_found", "The item is not in the vault."))?;
        if fields.kind != item.kind {
            return Err(fail(
                "category_locked",
                "This desktop does not change item category. Delete the item and add a new item.",
            ));
        }
        if fields.name.is_empty() {
            return Err(fail("invalid_name", "The item name is required."));
        }
        apply_fields(item, &fields);
        item.revision = item.revision.saturating_add(1);
        self.revealed.remove(&item.id);
        let item_id = item.id.clone();
        let name = item.name.clone();
        let summary = public_item(item);
        self.invalidate_pending_for_item(
            &item_id,
            "item_revision_changed",
            "The item revision changed. Pending demo authority for this item is not valid.",
        );
        self.record("item_update", &format!("The desktop updated {name}."));
        Ok(summary)
    }

    pub fn delete_item(&mut self, id: &str) -> ModelResult<()> {
        self.require_open()?;
        let index = self
            .items
            .iter()
            .position(|item| item.id == id)
            .ok_or_else(|| fail("not_found", "The item is not in the vault."))?;
        let item = self.items.remove(index);
        self.revealed.remove(&item.id);
        if let Some(rule) = self.active_rule.as_mut()
            && rule.public.item_id == id
        {
            rule.public.status = "revoked";
        }
        if self
            .draft
            .as_ref()
            .is_some_and(|draft| draft.examples.is_some() && id == REPORTING_ITEM_ID)
        {
            self.draft = None;
        }
        self.invalidate_pending_for_item(
            id,
            "item_deleted",
            "The item was deleted. Pending demo authority for this item is not valid.",
        );
        self.record(
            "item_delete",
            &format!("The desktop deleted {}.", item.name),
        );
        Ok(())
    }

    pub fn reveal_item(&mut self, id: &str) -> ModelResult<ItemDetails> {
        self.require_open()?;
        let item = self
            .find_item(id)
            .ok_or_else(|| fail("not_found", "The item is not in the vault."))?;
        let name = item.name.clone();
        let item_id = item.id.clone();
        self.revealed.insert(item_id);
        self.record(
            "reveal",
            &format!("A demo reveal showed the synthetic value for {name}."),
        );
        self.item_details(id)
    }

    pub fn hide_item(&mut self, id: &str) -> ModelResult<ItemDetails> {
        if self.find_item(id).is_none() {
            return Err(fail("not_found", "The item is not in the vault."));
        }
        self.revealed.remove(id);
        self.item_details(id)
    }

    pub fn demo_copy_item(&mut self, id: &str) -> ModelResult<CopyDemo> {
        self.require_open()?;
        let item = self
            .find_item(id)
            .ok_or_else(|| fail("not_found", "The item is not in the vault."))?;
        if !self.revealed.contains(&item.id) {
            return Err(fail(
                "not_revealed",
                "Show the demo value before you use the copy control.",
            ));
        }
        let name = item.name.clone();
        self.record(
            "copy_demo",
            &format!("Copy control used for {name}. The desktop did not write to the clipboard."),
        );
        Ok(CopyDemo {
            wrote_clipboard: false,
            warning: COPY_WARNING,
        })
    }

    pub fn catalog_agents(&self) -> [AgentRecord; 2] {
        [
            self.agent_record(
                REPORTING_AGENT_ID,
                "Reporting agent",
                "Synthetic agent for Project A reports.",
            ),
            self.agent_record(
                OTHER_AGENT_ID,
                "Other agent",
                "Synthetic agent with no sample grant.",
            ),
        ]
    }

    pub fn list_agents(&self) -> Vec<AgentRecord> {
        self.agents.iter().map(public_agent).collect()
    }

    pub fn connect_agent(&mut self, id: &str) -> ModelResult<AgentRecord> {
        let known = catalog_meta(id).ok_or_else(|| {
            fail(
                "unknown_agent",
                "This desktop can connect only the synthetic catalog agents.",
            )
        })?;
        if let Some(existing) = self.agents.iter_mut().find(|agent| agent.id == id) {
            if existing.connected {
                return Err(fail(
                    "already_connected",
                    &format!("{} is already connected.", known.1),
                ));
            }
            existing.connected = true;
            existing.generation = existing.generation.saturating_add(1);
            let record = public_agent(existing);
            self.record(
                "agent_connect",
                &format!(
                    "{} is connected again. Old grants do not return.",
                    record.name
                ),
            );
            return Ok(record);
        }
        let agent = Agent {
            id: known.0.to_owned(),
            name: known.1.to_owned(),
            summary: known.2.to_owned(),
            connected: true,
            generation: 1,
        };
        let record = public_agent(&agent);
        self.agents.push(agent);
        self.record("agent_connect", &format!("{} is connected.", record.name));
        Ok(record)
    }

    pub fn revoke_agent(&mut self, id: &str) -> ModelResult<AgentRecord> {
        let agent = self
            .agents
            .iter_mut()
            .find(|agent| agent.id == id && agent.connected)
            .ok_or_else(|| fail("not_connected", "The agent is not connected."))?;
        agent.connected = false;
        let record = public_agent(agent);
        if let Some(rule) = self.active_rule.as_mut()
            && rule.public.agent_id == id
        {
            rule.public.status = "revoked";
        }
        self.invalidate_pending_for_agent(
            id,
            "agent_revoked",
            "The agent is revoked. Pending demo authority for this agent is not valid.",
        );
        self.record(
            "agent_revoke",
            &format!("{} is revoked. Future sample use is denied.", record.name),
        );
        Ok(record)
    }

    pub fn interpret_rule(&mut self, text: &str) -> ModelResult<RuleDraft> {
        let original = text.to_owned();
        let normalized = normalize_rule_text(text);
        let draft_id = format!("draft-{}", self.seq_draft);
        self.seq_draft += 1;
        let draft = if normalized.is_empty() {
            blocked_draft(
                draft_id,
                original,
                "empty",
                vec![issue("missing_text", "Rule text is missing.")],
            )
        } else if normalized == normalize_rule_text(SAMPLE_RULE_TEXT) {
            self.sample_draft(draft_id, original)
        } else if normalized == normalize_rule_text(AMBIGUOUS_SAMPLE_TEXT) {
            ambiguous_draft(draft_id, original)
        } else if normalized == normalize_rule_text(CONFLICTING_SAMPLE_TEXT) {
            conflicting_draft(draft_id, original)
        } else if normalized == normalize_rule_text(UNSUPPORTED_SAMPLE_TEXT) {
            unsupported_draft(draft_id, original)
        } else {
            blocked_draft(
                draft_id,
                original,
                "unfamiliar_text",
                vec![issue(
                    "unfamiliar_text",
                    "The fixture interpreter does not recognize this text. It does not guess missing meaning.",
                )],
            )
        };
        let ready = draft.status == DraftStatus::ReadyForReview;
        let message = if ready {
            "The fixture interpreter produced a reviewable sample draft."
        } else {
            "The fixture interpreter did not activate a rule. Review the issues."
        };
        self.draft = Some(draft.clone());
        self.record("rule_interpret", message);
        Ok(draft)
    }

    pub fn rule_draft(&self) -> Option<&RuleDraft> {
        self.draft.as_ref()
    }

    pub fn confirm_rule(&mut self) -> ModelResult<RuleDraft> {
        self.require_open()?;
        if self.draft.is_none() {
            return Err(fail("no_draft", "There is no rule draft to confirm."));
        }
        let not_ready = self
            .draft
            .as_ref()
            .is_some_and(|draft| draft.status != DraftStatus::ReadyForReview);
        if not_ready {
            return Err(fail(
                "not_ready",
                "This draft is not ready. The fixture interpreter does not activate unclear or unsupported text.",
            ));
        }
        let live = sample_binding_issues(
            self.connected_agent(REPORTING_AGENT_ID).is_some(),
            self.find_item(REPORTING_ITEM_ID).is_some(),
        );
        let draft = self.draft.as_mut().expect("draft checked above");
        if !live.is_empty() {
            draft.status = DraftStatus::NeedsClarification;
            draft.issues = live.clone();
            draft.confirmed = false;
            draft.can_activate = false;
            return Err(fail("not_ready", &live[0].message));
        }
        draft.confirmed = true;
        let out = draft.clone();
        self.record(
            "rule_confirm",
            "The owner demo confirmation accepted the sample interpretation.",
        );
        Ok(out)
    }

    pub fn activate_rule(&mut self) -> ModelResult<ActiveRule> {
        self.require_open()?;
        let (draft_id, original_text, status, confirmed) = {
            let Some(draft) = self.draft.as_ref() else {
                return Err(fail("no_draft", "There is no rule draft to activate."));
            };
            (
                draft.id.clone(),
                draft.original_text.clone(),
                draft.status,
                draft.confirmed,
            )
        };
        if status != DraftStatus::ReadyForReview {
            return Err(fail(
                "not_ready",
                "Activation is blocked. The fixture interpreter does not activate this text.",
            ));
        }
        if !confirmed {
            return Err(fail(
                "confirmation_required",
                "Activation is blocked until the owner demo confirmation is recorded.",
            ));
        }
        let live = sample_binding_issues(
            self.connected_agent(REPORTING_AGENT_ID).is_some(),
            self.find_item(REPORTING_ITEM_ID).is_some(),
        );
        if !live.is_empty() {
            if let Some(draft) = self.draft.as_mut() {
                draft.status = DraftStatus::NeedsClarification;
                draft.issues = live.clone();
                draft.can_activate = false;
            }
            return Err(fail("not_ready", &live[0].message));
        }
        if self.now_ms >= SAMPLE_EXPIRY_MS {
            return Err(fail(
                "expired",
                "The sample expiry is in the past. The rule is not active.",
            ));
        }
        let (agent_id, agent_name, agent_generation) = {
            let Some(agent) = self.connected_agent(REPORTING_AGENT_ID) else {
                return Err(fail("not_ready", "The reporting agent is not connected."));
            };
            (agent.id.clone(), agent.name.clone(), agent.generation)
        };
        let (item_id, item_name, item_revision) = {
            let Some(item) = self.find_item(REPORTING_ITEM_ID) else {
                return Err(fail(
                    "not_ready",
                    "Project A reporting service is not in the vault.",
                ));
            };
            (item.id.clone(), item.name.clone(), item.revision)
        };
        let version = self
            .active_rule
            .as_ref()
            .map(|rule| rule.public.version.saturating_add(1))
            .unwrap_or(1);
        if let Some(rule) = self.active_rule.as_mut()
            && rule.public.status == "active"
        {
            rule.public.status = "superseded";
        }
        let public = ActiveRule {
            id: format!("rule-{draft_id}"),
            status: "active",
            original_text,
            interpreter: INTERPRETER_ID,
            schema: POLICY_SCHEMA,
            version,
            agent_id,
            agent_name,
            agent_generation,
            item_id,
            item_name,
            item_revision,
            destination: SAMPLE_DESTINATION,
            denied_destinations: vec![DENIED_DESTINATION],
            operation: SAMPLE_OPERATION,
            expiry_iso: SAMPLE_EXPIRY_ISO,
            time_zone: SAMPLE_TIME_ZONE,
            usage_limit: SAMPLE_USAGE_LIMIT,
            use_count: 0,
            remaining_uses: SAMPLE_USAGE_LIMIT,
        };
        self.active_rule = Some(LiveRule {
            public: public.clone(),
            expiry_ms: SAMPLE_EXPIRY_MS,
        });
        self.record(
            "rule_activate",
            "The sample rule is active in this desktop demo.",
        );
        Ok(public)
    }

    pub fn active_rule(&self) -> Option<&ActiveRule> {
        self.active_rule.as_ref().map(|rule| &rule.public)
    }

    pub fn simulate(&mut self, scenario: DemoScenario) -> ModelResult<DemoRequest> {
        let (destination, purpose) = match scenario {
            DemoScenario::Normal => (SAMPLE_DESTINATION, "weekly Project A report"),
            DemoScenario::Uncertain => (SAMPLE_DESTINATION, "unclear task"),
            DemoScenario::Production => (DENIED_DESTINATION, "weekly Project A report"),
        };
        self.submit_request(
            REPORTING_AGENT_ID,
            REPORTING_ITEM_ID,
            destination,
            SAMPLE_OPERATION,
            purpose,
        )
    }

    pub fn submit_request(
        &mut self,
        agent_id: &str,
        item_id: &str,
        destination: &str,
        operation: &str,
        purpose: &str,
    ) -> ModelResult<DemoRequest> {
        if agent_id.trim().is_empty()
            || item_id.trim().is_empty()
            || destination.trim().is_empty()
            || operation.trim().is_empty()
            || purpose.trim().is_empty()
        {
            return Err(fail(
                "invalid_request",
                "Agent, item, destination, operation, and purpose are required.",
            ));
        }
        let agent_name = self
            .agents
            .iter()
            .find(|agent| agent.id == agent_id)
            .map(|agent| agent.name.clone())
            .or_else(|| catalog_meta(agent_id).map(|meta| meta.1.to_owned()))
            .unwrap_or_else(|| agent_id.to_owned());
        let item_name = self
            .find_item(item_id)
            .map(|item| item.name.clone())
            .unwrap_or_else(|| item_id.to_owned());
        let item_revision = self.find_item(item_id).map(|item| item.revision);
        let agent_generation = self.connected_agent(agent_id).map(|agent| agent.generation);
        let id = format!("req-{}", self.seq_request);
        self.seq_request += 1;
        let digest = request_digest(
            agent_id,
            item_id,
            item_revision,
            destination,
            operation,
            purpose,
            agent_generation,
        );
        let mut request = DemoRequest {
            id,
            agent_id: agent_id.to_owned(),
            agent_name,
            item_id: item_id.to_owned(),
            item_name,
            item_revision,
            destination: destination.to_owned(),
            operation: operation.to_owned(),
            purpose: purpose.to_owned(),
            decision: Decision::Deny,
            initial_decision: Decision::Deny,
            reason_code: "no_grant",
            initial_reason_code: "no_grant",
            status: RequestStatus::Denied,
            message: String::new(),
            approvable: false,
            executed: false,
            approval_consumed: false,
            digest,
            delivery_status: "attempted",
            epoch: self.epoch,
        };
        let outcome = self.decide(&request);
        request.decision = outcome.decision;
        request.initial_decision = outcome.decision;
        request.reason_code = outcome.reason_code;
        request.initial_reason_code = outcome.reason_code;
        request.message = outcome.message;
        request.approvable = outcome.approvable;
        request.status = outcome.status;
        if outcome.decision == Decision::Allow {
            self.consume_use(&request);
            request.status = RequestStatus::Completed;
            request.executed = true;
        }
        let delivery_status = if self.notification_healthy {
            "attempted"
        } else {
            "failed"
        };
        let delivery_message = if request.status == RequestStatus::Pending {
            if self.notification_healthy {
                "A local demo notification was attempted. This is not proof that an owner saw it."
            } else {
                "Notification delivery failed. The request still waits in the inbox."
            }
        } else if self.notification_healthy {
            "A local demo notification was attempted."
        } else {
            "Notification delivery failed. The recorded decision is still in the inbox."
        };
        request.delivery_status = delivery_status;
        let alert = DemoAlert {
            id: format!("alert-{}", self.seq_alert),
            request_id: request.id.clone(),
            title: alert_title(request.decision, request.status),
            message: request.message.clone(),
            decision: request.decision,
            status: request.status,
            agent_id: request.agent_id.clone(),
            agent_name: request.agent_name.clone(),
            item_name: request.item_name.clone(),
            destination: request.destination.clone(),
            operation: request.operation.clone(),
            delivery_status,
            delivery_message: delivery_message.to_owned(),
        };
        self.seq_alert += 1;
        self.assert_no_secret(&request.message);
        self.assert_no_secret(&alert.message);
        let message = request.message.clone();
        self.requests.push(request.clone());
        self.alerts.push(alert);
        self.record("request", &message);
        Ok(request)
    }

    pub fn approve_once(
        &mut self,
        request_id: &str,
        claimed_digest: Option<&str>,
    ) -> ModelResult<DemoRequest> {
        if self.locked {
            return Err(fail(
                "vault_locked",
                "The vault is locked. Pending demo authority is not valid.",
            ));
        }
        let index = self
            .requests
            .iter()
            .position(|request| request.id == request_id)
            .ok_or_else(|| fail("not_found", "The request is not in the inbox."))?;
        if self.requests[index].status != RequestStatus::Pending {
            return Err(fail(
                "not_pending",
                "The request does not wait for approval.",
            ));
        }
        if !self.requests[index].approvable
            || self.requests[index].decision != Decision::RequireApproval
        {
            return Err(fail("not_approvable", "This decision cannot be approved."));
        }
        if self.requests[index].epoch != self.epoch {
            return Err(fail(
                "invalidated",
                "Pending demo authority is not valid after lock.",
            ));
        }
        if let Some(claimed) = claimed_digest
            && claimed != self.requests[index].digest
        {
            return Err(fail(
                "request_mismatch",
                "The approval is bound to one exact request. This digest does not match.",
            ));
        }
        let live = self.decide(&self.requests[index]);
        if live.decision == Decision::Deny {
            let reason_code = live.reason_code;
            let message = live.message.clone();
            self.requests[index].status = RequestStatus::Denied;
            self.requests[index].decision = Decision::Deny;
            self.requests[index].reason_code = reason_code;
            self.requests[index].message = message.clone();
            self.requests[index].approvable = false;
            self.sync_alert_with_request(&self.requests[index].id.clone());
            return Err(fail(reason_code, &message));
        }
        self.requests[index].approval_consumed = true;
        let snapshot = self.requests[index].clone();
        self.consume_use(&snapshot);
        self.requests[index].decision = Decision::Allow;
        self.requests[index].reason_code = "owner_approved_once";
        self.requests[index].status = RequestStatus::Completed;
        self.requests[index].executed = true;
        self.requests[index].approvable = false;
        self.requests[index].message =
            "The owner approved this exact request once. The demo use is complete.".to_owned();
        let out = self.requests[index].clone();
        self.sync_alert_with_request(&out.id);
        self.record("approve_once", &out.message);
        Ok(out)
    }

    pub fn deny_request(&mut self, request_id: &str) -> ModelResult<DemoRequest> {
        let index = self
            .requests
            .iter()
            .position(|request| request.id == request_id)
            .ok_or_else(|| fail("not_found", "The request is not in the inbox."))?;
        if self.requests[index].status != RequestStatus::Pending {
            return Err(fail(
                "not_pending",
                "The request does not wait for a decision.",
            ));
        }
        self.requests[index].status = RequestStatus::Denied;
        self.requests[index].decision = Decision::Deny;
        self.requests[index].reason_code = "owner_denied";
        self.requests[index].approvable = false;
        self.requests[index].message =
            "The owner denied this request. The demo did not execute.".to_owned();
        let out = self.requests[index].clone();
        self.sync_alert_with_request(&out.id);
        self.record("deny", &out.message);
        Ok(out)
    }

    pub fn list_requests(&self) -> &[DemoRequest] {
        &self.requests
    }

    pub fn list_alerts(&self) -> Vec<&DemoAlert> {
        self.alerts.iter().rev().collect()
    }

    pub fn list_activity(&self) -> Vec<&ActivityEvent> {
        self.activity.iter().rev().collect()
    }

    pub fn notification_health(&self) -> NotificationHealth {
        if self.notification_healthy {
            NotificationHealth {
                healthy: true,
                label: "Notification channel is healthy in this demo.",
            }
        } else {
            NotificationHealth {
                healthy: false,
                label: "Notification channel failed in this demo.",
            }
        }
    }

    pub fn set_notification_healthy(&mut self, healthy: bool) -> ModelResult<NotificationHealth> {
        self.notification_healthy = healthy;
        let health = self.notification_health();
        let message = if healthy {
            "The demo notification channel is healthy."
        } else {
            "The demo notification channel failed. Waiting requests stay in the inbox."
        };
        self.record("notification_health", message);
        Ok(health)
    }

    pub fn set_now(&mut self, iso: &str) -> ModelResult<String> {
        let (ms, canon) = match iso {
            DEFAULT_NOW_ISO => (DEFAULT_NOW_MS, DEFAULT_NOW_ISO),
            AFTER_EXPIRY_ISO => (AFTER_EXPIRY_MS, AFTER_EXPIRY_ISO),
            SAMPLE_EXPIRY_ISO => (SAMPLE_EXPIRY_MS, SAMPLE_EXPIRY_ISO),
            _ => return Err(fail("invalid_time", "The demo clock value is not valid.")),
        };
        self.now_ms = ms;
        self.now_iso = canon.to_owned();
        self.record("clock", "The demo clock changed.");
        Ok(self.now_iso.clone())
    }

    pub fn extra_fields(kind: CredentialKind) -> &'static [ExtraField] {
        match kind {
            CredentialKind::ApiKey => &[],
            CredentialKind::Login => &[ExtraField::Username],
            CredentialKind::SshKey => &[ExtraField::PublicLabel],
            CredentialKind::Database => &[
                ExtraField::Username,
                ExtraField::Host,
                ExtraField::DatabaseName,
            ],
            CredentialKind::Custom => &[ExtraField::FieldName],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraField {
    Username,
    Host,
    DatabaseName,
    FieldName,
    PublicLabel,
}

impl ExtraField {
    pub fn label(self) -> &'static str {
        match self {
            Self::Username => "Username",
            Self::Host => "Host",
            Self::DatabaseName => "Database name",
            Self::FieldName => "Field name",
            Self::PublicLabel => "Public label",
        }
    }
}

struct DecisionOutcome {
    decision: Decision,
    reason_code: &'static str,
    message: String,
    approvable: bool,
    status: RequestStatus,
}

impl DesktopModel {
    fn load_fixtures(&mut self) {
        self.locked = true;
        self.epoch = 1;
        self.now_ms = DEFAULT_NOW_MS;
        self.now_iso = DEFAULT_NOW_ISO.to_owned();
        self.revealed.clear();
        self.agents.clear();
        self.draft = None;
        self.active_rule = None;
        self.requests.clear();
        self.alerts.clear();
        self.activity.clear();
        self.notification_healthy = true;
        self.seq_item = 1;
        self.seq_request = 1;
        self.seq_alert = 1;
        self.seq_event = 1;
        self.seq_draft = 1;
        self.issued_secrets.clear();
        self.items = fixture_items();
        for item in &self.items {
            self.issued_secrets.insert(item.synthetic_value.clone());
        }
    }

    fn require_open(&self) -> ModelResult<()> {
        if self.locked {
            Err(fail(
                "vault_locked",
                "The vault is locked. Item details are hidden.",
            ))
        } else {
            Ok(())
        }
    }

    fn find_item(&self, id: &str) -> Option<&Item> {
        self.items.iter().find(|item| item.id == id)
    }

    fn connected_agent(&self, id: &str) -> Option<&Agent> {
        self.agents
            .iter()
            .find(|agent| agent.id == id && agent.connected)
    }

    fn agent_record(&self, id: &str, name: &str, summary: &str) -> AgentRecord {
        if let Some(agent) = self.agents.iter().find(|agent| agent.id == id) {
            public_agent(agent)
        } else {
            AgentRecord {
                id: id.to_owned(),
                name: name.to_owned(),
                summary: summary.to_owned(),
                connected: false,
                generation: 0,
                status_label: "not connected",
            }
        }
    }

    fn sample_draft(&self, draft_id: String, original: String) -> RuleDraft {
        let issues = sample_binding_issues(
            self.connected_agent(REPORTING_AGENT_ID).is_some(),
            self.find_item(REPORTING_ITEM_ID).is_some(),
        );
        let ready = issues.is_empty();
        RuleDraft {
            id: draft_id,
            original_text: original,
            interpreter: INTERPRETER_ID,
            status: if ready {
                DraftStatus::ReadyForReview
            } else {
                DraftStatus::NeedsClarification
            },
            reason_code: if ready {
                "sample_ready"
            } else {
                issues[0].code
            },
            confirmed: false,
            can_activate: ready,
            clauses: sample_clauses(),
            questions: if ready {
                vec![
                    "Confirm that Friday means 2026-09-18 23:59:59 America/New_York.".to_owned(),
                    "Confirm that production stays denied.".to_owned(),
                    "Confirm that an unclear task waits for an owner decision.".to_owned(),
                ]
            } else {
                issues.iter().map(|issue| issue.message.clone()).collect()
            },
            issues,
            examples: Some(Examples {
                allow: "Read a Project A report from staging with a clear task.".to_owned(),
                ask: "Read a Project A report from staging with an unclear task.".to_owned(),
                deny: "Read a Project A report from production.".to_owned(),
            }),
        }
    }

    fn decide(&self, request: &DemoRequest) -> DecisionOutcome {
        if self.locked {
            return outcome(
                Decision::Deny,
                "vault_locked",
                "The vault is locked. The demo did not use a credential.",
                false,
                RequestStatus::Denied,
            );
        }
        let Some(agent) = self.connected_agent(&request.agent_id) else {
            if self
                .agents
                .iter()
                .any(|agent| agent.id == request.agent_id && !agent.connected)
            {
                return outcome(
                    Decision::Deny,
                    "agent_revoked",
                    "The agent is revoked. The demo did not use a credential.",
                    false,
                    RequestStatus::Denied,
                );
            }
            return outcome(
                Decision::Deny,
                "no_grant",
                "There is no connected agent grant for this request.",
                false,
                RequestStatus::Denied,
            );
        };
        if self.find_item(&request.item_id).is_none() {
            return outcome(
                Decision::Deny,
                "item_missing",
                "The item is not in the vault.",
                false,
                RequestStatus::Denied,
            );
        }
        let Some(rule) = self.active_grant(request, agent.generation) else {
            return outcome(
                Decision::Deny,
                "no_grant",
                "There is no active grant for this agent and item.",
                false,
                RequestStatus::Denied,
            );
        };
        if self.now_ms >= rule.expiry_ms {
            return outcome(
                Decision::Deny,
                "expired",
                &format!("The sample rule expired at {}.", rule.public.expiry_iso),
                false,
                RequestStatus::Denied,
            );
        }
        if rule.public.use_count >= rule.public.usage_limit {
            return outcome(
                Decision::Deny,
                "usage_limit",
                &format!(
                    "The sample usage limit of {} is reached.",
                    rule.public.usage_limit
                ),
                false,
                RequestStatus::Denied,
            );
        }
        if request.operation != rule.public.operation {
            return outcome(
                Decision::Deny,
                "unsupported_operation",
                "The operation is not the sample report operation.",
                false,
                RequestStatus::Denied,
            );
        }
        if rule
            .public
            .denied_destinations
            .iter()
            .any(|denied| *denied == request.destination)
        {
            return outcome(
                Decision::Deny,
                "explicit_denial",
                "The rule blocks production. This denial cannot be approved.",
                false,
                RequestStatus::Denied,
            );
        }
        if request.destination != rule.public.destination {
            return outcome(
                Decision::Deny,
                "destination_not_permitted",
                "The destination is not staging.",
                false,
                RequestStatus::Denied,
            );
        }
        let purpose = request.purpose.to_lowercase();
        if purpose.contains("unclear")
            || purpose.contains("uncertain")
            || purpose.contains("does not fit")
        {
            return outcome(
                Decision::RequireApproval,
                "uncertain_task",
                "The task fit is unclear. The request waits for an owner decision.",
                true,
                RequestStatus::Pending,
            );
        }
        outcome(
            Decision::Allow,
            "automatic_permit",
            "The fixture bouncer permitted this normal request. The request did not need extra approval.",
            false,
            RequestStatus::Completed,
        )
    }

    fn active_grant(&self, request: &DemoRequest, generation: u32) -> Option<&LiveRule> {
        let rule = self.active_rule.as_ref()?;
        if rule.public.status != "active" {
            return None;
        }
        if rule.public.agent_id != request.agent_id || rule.public.item_id != request.item_id {
            return None;
        }
        if rule.public.agent_generation != generation {
            return None;
        }
        Some(rule)
    }

    fn consume_use(&mut self, request: &DemoRequest) {
        let generation = self
            .connected_agent(&request.agent_id)
            .map(|agent| agent.generation);
        let Some(generation) = generation else {
            return;
        };
        if let Some(rule) = self.active_rule.as_mut()
            && rule.public.status == "active"
            && rule.public.agent_id == request.agent_id
            && rule.public.item_id == request.item_id
            && rule.public.agent_generation == generation
        {
            rule.public.use_count = rule.public.use_count.saturating_add(1);
            rule.public.remaining_uses = rule
                .public
                .usage_limit
                .saturating_sub(rule.public.use_count);
        }
    }

    fn invalidate_pending(&mut self, reason_code: &'static str, message: &str) {
        let changed = self.mark_pending_invalidated(|_| true, reason_code, message);
        self.sync_alerts(&changed);
    }

    fn invalidate_pending_for_item(
        &mut self,
        item_id: &str,
        reason_code: &'static str,
        message: &str,
    ) {
        let changed = self.mark_pending_invalidated(
            |request| request.item_id == item_id,
            reason_code,
            message,
        );
        self.sync_alerts(&changed);
    }

    fn invalidate_pending_for_agent(
        &mut self,
        agent_id: &str,
        reason_code: &'static str,
        message: &str,
    ) {
        let changed = self.mark_pending_invalidated(
            |request| request.agent_id == agent_id,
            reason_code,
            message,
        );
        self.sync_alerts(&changed);
    }

    fn mark_pending_invalidated(
        &mut self,
        matches: impl Fn(&DemoRequest) -> bool,
        reason_code: &'static str,
        message: &str,
    ) -> Vec<String> {
        let mut changed = Vec::new();
        for request in &mut self.requests {
            if request.status == RequestStatus::Pending && matches(request) {
                request.status = RequestStatus::Invalidated;
                request.decision = Decision::Deny;
                request.approvable = false;
                request.reason_code = reason_code;
                request.message = message.to_owned();
                changed.push(request.id.clone());
            }
        }
        changed
    }

    fn sync_alerts(&mut self, request_ids: &[String]) {
        for request_id in request_ids {
            self.sync_alert_with_request(request_id);
        }
    }

    fn sync_alert_with_request(&mut self, request_id: &str) {
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.id == request_id)
        else {
            return;
        };
        let title = alert_title(request.decision, request.status);
        let message = request.message.clone();
        let decision = request.decision;
        let status = request.status;
        for alert in &mut self.alerts {
            if alert.request_id == request_id {
                alert.title = title.clone();
                alert.message = message.clone();
                alert.decision = decision;
                alert.status = status;
            }
        }
    }

    fn record(&mut self, kind: &'static str, message: &str) {
        self.assert_no_secret(message);
        let event = ActivityEvent {
            id: format!("event-{}", self.seq_event),
            at_iso: self.now_iso.clone(),
            kind,
            message: message.to_owned(),
        };
        self.seq_event += 1;
        self.activity.push(event);
    }

    fn assert_no_secret(&self, text: &str) {
        debug_assert!(
            !self
                .issued_secrets
                .iter()
                .any(|secret| !secret.is_empty() && text.contains(secret)),
            "activity or alert contained a synthetic value"
        );
    }
}

fn fail(code: &'static str, message: &str) -> ModelError {
    ModelError {
        code,
        message: message.to_owned(),
    }
}

fn issue(code: &'static str, message: &str) -> Issue {
    Issue {
        code,
        message: message.to_owned(),
    }
}

fn outcome(
    decision: Decision,
    reason_code: &'static str,
    message: &str,
    approvable: bool,
    status: RequestStatus,
) -> DecisionOutcome {
    DecisionOutcome {
        decision,
        reason_code,
        message: message.to_owned(),
        approvable,
        status,
    }
}

fn normalize_rule_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn catalog_meta(id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match id {
        REPORTING_AGENT_ID => Some((
            REPORTING_AGENT_ID,
            "Reporting agent",
            "Synthetic agent for Project A reports.",
        )),
        OTHER_AGENT_ID => Some((
            OTHER_AGENT_ID,
            "Other agent",
            "Synthetic agent with no sample grant.",
        )),
        _ => None,
    }
}

fn agent_use_label(kind: CredentialKind) -> &'static str {
    if kind == CredentialKind::ApiKey {
        "The sample reporting path can use a fixture API key."
    } else {
        "This desktop stores this item. This desktop does not support agent use of this item."
    }
}

fn synthetic_value(kind: CredentialKind, id: &str) -> String {
    let token = match kind {
        CredentialKind::ApiKey => "API-KEY",
        CredentialKind::Login => "LOGIN",
        CredentialKind::SshKey => "SSH-KEY",
        CredentialKind::Database => "DATABASE",
        CredentialKind::Custom => "CUSTOM",
    };
    format!("SYNTH-{token}-{id}-NOT-A-SECRET")
}

fn public_item(item: &Item) -> ItemSummary {
    ItemSummary {
        id: item.id.clone(),
        name: item.name.clone(),
        kind: item.kind,
        service: item.service.clone(),
        project: item.project.clone(),
        notes: item.notes.clone(),
        username: item.username.clone(),
        host: item.host.clone(),
        database_name: item.database_name.clone(),
        field_name: item.field_name.clone(),
        public_label: item.public_label.clone(),
        revision: item.revision,
        agent_use_label: agent_use_label(item.kind),
    }
}

fn details_from_item(item: &Item, revealed: bool) -> ItemDetails {
    ItemDetails {
        id: item.id.clone(),
        name: item.name.clone(),
        kind: item.kind,
        service: item.service.clone(),
        project: item.project.clone(),
        notes: item.notes.clone(),
        username: item.username.clone(),
        host: item.host.clone(),
        database_name: item.database_name.clone(),
        field_name: item.field_name.clone(),
        public_label: item.public_label.clone(),
        revision: item.revision,
        agent_use_label: agent_use_label(item.kind),
        hidden: false,
        revealed,
        synthetic_value: revealed.then(|| item.synthetic_value.clone()),
        masked_value: MASKED_VALUE,
        display_value: if revealed {
            item.synthetic_value.clone()
        } else {
            MASKED_VALUE.to_owned()
        },
        reveal_warning: REVEAL_WARNING,
        copy_warning: COPY_WARNING,
        message: String::new(),
    }
}

fn public_agent(agent: &Agent) -> AgentRecord {
    AgentRecord {
        id: agent.id.clone(),
        name: agent.name.clone(),
        summary: agent.summary.clone(),
        connected: agent.connected,
        generation: agent.generation,
        status_label: if agent.connected {
            "connected"
        } else {
            "revoked"
        },
    }
}

fn item_matches(item: &Item, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = [
        item.name.as_str(),
        item.kind.label(),
        item.service.as_str(),
        item.project.as_str(),
        item.notes.as_str(),
        item.username.as_str(),
        item.host.as_str(),
        item.database_name.as_str(),
        item.field_name.as_str(),
        item.public_label.as_str(),
    ]
    .join(" ")
    .to_lowercase();
    haystack.contains(needle)
}

fn checked_fields(draft: ItemDraft, _require_kind: bool) -> ModelResult<ItemDraft> {
    Ok(ItemDraft {
        name: draft.name.trim().to_owned(),
        kind: draft.kind,
        service: draft.service.trim().to_owned(),
        project: draft.project.trim().to_owned(),
        notes: draft.notes.trim().to_owned(),
        username: draft.username.trim().to_owned(),
        host: draft.host.trim().to_owned(),
        database_name: draft.database_name.trim().to_owned(),
        field_name: draft.field_name.trim().to_owned(),
        public_label: draft.public_label.trim().to_owned(),
    })
}

fn apply_fields(item: &mut Item, fields: &ItemDraft) {
    item.name = fields.name.clone();
    item.service = fields.service.clone();
    item.project = fields.project.clone();
    item.notes = fields.notes.clone();
    item.username = fields.username.clone();
    item.host = fields.host.clone();
    item.database_name = fields.database_name.clone();
    item.field_name = fields.field_name.clone();
    item.public_label = fields.public_label.clone();
}

fn build_item(id: String, fields: &ItemDraft, revision: u32) -> Item {
    let synthetic_value = synthetic_value(fields.kind, &id);
    Item {
        id,
        name: fields.name.clone(),
        kind: fields.kind,
        service: fields.service.clone(),
        project: fields.project.clone(),
        notes: fields.notes.clone(),
        username: fields.username.clone(),
        host: fields.host.clone(),
        database_name: fields.database_name.clone(),
        field_name: fields.field_name.clone(),
        public_label: fields.public_label.clone(),
        revision,
        synthetic_value,
    }
}

fn fixture_items() -> Vec<Item> {
    vec![
        build_item(
            REPORTING_ITEM_ID.to_owned(),
            &ItemDraft {
                name: "Project A reporting service".to_owned(),
                kind: CredentialKind::ApiKey,
                service: "reporting-api".to_owned(),
                project: "Project A".to_owned(),
                notes: "Fixture API key for staging reports.".to_owned(),
                ..ItemDraft::default()
            },
            1,
        ),
        build_item(
            "item-dashboard-login".to_owned(),
            &ItemDraft {
                name: "Project A dashboard login".to_owned(),
                kind: CredentialKind::Login,
                service: "reporting-dashboard".to_owned(),
                project: "Project A".to_owned(),
                notes: "Stored login. Agent use is not available in this desktop.".to_owned(),
                username: "report-owner".to_owned(),
                ..ItemDraft::default()
            },
            1,
        ),
        build_item(
            "item-jump-ssh".to_owned(),
            &ItemDraft {
                name: "Jump host key".to_owned(),
                kind: CredentialKind::SshKey,
                service: "jump-host".to_owned(),
                project: "Project A".to_owned(),
                notes: "Stored SSH key. Agent use is not available in this desktop.".to_owned(),
                public_label: "project-a-jump".to_owned(),
                ..ItemDraft::default()
            },
            1,
        ),
        build_item(
            "item-staging-db".to_owned(),
            &ItemDraft {
                name: "Project A staging database".to_owned(),
                kind: CredentialKind::Database,
                service: "postgres-staging".to_owned(),
                project: "Project A".to_owned(),
                notes: "Stored database credential. This desktop does not run a connector."
                    .to_owned(),
                username: "report_reader".to_owned(),
                host: "db.staging.example.invalid".to_owned(),
                database_name: "project_a".to_owned(),
                ..ItemDraft::default()
            },
            1,
        ),
        build_item(
            "item-custom-token".to_owned(),
            &ItemDraft {
                name: "Internal note token".to_owned(),
                kind: CredentialKind::Custom,
                service: String::new(),
                project: "Project A".to_owned(),
                notes: "Stored custom field. Agent use is not available in this desktop."
                    .to_owned(),
                field_name: "note_token".to_owned(),
                ..ItemDraft::default()
            },
            1,
        ),
    ]
}

fn sample_binding_issues(agent_connected: bool, item_present: bool) -> Vec<Issue> {
    let mut issues = Vec::new();
    if !agent_connected {
        issues.push(issue(
            "agent_not_connected",
            "The reporting agent is not connected. Connect the agent, then review the rule again.",
        ));
    }
    if !item_present {
        issues.push(issue(
            "item_missing",
            "Project A reporting service is not in the vault. The sample cannot bind to it.",
        ));
    }
    issues
}

fn sample_clauses() -> Vec<Clause> {
    vec![
        Clause {
            text: "My reporting agent".to_owned(),
            kind_label: "Restriction",
            meaning: "Bound to connected agent reporting-agent.".to_owned(),
        },
        Clause {
            text: "can use this credential".to_owned(),
            kind_label: "Restriction",
            meaning: "Bound to Project A reporting service.".to_owned(),
        },
        Clause {
            text: "for Project A".to_owned(),
            kind_label: "Restriction",
            meaning: "Project tag Project A.".to_owned(),
        },
        Clause {
            text: "against staging".to_owned(),
            kind_label: "Restriction",
            meaning: "Destination staging only.".to_owned(),
        },
        Clause {
            text: "until Friday".to_owned(),
            kind_label: "Restriction",
            meaning: format!("Expires {SAMPLE_EXPIRY_ISO} in time zone {SAMPLE_TIME_ZONE}."),
        },
        Clause {
            text: "Never use it for production".to_owned(),
            kind_label: "Restriction",
            meaning: "Explicit denial for production. This denial wins.".to_owned(),
        },
        Clause {
            text: "Ask me if the request does not fit the task".to_owned(),
            kind_label: "Contextual check",
            meaning: "If the task fit is unclear, the request waits for owner approval. This is a judgment, not a destination check.".to_owned(),
        },
    ]
}

fn blocked_draft(
    draft_id: String,
    original: String,
    reason_code: &'static str,
    issues: Vec<Issue>,
) -> RuleDraft {
    let questions: Vec<String> = issues.iter().map(|issue| issue.message.clone()).collect();
    RuleDraft {
        id: draft_id,
        original_text: original,
        interpreter: INTERPRETER_ID,
        status: DraftStatus::Blocked,
        reason_code,
        confirmed: false,
        can_activate: false,
        clauses: Vec::new(),
        questions,
        issues,
        examples: None,
    }
}

fn ambiguous_draft(draft_id: String, original: String) -> RuleDraft {
    RuleDraft {
        id: draft_id,
        original_text: original,
        interpreter: INTERPRETER_ID,
        status: DraftStatus::NeedsClarification,
        reason_code: "ambiguous_text",
        confirmed: false,
        can_activate: false,
        clauses: Vec::new(),
        issues: vec![
            issue(
                "ambiguous_who",
                "Which agent is named? The text says only the agent.",
            ),
            issue(
                "ambiguous_what",
                "Which credential is named? The text says only the credential.",
            ),
            issue(
                "ambiguous_where",
                "Which destination is named? The text does not say staging or production.",
            ),
        ],
        questions: vec![
            "Name the agent from the catalog.".to_owned(),
            "Name the credential in the vault.".to_owned(),
            "Name the destination that the connector can enforce.".to_owned(),
        ],
        examples: None,
    }
}

fn conflicting_draft(draft_id: String, original: String) -> RuleDraft {
    RuleDraft {
        id: draft_id,
        original_text: original,
        interpreter: INTERPRETER_ID,
        status: DraftStatus::Blocked,
        reason_code: "conflicting_text",
        confirmed: false,
        can_activate: false,
        clauses: vec![
            Clause {
                text: "against staging and production".to_owned(),
                kind_label: "Conflict",
                meaning: "This clause permits production.".to_owned(),
            },
            Clause {
                text: "Never use it for production".to_owned(),
                kind_label: "Conflict",
                meaning: "This clause denies production.".to_owned(),
            },
        ],
        issues: vec![issue(
            "conflicting_text",
            "The text both permits production and denies production. The fixture interpreter does not pick a side.",
        )],
        questions: vec![
            "Remove the production permission, or remove the production denial. Then review the text again."
                .to_owned(),
        ],
        examples: None,
    }
}

fn unsupported_draft(draft_id: String, original: String) -> RuleDraft {
    RuleDraft {
        id: draft_id,
        original_text: original,
        interpreter: INTERPRETER_ID,
        status: DraftStatus::Blocked,
        reason_code: "unsupported_text",
        confirmed: false,
        can_activate: false,
        clauses: vec![
            Clause {
                text: "run any SQL on any database".to_owned(),
                kind_label: "Unsupported",
                meaning: "Arbitrary SQL is not a bounded connector operation in this desktop."
                    .to_owned(),
            },
            Clause {
                text: "send the password to the agent".to_owned(),
                kind_label: "Unsupported",
                meaning: "Raw secret delivery to an agent is outside the desktop contract."
                    .to_owned(),
            },
        ],
        issues: vec![issue(
            "unsupported_text",
            "The fixture interpreter does not support arbitrary SQL or raw secret delivery.",
        )],
        questions: vec![
            "Use the supported sample. It permits a named report operation against staging."
                .to_owned(),
        ],
        examples: None,
    }
}

fn request_digest(
    agent_id: &str,
    item_id: &str,
    item_revision: Option<u32>,
    destination: &str,
    operation: &str,
    purpose: &str,
    agent_generation: Option<u32>,
) -> String {
    format!(
        "{agent_id}|{item_id}|{}|{destination}|{operation}|{purpose}|{}",
        item_revision
            .map(|value| value.to_string())
            .unwrap_or_default(),
        agent_generation
            .map(|value| value.to_string())
            .unwrap_or_default()
    )
}

fn alert_title(decision: Decision, status: RequestStatus) -> String {
    if status == RequestStatus::Pending {
        "Request waits for a decision".to_owned()
    } else if status == RequestStatus::Invalidated {
        "Request is not valid".to_owned()
    } else if decision == Decision::Allow {
        "Permitted request".to_owned()
    } else {
        "Request denied".to_owned()
    }
}
