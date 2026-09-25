//! Owner vault and item session for the desktop shell.
//!
//! Agents, grants, and agent activity use the vault (ADR 0004). Rules and demo
//! approvals stay on the in-memory demo model.
//! This session is a trusted-process adapter over [`crate::vault`].
//! It is not an authenticated owner channel. Real-secret use stays blocked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::broker::SharedVault;
use crate::broker::http::parse_destination;
use crate::broker::profile;
use crate::contracts::CredentialKind;
use crate::desktop::model::{ItemDraft, MASKED_VALUE, ModelError, ModelResult};
use crate::vault::{
    ActivityDecision, AgentSummary, AgentToken, Declaration, Destination, EnvBinding, Environment,
    ExecGrant, ExecMode, ExecRule, Field, ItemDraft as VaultDraft, MAX_PASSPHRASE_BYTES,
    MIN_PASSPHRASE_BYTES, Reversibility, RiskLevel, Scope, SecretValue, Vault, VaultError,
    VaultErrorKind, checked_env_name,
};

const MAX_TAG_BYTES: usize = 64;

const AGENT_USE_LABEL: &str = "Stored in the vault. Agent use is not connected.";
const REVEAL_WARNING: &str = "The value is visible in this window until you hide it or lock the vault. This is not an authenticated owner channel.";

/// Secret inputs for one item form. Debug output is redacted.
#[derive(Clone, Default)]
pub struct SecretForm {
    pub token: String,
    pub password: String,
    pub private_key: String,
    pub key_passphrase: String,
    pub custom_value: String,
}

impl SecretForm {
    pub fn is_blank(&self) -> bool {
        self.token.is_empty()
            && self.password.is_empty()
            && self.private_key.is_empty()
            && self.key_passphrase.is_empty()
            && self.custom_value.is_empty()
    }

    pub fn clear(&mut self) {
        self.token.clear();
        self.password.clear();
        self.private_key.clear();
        self.key_passphrase.clear();
        self.custom_value.clear();
    }
}

impl fmt::Debug for SecretForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretForm([redacted])")
    }
}

impl Drop for SecretForm {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Passphrase or other short-lived secret text. Drop clears the `String`.
pub struct Ephemeral(String);

impl Ephemeral {
    pub fn take(slot: &mut String) -> Self {
        Self(std::mem::take(slot))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.0.clear();
    }
}

/// Declaration form fields for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationForm {
    pub project: String,
    pub environment: Environment,
    pub risk: RiskLevel,
    pub scope: Scope,
    pub reversibility: Reversibility,
    /// The item has a stored declaration.
    pub stored: bool,
}

impl Default for DeclarationForm {
    /// Conservative defaults. The owner changes them on purpose.
    fn default() -> Self {
        Self {
            project: String::new(),
            environment: Environment::Production,
            risk: RiskLevel::High,
            scope: Scope::Admin,
            reversibility: Reversibility::Irreversible,
            stored: false,
        }
    }
}

impl DeclarationForm {
    pub fn from_declaration(declaration: Option<Declaration>) -> Self {
        declaration.map_or_else(Self::default, |d| Self {
            project: d.project,
            environment: d.environment,
            risk: d.risk,
            scope: d.scope,
            reversibility: d.reversibility,
            stored: true,
        })
    }

    pub fn to_declaration(&self) -> Declaration {
        Declaration {
            project: self.project.trim().to_owned(),
            environment: self.environment,
            risk: self.risk,
            scope: self.scope,
            reversibility: self.reversibility,
        }
    }
}

/// Rule editor fields. Lists are one entry per line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleForm {
    pub prefixes: String,
    pub forbidden: String,
    pub expires_hours: String,
    pub max_runs: String,
    pub instruction: String,
}

impl RuleForm {
    pub fn from_rule(rule: &ExecRule, now: u64) -> Self {
        Self {
            prefixes: rule.allowed_prefixes.join("\n"),
            forbidden: rule.forbidden_words.join("\n"),
            expires_hours: rule
                .expires_at
                .map(|at| at.saturating_sub(now).div_ceil(3600).to_string())
                .unwrap_or_default(),
            max_runs: rule
                .max_runs_per_hour
                .map(|max| max.to_string())
                .unwrap_or_default(),
            instruction: rule.instruction.clone(),
        }
    }

    /// Build a rule. Empty number fields mean no limit.
    pub fn to_rule(&self, now: u64) -> Result<ExecRule, String> {
        let lines = |text: &str| -> Vec<String> {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let expires_at = match self.expires_hours.trim() {
            "" => None,
            hours => Some(
                hours
                    .parse::<u64>()
                    .ok()
                    .filter(|hours| (1..=24 * 366).contains(hours))
                    .ok_or("Expiry must be a whole number of hours from 1 to 8784.")?
                    * 3600
                    + now,
            ),
        };
        let max_runs_per_hour = match self.max_runs.trim() {
            "" => None,
            runs => Some(
                runs.parse::<u32>()
                    .ok()
                    .filter(|runs| (1..=10_000).contains(runs))
                    .ok_or("The run limit must be a whole number from 1 to 10000.")?,
            ),
        };
        Ok(ExecRule {
            allowed_prefixes: lines(&self.prefixes),
            forbidden_words: lines(&self.forbidden),
            expires_at,
            max_runs_per_hour,
            instruction: self.instruction.trim().to_owned(),
        })
    }
}

/// Text fields that bind the vault file controls.
#[derive(Default)]
pub struct OwnerUiState {
    pub session: OwnerSession,
    pub create_path: String,
    pub open_path: String,
    pub passphrase: String,
    pub backup_path: String,
    pub restore_source: String,
    pub restore_dest: String,
    pub add_secrets: SecretForm,
    pub edit_secrets: SecretForm,
    pub edit_revision: u64,
    pub connector_url: String,
    pub new_agent_name: String,
    /// The token of the agent that the owner registered last. It is shown one time.
    pub fresh_token: Option<(String, AgentToken)>,
    pub selected_agent: Option<u64>,
    pub env_name_input: String,
    pub env_field_input: String,
    /// Declaration form of the selected item (ADR 0008).
    pub declaration_form: DeclarationForm,
    /// Project directory text for each (agent, item) pair in the Agents view.
    pub exec_dir_inputs: BTreeMap<(u64, u64), String>,
    /// Rule editor text for each (agent, item) pair.
    pub rule_inputs: BTreeMap<(u64, u64), RuleForm>,
    /// Pending run IDs that the app already signaled to the owner.
    pub signaled_runs: BTreeSet<u64>,
}

/// One vault file open inside this process. The broker shares the same slot.
#[derive(Debug)]
pub struct OwnerSession {
    vault: SharedVault,
    path: Option<PathBuf>,
    revealed: BTreeMap<(u64, String), RevealedValue>,
}

/// Mutex guard over an unlocked vault. Hold it only for one short operation.
struct Unlocked<'a>(MutexGuard<'a, Option<Vault>>);

impl Deref for Unlocked<'_> {
    type Target = Vault;

    fn deref(&self) -> &Vault {
        self.0.as_ref().expect("Unlocked holds an open vault")
    }
}

impl DerefMut for Unlocked<'_> {
    fn deref_mut(&mut self) -> &mut Vault {
        self.0.as_mut().expect("Unlocked holds an open vault")
    }
}

impl OwnerSession {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(Mutex::new(None)),
            path: None,
            revealed: BTreeMap::new(),
        }
    }

    /// The vault slot for the broker. The broker sees each open, lock, and restore.
    pub fn shared_vault(&self) -> SharedVault {
        Arc::clone(&self.vault)
    }

    fn slot(&self) -> MutexGuard<'_, Option<Vault>> {
        self.vault.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn has_file(&self) -> bool {
        self.slot().is_some()
    }

    pub fn is_locked(&self) -> bool {
        self.slot().as_ref().is_none_or(Vault::is_locked)
    }

    pub fn location(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn lock_label(&self) -> &'static str {
        if !self.has_file() {
            "The vault is locked. No vault file is open. Item details are hidden."
        } else if self.is_locked() {
            "The vault is locked. Item details are hidden."
        } else {
            "The vault file is unlocked in this process. This is not an authenticated owner channel."
        }
    }

    pub fn create_file(&mut self, path: &Path, passphrase: &str) -> ModelResult<()> {
        require_path(path)?;
        require_new_passphrase(passphrase)?;
        let vault = Vault::create(path, passphrase).map_err(map_err)?;
        self.install(vault, path.to_path_buf());
        Ok(())
    }

    pub fn open_file(&mut self, path: &Path) -> ModelResult<()> {
        require_path(path)?;
        let previous = self.detach();
        match Vault::open(path) {
            Ok(vault) => {
                self.install(vault, path.to_path_buf());
                Ok(())
            }
            Err(err) => {
                self.attach(previous);
                Err(map_err(err))
            }
        }
    }

    pub fn unlock(&mut self, passphrase: &str) -> ModelResult<()> {
        self.revealed.clear();
        require_passphrase(passphrase)?;
        let mut slot = self.slot();
        let vault = slot
            .as_mut()
            .ok_or_else(|| fail("vault_locked", "No vault file is open."))?;
        vault.unlock(passphrase).map_err(map_err)
    }

    pub fn lock(&mut self) -> ModelResult<()> {
        self.revealed.clear();
        let mut slot = self.slot();
        let Some(vault) = slot.as_mut() else {
            return Ok(());
        };
        vault.lock().map_err(map_err)
    }

    pub fn search(&self, query: &str) -> ModelResult<Vec<OwnerSummary>> {
        let found = {
            let vault = self.unlocked()?;
            vault.search(query).map_err(map_err)?
        };
        found
            .into_iter()
            .map(|summary| self.row_from(summary))
            .collect()
    }

    pub fn details(&self, id: u64) -> ModelResult<OwnerDetails> {
        if !self.has_file() {
            return Ok(OwnerDetails::hidden(
                id,
                "No vault file is open. Item details are hidden.",
            ));
        }
        if self.is_locked() {
            return Ok(OwnerDetails::hidden(
                id,
                "The vault is locked. Item details are hidden.",
            ));
        }
        let meta = {
            let vault = self.unlocked()?;
            vault.details(id).map_err(map_err)?
        };
        self.details_from_meta(meta)
    }

    pub fn add(&mut self, draft: &ItemDraft, secrets: &SecretForm) -> ModelResult<OwnerSummary> {
        let vault_draft = {
            let vault = self.unlocked()?;
            build_vault_draft(&vault, None, draft, secrets)?
        };
        let summary = self.unlocked()?.add(vault_draft).map_err(map_err)?;
        self.row_from(summary)
    }

    pub fn update(
        &mut self,
        id: u64,
        expected_revision: u64,
        draft: &ItemDraft,
        secrets: &SecretForm,
    ) -> ModelResult<OwnerSummary> {
        let vault_draft = {
            let vault = self.unlocked()?;
            build_vault_draft(&vault, Some(id), draft, secrets)?
        };
        let summary = self
            .unlocked()?
            .update(id, expected_revision, vault_draft)
            .map_err(map_err)?;
        self.revealed.retain(|key, _| key.0 != id);
        self.row_from(summary)
    }

    /// True when a save would write the same labels and keep every stored secret.
    pub fn is_unchanged(
        &self,
        id: u64,
        draft: &ItemDraft,
        secrets: &SecretForm,
    ) -> ModelResult<bool> {
        if !secrets.is_blank() {
            return Ok(false);
        }
        let current = self.details(id)?;
        Ok(!current.hidden && current.to_draft() == *draft)
    }

    pub fn delete(&mut self, id: u64, expected_revision: u64) -> ModelResult<()> {
        self.unlocked()?
            .delete(id, expected_revision)
            .map_err(map_err)?;
        self.revealed.retain(|key, _| key.0 != id);
        Ok(())
    }

    pub fn reveal(&mut self, id: u64) -> ModelResult<OwnerDetails> {
        let pairs = {
            let vault = self.unlocked()?;
            let meta = vault.details(id).map_err(map_err)?;
            let mut pairs = Vec::new();
            for field in &meta.fields {
                if !field.secret {
                    continue;
                }
                let value = vault.reveal(id, &field.name).map_err(map_err)?;
                pairs.push((field.name.clone(), RevealedValue(value.expose().to_owned())));
            }
            pairs
        };
        self.revealed.retain(|key, _| key.0 != id);
        for (name, value) in pairs {
            self.revealed.insert((id, name), value);
        }
        self.details(id)
    }

    pub fn hide(&mut self, id: u64) -> ModelResult<OwnerDetails> {
        self.revealed.retain(|key, _| key.0 != id);
        self.details(id)
    }

    pub fn backup(&mut self, destination: &Path) -> ModelResult<()> {
        require_path(destination)?;
        let result = self.unlocked()?.backup(destination);
        if self.is_locked() {
            self.revealed.clear();
        }
        result.map_err(map_err)
    }

    pub fn restore(
        &mut self,
        backup: &Path,
        destination: &Path,
        passphrase: &str,
    ) -> ModelResult<()> {
        require_path(backup)?;
        require_path(destination)?;
        require_passphrase(passphrase)?;
        let previous = self.detach();
        match Vault::restore(backup, destination, passphrase) {
            Ok(vault) => {
                self.install(vault, destination.to_path_buf());
                Ok(())
            }
            Err(err) => {
                self.attach(previous);
                Err(map_err(err))
            }
        }
    }

    // ---- Agent access (ADR 0004). Manual grants are temporary. ----

    pub fn agents(&self) -> ModelResult<Vec<AgentSummary>> {
        self.unlocked()?.list_agents().map_err(map_err)
    }

    /// Register an agent. Show the token to the owner one time only.
    pub fn register_agent(&mut self, name: &str) -> ModelResult<(AgentSummary, AgentToken)> {
        if name.trim().is_empty() {
            return Err(fail("invalid_input", "Type a name for the agent."));
        }
        self.unlocked()?.register_agent(name).map_err(map_err)
    }

    pub fn revoke_agent(&mut self, agent_id: u64) -> ModelResult<()> {
        self.unlocked()?.revoke_agent(agent_id).map_err(map_err)
    }

    /// API key items that have a connector destination, with the operations of their profile.
    pub fn connectors(&self) -> ModelResult<Vec<ConnectorRow>> {
        let vault = self.unlocked()?;
        let items = vault.search("").map_err(map_err)?;
        let mut rows = Vec::new();
        for item in items {
            let Some(destination) = vault.destination(item.id).map_err(map_err)? else {
                continue;
            };
            let Some(profile) = profile::find(&destination.profile) else {
                continue;
            };
            rows.push(ConnectorRow {
                item_id: item.id,
                item_name: item.title,
                profile_label: profile.label,
                base_url: destination.base_url,
                operations: profile
                    .operations
                    .iter()
                    .map(|op| (op.name, op.description))
                    .collect(),
            });
        }
        Ok(rows)
    }

    pub fn grants(&self, agent_id: u64) -> ModelResult<BTreeSet<(u64, String)>> {
        let grants = self
            .unlocked()?
            .grants_for_agent(agent_id)
            .map_err(map_err)?;
        Ok(grants
            .into_iter()
            .map(|grant| (grant.item_id, grant.operation))
            .collect())
    }

    pub fn set_grant(
        &mut self,
        agent_id: u64,
        item_id: u64,
        operation: &str,
        allowed: bool,
    ) -> ModelResult<()> {
        self.unlocked()?
            .set_grant(agent_id, item_id, operation, allowed)
            .map_err(map_err)
    }

    pub fn connector(&self, item_id: u64) -> ModelResult<Option<Destination>> {
        self.unlocked()?.destination(item_id).map_err(map_err)
    }

    /// Register the connector for an item: `https://`, or `http://` on a loopback address.
    pub fn set_connector(
        &mut self,
        item_id: u64,
        profile_id: &str,
        base_url: &str,
    ) -> ModelResult<()> {
        let profile = profile::find(profile_id)
            .ok_or_else(|| fail("invalid_input", "The connector profile is not known."))?;
        parse_destination(base_url).map_err(|message| fail("invalid_input", message))?;
        let mut vault = self.unlocked()?;
        let kind = vault.details(item_id).map_err(map_err)?.summary.kind;
        if kind != profile.credential_kind {
            return Err(fail(
                "invalid_input",
                "This connector needs an API key item.",
            ));
        }
        vault
            .set_destination(item_id, profile.id, base_url.trim())
            .map_err(map_err)
    }

    /// Remove the connector and every grant for the item.
    pub fn clear_connector(&mut self, item_id: u64) -> ModelResult<()> {
        self.unlocked()?.clear_destination(item_id).map_err(map_err)
    }

    // ---- Process secrets (ADR 0006). ----

    pub fn env_binding(&self, item_id: u64) -> ModelResult<Option<EnvBinding>> {
        self.unlocked()?.env_binding(item_id).map_err(map_err)
    }

    /// Secret field names of an item, in stored order.
    pub fn secret_fields(&self, item_id: u64) -> ModelResult<Vec<String>> {
        let details = self.unlocked()?.details(item_id).map_err(map_err)?;
        Ok(details
            .fields
            .into_iter()
            .filter(|field| field.secret)
            .map(|field| field.name)
            .collect())
    }

    pub fn set_env_binding(
        &mut self,
        item_id: u64,
        env_name: &str,
        field: &str,
    ) -> ModelResult<()> {
        checked_env_name(env_name.trim()).map_err(|_| {
            fail(
                "invalid_input",
                "Use A-Z, 0-9, and _ and start with a letter or _. System names such as PATH or DYLD_* are not permitted.",
            )
        })?;
        match self.unlocked()?.set_env_binding(item_id, env_name, field) {
            Err(err) if err.kind() == VaultErrorKind::AlreadyExists => Err(fail(
                "already_exists",
                "Another item already uses this variable name.",
            )),
            other => other.map_err(map_err),
        }
    }

    /// Remove the variable and every process grant for the item.
    pub fn clear_env_binding(&mut self, item_id: u64) -> ModelResult<()> {
        self.unlocked()?.clear_env_binding(item_id).map_err(map_err)
    }

    /// Items with a variable name: (item ID, item name, variable name).
    pub fn env_bound_items(&self) -> ModelResult<Vec<(u64, String, String)>> {
        let vault = self.unlocked()?;
        let mut rows = Vec::new();
        for item in vault.search("").map_err(map_err)? {
            if let Some(binding) = vault.env_binding(item.id).map_err(map_err)? {
                rows.push((item.id, item.title, binding.env_name));
            }
        }
        Ok(rows)
    }

    pub fn exec_grants(&self, agent_id: u64) -> ModelResult<Vec<ExecGrant>> {
        self.unlocked()?
            .exec_grants_for_agent(agent_id)
            .map_err(map_err)
    }

    pub fn set_exec_grant(
        &mut self,
        agent_id: u64,
        item_id: u64,
        project_dir: &str,
        mode: ExecMode,
    ) -> ModelResult<()> {
        let dir = project_dir.trim();
        let canonical = std::fs::canonicalize(dir)
            .ok()
            .filter(|path| path.is_dir())
            .ok_or_else(|| {
                fail(
                    "invalid_input",
                    "Type the absolute path of an existing project directory.",
                )
            })?;
        if canonical == Path::new("/") {
            return Err(fail(
                "invalid_input",
                "The project directory cannot be the root directory.",
            ));
        }
        self.unlocked()?
            .set_exec_grant(agent_id, item_id, &canonical.display().to_string(), mode)
            .map_err(map_err)
    }

    pub fn declaration(&self, item_id: u64) -> ModelResult<Option<Declaration>> {
        self.unlocked()?.declaration(item_id).map_err(map_err)
    }

    /// Store the owner declaration of an item (ADR 0008).
    pub fn set_declaration(&mut self, item_id: u64, form: &DeclarationForm) -> ModelResult<()> {
        if form.project.trim().is_empty() {
            return Err(fail("invalid_input", "Type the project name."));
        }
        self.unlocked()?
            .set_declaration(item_id, &form.to_declaration())
            .map_err(map_err)
    }

    /// Replace the rule of a process grant (ADR 0007).
    pub fn set_exec_rule(
        &mut self,
        agent_id: u64,
        item_id: u64,
        rule: ExecRule,
    ) -> ModelResult<()> {
        match self.unlocked()?.set_exec_rule(agent_id, item_id, rule) {
            Err(err) if err.kind() == VaultErrorKind::InvalidInput => Err(fail(
                "invalid_input",
                "The rule is not valid. Use at most 32 entries of 128 characters, an instruction of at most 1000 characters, and a run limit of 1 or more.",
            )),
            other => other.map_err(map_err),
        }
    }

    pub fn remove_exec_grant(&mut self, agent_id: u64, item_id: u64) -> ModelResult<()> {
        self.unlocked()?
            .remove_exec_grant(agent_id, item_id)
            .map_err(map_err)
    }

    /// Newest entries first. Item names come from the vault. Deleted items show their ID.
    pub fn activity(&self, limit: usize) -> ModelResult<Vec<AgentActivityRow>> {
        let vault = self.unlocked()?;
        let records = vault.recent_activity(limit).map_err(map_err)?;
        Ok(records
            .into_iter()
            .map(|record| {
                let item = match record.item_id {
                    Some(id) => vault
                        .details(id)
                        .map_or_else(|_| format!("Item {id} (deleted)"), |d| d.summary.title),
                    None => "No item".to_owned(),
                };
                AgentActivityRow {
                    when: format_utc(record.at),
                    agent: record.agent_name,
                    item,
                    operation: record.operation,
                    decision: record.decision,
                    reason: record.reason,
                }
            })
            .collect())
    }

    fn install(&mut self, vault: Vault, path: PathBuf) {
        self.revealed.clear();
        *self.slot() = Some(vault);
        self.path = Some(path);
    }

    fn detach(&mut self) -> HeldVault {
        self.revealed.clear();
        let vault = self.slot().take();
        HeldVault {
            vault,
            path: self.path.take(),
        }
    }

    fn attach(&mut self, held: HeldVault) {
        *self.slot() = held.vault;
        self.path = held.path;
    }

    fn unlocked(&self) -> ModelResult<Unlocked<'_>> {
        let slot = self.slot();
        match slot.as_ref() {
            Some(vault) if !vault.is_locked() => Ok(Unlocked(slot)),
            Some(_) => Err(fail("vault_locked", "The vault is locked.")),
            None => Err(fail("vault_locked", "No vault file is open.")),
        }
    }

    fn row_from(&self, summary: crate::vault::ItemSummary) -> ModelResult<OwnerSummary> {
        let (service, project) = self.service_project(summary.id)?;
        Ok(OwnerSummary {
            id: summary.id,
            name: summary.title,
            kind: summary.kind,
            service,
            project,
            revision: summary.revision,
        })
    }

    fn service_project(&self, id: u64) -> ModelResult<(String, String)> {
        let vault = self.unlocked()?;
        Ok((
            plain_value(&vault, id, "service")?,
            plain_value(&vault, id, "project")?,
        ))
    }

    fn details_from_meta(&self, meta: crate::vault::ItemDetails) -> ModelResult<OwnerDetails> {
        let id = meta.summary.id;
        let (service, project, username, host, database_name, public_label) = {
            let vault = self.unlocked()?;
            (
                plain_value(&vault, id, "service")?,
                plain_value(&vault, id, "project")?,
                plain_value(&vault, id, "username")?,
                plain_value(&vault, id, "host")?,
                plain_value(&vault, id, "database")?,
                plain_value(&vault, id, "public_key")?,
            )
        };
        let field_name = meta
            .fields
            .iter()
            .find(|field| field.secret && meta.summary.kind == CredentialKind::Custom)
            .map(|field| field.name.clone())
            .unwrap_or_default();
        let mut secret_lines = Vec::new();
        for field in &meta.fields {
            if !field.secret {
                continue;
            }
            let revealed = self.revealed.get(&(id, field.name.clone()));
            secret_lines.push(SecretLine {
                name: field.name.clone(),
                revealed: revealed.is_some(),
                display: revealed.map_or_else(|| MASKED_VALUE.to_owned(), |value| value.0.clone()),
            });
        }
        Ok(OwnerDetails {
            id,
            name: meta.summary.title,
            kind: meta.summary.kind,
            service,
            project,
            notes: meta.notes,
            username,
            host,
            database_name,
            field_name,
            public_label,
            revision: meta.summary.revision,
            hidden: false,
            secret_lines,
            message: String::new(),
        })
    }
}

impl Default for OwnerSession {
    fn default() -> Self {
        Self::new()
    }
}

struct HeldVault {
    vault: Option<Vault>,
    path: Option<PathBuf>,
}

struct RevealedValue(String);

impl fmt::Debug for RevealedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Drop for RevealedValue {
    fn drop(&mut self) {
        self.0.clear();
    }
}

/// A connector row for the Agents view. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRow {
    pub item_id: u64,
    pub item_name: String,
    pub profile_label: &'static str,
    pub base_url: String,
    pub operations: Vec<(&'static str, &'static str)>,
}

/// An activity row for the Activity view. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentActivityRow {
    pub when: String,
    pub agent: String,
    pub item: String,
    pub operation: String,
    pub decision: ActivityDecision,
    pub reason: String,
}

/// UTC time as `YYYY-MM-DD HH:MM:SS UTC`. Uses the civil-from-days method.
pub fn format_utc(unix: u64) -> String {
    let days = unix / 86_400;
    let rem = unix % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Vault list row. It has no field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSummary {
    pub id: u64,
    pub name: String,
    pub kind: CredentialKind,
    pub service: String,
    pub project: String,
    pub revision: u64,
}

/// Item detail for the owner view. Debug redacts notes and revealed values.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerDetails {
    pub id: u64,
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
    pub revision: u64,
    pub hidden: bool,
    pub secret_lines: Vec<SecretLine>,
    pub message: String,
}

impl OwnerDetails {
    fn hidden(id: u64, message: &str) -> Self {
        Self {
            id,
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
            revision: 0,
            hidden: true,
            secret_lines: Vec::new(),
            message: message.to_owned(),
        }
    }

    pub fn to_draft(&self) -> ItemDraft {
        ItemDraft {
            name: self.name.clone(),
            kind: self.kind,
            service: self.service.clone(),
            project: self.project.clone(),
            notes: self.notes.clone(),
            username: self.username.clone(),
            host: self.host.clone(),
            database_name: self.database_name.clone(),
            field_name: self.field_name.clone(),
            public_label: self.public_label.clone(),
        }
    }

    pub fn agent_use_label(&self) -> &'static str {
        AGENT_USE_LABEL
    }

    pub fn reveal_warning(&self) -> &'static str {
        REVEAL_WARNING
    }

    pub fn any_revealed(&self) -> bool {
        self.secret_lines.iter().any(|line| line.revealed)
    }
}

impl fmt::Debug for OwnerDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerDetails")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("service", &self.service)
            .field("project", &self.project)
            .field("notes", &"[redacted]")
            .field("username", &self.username)
            .field("host", &self.host)
            .field("database_name", &self.database_name)
            .field("field_name", &self.field_name)
            .field("public_label", &self.public_label)
            .field("revision", &self.revision)
            .field("hidden", &self.hidden)
            .field("secret_lines", &self.secret_lines)
            .field("message", &self.message)
            .finish()
    }
}

/// One secret field on the item screen.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretLine {
    pub name: String,
    pub revealed: bool,
    pub display: String,
}

impl fmt::Debug for SecretLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretLine")
            .field("name", &self.name)
            .field("revealed", &self.revealed)
            .field(
                "display",
                &if self.revealed {
                    "[redacted]"
                } else {
                    MASKED_VALUE
                },
            )
            .finish()
    }
}

fn fail(code: &'static str, message: impl Into<String>) -> ModelError {
    ModelError {
        code,
        message: message.into(),
    }
}

fn map_err(err: VaultError) -> ModelError {
    let code = match err.kind() {
        VaultErrorKind::Locked => "vault_locked",
        VaultErrorKind::AlreadyExists => "already_exists",
        VaultErrorKind::NotFound => "not_found",
        VaultErrorKind::Conflict => "conflict",
        VaultErrorKind::InvalidInput => "invalid_input",
        VaultErrorKind::WrongKeyOrCorrupt => "wrong_key",
        VaultErrorKind::UnsupportedSchema => "unsupported_schema",
        VaultErrorKind::Busy => "busy",
        VaultErrorKind::Io => "io",
        VaultErrorKind::Storage => "storage",
    };
    ModelError {
        code,
        message: owner_message(err.kind()).to_owned(),
    }
}

/// Owner-facing text for a vault failure. `VaultError` text stays terse for logs and callers.
fn owner_message(kind: VaultErrorKind) -> &'static str {
    match kind {
        VaultErrorKind::Locked => "The vault is locked. Unlock it first.",
        VaultErrorKind::AlreadyExists => {
            "A file already exists at this path. Use a different path."
        }
        VaultErrorKind::NotFound => "The vault file or the item was not found.",
        VaultErrorKind::Conflict => "The item changed after you opened it. Open the item again.",
        VaultErrorKind::InvalidInput => {
            "A value is not valid. Examine the required fields and the passphrase."
        }
        VaultErrorKind::WrongKeyOrCorrupt => {
            "The passphrase is incorrect, or the vault file is damaged."
        }
        VaultErrorKind::UnsupportedSchema => {
            "The vault file has a format that this app cannot read."
        }
        VaultErrorKind::Busy => "Another process uses the vault file. Try again later.",
        VaultErrorKind::Io => {
            "The app cannot read or write the file. Examine the path and the file permissions."
        }
        VaultErrorKind::Storage => "The vault storage operation failed.",
    }
}

fn require_passphrase(passphrase: &str) -> ModelResult<()> {
    if passphrase.is_empty() {
        Err(fail("invalid_input", "Type the passphrase."))
    } else {
        Ok(())
    }
}

fn require_new_passphrase(passphrase: &str) -> ModelResult<()> {
    require_passphrase(passphrase)?;
    if passphrase.len() < MIN_PASSPHRASE_BYTES {
        return Err(fail(
            "invalid_input",
            format!("The passphrase must have a minimum of {MIN_PASSPHRASE_BYTES} characters."),
        ));
    }
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(fail(
            "invalid_input",
            format!("The passphrase must have a maximum of {MAX_PASSPHRASE_BYTES} bytes."),
        ));
    }
    if passphrase.contains('\0') || passphrase.starts_with("x'") || passphrase.starts_with("X'") {
        return Err(fail(
            "invalid_input",
            "The passphrase cannot start with x' or X'. It cannot contain a NUL character.",
        ));
    }
    Ok(())
}

fn require_path(path: &Path) -> ModelResult<()> {
    if path.as_os_str().is_empty() {
        Err(fail("invalid_input", "A file path is required."))
    } else {
        Ok(())
    }
}

fn plain_value(vault: &Vault, id: u64, name: &str) -> ModelResult<String> {
    match vault.reveal(id, name) {
        Ok(value) => Ok(value.expose().to_owned()),
        Err(err) if err.kind() == VaultErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(map_err(err)),
    }
}

fn build_vault_draft(
    vault: &Vault,
    existing: Option<u64>,
    draft: &ItemDraft,
    secrets: &SecretForm,
) -> ModelResult<VaultDraft> {
    let title = draft.name.trim();
    if title.is_empty() {
        return Err(fail("invalid_input", "The item name is required."));
    }
    if let Some(id) = existing {
        let current = vault.details(id).map_err(map_err)?;
        if current.summary.kind != draft.kind {
            return Err(fail(
                "category_locked",
                "The item category cannot change. Delete the item and add a new one.",
            ));
        }
    }

    let mut fields = Vec::new();
    push_plain(&mut fields, "service", &draft.service);
    push_plain(&mut fields, "project", &draft.project);
    match draft.kind {
        CredentialKind::ApiKey => {
            push_secret(
                &mut fields,
                vault,
                existing,
                "token",
                &secrets.token,
                true,
                "Enter the API token.",
            )?;
        }
        CredentialKind::Login => {
            push_required_plain(
                &mut fields,
                "username",
                &draft.username,
                "Enter the username.",
            )?;
            push_secret(
                &mut fields,
                vault,
                existing,
                "password",
                &secrets.password,
                true,
                "Enter the password.",
            )?;
        }
        CredentialKind::SshKey => {
            push_secret(
                &mut fields,
                vault,
                existing,
                "private_key",
                &secrets.private_key,
                true,
                "Enter the private key.",
            )?;
            push_secret(
                &mut fields,
                vault,
                existing,
                "passphrase",
                &secrets.key_passphrase,
                false,
                "",
            )?;
            push_plain(&mut fields, "public_key", &draft.public_label);
        }
        CredentialKind::Database => {
            push_required_plain(&mut fields, "host", &draft.host, "Enter the database host.")?;
            push_required_plain(
                &mut fields,
                "database",
                &draft.database_name,
                "Enter the database name.",
            )?;
            push_required_plain(
                &mut fields,
                "username",
                &draft.username,
                "Enter the database username.",
            )?;
            push_secret(
                &mut fields,
                vault,
                existing,
                "password",
                &secrets.password,
                true,
                "Enter the database password.",
            )?;
        }
        CredentialKind::Custom => {
            let name = draft.field_name.trim();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || is_reserved_field(name)
            {
                return Err(fail(
                    "invalid_input",
                    "The custom field name must use letters, digits, or underscores, and it cannot reuse a built-in field name.",
                ));
            }
            push_secret(
                &mut fields,
                vault,
                existing,
                name,
                &secrets.custom_value,
                true,
                "Enter the custom secret.",
            )?;
        }
    }

    let mut tags = Vec::new();
    push_tag(&mut tags, &draft.service)?;
    push_tag(&mut tags, &draft.project)?;
    Ok(VaultDraft {
        title: title.to_owned(),
        kind: draft.kind,
        notes: draft.notes.trim().to_owned(),
        tags,
        fields,
    })
}

fn push_plain(fields: &mut Vec<Field>, name: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    fields.push(Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret: false,
    });
}

fn push_required_plain(
    fields: &mut Vec<Field>,
    name: &str,
    value: &str,
    missing: &str,
) -> ModelResult<()> {
    let value = value.trim();
    if value.is_empty() {
        return Err(fail("invalid_input", missing));
    }
    push_plain(fields, name, value);
    Ok(())
}

fn push_secret(
    fields: &mut Vec<Field>,
    vault: &Vault,
    existing: Option<u64>,
    name: &str,
    typed: &str,
    required: bool,
    missing: &str,
) -> ModelResult<()> {
    let value = if !typed.is_empty() {
        typed.to_owned()
    } else if let Some(id) = existing {
        match vault.reveal(id, name) {
            Ok(value) => value.expose().to_owned(),
            Err(err) if err.kind() == VaultErrorKind::NotFound && !required => return Ok(()),
            Err(err) => return Err(map_err(err)),
        }
    } else if required {
        return Err(fail("invalid_input", missing));
    } else {
        return Ok(());
    };
    if value.is_empty() {
        if required {
            return Err(fail("invalid_input", missing));
        }
        return Ok(());
    }
    fields.push(Field {
        name: name.to_owned(),
        value: SecretValue::new(value),
        secret: true,
    });
    Ok(())
}

fn push_tag(tags: &mut Vec<String>, value: &str) -> ModelResult<()> {
    let value = value.trim();
    if value.is_empty() || tags.iter().any(|tag| tag == value) {
        return Ok(());
    }
    if value.len() > MAX_TAG_BYTES {
        return Err(fail(
            "invalid_input",
            "A project or service label is too long to search.",
        ));
    }
    tags.push(value.to_owned());
    Ok(())
}

fn is_reserved_field(name: &str) -> bool {
    matches!(
        name,
        "service"
            | "project"
            | "token"
            | "password"
            | "private_key"
            | "passphrase"
            | "username"
            | "host"
            | "database"
            | "public_key"
    )
}

/// Windowless round trip used by `--smoke-test` when the vault feature is on.
/// Errors do not include secret values.
pub(crate) fn smoke_roundtrip() -> Result<(), String> {
    let dir =
        tempfile::tempdir().map_err(|_| "smoke vault directory was not created".to_owned())?;
    let path = dir.path().join("smoke.vault");
    let backup = dir.path().join("smoke.backup");
    let restored = dir.path().join("smoke.restored");
    let mut session = OwnerSession::new();
    session
        .create_file(&path, "smoke-vault-pass-1")
        .map_err(|err| err.message)?;
    if !session.is_locked() {
        return Err("a new vault file must start locked".to_owned());
    }
    if session.unlock("smoke-vault-pass-no").is_ok() {
        return Err("the wrong passphrase must not unlock the smoke vault".to_owned());
    }
    session
        .unlock("smoke-vault-pass-1")
        .map_err(|err| err.message)?;
    let mut secrets = SecretForm::default();
    secrets.token = "smoke-secret-token".to_owned();
    let created = session
        .add(
            &ItemDraft {
                name: "Smoke API key".to_owned(),
                kind: CredentialKind::ApiKey,
                project: "Smoke project".to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .map_err(|err| err.message)?;
    secrets.clear();
    if session
        .search("Smoke project")
        .map_err(|err| err.message)?
        .len()
        != 1
    {
        return Err("search missed the smoke item".to_owned());
    }
    if !session
        .search("smoke-secret-token")
        .map_err(|err| err.message)?
        .is_empty()
    {
        return Err("search matched a secret value".to_owned());
    }
    let revealed = session.reveal(created.id).map_err(|err| err.message)?;
    if !revealed.any_revealed() {
        return Err("reveal did not show a value".to_owned());
    }
    session.lock().map_err(|err| err.message)?;
    if !session
        .details(created.id)
        .map_err(|err| err.message)?
        .hidden
    {
        return Err("lock did not hide item details".to_owned());
    }
    session
        .unlock("smoke-vault-pass-1")
        .map_err(|err| err.message)?;
    session.backup(&backup).map_err(|err| err.message)?;
    if !session.is_locked() {
        return Err("backup must leave the vault locked".to_owned());
    }
    session
        .restore(&backup, &restored, "smoke-vault-pass-1")
        .map_err(|err| err.message)?;
    session
        .unlock("smoke-vault-pass-1")
        .map_err(|err| err.message)?;
    let found = session.search("Smoke API key").map_err(|err| err.message)?;
    if found.len() != 1 {
        return Err("restore did not keep the smoke item".to_owned());
    }
    session
        .delete(found[0].id, found[0].revision)
        .map_err(|err| err.message)?;
    Ok(())
}
