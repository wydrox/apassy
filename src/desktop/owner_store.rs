//! Owner vault and item session for the desktop shell.
//!
//! Agents, grants, and agent activity use the vault (ADR 0004). Rules and demo
//! approvals stay on the in-memory demo model.
//! This session is a trusted-process adapter over [`crate::vault`].
//! Reveal, grant and rule changes, and token rotation take an [`OwnerProof`] from
//! [`crate::broker::approvals::OwnerGate::authorize`] (goal item A4). Real-secret
//! use stays blocked.
//!
//! Secret text in this module is erased with `zeroize` when it is dropped or cleared
//! (key-memory review F3). This is best effort: copies in egui, SQLite, the
//! allocator, and swap can stay.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::broker::SharedVault;
use crate::broker::approvals::{ApprovalQueue, OwnerAction, OwnerProof};
use crate::broker::http::parse_destination;
use crate::broker::profile;
use crate::contracts::CredentialKind;
use crate::desktop::model::{DetailDraft, ItemDraft, ModelError, ModelResult};
use crate::vault::providers::{self, Suggestion};
use crate::vault::{
    AccessRequest, ActivityDecision, ActivityRecord, AgentSummary, AgentToken, CompanionDevice,
    CompanionSetting, Declaration, Destination, EnvBinding, EnvDelivery, Environment, ExecGrant,
    ExecMode, ExecRule, Field, GrantPlace, ItemDraft as VaultDraft, ItemEvent, ItemTimes,
    MAX_PASSPHRASE_BYTES, MAX_PLACEHOLDER_HOSTS, MAX_TOKEN_LIFETIME_DAYS, MIN_PASSPHRASE_BYTES,
    Reversibility, RiskLevel, Scope, SecretValue, SuggestionStats, Vault, VaultError,
    VaultErrorKind, checked_env_name, parse_placeholder_host,
};

mod browser;
pub use browser::{FillValues, PageLogin};

const MAX_TAG_BYTES: usize = 64;
/// The most tags on one item (`MAX_TAG_COUNT` in `src/vault/types.rs`).
const MAX_TAG_COUNT: usize = 32;

/// A custom detail is an item field with this prefix. The rest of the name is the label
/// in hexadecimal, because a field name takes only ASCII letters, digits, and `_`, and a
/// label can have any text.
pub const DETAIL_PREFIX: &str = "x_";
/// The longest label of a custom detail, in bytes. The field name takes 2 + 2 × 31 bytes.
pub const MAX_DETAIL_LABEL_BYTES: usize = 31;
/// The most custom details on one item.
pub const MAX_DETAILS: usize = 10;

/// The field name of a custom detail with `label`.
pub fn detail_field_name(label: &str) -> String {
    let mut name = String::from(DETAIL_PREFIX);
    for byte in label.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// The label of a custom detail field. `None` for another field.
pub fn detail_label(name: &str) -> Option<String> {
    crate::vault::custom_detail_label(name)
}

/// The owner-facing name of a field: a built-in name, or the label of a custom detail.
pub fn field_label(name: &str) -> String {
    match name {
        "token" => "Token".to_owned(),
        "password" => "Password".to_owned(),
        "private_key" => "Private key".to_owned(),
        "passphrase" => "Key passphrase".to_owned(),
        "username" => "Username".to_owned(),
        "website" => "Website".to_owned(),
        "host" => "Host".to_owned(),
        "database" => "Database".to_owned(),
        "public_key" => "Public key".to_owned(),
        "service" => "Service".to_owned(),
        "project" => "Project".to_owned(),
        other => detail_label(other).unwrap_or_else(|| other.to_owned()),
    }
}

/// A revealed value hides itself after this time (key-memory review F10).
pub const REVEAL_TIME: Duration = Duration::from_secs(30);

const AGENT_USE_LABEL: &str = "Stored in the vault. Agent use is not connected.";
const REVEAL_WARNING: &str =
    "The value is visible in this window for 30 seconds, or until you hide it or lock the vault.";

/// Activity text when the owner locks the vault while runs wait (goal item N3).
pub const ENDED_BY_LOCK: &str =
    "The owner locked the vault before a decision. The run did not start.";
/// Activity text when Apassy quits while runs wait (goal item N3).
pub const ENDED_BY_QUIT: &str = "Apassy stopped before the owner decided. The run did not start.";
/// Activity text when the owner switches to another vault while runs wait (ADR 0013).
pub const ENDED_BY_SWITCH: &str =
    "The owner switched to another vault before a decision. The run did not start.";

/// Secret inputs for one item form. Debug output is redacted. There is no `Clone`,
/// so the form is the only copy that the app keeps.
#[derive(Default)]
pub struct SecretForm {
    pub token: String,
    pub password: String,
    pub private_key: String,
    pub key_passphrase: String,
    pub custom_value: String,
    /// The values of hidden custom details, by the position of the detail.
    pub details: [String; MAX_DETAILS],
}

impl SecretForm {
    pub fn is_blank(&self) -> bool {
        self.token.is_empty()
            && self.password.is_empty()
            && self.private_key.is_empty()
            && self.key_passphrase.is_empty()
            && self.custom_value.is_empty()
            && self.details.iter().all(String::is_empty)
    }

    /// Erase every field. The buffers keep their capacity (key-memory review F4).
    pub fn clear(&mut self) {
        self.token.zeroize();
        self.password.zeroize();
        self.private_key.zeroize();
        self.key_passphrase.zeroize();
        self.custom_value.zeroize();
        for detail in &mut self.details {
            detail.zeroize();
        }
    }

    /// Remove the hidden value at `index` when the owner removes that detail. The later
    /// values move down one place. The buffers move; their text is not copied.
    pub fn remove_detail(&mut self, index: usize) {
        if index >= MAX_DETAILS {
            return;
        }
        self.details[index].zeroize();
        self.details[index..].rotate_left(1);
    }

    /// The fields and their widget names in the item forms.
    pub fn fields_mut(&mut self) -> [(&'static str, &mut String); 5] {
        [
            ("token", &mut self.token),
            ("password", &mut self.password),
            ("private", &mut self.private_key),
            ("phrase", &mut self.key_passphrase),
            ("custom", &mut self.custom_value),
        ]
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

/// Passphrase or other short-lived secret text. Drop erases the bytes.
pub struct Ephemeral(String);

impl Ephemeral {
    /// Move the text out of `slot`. The slot gets a new empty buffer with the same
    /// capacity, so the next typing does not move the text (key-memory review F4).
    pub fn take(slot: &mut String) -> Self {
        let capacity = slot.capacity();
        Self(std::mem::replace(slot, String::with_capacity(capacity)))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Move the text into an erasing buffer without a copy.
    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Ephemeral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ephemeral([redacted])")
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
    /// The provider ID (schema 8). The command analysis gets its known hosts.
    pub provider: Option<String>,
    /// The suggestion from the item (goal item B4). `None` when no signal matched.
    pub suggestion: Option<Suggestion>,
}

impl Default for DeclarationForm {
    /// Conservative defaults. The owner changes them on purpose.
    fn default() -> Self {
        Self {
            project: String::new(),
            environment: providers::DEFAULT_ENVIRONMENT,
            risk: providers::DEFAULT_RISK,
            scope: providers::DEFAULT_SCOPE,
            reversibility: providers::DEFAULT_REVERSIBILITY,
            stored: false,
            provider: None,
            suggestion: None,
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
            ..Self::default()
        })
    }

    /// The form of one item (goal item B4). A stored declaration fills the form, and the
    /// suggestion stays as a hint. Without one, each suggested field fills the form, and
    /// a field without a suggestion keeps the most sensitive default. The project name
    /// comes from the project of the item.
    pub fn for_item(
        stored: Option<(Declaration, Option<String>)>,
        suggestion: Suggestion,
        project: &str,
    ) -> Self {
        let suggestion = (!suggestion.is_empty()).then_some(suggestion);
        if let Some((declaration, provider)) = stored {
            return Self {
                provider,
                suggestion,
                ..Self::from_declaration(Some(declaration))
            };
        }
        let Some(suggestion) = suggestion else {
            return Self {
                project: project.trim().to_owned(),
                ..Self::default()
            };
        };
        let form = suggestion.prefilled();
        Self {
            project: project.trim().to_owned(),
            environment: form.environment,
            risk: form.risk,
            scope: form.scope,
            reversibility: form.reversibility,
            stored: false,
            provider: form.provider,
            suggestion: Some(suggestion),
        }
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

/// A token that the app shows one time, after a registration or a rotation.
#[derive(Debug)]
pub struct FreshToken {
    pub agent_name: String,
    pub token: AgentToken,
    /// The token replaces an older token. The old token does not work.
    pub rotated: bool,
}

/// Text fields that bind the vault file controls.
#[derive(Default)]
pub struct OwnerUiState {
    pub session: OwnerSession,
    pub create_path: String,
    pub open_path: String,
    pub passphrase: String,
    /// The passphrase typed a second time when the owner creates a vault. The app
    /// erases it after each try.
    pub passphrase_confirm: String,
    /// Passphrase change fields (goal item V5). The app clears them after each attempt.
    pub passphrase_current: String,
    pub passphrase_new: String,
    pub passphrase_repeat: String,
    pub backup_path: String,
    pub restore_source: String,
    pub restore_dest: String,
    pub add_secrets: SecretForm,
    pub edit_secrets: SecretForm,
    pub edit_revision: u64,
    pub connector_url: String,
    pub new_agent_name: String,
    /// The token of the agent that the owner registered or rotated last. It is shown one time.
    pub fresh_token: Option<FreshToken>,
    /// Token lifetime text in the Agents view, in days.
    pub token_lifetime_input: String,
    pub selected_agent: Option<u64>,
    pub env_name_input: String,
    pub env_field_input: String,
    /// The variable holds a placeholder, and the run proxy adds the value (ADR 0011).
    pub env_placeholder_input: bool,
    /// The hosts of a placeholder variable, as the owner typed them.
    pub env_hosts_input: String,
    /// Declaration form of the selected item (ADR 0008).
    pub declaration_form: DeclarationForm,
    /// Project directory text for each (agent, item) pair in the Agents view.
    pub exec_dir_inputs: BTreeMap<(u64, u64), String>,
    /// Rule editor text for each (agent, item) pair.
    pub rule_inputs: BTreeMap<(u64, u64), RuleForm>,
    /// Pending run IDs that the app already signaled to the owner.
    pub signaled_runs: BTreeSet<u64>,
}

/// A step with the unlocked vault just before the session locks it: a lock, a switch,
/// a quit, a restart for an update, a backup, or an open or a restore that replaces it.
/// Runs that waited have ended by then. iCloud sync pushes here (ADR 0014). The step
/// must not fail the lock, so it returns nothing.
pub type BeforeLock = Box<dyn FnMut(&mut Vault) + Send>;

/// The [`BeforeLock`] step of a session, if any.
#[derive(Default)]
struct LockHook(Option<BeforeLock>);

impl LockHook {
    fn run(&mut self, vault: &mut Vault) {
        if let Some(step) = self.0.as_mut()
            && !vault.is_locked()
        {
            step(vault);
        }
    }
}

impl fmt::Debug for LockHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "LockHook(set)"
        } else {
            "LockHook(none)"
        })
    }
}

/// One vault file open inside this process. The broker shares the same slot.
#[derive(Debug)]
pub struct OwnerSession {
    vault: SharedVault,
    path: Option<PathBuf>,
    revealed: BTreeMap<(u64, String), RevealedValue>,
    before_lock: LockHook,
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
            before_lock: LockHook::default(),
        }
    }

    /// Set the step that runs before each lock ([`BeforeLock`]). `None` removes it.
    pub fn set_before_lock(&mut self, step: Option<BeforeLock>) {
        self.before_lock = LockHook(step);
    }

    /// Run `f` with the open vault, locked or unlocked. The vault mutex is held for the
    /// call, so the broker waits: keep it short. `None` when no file is open.
    pub fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> Option<T> {
        self.slot().as_mut().map(f)
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
                previous.retire(&mut self.before_lock);
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

    /// Change the master passphrase (goal item V5). The owner types the new passphrase
    /// two times. After a failure, the old passphrase stays valid.
    pub fn change_passphrase(&mut self, current: &str, new: &str, repeat: &str) -> ModelResult<()> {
        if current.is_empty() {
            return Err(fail("invalid_input", "Type the current passphrase."));
        }
        if new != repeat {
            return Err(fail(
                "invalid_input",
                "The two new passphrases are different. Type the new passphrase two times.",
            ));
        }
        require_new_passphrase(new)?;
        if new == current {
            return Err(fail(
                "invalid_input",
                "The new passphrase is the same as the current passphrase.",
            ));
        }
        self.revealed.clear();
        let result = self.unlocked()?.change_passphrase(current, new);
        let Err(err) = result else {
            return Ok(());
        };
        Err(match (err.kind(), self.is_locked()) {
            (VaultErrorKind::WrongKeyOrCorrupt, false) => fail(
                "wrong_key",
                "The current passphrase is incorrect. The passphrase did not change.",
            ),
            (VaultErrorKind::Busy, true) => fail(
                "busy",
                "Another program uses the vault file. The passphrase did not change. The vault is locked. Close the other program, then unlock with the old passphrase.",
            ),
            (VaultErrorKind::Storage, true) => fail(
                "storage",
                "The passphrase did not change. The vault is locked. Unlock it with the old passphrase.",
            ),
            (VaultErrorKind::WrongKeyOrCorrupt, true) => fail(
                "wrong_key",
                "The passphrase change did not finish. Unlock the vault with the old passphrase. If it does not open, use the new passphrase. If neither opens, restore a backup.",
            ),
            _ => map_err(err),
        })
    }

    pub fn lock(&mut self) -> ModelResult<()> {
        self.lock_ending_runs(None, ENDED_BY_LOCK)
    }

    /// Lock the vault and end every run that waits in `approvals` (goal items V3, N3).
    ///
    /// Before the lock, each waiting run gets a denial in the activity log with `why`,
    /// from its wait record, so the inbox keeps the event after a restart. The vault
    /// mutex is held from the record to the lock, so the broker does not record the same
    /// run again: it finds the vault locked or its wait record gone.
    pub fn lock_ending_runs(
        &mut self,
        approvals: Option<&ApprovalQueue>,
        why: &str,
    ) -> ModelResult<()> {
        self.revealed.clear();
        let mut slot = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let result = match slot.as_mut() {
            None => Ok(()),
            Some(vault) => {
                // The broker stores a record for each waiting run (schema 7). Each
                // record becomes one entry, also for a run that the queue does not
                // list yet.
                if !vault.is_locked() {
                    let _ = vault.end_waits(why);
                }
                self.before_lock.run(vault);
                vault.lock().map_err(map_err)
            }
        };
        if let Some(queue) = approvals {
            queue.invalidate_all();
        }
        result
    }

    /// The canonical path of the open vault file, also when it is locked.
    pub fn vault_path(&self) -> Option<PathBuf> {
        self.slot().as_ref().map(|vault| vault.path().to_path_buf())
    }

    /// The epoch of the unlocked vault session. A lock or an unlock changes it.
    pub fn epoch(&self) -> Option<[u8; 32]> {
        self.slot()
            .as_ref()
            .filter(|vault| !vault.is_locked())
            .map(Vault::epoch)
    }

    /// The remembered patterns (ADR 0010).
    pub fn patterns(&self) -> ModelResult<Vec<crate::vault::PatternRecord>> {
        self.unlocked()?.patterns().map_err(map_err)
    }

    /// Remove a pattern. Matching runs ask the owner again. It takes authority away, so
    /// it needs no owner check.
    pub fn remove_pattern(&mut self, id: u64) -> ModelResult<()> {
        self.unlocked()?.remove_pattern(id).map_err(map_err)
    }

    /// All decisions as JSON Lines (`docs/operations/learning.md`). They have commands
    /// and user requests, but no secret value.
    pub fn export_decisions(&self) -> ModelResult<String> {
        self.unlocked()?.export_decisions_jsonl().map_err(map_err)
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

    /// Add an item from an import (`crate::import`). The draft already has the layout of
    /// the item forms: built-in fields and custom details. No agent gets access.
    pub fn add_imported(&mut self, draft: VaultDraft) -> ModelResult<OwnerSummary> {
        let summary = self.unlocked()?.add(draft).map_err(map_err)?;
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

    /// Show the secret values of an item for [`REVEAL_TIME`]. Needs a fresh owner
    /// check for [`OwnerAction::Reveal`] of this item (goal item A4).
    pub fn reveal(&mut self, id: u64, proof: OwnerProof) -> ModelResult<OwnerDetails> {
        let pairs = {
            let mut vault = self.unlocked_for(proof, &OwnerAction::Reveal { item_id: id })?;
            // The history says when the owner saw the values (schema 10).
            vault.record_reveal(id).map_err(map_err)?;
            let meta = vault.details(id).map_err(map_err)?;
            let mut pairs = Vec::new();
            for field in &meta.fields {
                if !field.secret {
                    continue;
                }
                // Move the value into the erasing buffer without a copy (F10).
                let value = vault.reveal(id, &field.name).map_err(map_err)?;
                pairs.push((
                    field.name.clone(),
                    RevealedValue {
                        value: value.into_zeroizing(),
                        shown_at: Instant::now(),
                    },
                ));
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

    /// The revealed value of one field. The view borrows it. There is no copy in
    /// [`OwnerDetails`] (key-memory review F10). `None` after [`REVEAL_TIME`].
    pub fn revealed_value(&self, id: u64, field: &str) -> Option<&str> {
        self.revealed
            .get(&(id, field.to_owned()))
            .filter(|value| value.shown_at.elapsed() < REVEAL_TIME)
            .map(|value| value.value.as_str())
    }

    /// Hide values that are older than [`REVEAL_TIME`]. The app calls this each frame.
    pub fn expire_reveals(&mut self) {
        self.expire_reveals_at(Instant::now());
    }

    /// Hide values that are older than [`REVEAL_TIME`] at `now`.
    pub fn expire_reveals_at(&mut self, now: Instant) {
        self.revealed
            .retain(|_, value| now.saturating_duration_since(value.shown_at) < REVEAL_TIME);
    }

    /// Time until the next revealed value hides itself.
    pub fn next_reveal_expiry(&self) -> Option<Duration> {
        self.revealed
            .values()
            .map(|value| REVEAL_TIME.saturating_sub(value.shown_at.elapsed()))
            .min()
    }

    pub fn backup(&mut self, destination: &Path) -> ModelResult<()> {
        require_path(destination)?;
        let result = {
            let mut slot = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
            let vault = match slot.as_mut() {
                Some(vault) if !vault.is_locked() => vault,
                Some(_) => return Err(fail("vault_locked", "The vault is locked.")),
                None => return Err(fail("vault_locked", "No vault file is open.")),
            };
            self.before_lock.run(vault);
            vault.backup(destination)
        };
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
                previous.retire(&mut self.before_lock);
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

    /// Give the agent a new token. Show it to the owner one time. The old token stops working.
    /// Needs a fresh owner check (goal item A4).
    pub fn rotate_agent_token(
        &mut self,
        agent_id: u64,
        proof: OwnerProof,
    ) -> ModelResult<AgentToken> {
        let mut vault = self.unlocked_for(proof, &OwnerAction::RotateToken { agent_id })?;
        match vault.rotate_agent_token(agent_id) {
            Err(err) if err.kind() == VaultErrorKind::InvalidInput => Err(fail(
                "invalid_input",
                "A revoked agent cannot get a new token. Register the agent again.",
            )),
            other => other.map_err(map_err),
        }
    }

    pub fn token_lifetime_days(&self) -> ModelResult<u32> {
        self.unlocked()?.token_lifetime_days().map_err(map_err)
    }

    /// Change the token lifetime from the text in the Agents view. Needs a fresh owner
    /// check (goal item A4).
    pub fn set_token_lifetime_days(&mut self, days: &str, proof: OwnerProof) -> ModelResult<u32> {
        let days = parse_lifetime_days(days)?;
        self.unlocked_for(proof, &OwnerAction::ChangeTokenLifetime)?
            .set_token_lifetime_days(days)
            .map_err(map_err)?;
        Ok(days)
    }

    /// The companion setting and the epoch of the open vault session. The app starts the
    /// listener for exactly this epoch.
    pub fn companion_status(&self) -> ModelResult<(CompanionSetting, [u8; 32])> {
        let vault = self.unlocked()?;
        let setting = vault.companion_setting().map_err(map_err)?;
        Ok((setting, vault.epoch()))
    }

    /// Turn the iPhone listener on or off. It needs no owner check: the setting gives no
    /// authority, and every endpoint except pairing needs a paired device.
    pub fn set_companion_enabled(&mut self, enabled: bool) -> ModelResult<()> {
        self.unlocked()?
            .set_companion_enabled(enabled)
            .map_err(map_err)
    }

    /// The paired iPhones, oldest first.
    pub fn companion_devices(&self) -> ModelResult<Vec<CompanionDevice>> {
        self.unlocked()?.companion_devices().map_err(map_err)
    }

    /// Remove one paired iPhone. It needs no owner check: it only takes authority away.
    pub fn remove_companion_device(&mut self, device_id: &str) -> ModelResult<bool> {
        self.unlocked()?
            .remove_companion_device(device_id)
            .map_err(map_err)
    }

    /// Remove every paired iPhone and the certificate. It needs no owner check: it only
    /// takes authority away.
    pub fn reset_companion_pairing(&mut self) -> ModelResult<()> {
        self.unlocked()?.reset_companion_pairing().map_err(map_err)
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

    /// Let the agent use a connector operation of the item. Needs a fresh owner check
    /// (goal item A4).
    pub fn allow_operation(
        &mut self,
        agent_id: u64,
        item_id: u64,
        operation: &str,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        self.unlocked_for(proof, &OwnerAction::ChangeGrant { agent_id, item_id })?
            .set_grant(agent_id, item_id, operation, true)
            .map_err(map_err)
    }

    /// Take a connector operation away from the agent. This only removes authority, so
    /// it needs no owner check.
    pub fn remove_operation(
        &mut self,
        agent_id: u64,
        item_id: u64,
        operation: &str,
    ) -> ModelResult<()> {
        self.unlocked()?
            .set_grant(agent_id, item_id, operation, false)
            .map_err(map_err)
    }

    pub fn connector(&self, item_id: u64) -> ModelResult<Option<Destination>> {
        self.unlocked()?.destination(item_id).map_err(map_err)
    }

    /// Register the connector for an item: `https://`, or `http://` on a loopback address.
    /// The connector decides where the secret goes, so it needs a fresh owner check.
    pub fn set_connector(
        &mut self,
        item_id: u64,
        profile_id: &str,
        base_url: &str,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        let profile = profile::find(profile_id)
            .ok_or_else(|| fail("invalid_input", "The connector profile is not known."))?;
        parse_destination(base_url).map_err(|message| fail("invalid_input", message))?;
        let mut vault = self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id })?;
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

    /// Bind a secret field of the item to an environment variable for agent processes.
    /// Needs a fresh owner check (goal item A4). A placeholder variable (ADR 0011)
    /// needs valid hosts and a value that is long enough for a placeholder.
    pub fn set_env_binding(
        &mut self,
        item_id: u64,
        env_name: &str,
        field: &str,
        delivery: &EnvDelivery,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        checked_env_name(env_name.trim()).map_err(|_| {
            fail(
                "invalid_input",
                "Use A-Z, 0-9, and _ and start with a letter or _. System names such as PATH or DYLD_* are not permitted.",
            )
        })?;
        if let EnvDelivery::Placeholder(hosts) = delivery
            && (hosts.is_empty()
                || hosts.len() > MAX_PLACEHOLDER_HOSTS
                || hosts
                    .iter()
                    .any(|host| parse_placeholder_host(host).is_none()))
        {
            return Err(fail(
                "invalid_input",
                "Name 1 to 16 hosts, such as api.stripe.com or api.example.com:8443.",
            ));
        }
        let mut vault = self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id })?;
        if matches!(delivery, EnvDelivery::Placeholder(_)) {
            let value = vault.reveal(item_id, field).map_err(map_err)?;
            if crate::broker::proxy::mint_placeholder(value.expose()).is_none() {
                return Err(fail(
                    "invalid_input",
                    "This value is too short to hide behind a placeholder. Use the real value, or a key with at least 16 random characters.",
                ));
            }
        }
        match vault.set_env_binding_with(item_id, env_name, field, delivery) {
            Err(err) if err.kind() == VaultErrorKind::AlreadyExists => Err(fail(
                "already_exists",
                "Another item already uses this variable name.",
            )),
            other => other.map_err(map_err),
        }
    }

    /// The known API hosts of the provider of the item: the stored one, or the
    /// suggestion. A placeholder variable starts with them.
    pub fn suggested_placeholder_hosts(&self, item_id: u64) -> Vec<String> {
        self.declaration_form(item_id)
            .ok()
            .and_then(|form| form.provider)
            .map(|provider| providers::known_hosts(&provider).to_vec())
            .unwrap_or_default()
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

    /// Give an agent process access to an item, or change the mode or the place. Needs a
    /// fresh owner check (goal item A4).
    pub fn set_exec_grant(
        &mut self,
        agent_id: u64,
        item_id: u64,
        place: &GrantPlace,
        mode: ExecMode,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        let place = checked_place(place)?;
        self.unlocked_for(proof, &OwnerAction::ChangeGrant { agent_id, item_id })?
            .set_exec_grants(agent_id, &[item_id], &place, mode)
            .map_err(map_err)
    }

    /// Give an agent process access to several items with one owner check (ADR 0012).
    /// When one item fails, no grant changes.
    pub fn set_exec_grants(
        &mut self,
        agent_id: u64,
        item_ids: &[u64],
        place: &GrantPlace,
        mode: ExecMode,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        let place = checked_place(place)?;
        let action = OwnerAction::ChangeGrants {
            agent_id,
            item_ids: item_ids.to_vec(),
        };
        self.unlocked_for(proof, &action)?
            .set_exec_grants(agent_id, item_ids, &place, mode)
            .map_err(|err| match err.kind() {
                VaultErrorKind::InvalidInput => fail(
                    "invalid_input",
                    "Select 1 to 64 credentials. Each needs an environment variable.",
                ),
                _ => map_err(err),
            })
    }

    /// The agent sees all credentials without values (ADR 0012).
    pub fn agent_sees_all(&self, agent_id: u64) -> ModelResult<bool> {
        self.unlocked()?.agent_sees_all(agent_id).map_err(map_err)
    }

    /// Turn "see all credentials" on (needs the owner check) or off (takes authority
    /// away, so it needs none). Off also denies the open requests of the agent.
    pub fn set_agent_sees_all(
        &mut self,
        agent_id: u64,
        on: bool,
        proof: Option<OwnerProof>,
    ) -> ModelResult<()> {
        let mut vault = if on {
            let proof = proof.ok_or_else(|| {
                fail(
                    "owner_check_required",
                    "Confirm that it is you to let an agent see all credentials.",
                )
            })?;
            self.unlocked_for(proof, &OwnerAction::ShowAllCredentials { agent_id })?
        } else {
            self.unlocked()?
        };
        vault.set_agent_sees_all(agent_id, on).map_err(map_err)
    }

    /// Access requests of agents, newest first.
    pub fn access_requests(&self, open_only: bool) -> ModelResult<Vec<AccessRequest>> {
        self.unlocked()?
            .access_requests(open_only, 100)
            .map_err(map_err)
    }

    /// Deny an open request. It gives nothing, so it needs no owner check.
    pub fn deny_access_request(&mut self, request_id: u64) -> ModelResult<()> {
        self.unlocked()?
            .deny_access_request(request_id)
            .map_err(map_err)
    }

    /// Give the access that an agent asked for. Needs a fresh owner check for the
    /// agent and the item of the request.
    pub fn grant_access_request(
        &mut self,
        request_id: u64,
        place: &GrantPlace,
        mode: ExecMode,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        let place = checked_place(place)?;
        let (agent_id, item_id) = self
            .unlocked()?
            .open_request_target(request_id)
            .map_err(|_| fail("not_found", "The request is not open any more."))?;
        self.unlocked_for(proof, &OwnerAction::ChangeGrant { agent_id, item_id })?
            .set_exec_grants(agent_id, &[item_id], &place, mode)
            .map_err(map_err)
    }

    pub fn declaration(&self, item_id: u64) -> ModelResult<Option<Declaration>> {
        self.unlocked()?.declaration(item_id).map_err(map_err)
    }

    /// The declaration form of an item: the stored declaration, or the suggestion from
    /// the item (goal item B4). The detection runs here, in the owner flow, with the
    /// vault unlocked.
    pub fn declaration_form(&self, item_id: u64) -> ModelResult<DeclarationForm> {
        let (_, project) = self.service_project(item_id)?;
        let vault = self.unlocked()?;
        let suggestion = vault.suggest_declaration(item_id).map_err(map_err)?;
        let stored = match vault.declaration(item_id).map_err(map_err)? {
            Some(declaration) => Some((
                declaration,
                vault.declaration_provider(item_id).map_err(map_err)?,
            )),
            None => None,
        };
        Ok(DeclarationForm::for_item(stored, suggestion, &project))
    }

    /// The share of suggested declarations that the owner saved without a change.
    pub fn suggestion_stats(&self) -> ModelResult<SuggestionStats> {
        self.unlocked()?.suggestion_stats().map_err(map_err)
    }

    /// Store the owner declaration of an item and its provider (ADR 0008, goal item
    /// B4). The declaration is a rule input for the bouncer, so it needs a fresh owner
    /// check (goal item A4). The first save with a suggestion records its outcome.
    pub fn set_declaration(
        &mut self,
        item_id: u64,
        form: &DeclarationForm,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        if form.project.trim().is_empty() {
            return Err(fail("invalid_input", "Type the project name."));
        }
        if form
            .provider
            .as_deref()
            .is_some_and(|id| providers::find(id).is_none())
        {
            return Err(fail("invalid_input", "The provider is not known."));
        }
        let suggested = form.suggestion.as_ref().map(Suggestion::prefilled);
        self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id })?
            .save_declaration(
                item_id,
                &form.to_declaration(),
                form.provider.as_deref(),
                suggested.as_ref(),
            )
            .map(|_| ())
            .map_err(map_err)
    }

    /// Replace the rule of a process grant (ADR 0007). Needs a fresh owner check (goal
    /// item A4).
    pub fn set_exec_rule(
        &mut self,
        agent_id: u64,
        item_id: u64,
        rule: ExecRule,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        let mut vault = self.unlocked_for(proof, &OwnerAction::ChangeRule { agent_id, item_id })?;
        match vault.set_exec_rule(agent_id, item_id, rule) {
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

    // ---- Review after a restore (goal item V4). ----

    /// Items from a restored backup that wait for the owner review: (item ID, item name).
    pub fn items_needing_review(&self) -> ModelResult<Vec<(u64, String)>> {
        let vault = self.unlocked()?;
        let mut rows = Vec::new();
        for id in vault.items_needing_review().map_err(map_err)? {
            let name = vault
                .details(id)
                .map_or_else(|_| format!("Item {id}"), |details| details.summary.title);
            rows.push((id, name));
        }
        Ok(rows)
    }

    pub fn needs_review(&self, item_id: u64) -> ModelResult<bool> {
        self.unlocked()?.needs_review(item_id).map_err(map_err)
    }

    /// The owner confirms the agent settings of a restored item. Agents can use it again,
    /// so this needs a fresh owner check (goal item A4).
    pub fn confirm_review(&mut self, item_id: u64, proof: OwnerProof) -> ModelResult<()> {
        self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id })?
            .confirm_review(item_id)
            .map_err(map_err)
    }

    /// Newest entries first. Item names come from the vault. Deleted items show their ID.
    pub fn activity(&self, limit: usize) -> ModelResult<Vec<AgentActivityRow>> {
        let vault = self.unlocked()?;
        let records = vault.recent_activity(limit).map_err(map_err)?;
        Ok(activity_rows(&vault, records))
    }

    /// Archive an item. Agents cannot use it, and the list hides it. This only takes
    /// authority away, so it needs no owner check. Revealed values hide.
    pub fn archive(&mut self, id: u64) -> ModelResult<()> {
        self.unlocked()?.set_archived(id, true).map_err(map_err)?;
        self.revealed.retain(|key, _| key.0 != id);
        Ok(())
    }

    /// Bring an item back from the archive. Agents with a grant can use it again, so
    /// this needs a fresh owner check for the agent settings of the item (goal item A4).
    pub fn unarchive(&mut self, id: u64, proof: OwnerProof) -> ModelResult<()> {
        self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id: id })?
            .set_archived(id, false)
            .map_err(map_err)
    }

    pub fn is_archived(&self, id: u64) -> ModelResult<bool> {
        self.unlocked()?.is_archived(id).map_err(map_err)
    }

    /// Archived items and the time of the archive.
    pub fn archived(&self) -> ModelResult<BTreeMap<u64, u64>> {
        self.unlocked()?.archived_items().map_err(map_err)
    }

    /// Verified conflict copies and their original item, when it still exists.
    /// Restored copies retain the relation. Item titles do not establish it.
    pub fn conflict_copies(&self) -> ModelResult<BTreeMap<u64, Option<u64>>> {
        self.unlocked()?.conflict_copies().map_err(map_err)
    }

    /// When each item was added, changed, and used, for sorting.
    pub fn item_times(&self) -> ModelResult<BTreeMap<u64, ItemTimes>> {
        self.unlocked()?.item_times().map_err(map_err)
    }

    /// The change history of an item, newest first. It has no secret value.
    pub fn item_events(&self, id: u64, limit: usize) -> ModelResult<Vec<ItemEvent>> {
        self.unlocked()?.item_events(id, limit).map_err(map_err)
    }

    /// Agent requests with an item, newest first.
    pub fn item_activity(&self, id: u64, limit: usize) -> ModelResult<Vec<AgentActivityRow>> {
        let vault = self.unlocked()?;
        let records = vault.item_activity(id, limit).map_err(map_err)?;
        Ok(activity_rows(&vault, records))
    }

    /// Requests of one agent, newest first.
    pub fn agent_activity(
        &self,
        agent_id: u64,
        limit: usize,
    ) -> ModelResult<Vec<AgentActivityRow>> {
        let vault = self.unlocked()?;
        let records = vault.agent_activity(agent_id, limit).map_err(map_err)?;
        Ok(activity_rows(&vault, records))
    }

    fn install(&mut self, vault: Vault, path: PathBuf) {
        self.revealed.clear();
        let replaced = self.slot().replace(vault);
        HeldVault {
            vault: replaced,
            path: None,
        }
        .retire(&mut self.before_lock);
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

    /// The unlocked vault, after a check of `proof` for `expected` in this vault
    /// session (goal item A4). The proof is used up, also when the check fails.
    fn unlocked_for(&self, proof: OwnerProof, expected: &OwnerAction) -> ModelResult<Unlocked<'_>> {
        let vault = self.unlocked()?;
        proof
            .check(expected, &vault.epoch())
            .map_err(|refusal| fail("owner_check_required", refusal.message()))?;
        Ok(vault)
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
        let (service, project, username, website, host, database_name, public_label) = {
            let vault = self.unlocked()?;
            (
                plain_value(&vault, id, "service")?,
                plain_value(&vault, id, "project")?,
                plain_value(&vault, id, "username")?,
                plain_value(&vault, id, "website")?,
                plain_value(&vault, id, "host")?,
                plain_value(&vault, id, "database")?,
                plain_value(&vault, id, "public_key")?,
            )
        };
        let field_name = meta
            .fields
            .iter()
            .find(|field| {
                field.secret
                    && meta.summary.kind == CredentialKind::Custom
                    && !field.name.starts_with(DETAIL_PREFIX)
            })
            .map(|field| field.name.clone())
            .unwrap_or_default();
        let (details, archived) = {
            let vault = self.unlocked()?;
            let mut details = Vec::new();
            for field in &meta.fields {
                let Some(label) = detail_label(&field.name) else {
                    continue;
                };
                let value = if field.secret {
                    None
                } else {
                    Some(plain_value(&vault, id, &field.name)?)
                };
                details.push(DetailLine {
                    name: field.name.clone(),
                    label,
                    value,
                    hidden: field.secret,
                });
            }
            (details, vault.is_archived(id).map_err(map_err)?)
        };
        // The lines say only which values are revealed. The view borrows a revealed value
        // from the session (key-memory review F10).
        let secret_lines = meta
            .fields
            .iter()
            .filter(|field| field.secret)
            .map(|field| SecretLine {
                name: field.name.clone(),
                revealed: self.revealed_value(id, &field.name).is_some(),
            })
            .collect();
        Ok(OwnerDetails {
            id,
            name: meta.summary.title,
            kind: meta.summary.kind,
            service,
            project,
            notes: meta.notes,
            username,
            website,
            host,
            database_name,
            field_name,
            public_label,
            revision: meta.summary.revision,
            hidden: false,
            secret_lines,
            details,
            archived,
            message: String::new(),
        })
    }
}

/// Activity rows with item names. A deleted item keeps its number.
fn activity_rows(vault: &Vault, records: Vec<ActivityRecord>) -> Vec<AgentActivityRow> {
    records
        .into_iter()
        .map(|record| {
            let item = match record.item_id {
                Some(id) => vault
                    .details(id)
                    .map_or_else(|_| format!("Item {id} (deleted)"), |d| d.summary.title),
                None => "No item".to_owned(),
            };
            AgentActivityRow {
                id: record.id,
                at: record.at,
                when: format_utc(record.at),
                agent: record.agent_name,
                item,
                operation: record.operation,
                decision: record.decision,
                reason: record.reason,
            }
        })
        .collect()
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

impl HeldVault {
    /// Close a vault that another file replaced (ADR 0013). When it is still
    /// unlocked, each run that waits in it gets its denial first, as at a lock, and the
    /// step before a lock runs.
    fn retire(self, before_lock: &mut LockHook) {
        if let Some(mut vault) = self.vault
            && !vault.is_locked()
        {
            let _ = vault.end_waits(ENDED_BY_SWITCH);
            before_lock.run(&mut vault);
            let _ = vault.lock();
        }
    }
}

/// One revealed value. `Zeroizing` erases it when it is hidden, expires, or the vault
/// locks. There is no `Clone`.
struct RevealedValue {
    value: Zeroizing<String>,
    shown_at: Instant,
}

impl fmt::Debug for RevealedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
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
    /// The ID of the activity entry. It grows with each entry.
    pub id: u64,
    /// Unix time of the entry.
    pub at: u64,
    pub when: String,
    pub agent: String,
    pub item: String,
    pub operation: String,
    pub decision: ActivityDecision,
    pub reason: String,
}

pub use crate::vault::format_utc;

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
    /// The `website` field of a login (ADR 0021).
    pub website: String,
    pub host: String,
    pub database_name: String,
    pub field_name: String,
    pub public_label: String,
    pub revision: u64,
    pub hidden: bool,
    /// Every secret field, with the hidden custom details. The view borrows a revealed
    /// value from the session.
    pub secret_lines: Vec<SecretLine>,
    /// Custom details in order. A hidden one has no value here.
    pub details: Vec<DetailLine>,
    /// Agents cannot use an archived item.
    pub archived: bool,
    pub message: String,
}

/// One custom detail on the item page. It has no hidden value.
#[derive(Clone, PartialEq, Eq)]
pub struct DetailLine {
    /// The field name.
    pub name: String,
    pub label: String,
    /// The value of a visible detail. `None` for a hidden detail.
    pub value: Option<String>,
    pub hidden: bool,
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
            website: String::new(),
            host: String::new(),
            database_name: String::new(),
            field_name: String::new(),
            public_label: String::new(),
            revision: 0,
            hidden: true,
            secret_lines: Vec::new(),
            details: Vec::new(),
            archived: false,
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
            website: self.website.clone(),
            host: self.host.clone(),
            database_name: self.database_name.clone(),
            field_name: self.field_name.clone(),
            public_label: self.public_label.clone(),
            details: self
                .details
                .iter()
                .map(|detail| DetailDraft {
                    label: detail.label.clone(),
                    value: detail.value.clone().unwrap_or_default(),
                    hidden: detail.hidden,
                    stored: detail.hidden.then(|| detail.name.clone()),
                })
                .collect(),
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

/// One secret field on the item screen. It has no value: the view borrows a revealed
/// value with [`OwnerSession::revealed_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLine {
    pub name: String,
    pub revealed: bool,
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
        VaultErrorKind::Expired => "token_expired",
        VaultErrorKind::Damaged => "sync_damaged",
        VaultErrorKind::OtherVault => "sync_other_vault",
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
        VaultErrorKind::Expired => "The agent token expired. Rotate the token in Agents.",
        VaultErrorKind::Damaged => "The synced copy of the vault is damaged.",
        VaultErrorKind::OtherVault => "The synced file holds another vault.",
    }
}

/// The token lifetime from the text in the Agents view, in days.
pub fn parse_lifetime_days(days: &str) -> ModelResult<u32> {
    days.trim()
        .parse::<u32>()
        .ok()
        .filter(|days| (1..=MAX_TOKEN_LIFETIME_DAYS).contains(days))
        .ok_or_else(|| {
            fail(
                "invalid_input",
                format!(
                    "The token lifetime must be a whole number of days from 1 to {MAX_TOKEN_LIFETIME_DAYS}."
                ),
            )
        })
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

/// A folder must be an existing directory that is not the root. It is stored in its
/// canonical form.
/// The place of a grant with a canonical, existing folder that is not `/`.
pub(crate) fn checked_place(place: &GrantPlace) -> ModelResult<GrantPlace> {
    let GrantPlace::Folder(dir) = place else {
        return Ok(GrantPlace::AnyFolder);
    };
    let canonical = std::fs::canonicalize(dir.trim())
        .ok()
        .filter(|path| path.is_dir())
        .ok_or_else(|| {
            fail(
                "invalid_input",
                "Type the absolute path of an existing project directory, or choose Any folder.",
            )
        })?;
    if canonical == Path::new("/") {
        return Err(fail(
            "invalid_input",
            "The project directory cannot be the root directory. Choose Any folder instead.",
        ));
    }
    Ok(GrantPlace::Folder(canonical.display().to_string()))
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
    let current = match existing {
        Some(id) => Some(vault.details(id).map_err(map_err)?),
        None => None,
    };
    if let Some(current) = &current
        && current.summary.kind != draft.kind
    {
        return Err(fail(
            "category_locked",
            "The item category cannot change. Delete the item and add a new one.",
        ));
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
            let website = draft.website.trim();
            if !website.is_empty() && crate::browser::site::Website::parse(website).is_none() {
                return Err(fail(
                    "invalid_input",
                    "Enter the website as a web address, for example https://example.com/login.",
                ));
            }
            push_plain(&mut fields, "website", website);
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
                || name.starts_with(DETAIL_PREFIX)
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

    push_details(&mut fields, vault, existing, draft, secrets)?;

    let mut tags = Vec::new();
    push_tag(&mut tags, &draft.service)?;
    push_tag(&mut tags, &draft.project)?;
    if let Some(current) = current {
        // The form has no tag field. An edit keeps the other tags of the item, for
        // example the tags of a 1Password import, and replaces the old service and
        // project labels.
        let id = current.summary.id;
        let old = [
            plain_value(vault, id, "service")?,
            plain_value(vault, id, "project")?,
        ];
        for tag in current.tags {
            if tags.len() < MAX_TAG_COUNT && !old.contains(&tag) && !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
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

/// Add the custom details. A hidden detail takes its typed value, or keeps its stored
/// value when the input is blank. A label must be unique on the item.
fn push_details(
    fields: &mut Vec<Field>,
    vault: &Vault,
    existing: Option<u64>,
    draft: &ItemDraft,
    secrets: &SecretForm,
) -> ModelResult<()> {
    if draft.details.len() > MAX_DETAILS {
        return Err(fail(
            "invalid_input",
            format!("An item can have at most {MAX_DETAILS} custom details."),
        ));
    }
    let mut labels = BTreeSet::new();
    for (index, detail) in draft.details.iter().enumerate() {
        let label = detail.label.trim();
        if label.is_empty() {
            return Err(fail("invalid_input", "Type a name for each custom detail."));
        }
        if label.len() > MAX_DETAIL_LABEL_BYTES {
            return Err(fail(
                "invalid_input",
                format!(
                    "The name “{label}” is too long. Use {MAX_DETAIL_LABEL_BYTES} bytes or fewer."
                ),
            ));
        }
        if !labels.insert(label.to_lowercase()) {
            return Err(fail(
                "invalid_input",
                format!("Two custom details have the name “{label}”."),
            ));
        }
        let name = detail_field_name(label);
        let missing = format!("Type the value of “{label}”.");
        if !detail.hidden {
            push_required_plain(fields, &name, &detail.value, &missing)?;
            continue;
        }
        let typed = &secrets.details[index];
        let value = if !typed.is_empty() {
            SecretValue::new(typed.clone())
        } else if let (Some(id), Some(stored)) = (existing, &detail.stored) {
            vault.reveal(id, stored).map_err(map_err)?
        } else if !detail.value.trim().is_empty() {
            // A visible detail that the owner made hidden keeps its value.
            SecretValue::new(detail.value.trim().to_owned())
        } else {
            return Err(fail("invalid_input", missing));
        };
        fields.push(Field {
            name,
            value,
            secret: true,
        });
    }
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
            | "website"
            | "host"
            | "database"
            | "public_key"
    )
}

/// Windowless round trip used by `--smoke-test` when the vault feature is on.
/// Errors do not include secret values.
pub(crate) fn smoke_roundtrip() -> Result<(), String> {
    use crate::broker::approvals::{OwnerCheck, OwnerGate};

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
    // Reveal needs a fresh owner check for this item (goal item A4).
    let gate = OwnerGate::new(session.shared_vault(), None);
    let owner_check = |item_id: u64| {
        gate.authorize(
            OwnerAction::Reveal { item_id },
            OwnerCheck::passphrase("smoke-vault-pass-1"),
        )
        .map_err(|err| err.message())
    };
    if session
        .reveal(created.id, owner_check(created.id + 1)?)
        .is_ok()
    {
        return Err("reveal accepted a check for another item".to_owned());
    }
    let revealed = session
        .reveal(created.id, owner_check(created.id)?)
        .map_err(|err| err.message)?;
    if !revealed.any_revealed() || session.revealed_value(created.id, "token").is_none() {
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
