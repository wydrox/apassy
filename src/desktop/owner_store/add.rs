//! Adding a credential from pasted text (ADR 0025 §4).
//!
//! The owner pastes a secret, a `KEY=value` line, a `.env` file, a URL with credentials,
//! or an `otpauth://` link. [`crate::vault::detect`] finds each credential on this Mac,
//! and [`Vault::add_detected_all`](crate::vault::Vault::add_detected_all) saves them in
//! one transaction with the variable, the declaration, and the folder. No owner check:
//! a new credential moves no authority (the bouncer decides each use of it).

use super::{OwnerSession, fail, map_err};
use crate::desktop::model::ModelResult;
use crate::vault::detect::{self, Detected};
use crate::vault::{Environment, ItemSummary, VaultErrorKind};

/// The text when a paste has no credential.
pub const NOTHING_FOUND: &str = "Apassy found no credential in the text. Paste a secret, a KEY=value line, a .env file, a URL with a password, or an otpauth:// link.";

/// One credential that a paste added, for the result line. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedCredential {
    pub summary: ItemSummary,
    /// The variable that programs get, if any.
    pub variable: Option<String>,
    pub environment: Environment,
    /// The folder names from the top level; empty at the top level.
    pub folder: Vec<String>,
}

impl AddedCredential {
    /// The result in one line, as [`detect::summary_line`]: "Anthropic API key ·
    /// ANTHROPIC_API_KEY · development". The title and the variable are the stored ones.
    pub fn line(&self) -> String {
        let mut parts = vec![self.summary.title.as_str()];
        if let Some(variable) = &self.variable {
            parts.push(variable);
        }
        parts.push(self.environment.as_str());
        parts.join(" · ")
    }
}

impl OwnerSession {
    /// Detect the credentials of `text` and add all of them to `folder` (a folder UUID;
    /// `None`: the top level), in one transaction. `invalid_input` when the text has no
    /// credential.
    pub fn add_detected(
        &mut self,
        text: &str,
        folder: Option<&str>,
    ) -> ModelResult<Vec<ItemSummary>> {
        let detected = detect::detect(text);
        if detected.is_empty() {
            return Err(fail("invalid_input", NOTHING_FOUND));
        }
        self.add_detected_items(&detected, folder)
    }

    /// Add the detected credentials that the owner kept, in one transaction: all of
    /// them, or none. Nothing to add is not an error.
    pub fn add_detected_items(
        &mut self,
        detected: &[Detected],
        folder: Option<&str>,
    ) -> ModelResult<Vec<ItemSummary>> {
        if detected.is_empty() {
            return Ok(Vec::new());
        }
        let mut vault = self.unlocked()?;
        match vault.add_detected_all(detected, folder, None) {
            Err(err) if err.kind() == VaultErrorKind::NotFound => Err(fail(
                "not_found",
                "The folder is gone. Select another folder.",
            )),
            other => other.map_err(map_err),
        }
    }

    /// The result of each added credential: its variable, its environment, and its
    /// folder.
    pub fn added_credentials(&self, added: &[ItemSummary]) -> ModelResult<Vec<AddedCredential>> {
        let vault = self.unlocked()?;
        added
            .iter()
            .map(|summary| {
                let variable = vault
                    .process_binding(summary.id)
                    .map_err(map_err)?
                    .map(|binding| binding.env_name);
                let environment = vault
                    .declaration(summary.id)
                    .map_err(map_err)?
                    .map_or(crate::vault::providers::DEFAULT_ENVIRONMENT, |d| {
                        d.environment
                    });
                let folder = vault.item_folder(summary.id).map_err(map_err)?;
                let folder = vault.folder_path(folder.as_deref()).map_err(map_err)?;
                Ok(AddedCredential {
                    summary: summary.clone(),
                    variable,
                    environment,
                    folder,
                })
            })
            .collect()
    }

    /// The folder UUID of a path such as `Work/Acme`. Each name matches a folder name
    /// exactly, else without regard to case. An empty path is the top level (`None`).
    /// With `create`, the missing folders are made; without it, a missing folder is
    /// `not_found`.
    pub fn folder_by_path(&mut self, path: &str, create: bool) -> ModelResult<Option<String>> {
        let names: Vec<&str> = path
            .split('/')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();
        let mut vault = self.unlocked()?;
        let mut parent: Option<String> = None;
        for (depth, name) in names.iter().enumerate() {
            let folders = vault.folders().map_err(map_err)?;
            let siblings: Vec<_> = folders
                .iter()
                .filter(|folder| folder.parent == parent)
                .collect();
            let found = siblings
                .iter()
                .find(|folder| folder.name == *name)
                .or_else(|| {
                    siblings
                        .iter()
                        .find(|folder| folder.name.to_lowercase() == name.to_lowercase())
                })
                .map(|folder| folder.uuid.clone());
            parent = Some(match found {
                Some(uuid) => uuid,
                None if create => match vault.create_folder(parent.as_deref(), name) {
                    Ok(folder) => folder.uuid,
                    Err(err) if err.kind() == VaultErrorKind::InvalidInput => {
                        return Err(fail(
                            "invalid_input",
                            format!(
                                "Apassy cannot make the folder \"{name}\": a name has 1 to {} bytes and no control characters, and folders nest at most {} levels.",
                                crate::vault::MAX_FOLDER_NAME_BYTES,
                                crate::vault::MAX_FOLDER_DEPTH
                            ),
                        ));
                    }
                    Err(err) => return Err(map_err(err)),
                },
                None => {
                    return Err(fail(
                        "not_found",
                        format!(
                            "There is no folder \"{}\". Make it in the window, or add --create-folder.",
                            names[..=depth].join("/")
                        ),
                    ));
                }
            });
        }
        Ok(parent)
    }
}
