//! Folders, adding by paste, and the options of a credential (contract section 5.11,
//! ADR 0026 §4, §5, §8, ADR 0025 §4).
//!
//! The rules are the Mac's: the folders of `apassy::vault` (`src/vault/folders.rs`), the
//! paste detection and the one-transaction add of "New Credential"
//! (`src/desktop/ui/new_credential.rs`, `src/desktop/owner_store/add.rs`), and the
//! options of the credential screen (`src/desktop/ui/items.rs`). Each change goes
//! through the vault, so it syncs as `save` does: the app syncs after the call.
//!
//! The pasted text is a secret. It is parsed into an erasing buffer, and `detect` never
//! answers a secret value: a secret field has a masked `preview`. `add_pasted` detects
//! the text again in the core, so no secret value goes through the app twice.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use apassy::vault::detect::{self, Detected, MAX_INPUT_BYTES};
use apassy::vault::{
    Environment, MAX_FOLDER_DEPTH, MAX_FOLDER_NAME_BYTES, Vault, VaultError, VaultErrorKind,
    providers,
};

use super::Core;
use super::errors::{CoreError, CoreResult};
use super::items::{field_label, kind_str};
use super::wire::{Empty, Secret, ok, params};

/// The mask of a secret value in a preview. Its length says nothing of the value.
pub const MASK: &str = "••••••••";

/// The note when a paste has no credential (the Mac's `NOTHING_FOUND`).
const NOTHING_FOUND: &str = "Apassy found no credential in the text. Paste a secret, a KEY=value line, a .env file, a URL with a password, or an otpauth:// link.";

/// The largest title of an item (the vault's `MAX_TITLE_BYTES`).
const MAX_TITLE_BYTES: usize = 128;

// ---- Answers ----

#[derive(Serialize)]
struct FolderOut {
    uuid: String,
    parent: Option<String>,
    name: String,
    position: i64,
    /// The credentials directly in the folder that are not archived.
    count: usize,
}

#[derive(Serialize)]
struct Folders {
    folders: Vec<FolderOut>,
}

#[derive(Serialize)]
struct Created {
    folder: FolderOut,
}

#[derive(Serialize)]
struct Deleted {
    moved: usize,
}

/// A field of a detected credential. `preview` is the value of a plain field, and a mask
/// for a secret field.
#[derive(Serialize)]
struct FoundField {
    name: String,
    label: String,
    secret: bool,
    preview: String,
}

/// A detected credential, without a secret value.
#[derive(Serialize)]
struct Found {
    index: usize,
    title: String,
    kind: &'static str,
    /// The label of the provider of the catalog, such as "Stripe".
    provider: Option<String>,
    env_name: Option<String>,
    hosts: Vec<String>,
    environment: &'static str,
    /// `signal` or `default`. The Mac shows the environment only for a signal.
    environment_source: &'static str,
    risk: &'static str,
    line: Option<usize>,
    summary: String,
    fields: Vec<FoundField>,
}

#[derive(Serialize)]
struct Detection {
    found: Vec<Found>,
}

#[derive(Serialize)]
struct AddedItem {
    id: u64,
    revision: u64,
    title: String,
    /// The result in one line, as on the Mac: "Stripe live · STRIPE_SECRET_KEY ·
    /// production".
    summary: String,
}

#[derive(Serialize)]
struct Added {
    items: Vec<AddedItem>,
}

// ---- Requests ----

#[derive(Deserialize)]
struct Uuid {
    uuid: String,
}

#[derive(Deserialize)]
struct FolderCreate {
    #[serde(default)]
    parent: Option<String>,
    name: String,
}

#[derive(Deserialize)]
struct FolderRename {
    uuid: String,
    name: String,
}

#[derive(Deserialize)]
struct FolderMove {
    uuid: String,
    #[serde(default)]
    parent: Option<String>,
}

#[derive(Deserialize)]
struct ItemFolder {
    id: u64,
    #[serde(default)]
    folder: Option<String>,
}

#[derive(Deserialize)]
struct Paste {
    text: Secret,
}

#[derive(Deserialize)]
struct TitleIn {
    index: usize,
    title: String,
}

#[derive(Deserialize)]
struct AddPasted {
    text: Secret,
    #[serde(default)]
    folder: Option<String>,
    /// The indexes of `detect` to add; all when absent.
    #[serde(default)]
    pick: Option<Vec<usize>>,
    /// Titles that the owner typed for some rows, as the Mac's sheet allows.
    #[serde(default)]
    titles: Vec<TitleIn>,
}

#[derive(Deserialize)]
struct Options {
    id: u64,
    #[serde(default)]
    always_ask: Option<bool>,
    #[serde(default)]
    environment: Option<String>,
}

// ---- Errors ----

fn folder_gone() -> CoreError {
    CoreError::new(
        "not_found",
        "The folder is gone. Another device may have deleted it.",
    )
}

fn name_taken() -> CoreError {
    CoreError::new("exists", "A folder with this name is already there.")
}

fn bad_name() -> CoreError {
    CoreError::invalid(format!(
        "Type a name of at most {MAX_FOLDER_NAME_BYTES} bytes, without control characters. Folders nest at most {MAX_FOLDER_DEPTH} levels deep."
    ))
}

/// What the owner reads when a folder change fails (the Mac's `folder_error`).
fn folder_error(error: VaultError, invalid: fn() -> CoreError) -> CoreError {
    match error.kind() {
        VaultErrorKind::AlreadyExists => name_taken(),
        VaultErrorKind::InvalidInput => invalid(),
        VaultErrorKind::NotFound => folder_gone(),
        _ => error.into(),
    }
}

fn bad_move() -> CoreError {
    CoreError::invalid(format!(
        "A folder cannot move into itself or one of its subfolders. Folders nest at most {MAX_FOLDER_DEPTH} levels deep."
    ))
}

/// Whether `uuid` is a folder of the vault that is not deleted.
fn require_folder(vault: &Vault, uuid: &str) -> CoreResult<()> {
    if vault.folders()?.iter().any(|folder| folder.uuid == uuid) {
        Ok(())
    } else {
        Err(folder_gone())
    }
}

/// An empty folder parameter is the top level.
fn place(folder: Option<String>) -> Option<String> {
    folder.filter(|uuid| !uuid.trim().is_empty())
}

// ---- Folders ----

fn folders(vault: &Vault) -> CoreResult<Folders> {
    let archived = vault.archived_items()?;
    let mut out = Vec::new();
    for folder in vault.folders()? {
        let count = vault
            .items_in_folder(Some(&folder.uuid), false)?
            .into_iter()
            .filter(|id| !archived.contains_key(id))
            .count();
        out.push(FolderOut {
            uuid: folder.uuid,
            parent: folder.parent,
            name: folder.name,
            position: folder.position,
            count,
        });
    }
    Ok(Folders { folders: out })
}

// ---- Detection ----

/// The label of a provider ID of the catalog.
pub fn provider_label(id: Option<&str>) -> Option<String> {
    id.and_then(providers::find)
        .map(|provider| provider.label.clone())
}

/// A field name as the owner reads it.
fn label_of(name: &str) -> String {
    match name {
        detect::URL_FIELD => "URL".to_owned(),
        _ => field_label(name),
    }
}

/// The preview of a secret value: the public value prefix of the provider of the
/// catalog (`sk_live_`, `ghp_`) or the URL scheme, then the mask. Nothing of the secret
/// part of the value.
fn masked(found: &Detected, value: &str) -> String {
    if let Some((provider, prefix)) = providers::prefix_match(value)
        && found.provider.as_deref() == Some(provider.id.as_str())
    {
        return format!("{prefix}{MASK}");
    }
    if let Some((scheme, _)) = value.split_once("://")
        && !scheme.is_empty()
        && scheme.len() <= 16
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return format!("{scheme}://{MASK}");
    }
    MASK.to_owned()
}

fn found(index: usize, detected: &Detected) -> Found {
    let secrets: Vec<&str> = detected
        .fields
        .iter()
        .filter(|field| field.secret)
        .map(|field| field.value.expose())
        .collect();
    let fields = detected
        .fields
        .iter()
        .map(|field| {
            let value = field.value.expose();
            // A plain value that holds a secret value of the same credential is masked
            // too, so no answer can carry one.
            let leaks = secrets
                .iter()
                .any(|secret| !secret.is_empty() && value.contains(secret));
            FoundField {
                name: field.name.clone(),
                label: label_of(&field.name),
                secret: field.secret,
                preview: if field.secret || leaks {
                    masked(detected, value)
                } else {
                    value.to_owned()
                },
            }
        })
        .collect();
    Found {
        index,
        title: detected.title.clone(),
        kind: kind_str(detected.kind),
        provider: provider_label(detected.provider.as_deref()),
        env_name: detected.env_name.clone(),
        hosts: detected.hosts.clone(),
        environment: detected.environment.as_str(),
        environment_source: detected.sources.environment.as_str(),
        risk: detected.risk.as_str(),
        line: detected.line,
        summary: detect::summary_line(detected),
        fields,
    }
}

fn check_size(text: &Secret) -> CoreResult<()> {
    if text.expose().len() > MAX_INPUT_BYTES {
        return Err(CoreError::invalid(
            "The text is too large. Paste at most 1 MB.",
        ));
    }
    Ok(())
}

/// The credentials of the pasted text, each without a secret value. Nothing found is an
/// empty list: the app shows the note.
fn detection(text: &Secret) -> CoreResult<Detection> {
    check_size(text)?;
    let detected = detect::detect(text.expose());
    Ok(Detection {
        found: detected
            .iter()
            .enumerate()
            .map(|(index, one)| found(index, one))
            .collect(),
    })
}

/// The picked credentials of `detected`, with the titles that the owner typed.
fn kept(
    detected: Vec<Detected>,
    pick: Option<Vec<usize>>,
    titles: Vec<TitleIn>,
) -> CoreResult<Vec<Detected>> {
    let count = detected.len();
    let picked: BTreeSet<usize> = match pick {
        Some(pick) => {
            let set: BTreeSet<usize> = pick.iter().copied().collect();
            if set.len() != pick.len() || set.iter().any(|index| *index >= count) {
                return Err(CoreError::invalid(
                    "The picked credentials do not match the text. Paste it again.",
                ));
            }
            set
        }
        None => (0..count).collect(),
    };
    if picked.is_empty() {
        return Err(CoreError::invalid("Pick at least one credential."));
    }
    let mut kept = Vec::new();
    for (index, mut one) in detected.into_iter().enumerate() {
        if !picked.contains(&index) {
            continue;
        }
        if let Some(typed) = titles.iter().rev().find(|title| title.index == index) {
            let title = typed.title.trim();
            if title.len() > MAX_TITLE_BYTES {
                return Err(CoreError::invalid("The item name is too long."));
            }
            if !title.is_empty() {
                title.clone_into(&mut one.title);
            }
        }
        kept.push(one);
    }
    if titles.iter().any(|title| title.index >= count) {
        return Err(CoreError::invalid(
            "The picked credentials do not match the text. Paste it again.",
        ));
    }
    Ok(kept)
}

/// Detect `text` again and add the picked credentials in one transaction, without an
/// origin: the owner pasted them (the Mac's "New Credential").
fn add_pasted(vault: &mut Vault, request: AddPasted) -> CoreResult<Added> {
    let AddPasted {
        text,
        folder,
        pick,
        titles,
    } = request;
    check_size(&text)?;
    let detected = detect::detect(text.expose());
    drop(text);
    if detected.is_empty() {
        return Err(CoreError::invalid(NOTHING_FOUND));
    }
    let kept = kept(detected, pick, titles)?;
    let folder = place(folder);
    if let Some(folder) = &folder {
        require_folder(vault, folder)?;
    }
    let added = match vault.add_detected_all(&kept, folder.as_deref(), None) {
        Err(error) if error.kind() == VaultErrorKind::NotFound => {
            return Err(CoreError::new(
                "not_found",
                "The folder is gone. Select another folder.",
            ));
        }
        other => other?,
    };
    drop(kept);
    let mut items = Vec::new();
    for summary in added {
        let variable = vault
            .process_binding(summary.id)?
            .map(|binding| binding.env_name);
        let environment = vault
            .declaration(summary.id)?
            .map_or(providers::DEFAULT_ENVIRONMENT, |d| d.environment);
        let mut parts = vec![summary.title.as_str()];
        if let Some(variable) = &variable {
            parts.push(variable);
        }
        parts.push(environment.as_str());
        let line = parts.join(" · ");
        items.push(AddedItem {
            id: summary.id,
            revision: summary.revision,
            summary: line,
            title: summary.title,
        });
    }
    Ok(Added { items })
}

// ---- Options ----

fn parse_environment(text: &str) -> CoreResult<Environment> {
    Environment::parse(text).map_err(|_| {
        CoreError::invalid("The environment is production, staging, development, or local.")
    })
}

/// "Always ask me" and the environment, as the owner set them. The core does not check
/// the owner: the app asks for Face ID first when the change makes the bouncer less
/// careful (turning "Always ask me" off, an environment other than production), as the
/// Mac does.
fn options(vault: &mut Vault, request: Options) -> CoreResult<()> {
    let environment = request
        .environment
        .as_deref()
        .map(parse_environment)
        .transpose()?;
    // The item first, so a missing item changes nothing.
    vault.details(request.id)?;
    if let Some(on) = request.always_ask {
        vault.set_always_ask(request.id, on)?;
    }
    if let Some(environment) = environment {
        vault.set_declaration_environment(request.id, environment)?;
    }
    Ok(())
}

impl Core {
    pub(super) fn organize_call(&self, op: &str, request: &str) -> CoreResult<String> {
        // AutoFill reads the folders; every other call is of the app.
        if op != "folders" {
            self.require_app()?;
        }
        match op {
            "folders" => self.with_vault(|vault| Ok(ok(&folders(vault)?))),
            "folder_create" => {
                let FolderCreate { parent, name } = params(request)?;
                let parent = place(parent);
                self.with_vault_mut(|vault| {
                    let folder = vault
                        .create_folder(parent.as_deref(), &name)
                        .map_err(|error| folder_error(error, bad_name))?;
                    Ok(ok(&Created {
                        folder: FolderOut {
                            uuid: folder.uuid,
                            parent: folder.parent,
                            name: folder.name,
                            position: folder.position,
                            count: 0,
                        },
                    }))
                })
            }
            "folder_rename" => {
                let FolderRename { uuid, name } = params(request)?;
                self.with_vault_mut(|vault| {
                    vault
                        .rename_folder(&uuid, &name)
                        .map_err(|error| folder_error(error, bad_name))?;
                    Ok(ok(&Empty {}))
                })
            }
            "folder_move" => {
                let FolderMove { uuid, parent } = params(request)?;
                let parent = place(parent);
                self.with_vault_mut(|vault| {
                    vault
                        .move_folder(&uuid, parent.as_deref())
                        .map_err(|error| folder_error(error, bad_move))?;
                    Ok(ok(&Empty {}))
                })
            }
            "folder_delete" => {
                let Uuid { uuid } = params(request)?;
                self.with_vault_mut(|vault| {
                    let moved = vault
                        .delete_folder(&uuid)
                        .map_err(|error| folder_error(error, bad_name))?;
                    Ok(ok(&Deleted { moved }))
                })
            }
            "item_folder_set" => {
                let ItemFolder { id, folder } = params(request)?;
                let folder = place(folder);
                self.with_vault_mut(|vault| {
                    vault.details(id)?;
                    if let Some(folder) = &folder {
                        require_folder(vault, folder)?;
                    }
                    vault
                        .set_item_folder(id, folder.as_deref())
                        .map_err(|error| folder_error(error, bad_name))?;
                    Ok(ok(&Empty {}))
                })
            }
            "detect" => {
                let Paste { text } = params(request)?;
                // Detection needs no vault, but the screen that pastes is behind the lock.
                self.with_vault(|_| Ok(ok(&detection(&text)?)))
            }
            "add_pasted" => {
                let request: AddPasted = params(request)?;
                self.with_vault_mut(|vault| Ok(ok(&add_pasted(vault, request)?)))
            }
            "item_options_set" => {
                let request: Options = params(request)?;
                self.with_vault_mut(|vault| {
                    options(vault, request)?;
                    Ok(ok(&Empty {}))
                })
            }
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_has_no_part_of_a_secret() {
        let found = detect::detect(concat!("sk_", "live_", "51SyntheticStripeKeyValue0000000000"));
        let answer = serde_json::to_string(&super::found(0, &found[0])).unwrap();
        assert!(!answer.contains("51SyntheticStripeKeyValue"), "{answer}");
        assert!(answer.contains(MASK));
    }
}
