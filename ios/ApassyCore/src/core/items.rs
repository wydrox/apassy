//! Items for the owner (contract section 5.3): the list, one item with its fields, and
//! a new or edited item. The labels, the field order, and the rules of a draft are the
//! Mac's (`src/desktop/owner_store.rs`), so an item looks and saves the same on both.

use std::collections::{BTreeMap, BTreeSet};

use apassy::contracts::CredentialKind;
use apassy::vault::{
    Field, ItemDetails, ItemDraft, ItemEventKind, SecretValue, Vault, VaultErrorKind,
    custom_detail_label,
};
use serde::{Deserialize, Serialize};

use super::errors::{CoreError, CoreResult};
use super::otp::is_otp_label;
use super::wire::Secret;

/// The prefix of a custom detail field (`x_<hex label>`).
pub const DETAIL_PREFIX: &str = "x_";
pub const MAX_DETAIL_LABEL_BYTES: usize = 31;
pub const MAX_DETAILS: usize = 10;
const MAX_TITLE_BYTES: usize = 128;
const MAX_NOTES_BYTES: usize = 8192;
const MAX_TAGS: usize = 32;
const MAX_TAG_BYTES: usize = 64;
const MAX_HISTORY: usize = 50;

pub fn kind_str(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::ApiKey => "api_key",
        CredentialKind::Login => "login",
        CredentialKind::SshKey => "ssh_key",
        CredentialKind::Database => "database",
        CredentialKind::Custom => "custom",
    }
}

fn parse_kind(kind: &str) -> CoreResult<CredentialKind> {
    Ok(match kind {
        "api_key" => CredentialKind::ApiKey,
        "login" => CredentialKind::Login,
        "ssh_key" => CredentialKind::SshKey,
        "database" => CredentialKind::Database,
        "custom" => CredentialKind::Custom,
        _ => return Err(CoreError::invalid("The kind of the item is not valid.")),
    })
}

/// The field name of a custom detail: `x_` and the UTF-8 bytes of the label in
/// lowercase hex, as the Mac writes it.
pub fn detail_field_name(label: &str) -> String {
    let mut name = String::from(DETAIL_PREFIX);
    for byte in label.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// The owner-facing name of a field (the Mac's `field_label`).
pub fn field_label(name: &str) -> String {
    match name {
        "token" => "Token".to_owned(),
        "password" => "Password".to_owned(),
        "private_key" => "Private key".to_owned(),
        "passphrase" => "Key passphrase".to_owned(),
        "username" => "Username".to_owned(),
        "host" => "Host".to_owned(),
        "database" => "Database".to_owned(),
        "public_key" => "Public key".to_owned(),
        "service" => "Service".to_owned(),
        "project" => "Project".to_owned(),
        other => custom_detail_label(other).unwrap_or_else(|| other.to_owned()),
    }
}

fn is_builtin(name: &str) -> bool {
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

/// Whether a label names a website (contract section 8).
pub fn is_website_label(label: &str) -> bool {
    let label = label.trim().to_lowercase();
    label.starts_with("website") || label.starts_with("url")
}

/// What the app does with a field (contract section 5.3).
pub fn field_role(name: &str, secret: bool) -> &'static str {
    match name {
        "username" => "username",
        "password" => "password",
        "token" => "token",
        "private_key" => "private_key",
        "passphrase" => "key_passphrase",
        "host" => "host",
        "database" => "database",
        "public_key" => "public_key",
        "service" => "service",
        "project" => "project",
        "website" | "url" if !secret => "website",
        other => {
            let label = custom_detail_label(other).unwrap_or_else(|| other.to_owned());
            if secret && is_otp_label(&label) {
                "totp"
            } else if !secret && custom_detail_label(other).is_some() && is_website_label(&label) {
                "website"
            } else {
                "other"
            }
        }
    }
}

/// The order of the fields of a kind, before service, project, and the details.
fn kind_order(kind: CredentialKind) -> &'static [&'static str] {
    match kind {
        CredentialKind::Login => &["username", "password"],
        CredentialKind::Database => &["host", "database", "username", "password"],
        CredentialKind::SshKey => &["private_key", "passphrase", "public_key"],
        CredentialKind::ApiKey => &["token"],
        CredentialKind::Custom => &[],
    }
}

fn rank(kind: CredentialKind, name: &str, secret: bool) -> u8 {
    if let Some(index) = kind_order(kind).iter().position(|first| *first == name) {
        return index as u8;
    }
    if kind == CredentialKind::Custom
        && secret
        && !name.starts_with(DETAIL_PREFIX)
        && !is_builtin(name)
    {
        return 0;
    }
    match name {
        "service" => 10,
        "project" => 11,
        _ if name.starts_with(DETAIL_PREFIX) => 20,
        _ => 30,
    }
}

/// An item in a list.
#[derive(Debug, Serialize)]
pub struct Row {
    pub id: u64,
    pub revision: u64,
    pub title: String,
    pub kind: &'static str,
    pub subtitle: String,
    pub websites: Vec<String>,
    pub tags: Vec<String>,
    pub archived: bool,
    pub has_totp: bool,
    pub conflict_of: Option<u64>,
    pub added_at: Option<u64>,
    pub changed_at: Option<u64>,
    pub used_at: Option<u64>,
}

/// A field of an item. `value` is set for a plain field only.
#[derive(Debug, Serialize)]
pub struct FieldOut {
    pub name: String,
    pub label: String,
    pub secret: bool,
    pub value: Option<String>,
    pub role: &'static str,
    pub custom: bool,
}

/// An item with its fields.
#[derive(Debug, Serialize)]
pub struct Detail {
    #[serde(flatten)]
    pub row: Row,
    pub notes: String,
    pub fields: Vec<FieldOut>,
}

/// The metadata of the vault that each row needs, read once for a list.
pub struct Context {
    archived: BTreeMap<u64, u64>,
    times: BTreeMap<u64, apassy::vault::ItemTimes>,
    conflicts: BTreeMap<u64, Option<u64>>,
}

impl Context {
    pub fn read(vault: &Vault) -> CoreResult<Self> {
        Ok(Self {
            archived: vault.archived_items()?,
            times: vault.item_times()?,
            conflicts: vault.conflict_copies()?,
        })
    }
}

/// A plain value, or empty when the field is not there.
fn plain(vault: &Vault, id: u64, name: &str) -> CoreResult<String> {
    match vault.reveal(id, name) {
        Ok(value) => Ok(value.expose().to_owned()),
        Err(error) if error.kind() == VaultErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error.into()),
    }
}

/// The fields of `details` in the Mac's order.
fn ordered(details: &ItemDetails) -> Vec<&apassy::vault::FieldSummary> {
    let kind = details.summary.kind;
    let mut fields: Vec<_> = details.fields.iter().collect();
    // A stable sort keeps the stored order inside each rank (the order of the details).
    fields.sort_by_key(|field| rank(kind, &field.name, field.secret));
    fields
}

fn row_of(vault: &Vault, context: &Context, details: &ItemDetails) -> CoreResult<Row> {
    let id = details.summary.id;
    let kind = details.summary.kind;
    let has = |name: &str| {
        details
            .fields
            .iter()
            .any(|field| field.name == name && !field.secret)
    };
    let subtitle = match kind {
        CredentialKind::Login | CredentialKind::Database if has("username") => {
            plain(vault, id, "username")?
        }
        CredentialKind::Database if has("host") => plain(vault, id, "host")?,
        CredentialKind::SshKey if has("public_key") => plain(vault, id, "public_key")?,
        _ if has("service") => plain(vault, id, "service")?,
        _ => String::new(),
    };
    let mut websites = Vec::new();
    for field in ordered(details) {
        if field_role(&field.name, field.secret) == "website" {
            let value = plain(vault, id, &field.name)?;
            if !value.trim().is_empty() {
                websites.push(value.trim().to_owned());
            }
        }
    }
    let times = context.times.get(&id);
    Ok(Row {
        id,
        revision: details.summary.revision,
        title: details.summary.title.clone(),
        kind: kind_str(kind),
        subtitle: subtitle.lines().next().unwrap_or("").trim().to_owned(),
        websites,
        tags: details.tags.clone(),
        archived: context.archived.contains_key(&id),
        has_totp: details
            .fields
            .iter()
            .any(|field| field_role(&field.name, field.secret) == "totp"),
        conflict_of: context.conflicts.get(&id).copied().flatten(),
        added_at: times.and_then(|times| times.added),
        changed_at: times.and_then(|times| times.changed),
        used_at: times.and_then(|times| times.used),
    })
}

/// Which items a list holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Archived {
    #[default]
    No,
    Yes,
    All,
}

/// The items, sorted by title without regard to case.
pub fn rows(vault: &Vault, archived: Archived) -> CoreResult<Vec<Row>> {
    let context = Context::read(vault)?;
    let mut rows = Vec::new();
    for summary in vault.search("")? {
        let is_archived = context.archived.contains_key(&summary.id);
        let wanted = match archived {
            Archived::No => !is_archived,
            Archived::Yes => is_archived,
            Archived::All => true,
        };
        if wanted {
            let details = vault.details(summary.id)?;
            rows.push(row_of(vault, &context, &details)?);
        }
    }
    rows.sort_by(|a, b| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then(a.id.cmp(&b.id))
    });
    Ok(rows)
}

/// One item with its fields.
pub fn detail(vault: &Vault, id: u64) -> CoreResult<Detail> {
    let context = Context::read(vault)?;
    let details = vault.details(id)?;
    let row = row_of(vault, &context, &details)?;
    let mut fields = Vec::new();
    for field in ordered(&details) {
        fields.push(FieldOut {
            name: field.name.clone(),
            label: field_label(&field.name),
            secret: field.secret,
            value: if field.secret {
                None
            } else {
                Some(plain(vault, id, &field.name)?)
            },
            role: field_role(&field.name, field.secret),
            custom: custom_detail_label(&field.name).is_some(),
        });
    }
    Ok(Detail {
        row,
        notes: details.notes,
        fields,
    })
}

/// An event of the history of an item, as the owner reads it.
#[derive(Debug, Serialize)]
pub struct Event {
    pub at: u64,
    pub kind: &'static str,
    pub detail: String,
}

pub fn history(vault: &Vault, id: u64) -> CoreResult<Vec<Event>> {
    vault.details(id)?;
    let events = vault.item_events(id, MAX_HISTORY)?;
    Ok(events
        .into_iter()
        .map(|event| {
            let detail = event.detail.replace(',', ", ");
            let text = match event.kind {
                ItemEventKind::Created => "Added".to_owned(),
                ItemEventKind::Tracked => "The history starts here".to_owned(),
                ItemEventKind::Edited if detail.is_empty() => "Changed".to_owned(),
                ItemEventKind::Edited => format!("Changed: {detail}"),
                ItemEventKind::Revealed => "Secret values shown".to_owned(),
                ItemEventKind::Archived => "Archived".to_owned(),
                ItemEventKind::Unarchived => "Restored from the archive".to_owned(),
                ItemEventKind::Declaration => format!("Declaration: {detail}"),
                ItemEventKind::Variable => format!("Variable {detail}"),
                ItemEventKind::VariableRemoved => "Variable removed".to_owned(),
                ItemEventKind::Connector => format!("Connector {detail}"),
                ItemEventKind::ConnectorRemoved => "Connector removed".to_owned(),
                ItemEventKind::AccessGiven => format!("Access given: {detail}"),
                ItemEventKind::AccessRemoved => format!("Access removed: {detail}"),
                ItemEventKind::AccessRequested => format!("Access asked: {detail}"),
                ItemEventKind::AccessDenied => format!("Access denied: {detail}"),
                ItemEventKind::RuleChanged => format!("Rules changed: {detail}"),
                ItemEventKind::OperationAllowed => format!("Operation allowed: {detail}"),
                ItemEventKind::OperationRemoved => format!("Operation removed: {detail}"),
                ItemEventKind::Restored => "Restored from a backup".to_owned(),
                ItemEventKind::ReviewConfirmed => "Agent settings confirmed".to_owned(),
            };
            Event {
                at: event.at,
                kind: event.kind.as_str(),
                detail: text,
            }
        })
        .collect())
}

// ---- A new or edited item. ----

#[derive(Deserialize)]
pub struct DraftIn {
    pub title: String,
    pub kind: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub fields: Vec<DraftFieldIn>,
}

#[derive(Deserialize)]
pub struct DraftFieldIn {
    /// A built-in field, the main field of a custom item, or, with `label`, the stored
    /// name of a custom detail whose value `value: null` keeps.
    #[serde(default)]
    pub name: Option<String>,
    /// The label of a custom detail.
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub value: Option<Secret>,
    #[serde(default)]
    pub secret: bool,
}

/// Whether `name` is a built-in field of `kind`, and then whether it is secret.
fn kind_field(kind: CredentialKind, name: &str) -> Option<bool> {
    match (kind, name) {
        (_, "service" | "project") => Some(false),
        (CredentialKind::Login, "username") => Some(false),
        (CredentialKind::Login, "password") => Some(true),
        (CredentialKind::ApiKey, "token") => Some(true),
        (CredentialKind::SshKey, "private_key" | "passphrase") => Some(true),
        (CredentialKind::SshKey, "public_key") => Some(false),
        (CredentialKind::Database, "host" | "database" | "username") => Some(false),
        (CredentialKind::Database, "password") => Some(true),
        _ => None,
    }
}

fn name_ok(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The required fields of a kind, with the message when one is missing.
fn required(kind: CredentialKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        CredentialKind::ApiKey => &[("token", "Enter the API token.")],
        CredentialKind::Login => &[
            ("username", "Enter the username."),
            ("password", "Enter the password."),
        ],
        CredentialKind::SshKey => &[("private_key", "Enter the private key.")],
        CredentialKind::Database => &[
            ("host", "Enter the host."),
            ("database", "Enter the database name."),
            ("username", "Enter the username."),
            ("password", "Enter the password."),
        ],
        CredentialKind::Custom => &[],
    }
}

/// The value that a secret field keeps: the typed one, else the stored one.
fn kept(vault: &Vault, existing: Option<u64>, stored: &str) -> CoreResult<Option<SecretValue>> {
    let Some(id) = existing else { return Ok(None) };
    match vault.reveal(id, stored) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == VaultErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Build the vault draft of `draft` with the Mac's rules (contract section 5.3).
pub fn build_draft(vault: &Vault, existing: Option<u64>, draft: DraftIn) -> CoreResult<ItemDraft> {
    let title = draft.title.trim();
    if title.is_empty() {
        return Err(CoreError::invalid("The item name is required."));
    }
    if title.len() > MAX_TITLE_BYTES {
        return Err(CoreError::invalid("The item name is too long."));
    }
    let kind = parse_kind(&draft.kind)?;
    let current = match existing {
        Some(id) => Some(vault.details(id)?),
        None => None,
    };
    if let Some(current) = &current
        && current.summary.kind != kind
    {
        return Err(CoreError::invalid(
            "The item category cannot change. Delete the item and add a new one.",
        ));
    }
    let notes = draft.notes.trim();
    if notes.len() > MAX_NOTES_BYTES {
        return Err(CoreError::invalid("The notes are too long."));
    }

    let mut fields: Vec<Field> = Vec::new();
    let mut names = BTreeSet::new();
    let mut labels = BTreeSet::new();
    let mut details = 0;
    let mut main_fields = 0;
    for field in draft.fields {
        let (name, label, detail, secret) = match (&field.label, &field.name) {
            (Some(label), _) => {
                let label = label.trim();
                if label.is_empty() {
                    return Err(CoreError::invalid("Type a name for each custom detail."));
                }
                if label.len() > MAX_DETAIL_LABEL_BYTES {
                    return Err(CoreError::invalid(format!(
                        "The name “{label}” is too long. Use {MAX_DETAIL_LABEL_BYTES} bytes or fewer."
                    )));
                }
                if !labels.insert(label.to_lowercase()) {
                    return Err(CoreError::invalid(format!(
                        "Two custom details have the name “{label}”."
                    )));
                }
                details += 1;
                if details > MAX_DETAILS {
                    return Err(CoreError::invalid(format!(
                        "An item can have at most {MAX_DETAILS} custom details."
                    )));
                }
                // A custom detail is hidden or visible as the owner chose.
                (
                    detail_field_name(label),
                    label.to_owned(),
                    true,
                    field.secret,
                )
            }
            (None, Some(name)) => {
                if !name_ok(name) || name.starts_with(DETAIL_PREFIX) {
                    return Err(CoreError::invalid(
                        "A field name can have only letters, digits, and _, and cannot start with x_.",
                    ));
                }
                // The name decides whether a field is secret, as on the Mac: the flag of
                // the request does not.
                let secret = match kind_field(kind, name) {
                    Some(secret) => secret,
                    None if kind == CredentialKind::Custom && !is_builtin(name) => {
                        main_fields += 1;
                        true
                    }
                    // A field that the item has already (an older import) keeps its flag.
                    None => current
                        .as_ref()
                        .and_then(|current| current.fields.iter().find(|f| f.name == *name))
                        .map(|stored| stored.secret)
                        .ok_or_else(|| {
                            CoreError::invalid(format!(
                                "“{}” is not a field of this kind of item.",
                                field_label(name)
                            ))
                        })?,
                };
                (name.clone(), field_label(name), false, secret)
            }
            (None, None) => return Err(CoreError::invalid("A field has no name.")),
        };
        if !names.insert(name.clone()) {
            return Err(CoreError::invalid(format!(
                "Two fields have the name “{label}”."
            )));
        }
        // The stored field whose value a blank secret keeps: the old name of a renamed
        // detail, or the field itself.
        let stored = match (&field.label, &field.name) {
            (Some(_), Some(old)) => old.clone(),
            _ => name.clone(),
        };
        let required_message = required(kind)
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, m)| *m);
        let missing = || {
            CoreError::invalid(
                required_message
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("Type the value of “{label}”.")),
            )
        };
        if secret {
            let typed = field
                .value
                .map(Secret::into_inner)
                .filter(|value| !value.is_empty());
            let value = match typed {
                Some(mut typed) => SecretValue::new(std::mem::take(&mut *typed)),
                None => match kept(vault, existing, &stored)? {
                    Some(value) if !value.expose().is_empty() => value,
                    // An optional secret without a value is left out, as on the Mac.
                    _ if !detail && required_message.is_none() && name == "passphrase" => continue,
                    _ => return Err(missing()),
                },
            };
            fields.push(Field {
                name,
                value,
                secret: true,
            });
        } else {
            let value = field.value.map(Secret::into_inner).unwrap_or_default();
            let value = value.trim();
            if value.is_empty() {
                if detail || required_message.is_some() {
                    return Err(missing());
                }
                continue;
            }
            fields.push(Field {
                name,
                value: SecretValue::new(value.to_owned()),
                secret: false,
            });
        }
    }
    for (name, message) in required(kind) {
        if !fields.iter().any(|field| field.name == *name) {
            return Err(CoreError::invalid(*message));
        }
    }
    if kind == CredentialKind::Custom && main_fields > 1 {
        return Err(CoreError::invalid(
            "An item of the kind Other has one secret field.",
        ));
    }
    if kind == CredentialKind::Custom
        && !fields.iter().any(|field| {
            field.secret && !field.name.starts_with(DETAIL_PREFIX) && !is_builtin(&field.name)
        })
    {
        return Err(CoreError::invalid(
            "Enter a field name and the secret value.",
        ));
    }
    let tags = build_tags(vault, existing, current.as_ref(), &fields, draft.tags)?;
    Ok(ItemDraft {
        title: title.to_owned(),
        kind,
        notes: notes.to_owned(),
        tags,
        fields,
    })
}

/// The tags, as the Mac keeps them: the service and the project first, then the other
/// tags, without the old service and project labels of an edit.
fn build_tags(
    vault: &Vault,
    existing: Option<u64>,
    current: Option<&ItemDetails>,
    fields: &[Field],
    given: Vec<String>,
) -> CoreResult<Vec<String>> {
    let value = |name: &str| {
        fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.expose().to_owned())
            .unwrap_or_default()
    };
    let mut old = Vec::new();
    if let (Some(id), Some(_)) = (existing, current) {
        for name in ["service", "project"] {
            let stored = plain(vault, id, name)?;
            if !stored.is_empty() && stored != value(name) {
                old.push(stored);
            }
        }
    }
    let mut tags: Vec<String> = Vec::new();
    let mut push = |tag: &str| -> CoreResult<()> {
        let tag = tag.trim();
        if tag.is_empty() || tags.iter().any(|t| t == tag) {
            return Ok(());
        }
        if tag.len() > MAX_TAG_BYTES {
            return Err(CoreError::invalid(format!(
                "A tag, the service, or the project is too long. Use {MAX_TAG_BYTES} bytes or fewer."
            )));
        }
        if tags.len() >= MAX_TAGS {
            return Err(CoreError::invalid(format!(
                "An item can have at most {MAX_TAGS} tags."
            )));
        }
        tags.push(tag.to_owned());
        Ok(())
    };
    push(&value("service"))?;
    push(&value("project"))?;
    for tag in &given {
        if !old.iter().any(|o| o == tag.trim()) {
            push(tag)?;
        }
    }
    Ok(tags)
}
