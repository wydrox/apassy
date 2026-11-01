//! Adding credentials that the paste detection found (ADR 0025 §4).
//!
//! [`Vault::add_detected`] saves one [`Detected`] in one SQLite transaction: the item and
//! its fields, the environment variable, the declaration with its provider, the source
//! of each declaration value, the folder, and the origin of an item that an agent
//! added. A failing step leaves nothing behind. [`Vault::add_detected_all`] saves
//! several in one transaction: all of them or none.
//!
//! - The title: a title that another item has (without regard to case) gets " 2",
//!   " 3", ... as the import and the vault list do.
//! - The variable: the detected name. A name that another item uses becomes the
//!   automatic name (`APASSY_ITEM_<id>`), so a paste never takes a variable from an
//!   item or fails on it. A setup key of a one-time password is never bound.
//! - The delivery (ADR 0011): a placeholder for the known hosts of the provider when
//!   the detection gives hosts and the value is long enough for a placeholder, as a new
//!   variable in the app starts. Else the real value: also for a provider that signs
//!   requests with the secret (`real_value` in the pack: AWS, Google Cloud). The
//!   known hosts stay recorded through the declaration's provider.
//! - No owner check: a new item moves no authority that an existing item has. The
//!   bouncer decides each use of it (ADR 0025 §3).

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};

use super::agents::{
    Declaration, EnvDelivery, MAX_PLACEHOLDER_HOSTS, checked_env_name, now_unix,
    parse_placeholder_host, to_sql_time,
};
use super::detect::{Detected, Source};
use super::history::{self, ItemEventKind};
use super::policy::{DeclarationSource, DeclarationSources};
use super::types::{
    ItemDraft, ItemSummary, MAX_TITLE_BYTES, VaultErrorKind, VaultResult, err, kind_as_str,
    validate_draft,
};
use super::{Vault, insert_tags_and_fields, providers, summary_from_parts};
use crate::contracts::CredentialKind;

/// How an agent added an item (ADR 0025 §6, table `item_origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginTool {
    /// The agent captured the value from the output of a command.
    Capture,
    /// The agent had Apassy generate the value.
    Generate,
    /// The agent saved a value that it had.
    Save,
    /// The agent asked the owner, and the owner saved the value.
    AskOwner,
}

impl OriginTool {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Generate => "generate",
            Self::Save => "save",
            Self::AskOwner => "ask_owner",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "capture" => Some(Self::Capture),
            "generate" => Some(Self::Generate),
            "save" => Some(Self::Save),
            "ask_owner" => Some(Self::AskOwner),
            _ => None,
        }
    }

    /// The agent made the value: capture, generate, or save. Only such an item is the
    /// agent's own for `update_credential`, `describe_credential`, and the value check
    /// (ADR 0025 §6). The owner pasted the value of an `ask_owner` item.
    pub fn is_agent_value(self) -> bool {
        !matches!(self, Self::AskOwner)
    }
}

/// The agent and the project of an item that an agent added. The owner adds items
/// without an origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemOrigin {
    pub agent_id: u64,
    pub agent_name: String,
    pub project_key: String,
    pub project_label: String,
    pub tool: OriginTool,
}

impl ItemOrigin {
    /// The detail of the "created" event of the item history (ADR 0025 §6): "Added by
    /// AGENT in PROJECT (capture)." It has no secret value.
    pub fn history_detail(&self) -> String {
        let place = if self.project_label.is_empty() {
            String::new()
        } else {
            format!(" in {}", self.project_label)
        };
        match self.tool {
            OriginTool::AskOwner => format!(
                "Saved by the owner for {}{place} (asked by the agent).",
                self.agent_name
            ),
            tool => format!("Added by {}{place} ({}).", self.agent_name, tool.as_str()),
        }
    }
}

/// The folder of the new items: its UUID and its path for the "moved" event.
pub(super) struct Place {
    uuid: String,
    path: String,
}

impl Vault {
    /// Save one detected credential in one transaction (see the module documentation).
    /// `folder` is a folder UUID, `None` the top level.
    ///
    /// - `InvalidInput`: the detection gives an item that the vault refuses, a variable
    ///   field that is not a secret field of the item, a host that is not valid, or a
    ///   provider that is not built in.
    /// - `NotFound`: `folder` is not a folder.
    pub fn add_detected(
        &mut self,
        detected: &Detected,
        folder: Option<&str>,
        origin: Option<&ItemOrigin>,
    ) -> VaultResult<ItemSummary> {
        self.add_detected_all(std::slice::from_ref(detected), folder, origin)?
            .pop()
            .ok_or_else(|| err(VaultErrorKind::Storage))
    }

    /// Save several detected credentials in one transaction: all of them, or none.
    /// Returns one summary for each, in order. The errors are those of
    /// [`Vault::add_detected`].
    pub fn add_detected_all(
        &mut self,
        detected: &[Detected],
        folder: Option<&str>,
        origin: Option<&ItemOrigin>,
    ) -> VaultResult<Vec<ItemSummary>> {
        self.require_unlocked()?;
        // The vault holds its exclusive lock, so the folder stays until the commit.
        let place = self.add_place(folder)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let added = add_all_in(&tx, detected, place.as_ref(), origin)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(added)
    }

    /// The folder of new items for [`add_all_in`]: its UUID and its path, checked now.
    pub(super) fn add_place(&self, folder: Option<&str>) -> VaultResult<Option<Place>> {
        folder
            .map(|uuid| {
                Ok(Place {
                    uuid: uuid.to_owned(),
                    path: self.folder_path(Some(uuid))?.join(" / "),
                })
            })
            .transpose()
    }
}

/// [`Vault::add_detected_all`] in a transaction of the caller, so that another change
/// commits with the new items (`Vault::save_for_request`).
pub(super) fn add_all_in(
    tx: &Transaction<'_>,
    detected: &[Detected],
    place: Option<&Place>,
    origin: Option<&ItemOrigin>,
) -> VaultResult<Vec<ItemSummary>> {
    detected
        .iter()
        .map(|one| add_one(tx, one, place, origin))
        .collect()
}

fn add_one(
    tx: &Transaction<'_>,
    detected: &Detected,
    place: Option<&Place>,
    origin: Option<&ItemOrigin>,
) -> VaultResult<ItemSummary> {
    let storage = |_| err(VaultErrorKind::Storage);
    let draft = validate_draft(ItemDraft {
        title: free_title(tx, &detected.title)?,
        kind: detected.kind,
        notes: String::new(),
        tags: Vec::new(),
        fields: detected.fields.clone(),
    })?;
    tx.execute(
        "INSERT INTO item (title, kind, notes, revision) VALUES (?1, ?2, ?3, 1)",
        (
            draft.title.as_str(),
            kind_as_str(draft.kind),
            draft.notes.as_str(),
        ),
    )
    .map_err(storage)?;
    let item = tx.last_insert_rowid();
    insert_tags_and_fields(tx, item, &draft)?;
    history::record(
        tx,
        item,
        ItemEventKind::Created,
        &origin.map_or_else(String::new, ItemOrigin::history_detail),
    )?;

    bind_variable(tx, item, detected)?;

    let provider = detected.provider.as_deref();
    if provider.is_some_and(|id| providers::find(id).is_none()) {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    let declaration = Declaration {
        project: String::new(),
        environment: detected.environment,
        risk: detected.risk,
        scope: detected.scope,
        reversibility: detected.reversibility,
    };
    tx.execute(
        "INSERT INTO declaration
             (item_id, project, environment, risk, scope, reversibility, provider)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        (
            item,
            declaration.project.as_str(),
            declaration.environment.as_str(),
            declaration.risk.as_str(),
            declaration.scope.as_str(),
            declaration.reversibility.as_str(),
            provider.unwrap_or_default(),
        ),
    )
    .map_err(storage)?;
    history::record(
        tx,
        item,
        ItemEventKind::Declaration,
        &declaration.history_detail(provider),
    )?;
    let sources = declaration_sources(detected);
    tx.execute(
        "INSERT INTO declaration_source (item_id, environment, risk, scope, reversibility)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            item,
            sources.environment.as_str(),
            sources.risk.as_str(),
            sources.scope.as_str(),
            sources.reversibility.as_str(),
        ),
    )
    .map_err(storage)?;

    if let Some(place) = place {
        place_item(tx, item, place)?;
    }

    if let Some(origin) = origin {
        tx.execute(
            "INSERT INTO item_origin (item_id, agent_id, agent_name, project_key, project_label,
                 tool, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                item,
                super::to_sql_id(origin.agent_id)?,
                origin.agent_name.as_str(),
                origin.project_key.as_str(),
                origin.project_label.as_str(),
                origin.tool.as_str(),
                to_sql_time(now_unix())?,
            ),
        )
        .map_err(storage)?;
    }
    summary_from_parts(item, draft.title, draft.kind, 1)
}

/// The variable of a new item, with the same history event as
/// [`Vault::set_env_binding_with`]. No row when the item has no variable name, no
/// placeholder hosts, and no variable field: the vault then delivers the one secret
/// field as `APASSY_ITEM_<id>`.
fn bind_variable(tx: &Transaction<'_>, item: i64, detected: &Detected) -> VaultResult<()> {
    if detected.env_name.is_none() && detected.hosts.is_empty() && detected.env_field.is_none() {
        return Ok(());
    }
    let field_name = match &detected.env_field {
        Some(name) => Some(name.as_str()),
        None => main_secret_field(detected),
    };
    let field = field_name
        .and_then(|name| detected.field(name))
        .filter(|field| field.secret)
        .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
    // A setup key never enters an agent process; generated codes use a separate selector.
    if super::is_setup_key_field(&field.name, field.value.expose()) {
        return Ok(());
    }
    let wanted = match detected.env_name.as_deref() {
        Some(name) => checked_env_name(name)?,
        None => "",
    };
    let taken: Option<i64> = tx
        .query_row(
            "SELECT item_id FROM env_binding WHERE ?1 != '' AND env_name = ?1",
            [wanted],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let env_name = if taken.is_some() { "" } else { wanted };
    let hosts = placeholder_hosts(&detected.hosts)?;
    // A provider that signs requests with the secret (AWS, Google Cloud) needs the real value.
    let signs = detected
        .provider
        .as_deref()
        .and_then(providers::find)
        .is_some_and(|provider| provider.real_value);
    let delivery = match hosts {
        Some(hosts)
            if !signs && crate::broker::proxy::mint_placeholder(field.value.expose()).is_some() =>
        {
            EnvDelivery::Placeholder(hosts)
        }
        _ => EnvDelivery::Value,
    };
    let stored_hosts = match &delivery {
        EnvDelivery::Value => None,
        EnvDelivery::Placeholder(hosts) => Some(hosts.join("\n")),
    };
    tx.execute(
        "INSERT INTO env_binding (item_id, env_name, field, placeholder_hosts)
         VALUES (?1, ?2, ?3, ?4)",
        (item, env_name, field.name.as_str(), stored_hosts.as_deref()),
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    let display_name = if env_name.is_empty() {
        "Automatic"
    } else {
        env_name
    };
    let detail = match delivery.history_text() {
        Some(text) => format!("{display_name}, {text}"),
        None => display_name.to_owned(),
    };
    history::record(tx, item, ItemEventKind::Variable, &detail)
}

/// Place a newly inserted item. The caller checked the folder while holding the vault.
pub(super) fn place_item(tx: &Transaction<'_>, item: i64, place: &Place) -> VaultResult<()> {
    tx.execute(
        "INSERT INTO item_folder (item_id, folder_uuid) VALUES (?1, ?2)",
        (item, place.uuid.as_str()),
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    history::record(tx, item, ItemEventKind::Moved, &place.path)
}

/// The field of the main secret: the token, the password, the private key, or the
/// first secret field of a Custom item.
fn main_secret_field(detected: &Detected) -> Option<&str> {
    let main = match detected.kind {
        CredentialKind::ApiKey => Some("token"),
        CredentialKind::Login | CredentialKind::Database => Some("password"),
        CredentialKind::SshKey => Some("private_key"),
        CredentialKind::Custom => None,
    };
    main.filter(|name| detected.field(name).is_some())
        .or_else(|| {
            detected
                .fields
                .iter()
                .find(|field| field.secret)
                .map(|field| field.name.as_str())
        })
}

/// The hosts of a placeholder, normalized as the vault stores them: `host`, or
/// `host:port` when the port is not 443, without repeats. `None` without hosts.
/// `InvalidInput`: a host that is not valid, or more than [`MAX_PLACEHOLDER_HOSTS`].
fn placeholder_hosts(hosts: &[String]) -> VaultResult<Option<Vec<String>>> {
    if hosts.is_empty() {
        return Ok(None);
    }
    if hosts.len() > MAX_PLACEHOLDER_HOSTS {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    let mut lines: Vec<String> = Vec::with_capacity(hosts.len());
    for host in hosts {
        let (name, port) =
            parse_placeholder_host(host).ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        let line = if port == 443 {
            name
        } else {
            format!("{name}:{port}")
        };
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    Ok(Some(lines))
}

fn declaration_sources(detected: &Detected) -> DeclarationSources {
    let source = |source: Source| match source {
        Source::Signal => DeclarationSource::Signal,
        Source::Default => DeclarationSource::Default,
    };
    DeclarationSources {
        environment: source(detected.sources.environment),
        risk: source(detected.sources.risk),
        scope: source(detected.sources.scope),
        reversibility: source(detected.sources.reversibility),
    }
}

/// `title`, or `title 2`, `title 3`, ... when another item has the title (without
/// regard to case). The base is cut on a character boundary so that the title with the
/// suffix stays within [`MAX_TITLE_BYTES`].
fn free_title(tx: &Transaction<'_>, title: &str) -> VaultResult<String> {
    let storage = |_| err(VaultErrorKind::Storage);
    let title = title.trim();
    let mut stmt = tx.prepare("SELECT title FROM item").map_err(storage)?;
    let used: std::collections::BTreeSet<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage)?
        .map(|row| row.map(|title| title.to_lowercase()))
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    if !used.contains(&title.to_lowercase()) {
        return Ok(title.to_owned());
    }
    for number in 2u64.. {
        let suffix = format!(" {number}");
        let mut end = title
            .len()
            .min(MAX_TITLE_BYTES.saturating_sub(suffix.len()));
        while !title.is_char_boundary(end) {
            end -= 1;
        }
        let candidate = format!("{}{suffix}", title[..end].trim_end());
        if !used.contains(&candidate.to_lowercase()) {
            return Ok(candidate);
        }
    }
    Err(err(VaultErrorKind::Storage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_normalized_without_repeats() {
        let hosts = vec![
            "api.example.com".to_owned(),
            "api.example.com:443".to_owned(),
            "files.example.com:8443".to_owned(),
        ];
        assert_eq!(
            placeholder_hosts(&hosts).unwrap(),
            Some(vec![
                "api.example.com".to_owned(),
                "files.example.com:8443".to_owned()
            ])
        );
        assert_eq!(placeholder_hosts(&[]).unwrap(), None);
        assert_eq!(
            placeholder_hosts(&["Not A Host".to_owned()])
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        let many = vec!["a.example.com".to_owned(); MAX_PLACEHOLDER_HOSTS + 1];
        assert!(placeholder_hosts(&many).is_err());
    }
}
