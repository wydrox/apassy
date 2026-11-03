//! Duplicate cleanup: find the items that hold the same credential, and merge a group
//! into one item.
//!
//! Imports (1Password on the Mac, Credential Exchange on the iPhone) and sync conflicts
//! leave duplicates. [`Vault::duplicate_groups`] finds them among the active items (not
//! archived, not a read-only mirror of a shared vault). Two items are duplicates when:
//!
//! - both are logins with a shared host and the same username. The hosts of a login are
//!   its website details and the RP ID of its passkey, without the scheme, the port, the
//!   path, and a leading `www.`, in lowercase. The username is trimmed and compared
//!   without regard to case. A login without a host is never a duplicate by this rule.
//! - both have the same kind and the same secret values: the same set of (field name,
//!   value) over the secret fields with a value. The core compares SHA-256 digests in
//!   memory; no digest and no value leaves this module. Items without a secret value are
//!   never duplicates by this rule.
//!
//! Items in different shared vaults never group. A group holds each item that a chain of
//! these matches reaches, in ID order.
//!
//! [`Vault::merge_duplicates`] keeps one item and archives the others in one transaction:
//!
//! - The kept item keeps its title, kind, folder, fields, values, passkey, and agent
//!   settings. A field of another item that it lacks is added. A field with another
//!   value stays, and the other value is added as the detail "Previous <label>" with the
//!   same secret flag. Equal values are not repeated; website details are joined.
//! - Notes are joined (distinct notes, a blank line between them); tags are joined. A
//!   merge over a limit of the vault or of the item forms (notes, tags, details, fields,
//!   size) changes nothing.
//! - Passkeys: when an item of the merge holds a passkey, the kept item must hold the
//!   canonical passkey of the credential, and each other item may hold only the same
//!   credential (a conflict copy). Reserved `passkey_` fields never pass through here.
//! - Agent settings that cannot move safely refuse the merge ("Used by agents"): a
//!   process grant, an API rule, or a connector of another item; a declaration of another
//!   item that differs from the declaration of the kept item; a variable of another item
//!   when the kept item has one, or two other items have one. One variable moves to a
//!   kept item without one, only when the kept item then delivers the same value. "Always
//!   ask me" and the per-agent exceptions "never" and "always ask" of the other items
//!   apply to the kept item too: they only make agent use stricter. Remembered answers and
//!   "only these items" exceptions do not move: the agent is asked again.
//! - Each other item is archived (the owner can bring it back), never deleted. The kept
//!   item gets an edit event whose detail starts with [`MERGED_PREFIX`]; each archived
//!   item gets an archive event with the detail [`MERGED_INTO_DETAIL`]. Neither names a
//!   value. Both kinds of event exist in older versions of Apassy, which show a plain
//!   edit and a plain archive.
//!
//! The SQL triggers of the sync mark each change, so a merge syncs as the edit and the
//! archives that it is.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::contracts::CredentialKind;

use super::history::{self, EditChange, ItemEventKind};
use super::passkey::{self, PasskeyError};
use super::types::{
    Field, ItemDraft, MAX_NOTES_BYTES, MAX_TAG_COUNT, SecretValue, VaultError, VaultErrorKind,
    VaultResult, err, is_passkey_field, kind_as_str, kind_from_str, validate_draft_with,
};
use super::{
    Vault, current_revision, custom_detail_label, edit_changes, insert_fields,
    insert_tags_and_fields, to_public_id, to_public_revision, to_sql_id,
};

/// The detail of the edit event of a merge starts with this text and the count of the
/// archived items, for example `merged:2`. The changed field names follow as in any
/// edit. See [`merged_count`].
pub const MERGED_PREFIX: &str = "merged:";
/// The detail of the archive event of an item that a merge archived.
pub const MERGED_INTO_DETAIL: &str = "merged";

/// The item forms take at most this many custom details (`x_<hex label>`).
const MAX_DETAILS: usize = 10;
/// A custom detail label has at most this many bytes.
const MAX_DETAIL_LABEL_BYTES: usize = 31;
const DETAIL_PREFIX: &str = "x_";

/// The count of merged items in the detail of an edit event, when the edit is a merge.
pub fn merged_count(detail: &str) -> Option<usize> {
    detail
        .split(',')
        .find_map(|token| token.strip_prefix(MERGED_PREFIX)?.parse().ok())
}

/// One item of a duplicate group. It holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateMember {
    pub id: u64,
    pub title: String,
    pub kind: CredentialKind,
    pub revision: u64,
    /// The item holds a passkey.
    pub has_passkey: bool,
    /// The newest change of the item (Unix seconds), when its history has one.
    pub changed_at: Option<u64>,
}

/// Items that hold the same credential. Names and labels only, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// In ID order.
    pub items: Vec<DuplicateMember>,
    /// The suggested item to keep: the item with the canonical passkey; else the item
    /// that agents use; else the most recently changed; the lowest ID on a tie.
    pub keep: u64,
    /// The owner-facing labels of the fields whose values differ, and "Notes", "Tags",
    /// and "Title" when those differ.
    pub differences: Vec<String>,
    /// No difference but the titles.
    pub identical: bool,
    /// The group merges into `keep`.
    pub mergeable: bool,
    /// Why the group does not merge into `keep`.
    pub reason: Option<String>,
    /// The items that the group can merge into, in ID order. Empty when none.
    pub keep_choices: Vec<u64>,
}

/// The result of a merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    /// The kept item.
    pub id: u64,
    /// Its new revision.
    pub revision: u64,
    /// The archived items, in the order of the request.
    pub archived: Vec<u64>,
}

/// Why a merge cannot go ahead. [`Vault::merge_duplicates`] answers each with
/// `InvalidInput`; [`Vault::merge_refusal`] names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeRefusal {
    /// Two items hold different passkeys, or a passkey that does not read.
    TwoPasskeys,
    /// Another item holds the passkey: keep that one.
    KeepPasskey,
    /// The canonical passkey of the credential is on an item outside the merge.
    PasskeyElsewhere,
    /// An agent setting of another item cannot move safely.
    UsedByAgents,
    /// The merged item would be over a limit.
    TooManyFields,
}

impl MergeRefusal {
    /// Short owner-facing text.
    pub fn reason(self) -> &'static str {
        match self {
            Self::TwoPasskeys => "Two different passkeys",
            Self::KeepPasskey => "Keep the item with the passkey",
            Self::PasskeyElsewhere => "The passkey is on another item",
            Self::UsedByAgents => "Used by agents",
            Self::TooManyFields => "Too many fields",
        }
    }
}

/// An active item as the duplicate check reads it. Values erase on drop.
struct Item {
    sql_id: i64,
    id: u64,
    title: String,
    kind: CredentialKind,
    notes: String,
    revision: u64,
    tags: Vec<String>,
    /// The generic fields in their stored order.
    fields: Vec<Field>,
    /// The item has reserved passkey rows. Their values are not read here.
    passkey_rows: bool,
    /// The shared vaults of the item: items in different places never group.
    place: String,
}

/// What agents have of an item.
#[derive(Default)]
struct AgentUse {
    /// The variable: its stored name and the field it delivers.
    binding: Option<(String, String)>,
    /// project, environment, risk, scope, reversibility.
    declaration: Option<[String; 5]>,
    /// A process grant, an API rule, or a connector.
    fixed: bool,
    /// "Always ask me".
    always_ask: bool,
}

impl AgentUse {
    fn used(&self) -> bool {
        self.binding.is_some() || self.declaration.is_some() || self.fixed
    }
}

/// A member of a duplicate group with what a merge needs.
struct Member {
    item: Item,
    /// (RP ID, credential ID) of a passkey that reads.
    credential: Option<(String, Vec<u8>)>,
    /// The item holds the canonical passkey of its credential.
    canonical: bool,
    /// The reserved rows with their values, for the limits of a merge into this item.
    passkey_fields: Vec<Field>,
    /// The reserved rows are one valid passkey.
    valid_passkey: bool,
    agent: AgentUse,
    changed_at: Option<u64>,
}

impl Member {
    fn public(&self) -> DuplicateMember {
        DuplicateMember {
            id: self.item.id,
            title: self.item.title.clone(),
            kind: self.item.kind,
            revision: self.item.revision,
            has_passkey: self.credential.is_some(),
            changed_at: self.changed_at,
        }
    }
}

/// The merged body of the kept item and the agent settings that move.
struct Plan {
    draft: ItemDraft,
    /// The other item whose variable moves to the kept item.
    binding_from: Option<(i64, String)>,
    /// The kept item becomes "Always ask me".
    always_ask: bool,
}

fn storage<E>(_: E) -> VaultError {
    err(VaultErrorKind::Storage)
}

fn passkey_error(error: PasskeyError) -> VaultError {
    match error {
        PasskeyError::Vault(vault) => vault,
        _ => err(VaultErrorKind::Storage),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The owner-facing label of a field, as the Mac's `field_label`.
fn field_label(name: &str) -> String {
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
        other => custom_detail_label(other).unwrap_or_else(|| other.to_owned()),
    }
}

/// The built-in field names of the item forms.
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

fn is_detail(name: &str) -> bool {
    custom_detail_label(name).is_some()
}

/// A field of a custom item that is its main secret: not a detail, not built in.
fn is_main(name: &str) -> bool {
    !is_detail(name) && !is_builtin(name)
}

fn is_website(field: &Field) -> bool {
    !field.secret
        && crate::browser::site::is_website_field(
            &field.name,
            custom_detail_label(&field.name).as_deref(),
        )
}

/// The field name of a custom detail: `x_` and the label in lowercase hex.
fn detail_field_name(label: &str) -> String {
    let mut name = String::from(DETAIL_PREFIX);
    for byte in label.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// `text` cut to `max` bytes on a character boundary, without trailing spaces.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].trim_end()
}

/// The host of a website value or an RP ID: no scheme, user, port, path, trailing dot,
/// or leading `www.`; lowercase. `None` for an empty host.
fn normalize_host(value: &str) -> Option<String> {
    let mut rest = value.trim();
    if let Some((scheme, after)) = rest.split_once("://")
        && !scheme.is_empty()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        rest = after;
    }
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let mut host = &rest[..end];
    if let Some((_, after)) = host.rsplit_once('@') {
        host = after;
    }
    if host.starts_with('[') {
        if let Some(close) = host.find(']') {
            host = &host[..=close];
        }
    } else if let Some((name, port)) = host.rsplit_once(':')
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        host = name;
    }
    let host = host.trim_end_matches('.').to_lowercase();
    let host = match host.strip_prefix("www.") {
        Some(bare) => bare.to_owned(),
        None => host,
    };
    (!host.is_empty() && !host.contains(char::is_whitespace)).then_some(host)
}

/// A website value for the comparison of a merge: without `http://` or `https://`, a
/// leading `www.`, and a trailing `/`, in lowercase. `https://github.com/` and
/// `github.com` are one website; another path is another website.
fn website_key(value: &str) -> String {
    let mut rest = value.trim().to_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(after) = rest.strip_prefix(scheme) {
            rest = after.to_owned();
            break;
        }
    }
    if let Some(after) = rest.strip_prefix("www.") {
        rest = after.to_owned();
    }
    rest.trim_end_matches('/').to_owned()
}

/// The digest of the kind and the secret values of an item, or `None` without a secret
/// value. It stays in memory for the comparison.
fn secret_digest(kind: CredentialKind, fields: &[Field]) -> Option<[u8; 32]> {
    let mut pairs: Vec<(&str, &str)> = fields
        .iter()
        .filter(|field| field.secret && !field.value.expose().is_empty())
        .map(|field| (field.name.as_str(), field.value.expose()))
        .collect();
    if pairs.is_empty() {
        return None;
    }
    pairs.sort_unstable();
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"apassy-duplicates-v1\0");
    ctx.update(kind_as_str(kind).as_bytes());
    for (name, value) in pairs {
        for part in [name, value] {
            ctx.update(&(part.len() as u64).to_be_bytes());
            ctx.update(part.as_bytes());
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Some(out)
}

fn find(parent: &mut [usize], mut index: usize) -> usize {
    while parent[index] != index {
        parent[index] = parent[parent[index]];
        index = parent[index];
    }
    index
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (find(parent, a), find(parent, b));
    if a != b {
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        parent[high] = low;
    }
}

/// The active items that are not read-only mirrors, in ID order, with their generic
/// fields. The values of reserved passkey rows are not read.
fn load_items(conn: &Connection) -> VaultResult<Vec<Item>> {
    let mut items: BTreeMap<i64, Item> = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, title, kind, notes, revision FROM item
                 WHERE id NOT IN (SELECT item_id FROM item_archive)
                   AND id NOT IN (SELECT item_id FROM item_home)
                 ORDER BY id",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(storage)?;
        for row in rows {
            let (sql_id, title, kind, notes, revision) = row.map_err(storage)?;
            items.insert(
                sql_id,
                Item {
                    sql_id,
                    id: to_public_id(sql_id)?,
                    title,
                    kind: kind_from_str(&kind)?,
                    notes,
                    revision: to_public_revision(revision)?,
                    tags: Vec::new(),
                    fields: Vec::new(),
                    passkey_rows: false,
                    place: String::new(),
                },
            );
        }
    }
    {
        let mut stmt = conn
            .prepare(
                "SELECT item_id, name,
                        CASE WHEN substr(name, 1, 8) = 'passkey_' THEN '' ELSE value END,
                        secret
                 FROM item_field ORDER BY item_id, position",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    SecretValue::new(row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)? == 1,
                ))
            })
            .map_err(storage)?;
        for row in rows {
            let (sql_id, name, value, secret) = row.map_err(storage)?;
            let Some(item) = items.get_mut(&sql_id) else {
                continue;
            };
            if is_passkey_field(&name) {
                item.passkey_rows = true;
            } else {
                item.fields.push(Field {
                    name,
                    value,
                    secret,
                });
            }
        }
    }
    {
        let mut stmt = conn
            .prepare("SELECT item_id, tag FROM item_tag ORDER BY item_id, position")
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        for row in rows {
            let (sql_id, tag) = row.map_err(storage)?;
            if let Some(item) = items.get_mut(&sql_id) {
                item.tags.push(tag);
            }
        }
    }
    {
        let mut stmt = conn
            .prepare(
                "SELECT item_id, shared_vault_uuid FROM item_share
                 ORDER BY item_id, shared_vault_uuid",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        for row in rows {
            let (sql_id, share) = row.map_err(storage)?;
            if let Some(item) = items.get_mut(&sql_id) {
                item.place.push_str(&share);
                item.place.push('\n');
            }
        }
    }
    Ok(items.into_values().collect())
}

fn agent_use(conn: &Connection, item: i64) -> VaultResult<AgentUse> {
    let binding = conn
        .query_row(
            "SELECT env_name, field FROM env_binding WHERE item_id = ?1",
            [item],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let declaration = conn
        .query_row(
            "SELECT project, environment, risk, scope, reversibility FROM declaration
             WHERE item_id = ?1",
            [item],
            |row| {
                Ok([
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ])
            },
        )
        .optional()
        .map_err(storage)?;
    let fixed: i64 = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM exec_grant WHERE item_id = ?1)
                 OR EXISTS (SELECT 1 FROM grant_rule WHERE item_id = ?1)
                 OR EXISTS (SELECT 1 FROM destination WHERE item_id = ?1)",
            [item],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let always_ask: Option<i64> = conn
        .query_row(
            "SELECT always_ask FROM item_policy WHERE item_id = ?1",
            [item],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    Ok(AgentUse {
        binding,
        declaration,
        fixed: fixed != 0,
        always_ask: always_ask == Some(1),
    })
}

/// The suggested item to keep (see [`DuplicateGroup::keep`]).
fn suggest_keep(members: &[Member]) -> u64 {
    if let Some(member) = members.iter().find(|member| member.canonical) {
        return member.item.id;
    }
    let used: Vec<&Member> = members
        .iter()
        .filter(|member| member.agent.used())
        .collect();
    let pool: Vec<&Member> = if used.is_empty() {
        members.iter().collect()
    } else {
        used
    };
    pool.iter()
        .max_by(|a, b| {
            a.changed_at
                .unwrap_or(0)
                .cmp(&b.changed_at.unwrap_or(0))
                .then(b.item.id.cmp(&a.item.id))
        })
        .map_or(members[0].item.id, |member| member.item.id)
}

/// The labels of the differences, and whether the members are the same but the titles.
fn differences(members: &[Member]) -> (Vec<String>, bool) {
    let mut names: Vec<&str> = Vec::new();
    for member in members {
        for field in &member.item.fields {
            if !names.contains(&field.name.as_str()) {
                names.push(&field.name);
            }
        }
    }
    let mut labels: Vec<String> = Vec::new();
    let mut same = true;
    for name in names {
        let values: Vec<Option<&str>> = members
            .iter()
            .map(|member| {
                member
                    .item
                    .fields
                    .iter()
                    .find(|field| field.name == name)
                    .map(|field| field.value.expose())
            })
            .collect();
        if values.windows(2).any(|pair| pair[0] != pair[1]) {
            same = false;
            push_label(&mut labels, field_label(name));
        }
    }
    if members
        .windows(2)
        .any(|pair| pair[0].item.notes.trim() != pair[1].item.notes.trim())
    {
        same = false;
        push_label(&mut labels, "Notes".to_owned());
    }
    let tag_set =
        |member: &Member| -> BTreeSet<String> { member.item.tags.iter().cloned().collect() };
    if members
        .windows(2)
        .any(|pair| tag_set(&pair[0]) != tag_set(&pair[1]))
    {
        same = false;
        push_label(&mut labels, "Tags".to_owned());
    }
    if members
        .windows(2)
        .any(|pair| pair[0].item.title != pair[1].item.title)
    {
        push_label(&mut labels, "Title".to_owned());
    }
    (labels, same)
}

fn push_label(labels: &mut Vec<String>, label: String) {
    if !labels.contains(&label) {
        labels.push(label);
    }
}

/// The index of the field of `fields` that `name` matches: the same name, or a custom
/// detail with the same label without regard to case.
fn find_same(fields: &[Field], name: &str) -> Option<usize> {
    let label = custom_detail_label(name).map(|label| label.to_lowercase());
    fields.iter().position(|field| {
        field.name == name
            || label.as_ref().is_some_and(|label| {
                custom_detail_label(&field.name).is_some_and(|other| other.to_lowercase() == *label)
            })
    })
}

fn label_taken(fields: &[Field], label: &str) -> bool {
    let label = label.to_lowercase();
    fields.iter().any(|field| {
        custom_detail_label(&field.name).is_some_and(|other| other.to_lowercase() == label)
    })
}

/// `base`, or `base 2`, `base 3`, …: a detail label that `fields` does not have, at most
/// [`MAX_DETAIL_LABEL_BYTES`].
fn unique_label(fields: &[Field], base: &str) -> Result<String, MergeRefusal> {
    let base = cut(base, MAX_DETAIL_LABEL_BYTES);
    if base.is_empty() {
        return Err(MergeRefusal::TooManyFields);
    }
    if !label_taken(fields, base) {
        return Ok(base.to_owned());
    }
    for n in 2..=super::types::MAX_FIELD_COUNT + 1 {
        let suffix = format!(" {n}");
        let candidate = format!(
            "{}{suffix}",
            cut(base, MAX_DETAIL_LABEL_BYTES.saturating_sub(suffix.len()))
        );
        if !label_taken(fields, &candidate) {
            return Ok(candidate);
        }
    }
    Err(MergeRefusal::TooManyFields)
}

/// Whether `label` is `base` or `base N`, without regard to case.
fn in_family(label: &str, base: &str) -> bool {
    let label = label.to_lowercase();
    let base = base.to_lowercase();
    label == base
        || label
            .strip_prefix(&base)
            .and_then(|rest| rest.strip_prefix(' '))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Add one field of another item to the merged fields.
fn add_field(
    kind: CredentialKind,
    fields: &mut Vec<Field>,
    field: &Field,
) -> Result<(), MergeRefusal> {
    if is_website(field) {
        let value = website_key(field.value.expose());
        if fields
            .iter()
            .any(|other| is_website(other) && website_key(other.value.expose()) == value)
        {
            return Ok(());
        }
        if find_same(fields, &field.name).is_none() {
            fields.push(field.clone());
        } else {
            let label = unique_label(fields, "Website")?;
            fields.push(Field {
                name: detail_field_name(&label),
                value: field.value.clone(),
                secret: false,
            });
        }
        return Ok(());
    }
    let label = field_label(&field.name);
    match find_same(fields, &field.name) {
        None => {
            // The item forms take one main secret in a custom item: another one becomes
            // a detail.
            if kind == CredentialKind::Custom
                && is_main(&field.name)
                && fields.iter().any(|other| is_main(&other.name))
            {
                let label = unique_label(fields, &label)?;
                fields.push(Field {
                    name: detail_field_name(&label),
                    value: field.value.clone(),
                    secret: field.secret,
                });
            } else {
                fields.push(field.clone());
            }
        }
        Some(index) => {
            if fields[index].value.expose() == field.value.expose() {
                return Ok(());
            }
            let base = format!("Previous {label}");
            let base = cut(&base, MAX_DETAIL_LABEL_BYTES);
            let repeated = fields.iter().any(|other| {
                other.secret == field.secret
                    && other.value.expose() == field.value.expose()
                    && custom_detail_label(&other.name).is_some_and(|other| in_family(&other, base))
            });
            if repeated {
                return Ok(());
            }
            let label = unique_label(fields, base)?;
            fields.push(Field {
                name: detail_field_name(&label),
                value: field.value.clone(),
                secret: field.secret,
            });
        }
    }
    Ok(())
}

/// The merge of `others` into `keep`, or why it cannot go ahead.
fn plan(keep: &Member, others: &[&Member]) -> Result<Plan, MergeRefusal> {
    // Passkeys: one credential at most, on the kept item as its canonical item.
    let with_passkey: Vec<&Member> = std::iter::once(keep)
        .chain(others.iter().copied())
        .filter(|member| member.item.passkey_rows)
        .collect();
    if let Some(first) = with_passkey.first() {
        let credential = first.credential.as_ref().ok_or(MergeRefusal::TwoPasskeys)?;
        if with_passkey
            .iter()
            .any(|member| member.credential.as_ref() != Some(credential))
        {
            return Err(MergeRefusal::TwoPasskeys);
        }
        if !keep.canonical {
            return Err(if with_passkey.iter().any(|member| member.canonical) {
                MergeRefusal::KeepPasskey
            } else {
                MergeRefusal::PasskeyElsewhere
            });
        }
    }
    // Agent settings.
    if others.iter().any(|member| member.agent.fixed) {
        return Err(MergeRefusal::UsedByAgents);
    }
    if others.iter().any(|member| {
        member.agent.declaration.is_some() && member.agent.declaration != keep.agent.declaration
    }) {
        return Err(MergeRefusal::UsedByAgents);
    }
    let bound: Vec<&Member> = others
        .iter()
        .copied()
        .filter(|member| member.agent.binding.is_some())
        .collect();
    let binding_from = match (bound.as_slice(), &keep.agent.binding) {
        ([], _) => None,
        ([one], None) => Some(*one),
        _ => return Err(MergeRefusal::UsedByAgents),
    };
    // Fields.
    let kind = keep.item.kind;
    let mut fields = keep.item.fields.clone();
    let kept_details = fields.iter().filter(|field| is_detail(&field.name)).count();
    for other in others {
        for field in &other.item.fields {
            add_field(kind, &mut fields, field)?;
        }
    }
    let details = fields.iter().filter(|field| is_detail(&field.name)).count();
    if details > MAX_DETAILS && details > kept_details {
        return Err(MergeRefusal::TooManyFields);
    }
    // A variable moves only when the kept item delivers the same value.
    let binding_from = match binding_from {
        None => None,
        Some(from) => {
            let Some((env_name, bound_field)) = from.agent.binding.as_ref() else {
                return Err(MergeRefusal::UsedByAgents);
            };
            let value = |list: &[Field]| {
                list.iter()
                    .find(|field| field.name == *bound_field && field.secret)
                    .map(|field| field.value.clone())
            };
            match (value(from.item.fields.as_slice()), value(fields.as_slice())) {
                (Some(source), Some(target)) if source == target => {}
                _ => return Err(MergeRefusal::UsedByAgents),
            }
            Some((from.item.sql_id, env_name.clone()))
        }
    };
    // Notes and tags.
    let mut notes = keep.item.notes.clone();
    let mut seen: Vec<&str> = vec![keep.item.notes.trim()];
    for other in others {
        let text = other.item.notes.trim();
        if text.is_empty() || seen.contains(&text) {
            continue;
        }
        notes = if notes.trim().is_empty() {
            text.to_owned()
        } else {
            format!("{}\n\n{text}", notes.trim_end())
        };
        seen.push(text);
    }
    if notes.len() > MAX_NOTES_BYTES {
        return Err(MergeRefusal::TooManyFields);
    }
    let mut tags = keep.item.tags.clone();
    for other in others {
        for tag in &other.item.tags {
            if !tags.contains(tag) {
                tags.push(tag.clone());
            }
        }
    }
    if tags.len() > MAX_TAG_COUNT {
        return Err(MergeRefusal::TooManyFields);
    }
    let draft = ItemDraft {
        title: keep.item.title.clone(),
        kind,
        notes,
        tags,
        fields,
    };
    let has_passkey = kind == CredentialKind::Login && keep.valid_passkey;
    let draft = validate_draft_with(draft, &keep.passkey_fields, has_passkey)
        .map_err(|_| MergeRefusal::TooManyFields)?;
    Ok(Plan {
        draft,
        binding_from,
        always_ask: !keep.agent.always_ask && others.iter().any(|member| member.agent.always_ask),
    })
}

/// The members of `members` but `keep`.
fn rest(members: &[Member], keep: u64) -> Vec<&Member> {
    members
        .iter()
        .filter(|member| member.item.id != keep)
        .collect()
}

fn describe(members: &[Member]) -> DuplicateGroup {
    let keep = suggest_keep(members);
    let (differences, identical) = differences(members);
    let refusal = members
        .iter()
        .find(|member| member.item.id == keep)
        .map_or(Some(MergeRefusal::TwoPasskeys), |kept| {
            plan(kept, &rest(members, keep)).err()
        });
    let keep_choices = members
        .iter()
        .filter(|member| plan(member, &rest(members, member.item.id)).is_ok())
        .map(|member| member.item.id)
        .collect();
    DuplicateGroup {
        items: members.iter().map(Member::public).collect(),
        keep,
        differences,
        identical,
        mergeable: refusal.is_none(),
        reason: refusal.map(|refusal| refusal.reason().to_owned()),
        keep_choices,
    }
}

/// The members of `keep` and `others` in one current group, in that order.
fn select<'a>(
    conn: &Connection,
    sets: &'a [Vec<Member>],
    keep: u64,
    others: &[u64],
) -> VaultResult<(&'a Member, Vec<&'a Member>)> {
    if others.is_empty() {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    let mut seen = BTreeSet::new();
    for id in std::iter::once(keep).chain(others.iter().copied()) {
        let sql_id = to_sql_id(id)?;
        if !seen.insert(id) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let found: i64 = conn
            .query_row("SELECT count(*) FROM item WHERE id = ?1", [sql_id], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        if found == 0 {
            return Err(err(VaultErrorKind::NotFound));
        }
    }
    let set = sets
        .iter()
        .find(|set| set.iter().any(|member| member.item.id == keep))
        .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
    let member = |id: u64| {
        set.iter()
            .find(|member| member.item.id == id)
            .ok_or_else(|| err(VaultErrorKind::InvalidInput))
    };
    let kept = member(keep)?;
    let rest = others
        .iter()
        .map(|id| member(*id))
        .collect::<VaultResult<Vec<_>>>()?;
    Ok((kept, rest))
}

impl Vault {
    /// The duplicate groups of the active items (see the module documentation), each in
    /// ID order, the groups by their first ID. No value is in the answer.
    pub fn duplicate_groups(&self) -> VaultResult<Vec<DuplicateGroup>> {
        self.require_unlocked()?;
        Ok(self
            .duplicate_sets()?
            .iter()
            .map(|members| describe(members))
            .collect())
    }

    /// Why `others` cannot merge into `keep`, or `None` when they can. `InvalidInput`
    /// when the items are not in one current duplicate group, `NotFound` for an ID that
    /// is not an item. Revisions are not checked.
    pub fn merge_refusal(&self, keep: u64, others: &[u64]) -> VaultResult<Option<MergeRefusal>> {
        self.require_unlocked()?;
        let sets = self.duplicate_sets()?;
        let (kept, rest) = select(self.conn_ref()?, &sets, keep, others)?;
        Ok(plan(kept, &rest).err())
    }

    /// Merge `others` into `keep` (each `(id, revision)`) in one transaction (see the
    /// module documentation). The items must be in one current duplicate group.
    ///
    /// - `InvalidInput`: no other item, an ID twice, the items are not one current
    ///   group, or a refusal of [`Vault::merge_refusal`] (passkeys, agent settings,
    ///   limits). Nothing changes.
    /// - `NotFound`: an ID is not an item.
    /// - `Conflict`: a revision is not current.
    pub fn merge_duplicates(
        &mut self,
        keep: (u64, u64),
        others: &[(u64, u64)],
    ) -> VaultResult<MergeOutcome> {
        self.require_unlocked()?;
        let other_ids: Vec<u64> = others.iter().map(|(id, _)| *id).collect();
        let sets = self.duplicate_sets()?;
        let (plan, keep_sql, other_sqls) = {
            let (kept, rest) = select(self.conn_ref()?, &sets, keep.0, &other_ids)?;
            if kept.item.revision != keep.1
                || rest
                    .iter()
                    .zip(others)
                    .any(|(member, (_, revision))| member.item.revision != *revision)
            {
                return Err(err(VaultErrorKind::Conflict));
            }
            let plan = plan(kept, &rest).map_err(|_| err(VaultErrorKind::InvalidInput))?;
            let other_sqls: Vec<(i64, i64)> = rest
                .iter()
                .zip(others)
                .map(|(member, (_, revision))| {
                    i64::try_from(*revision)
                        .map(|revision| (member.item.sql_id, revision))
                        .map_err(|_| err(VaultErrorKind::InvalidInput))
                })
                .collect::<VaultResult<_>>()?;
            (plan, kept.item.sql_id, other_sqls)
        };
        drop(sets);
        let expected = i64::try_from(keep.1).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if current_revision(&tx, keep_sql)? != expected {
            return Err(err(VaultErrorKind::Conflict));
        }
        for (sql_id, revision) in &other_sqls {
            if current_revision(&tx, *sql_id)? != *revision {
                return Err(err(VaultErrorKind::Conflict));
            }
        }
        // The reserved rows stay as they are, after the generic fields.
        let kept_passkey = passkey::stored_fields(&tx, keep_sql)?;
        let has_passkey =
            plan.draft.kind == CredentialKind::Login && passkey::is_valid_passkey(&kept_passkey);
        let draft = validate_draft_with(plan.draft, &kept_passkey, has_passkey)?;
        let next = expected.checked_add(1).ok_or_else(|| storage(()))?;
        let changes = edit_changes(&tx, keep_sql, &draft)?;
        tx.execute(
            "UPDATE item SET title = ?1, notes = ?2, revision = ?3 WHERE id = ?4",
            (draft.title.as_str(), draft.notes.as_str(), next, keep_sql),
        )
        .map_err(storage)?;
        tx.execute("DELETE FROM item_tag WHERE item_id = ?1", [keep_sql])
            .map_err(storage)?;
        tx.execute("DELETE FROM item_field WHERE item_id = ?1", [keep_sql])
            .map_err(storage)?;
        insert_tags_and_fields(&tx, keep_sql, &draft)?;
        insert_fields(&tx, keep_sql, draft.fields.len(), &kept_passkey)?;
        if let Some((from, env_name)) = &plan.binding_from {
            tx.execute(
                "UPDATE env_binding SET item_id = ?1 WHERE item_id = ?2",
                (keep_sql, *from),
            )
            .map_err(storage)?;
            let shown = if env_name.is_empty() {
                "Automatic"
            } else {
                env_name.as_str()
            };
            history::record(&tx, keep_sql, ItemEventKind::Variable, shown)?;
            history::record(&tx, *from, ItemEventKind::VariableRemoved, "")?;
        }
        if plan.always_ask {
            tx.execute(
                "INSERT INTO item_policy (item_id, always_ask) VALUES (?1, 1)
                 ON CONFLICT(item_id) DO UPDATE SET always_ask = 1",
                [keep_sql],
            )
            .map_err(storage)?;
        }
        let now = now_unix();
        for (sql_id, _) in &other_sqls {
            tx.execute(
                "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
                 SELECT agent_id, ?1, kind, created_at FROM agent_exception
                 WHERE item_id = ?2 AND kind IN ('never', 'always_ask')",
                (keep_sql, *sql_id),
            )
            .map_err(storage)?;
            tx.execute(
                "INSERT OR IGNORE INTO item_archive (item_id, archived_at) VALUES (?1, ?2)",
                (*sql_id, now),
            )
            .map_err(storage)?;
            history::record(&tx, *sql_id, ItemEventKind::Archived, MERGED_INTO_DETAIL)?;
        }
        let mut detail = format!("{MERGED_PREFIX}{}", other_sqls.len());
        if !changes.is_empty() {
            detail.push(',');
            detail.push_str(&EditChange::detail(&changes));
        }
        history::record(&tx, keep_sql, ItemEventKind::Edited, &detail)?;
        tx.commit().map_err(storage)?;
        Ok(MergeOutcome {
            id: keep.0,
            revision: u64::try_from(next).map_err(storage)?,
            archived: other_ids,
        })
    }

    /// The duplicate groups with what a merge needs, each in ID order.
    fn duplicate_sets(&self) -> VaultResult<Vec<Vec<Member>>> {
        let conn = self.conn_ref()?;
        let items = load_items(conn)?;
        let mut credentials: BTreeMap<u64, Option<(String, Vec<u8>)>> = BTreeMap::new();
        for item in items
            .iter()
            .filter(|item| item.passkey_rows && item.kind == CredentialKind::Login)
        {
            let credential = match self.passkey_info(item.id) {
                Ok(info) => Some((info.rp_id, info.credential_id)),
                Err(PasskeyError::Vault(error)) if error.kind() == VaultErrorKind::NotFound => None,
                Err(error) => return Err(passkey_error(error)),
            };
            credentials.insert(item.id, credential);
        }

        // Match the items: logins by host and username, every kind by its secrets.
        let mut parent: Vec<usize> = (0..items.len()).collect();
        let mut by_login: BTreeMap<(String, String, String), usize> = BTreeMap::new();
        let mut by_secret: BTreeMap<(String, &'static str, [u8; 32]), usize> = BTreeMap::new();
        for (index, item) in items.iter().enumerate() {
            if item.kind == CredentialKind::Login {
                let mut hosts: BTreeSet<String> = item
                    .fields
                    .iter()
                    .filter(|field| is_website(field))
                    .filter_map(|field| normalize_host(field.value.expose()))
                    .collect();
                if let Some(Some((rp_id, _))) = credentials.get(&item.id)
                    && let Some(host) = normalize_host(rp_id)
                {
                    hosts.insert(host);
                }
                let username = item
                    .fields
                    .iter()
                    .find(|field| field.name == "username")
                    .map(|field| field.value.expose().trim().to_lowercase())
                    .unwrap_or_default();
                for host in hosts {
                    let key = (item.place.clone(), host, username.clone());
                    match by_login.get(&key) {
                        Some(&first) => union(&mut parent, first, index),
                        None => {
                            by_login.insert(key, index);
                        }
                    }
                }
            }
            if let Some(digest) = secret_digest(item.kind, &item.fields) {
                let key = (item.place.clone(), kind_as_str(item.kind), digest);
                match by_secret.get(&key) {
                    Some(&first) => union(&mut parent, first, index),
                    None => {
                        by_secret.insert(key, index);
                    }
                }
            }
        }
        let mut components: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for index in 0..items.len() {
            let root = find(&mut parent, index);
            components.entry(root).or_default().push(index);
        }
        components.retain(|_, members| members.len() > 1);
        if components.is_empty() {
            return Ok(Vec::new());
        }

        let canonical: BTreeSet<u64> = if credentials.values().any(Option::is_some) {
            self.all_passkeys()
                .map_err(passkey_error)?
                .into_iter()
                .map(|info| info.item_id)
                .collect()
        } else {
            BTreeSet::new()
        };
        let times = self.item_times()?;
        let mut slots: Vec<Option<Item>> = items.into_iter().map(Some).collect();
        let mut sets = Vec::new();
        // The roots are the lowest index of each component, so the groups come in the
        // order of their first ID.
        for indexes in components.into_values() {
            let mut members = Vec::new();
            for index in indexes {
                let Some(item) = slots[index].take() else {
                    continue;
                };
                let passkey_fields = if item.passkey_rows {
                    passkey::stored_fields(conn, item.sql_id)?
                } else {
                    Vec::new()
                };
                let valid_passkey = item.passkey_rows && passkey::is_valid_passkey(&passkey_fields);
                members.push(Member {
                    credential: credentials.get(&item.id).cloned().flatten(),
                    canonical: canonical.contains(&item.id),
                    passkey_fields,
                    valid_passkey,
                    agent: agent_use(conn, item.sql_id)?,
                    changed_at: times.get(&item.id).and_then(|times| times.changed),
                    item,
                });
            }
            sets.push(members);
        }
        Ok(sets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_lose_the_scheme_port_path_and_www() {
        for value in [
            "https://www.Example.com:443/login?next=/",
            "example.com",
            "http://example.com:8080",
            "  EXAMPLE.com./path ",
            "https://user@www.example.com",
        ] {
            assert_eq!(
                normalize_host(value).as_deref(),
                Some("example.com"),
                "{value}"
            );
        }
        assert_eq!(
            normalize_host("example.com/redirect?to=https://other.test").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_host("").as_deref(), None);
        assert_eq!(normalize_host("https://").as_deref(), None);
        assert_eq!(normalize_host("[::1]:8443").as_deref(), Some("[::1]"));
    }

    #[test]
    fn previous_labels_fit_and_stay_unique() {
        let detail = |label: &str| Field {
            name: detail_field_name(label),
            value: SecretValue::new(String::new()),
            secret: true,
        };
        let fields = vec![detail("Previous password")];
        assert_eq!(
            unique_label(&fields, "Previous password").unwrap(),
            "Previous password 2"
        );
        let long = format!("Previous {}", "x".repeat(40));
        let label = unique_label(&[], &long).unwrap();
        assert_eq!(label.len(), MAX_DETAIL_LABEL_BYTES);
        let taken = vec![detail(label.as_str())];
        let next = unique_label(&taken, &long).unwrap();
        assert!(
            next.len() <= MAX_DETAIL_LABEL_BYTES && next.ends_with(" 2"),
            "{next}"
        );
        assert!(detail_field_name(&next).len() <= 64);
        assert!(in_family("previous password 3", "Previous password"));
        assert!(!in_family("Previous passwords", "Previous password"));
    }

    #[test]
    fn merge_details_count_and_name_only() {
        assert_eq!(merged_count("merged:2,secret:password"), Some(2));
        assert_eq!(merged_count("title,field:username"), None);
        assert!(EditChange::parse_detail("merged:2,title") == vec![EditChange::Title]);
    }

    #[test]
    fn the_digest_needs_a_secret_value_and_the_same_kind() {
        let field = |name: &str, value: &str, secret: bool| Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        };
        let a = [
            field("token", "SYNTH-digest", true),
            field("host", "a", false),
        ];
        let b = [
            field("host", "b", false),
            field("token", "SYNTH-digest", true),
        ];
        assert_eq!(
            secret_digest(CredentialKind::ApiKey, &a),
            secret_digest(CredentialKind::ApiKey, &b)
        );
        assert_ne!(
            secret_digest(CredentialKind::ApiKey, &a),
            secret_digest(CredentialKind::Custom, &a)
        );
        assert_eq!(
            secret_digest(CredentialKind::Custom, &[field("secret", "", true)]),
            None
        );
    }
}
