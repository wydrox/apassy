//! Public vault value types. Secret-bearing Debug output is redacted.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::contracts::CredentialKind;

pub const MIN_PASSPHRASE_BYTES: usize = 12;
pub const MAX_PASSPHRASE_BYTES: usize = 1024;
pub const MAX_TITLE_BYTES: usize = 128;
pub const MAX_NOTES_BYTES: usize = 8192;
pub const MAX_TAG_COUNT: usize = 32;
pub const MAX_TAG_BYTES: usize = 64;
pub const MAX_FIELD_COUNT: usize = 64;
pub const MAX_FIELD_NAME_BYTES: usize = 64;
pub const MAX_FIELD_VALUE_BYTES: usize = 65_536;
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_SEARCH_RESULTS: usize = 1000;
pub const SCHEMA_VERSION: i64 = 3;

/// Owned secret text. Debug is redacted. There is no public `Serialize` impl.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([redacted])")
    }
}

/// Named field on an item draft. Debug redacts the value.
#[derive(Clone)]
pub struct Field {
    pub name: String,
    pub value: SecretValue,
    pub secret: bool,
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.name)
            .field("value", &self.value)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Owner-supplied item body. Debug redacts notes and field values.
#[derive(Clone)]
pub struct ItemDraft {
    pub title: String,
    pub kind: CredentialKind,
    pub notes: String,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
}

impl fmt::Debug for ItemDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemDraft")
            .field("title", &self.title)
            .field("kind", &self.kind)
            .field("notes", &"[redacted]")
            .field("tags", &self.tags)
            .field("fields", &self.fields)
            .finish()
    }
}

/// Metadata returned by search and mutation. No field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: u64,
    pub title: String,
    pub kind: CredentialKind,
    pub revision: u64,
}

/// Field metadata without values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSummary {
    pub name: String,
    pub secret: bool,
}

/// Item metadata without field values. Debug redacts owner notes.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemDetails {
    pub summary: ItemSummary,
    pub notes: String,
    pub tags: Vec<String>,
    pub fields: Vec<FieldSummary>,
}

impl fmt::Debug for ItemDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemDetails")
            .field("summary", &self.summary)
            .field("notes", &"[redacted]")
            .field("tags", &self.tags)
            .field("fields", &self.fields)
            .finish()
    }
}

/// Stable vault failure class. Display text does not include SQL, inputs, or driver text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultErrorKind {
    Locked,
    AlreadyExists,
    NotFound,
    Conflict,
    InvalidInput,
    WrongKeyOrCorrupt,
    UnsupportedSchema,
    Busy,
    Io,
    Storage,
}

impl VaultErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "the vault is locked",
            Self::AlreadyExists => "the target already exists",
            Self::NotFound => "the item or vault was not found",
            Self::Conflict => "the item revision is not current",
            Self::InvalidInput => "the input is invalid",
            Self::WrongKeyOrCorrupt => "the key is wrong or the vault is corrupt",
            Self::UnsupportedSchema => "the vault schema is not supported",
            Self::Busy => "the vault is busy",
            Self::Io => "the vault I/O operation failed",
            Self::Storage => "the vault storage operation failed",
        }
    }
}

/// Vault failure. The message does not quote SQL, values, passphrases, or driver errors.
#[derive(Debug)]
pub struct VaultError {
    kind: VaultErrorKind,
}

impl VaultError {
    pub fn kind(&self) -> VaultErrorKind {
        self.kind
    }

    pub(crate) fn new(kind: VaultErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.as_str())
    }
}

impl std::error::Error for VaultError {}

pub type VaultResult<T> = Result<T, VaultError>;

pub(crate) fn err(kind: VaultErrorKind) -> VaultError {
    VaultError::new(kind)
}

#[derive(Serialize)]
struct StoredPayload<'a> {
    title: &'a str,
    kind: &'a str,
    notes: &'a str,
    tags: &'a [String],
    fields: Vec<StoredFieldWire<'a>>,
}

#[derive(Serialize)]
struct StoredFieldWire<'a> {
    name: &'a str,
    value: &'a str,
    secret: bool,
}

pub(crate) fn kind_as_str(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::ApiKey => "api_key",
        CredentialKind::Login => "login",
        CredentialKind::SshKey => "ssh_key",
        CredentialKind::Database => "database",
        CredentialKind::Custom => "custom",
    }
}

pub(crate) fn kind_from_str(kind: &str) -> VaultResult<CredentialKind> {
    match kind {
        "api_key" => Ok(CredentialKind::ApiKey),
        "login" => Ok(CredentialKind::Login),
        "ssh_key" => Ok(CredentialKind::SshKey),
        "database" => Ok(CredentialKind::Database),
        "custom" => Ok(CredentialKind::Custom),
        _ => Err(err(VaultErrorKind::UnsupportedSchema)),
    }
}

pub(crate) fn validate_create_passphrase(passphrase: &str) -> VaultResult<()> {
    validate_unlock_passphrase(passphrase)?;
    if passphrase.len() < MIN_PASSPHRASE_BYTES {
        Err(err(VaultErrorKind::InvalidInput))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_unlock_passphrase(passphrase: &str) -> VaultResult<()> {
    // SQLCipher interprets its x'...' syntax as a raw key, bypassing the KDF.
    // Reserve that prefix rather than changing or encoding the passphrase.
    // The PRAGMA string API cannot represent a NUL byte.
    if passphrase.is_empty()
        || passphrase.len() > MAX_PASSPHRASE_BYTES
        || passphrase.contains('\0')
        || passphrase.starts_with("x'")
        || passphrase.starts_with("X'")
    {
        Err(err(VaultErrorKind::InvalidInput))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_draft(draft: ItemDraft) -> VaultResult<ItemDraft> {
    let title = draft.title.trim();
    if title.is_empty() || title.len() > MAX_TITLE_BYTES {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    if draft.notes.len() > MAX_NOTES_BYTES {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    if draft.tags.len() > MAX_TAG_COUNT {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    for tag in &draft.tags {
        if tag.is_empty() || tag.len() > MAX_TAG_BYTES {
            return Err(err(VaultErrorKind::InvalidInput));
        }
    }
    if draft.fields.len() > MAX_FIELD_COUNT {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    let mut names = BTreeSet::new();
    for field in &draft.fields {
        if !field_name_ok(&field.name) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if field.value.expose().len() > MAX_FIELD_VALUE_BYTES {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if !names.insert(field.name.as_str()) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
    }
    validate_kind_fields(draft.kind, &draft.fields)?;
    let title = title.to_owned();
    reject_oversized_payload(&title, draft.kind, &draft.notes, &draft.tags, &draft.fields)?;
    Ok(ItemDraft {
        title,
        kind: draft.kind,
        notes: draft.notes,
        tags: draft.tags,
        fields: draft.fields,
    })
}

fn field_name_ok(name: &str) -> bool {
    let len = name.len();
    (1..=MAX_FIELD_NAME_BYTES).contains(&len)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn validate_kind_fields(kind: CredentialKind, fields: &[Field]) -> VaultResult<()> {
    match kind {
        CredentialKind::ApiKey => require_secret_value(fields, "token"),
        CredentialKind::Login => {
            require_nonempty(fields, "username")?;
            require_secret_value(fields, "password")
        }
        CredentialKind::SshKey => {
            require_secret_value(fields, "private_key")?;
            if let Some(field) = find_field(fields, "passphrase")
                && !field.secret
            {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            Ok(())
        }
        CredentialKind::Database => {
            require_nonempty(fields, "host")?;
            require_nonempty(fields, "database")?;
            require_nonempty(fields, "username")?;
            require_secret_value(fields, "password")
        }
        CredentialKind::Custom => {
            if fields.is_empty() {
                Err(err(VaultErrorKind::InvalidInput))
            } else {
                Ok(())
            }
        }
    }
}

fn find_field<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|field| field.name == name)
}

fn require_nonempty(fields: &[Field], name: &str) -> VaultResult<()> {
    match find_field(fields, name) {
        Some(field) if !field.value.expose().is_empty() => Ok(()),
        _ => Err(err(VaultErrorKind::InvalidInput)),
    }
}

fn require_secret_value(fields: &[Field], name: &str) -> VaultResult<()> {
    match find_field(fields, name) {
        Some(field) if field.secret && !field.value.expose().is_empty() => Ok(()),
        _ => Err(err(VaultErrorKind::InvalidInput)),
    }
}

/// Counts serialized bytes without allocating another plaintext payload.
#[derive(Default)]
struct PayloadSize(usize);

impl std::io::Write for PayloadSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_PAYLOAD_BYTES)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn reject_oversized_payload(
    title: &str,
    kind: CredentialKind,
    notes: &str,
    tags: &[String],
    fields: &[Field],
) -> VaultResult<()> {
    let payload = StoredPayload {
        title,
        kind: kind_as_str(kind),
        notes,
        tags,
        fields: fields
            .iter()
            .map(|field| StoredFieldWire {
                name: &field.name,
                value: field.value.expose(),
                secret: field.secret,
            })
            .collect(),
    };
    serde_json::to_writer(&mut PayloadSize::default(), &payload)
        .map_err(|_| err(VaultErrorKind::InvalidInput))
}

#[cfg(test)]
mod tests {
    use super::{MAX_PAYLOAD_BYTES, PayloadSize};
    use std::io::Write;

    #[test]
    fn payload_counter_matches_json_escaping_and_refuses_overflow() {
        let synthetic = ["synthetic-\0-\n-\"-\\-é", "plain"];
        let mut count = PayloadSize::default();
        serde_json::to_writer(&mut count, &synthetic).unwrap();
        assert_eq!(count.0, serde_json::to_vec(&synthetic).unwrap().len());
        let mut full = PayloadSize(MAX_PAYLOAD_BYTES - 1);
        assert_eq!(full.write(b"a").unwrap(), 1);
        assert_eq!(full.0, MAX_PAYLOAD_BYTES);
        assert!(full.write(b"b").is_err());
        assert_eq!(full.0, MAX_PAYLOAD_BYTES);
    }
}
