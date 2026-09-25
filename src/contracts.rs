//! Version 1 JSON contracts and validation for Apassy.
//!
//! JSON parse can produce a **representation**. A representation is not a trusted
//! record until [`parse_json`] or [`Validate::validate`] succeeds.
//!
//! Validation checks schema rules only. It does not authorize a request, encrypt
//! data, authenticate an agent, or compute a cryptographic digest.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema version for every top-level contract record.
pub const CONTRACT_VERSION: u32 = 1;

pub const MAX_ID_LEN: usize = 64;
pub const MAX_LABEL_LEN: usize = 128;
pub const MAX_NOTE_LEN: usize = 512;
pub const MAX_RULE_TEXT_LEN: usize = 4096;
pub const MAX_CLAUSE_TEXT_LEN: usize = 512;
pub const MAX_DIAGNOSTIC_LEN: usize = 256;
pub const MAX_PARAMETER_TEXT_LEN: usize = 128;
pub const MAX_TAG_COUNT: usize = 16;
pub const MAX_CLAUSE_COUNT: usize = 32;
pub const MAX_PARAMETER_COUNT: usize = 16;
pub const MAX_CUSTOM_FIELD_COUNT: usize = 16;
pub const MAX_USAGE_LIMIT: u32 = 1_000_000;
pub const MIN_DIGEST_OCTETS: usize = 16;
pub const MAX_DIGEST_OCTETS: usize = 64;

/// Credential categories stored in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ApiKey,
    Login,
    SshKey,
    Database,
    Custom,
}

impl CredentialKind {
    pub const ALL: [Self; 5] = [
        Self::ApiKey,
        Self::Login,
        Self::SshKey,
        Self::Database,
        Self::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::Login => "Login",
            Self::SshKey => "SSH key",
            Self::Database => "Database",
            Self::Custom => "Custom",
        }
    }

    /// Contract-level mediated-use flag. This is not a live connector.
    pub fn supports_mediated_use(self) -> bool {
        matches!(self, Self::ApiKey | Self::Database)
    }
}

/// Bouncer decision names used by the owner interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    RequireApproval,
    Deny,
}

impl Decision {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::RequireApproval => "Require approval",
            Self::Deny => "Deny",
        }
    }
}

/// Stable reason for a contract rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownField,
    InvalidId,
    InvalidText,
    InvalidJson,
    ZeroVersion,
    ZeroLimit,
    InvalidTimeOrdering,
    UnresolvedClause,
    UncoveredClause,
    MissingConfirmation,
    ChangedDraftBinding,
    UnsupportedOperation,
    UnsupportedDestination,
    InvalidRequestBounds,
    ContractVersionMismatch,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownField => "unknown_field",
            Self::InvalidId => "invalid_id",
            Self::InvalidText => "invalid_text",
            Self::InvalidJson => "invalid_json",
            Self::ZeroVersion => "zero_version",
            Self::ZeroLimit => "zero_limit",
            Self::InvalidTimeOrdering => "invalid_time_ordering",
            Self::UnresolvedClause => "unresolved_clause",
            Self::UncoveredClause => "uncovered_clause",
            Self::MissingConfirmation => "missing_confirmation",
            Self::ChangedDraftBinding => "changed_draft_binding",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::UnsupportedDestination => "unsupported_destination",
            Self::InvalidRequestBounds => "invalid_request_bounds",
            Self::ContractVersionMismatch => "contract_version_mismatch",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Schema validation failure. This is not an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    code: ErrorCode,
    detail: String,
}

impl ContractError {
    fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(self.code.as_str())
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.detail)
        }
    }
}

impl std::error::Error for ContractError {}

/// Cross-field rules that `Deserialize` does not prove on its own.
pub trait Validate {
    fn validate(&self) -> Result<(), ContractError>;
}

/// Parse JSON and apply [`Validate`]. This is the trusted constructor path.
pub fn parse_json<T>(s: &str) -> Result<T, ContractError>
where
    T: for<'de> Deserialize<'de> + Validate,
{
    let value: T = serde_json::from_str(s).map_err(map_de)?;
    value.validate()?;
    Ok(value)
}

/// Compact JSON. For a request, prefer [`AgentRequest::canonical_json_bytes`].
pub fn to_json<T: Serialize>(value: &T) -> Result<String, ContractError> {
    serde_json::to_string(value)
        .map_err(|err| ContractError::new(ErrorCode::InvalidJson, err.to_string()))
}

fn map_de(err: serde_json::Error) -> ContractError {
    let detail = err.to_string();
    let lower = detail.to_ascii_lowercase();
    let code = if lower.contains("unknown field") {
        ErrorCode::UnknownField
    } else if lower.contains("invalid_id") {
        ErrorCode::InvalidId
    } else if lower.contains("invalid_text") {
        ErrorCode::InvalidText
    } else if lower.contains("zero_version") {
        ErrorCode::ZeroVersion
    } else if lower.contains("zero_limit") {
        ErrorCode::ZeroLimit
    } else if lower.contains("invalid_time_ordering") {
        ErrorCode::InvalidTimeOrdering
    } else if lower.contains("invalid_request_bounds") {
        ErrorCode::InvalidRequestBounds
    } else if lower.contains("unsupported_operation") {
        ErrorCode::UnsupportedOperation
    } else if lower.contains("unsupported_destination") {
        ErrorCode::UnsupportedDestination
    } else {
        ErrorCode::InvalidJson
    };
    ContractError::new(code, detail)
}

fn require_contract_version(contract_version: u32) -> Result<(), ContractError> {
    if contract_version == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ContractError::new(
            ErrorCode::ContractVersionMismatch,
            format!("expected {CONTRACT_VERSION}, received {contract_version}"),
        ))
    }
}

fn require_time_order(
    left: UnixTime,
    right: UnixTime,
    equal_ok: bool,
) -> Result<(), ContractError> {
    if left.seconds() < right.seconds() || (equal_ok && left.seconds() == right.seconds()) {
        Ok(())
    } else {
        Err(ContractError::new(
            ErrorCode::InvalidTimeOrdering,
            format!("{} must precede {}", left.seconds(), right.seconds()),
        ))
    }
}

fn parse_entity_id(raw: &str) -> Result<String, ContractError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ID_LEN {
        return Err(ContractError::new(
            ErrorCode::InvalidId,
            format!("id length {} is outside 1..={MAX_ID_LEN}", bytes.len()),
        ));
    }
    let first = bytes[0];
    if !first.is_ascii_lowercase() {
        return Err(ContractError::new(
            ErrorCode::InvalidId,
            "id must start with a lowercase ASCII letter",
        ));
    }
    if !bytes
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
    {
        return Err(ContractError::new(
            ErrorCode::InvalidId,
            "id may contain lowercase letters, digits, '_' and '-'",
        ));
    }
    if bytes[bytes.len() - 1] == b'-' {
        return Err(ContractError::new(
            ErrorCode::InvalidId,
            "id must not end with '-'",
        ));
    }
    if bytes.windows(2).any(|pair| pair == b"--") {
        return Err(ContractError::new(
            ErrorCode::InvalidId,
            "id must not contain '--'",
        ));
    }
    Ok(raw.to_owned())
}

fn parse_free_text(raw: &str, max: usize) -> Result<String, ContractError> {
    if raw.is_empty() {
        return Err(ContractError::new(
            ErrorCode::InvalidText,
            "text must not be empty",
        ));
    }
    if raw.len() > max {
        return Err(ContractError::new(
            ErrorCode::InvalidText,
            format!("text length {} exceeds {max}", raw.len()),
        ));
    }
    if raw.starts_with(char::is_whitespace) || raw.ends_with(char::is_whitespace) {
        return Err(ContractError::new(
            ErrorCode::InvalidText,
            "text must not have leading or trailing whitespace",
        ));
    }
    if raw.chars().any(char::is_control) {
        return Err(ContractError::new(
            ErrorCode::InvalidText,
            "text must not contain control characters",
        ));
    }
    Ok(raw.to_owned())
}

fn parse_time_zone(raw: &str) -> Result<String, ContractError> {
    if raw == "UTC" {
        return Ok(raw.to_owned());
    }
    if raw.is_empty() || raw.len() > MAX_ID_LEN {
        return Err(ContractError::new(
            ErrorCode::InvalidText,
            "time zone length is outside the permitted bound",
        ));
    }
    let parts: Vec<&str> = raw.split('/').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(ContractError::new(
            ErrorCode::InvalidText,
            "time zone must be UTC or Area/Location",
        ));
    }
    let valid_part = |part: &str| {
        let bytes = part.as_bytes();
        !bytes.is_empty()
            && bytes[0].is_ascii_alphabetic()
            && bytes
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-' || *c == b'+')
    };
    if parts.iter().all(|part| valid_part(part)) {
        Ok(raw.to_owned())
    } else {
        Err(ContractError::new(
            ErrorCode::InvalidText,
            "time zone contains an invalid character",
        ))
    }
}

fn looks_like_url(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("://") || lower.starts_with("www.") {
        return true;
    }
    matches!(
        lower.split_once(':').map(|(scheme, _)| scheme),
        Some("http" | "https" | "ftp" | "file" | "data" | "javascript")
    )
}

fn looks_like_sql(raw: &str) -> bool {
    let head = raw
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    SQL_HEADS.iter().any(|name| *name == head)
}

fn looks_like_secret(raw: &str) -> bool {
    let upper = raw.to_ascii_uppercase();
    upper.contains("-----BEGIN") || upper.contains("PRIVATE KEY")
}

const SQL_HEADS: &[&str] = &[
    "alter", "attach", "call", "create", "delete", "drop", "exec", "execute", "explain", "grant",
    "insert", "merge", "pragma", "revoke", "select", "truncate", "update", "with",
];

const UNSUPPORTED_OPERATION_NAMES: &[&str] = &[
    "alter", "attach", "call", "create", "delete", "drop", "exec", "execute", "explain", "grant",
    "http", "https", "insert", "merge", "pragma", "proxy", "query", "raw_sql", "revoke", "select",
    "sql", "truncate", "update", "url", "with",
];

const RESERVED_PARAMETER_NAMES: &[&str] = &[
    "api_key",
    "authorization",
    "command",
    "conversation",
    "cookie",
    "credential",
    "endpoint",
    "header",
    "headers",
    "host",
    "href",
    "messages",
    "password",
    "private_key",
    "prompt",
    "query",
    "raw",
    "script",
    "secret",
    "sql",
    "statement",
    "token",
    "transcript",
    "uri",
    "url",
];

macro_rules! string_newtype {
    ($name:ident, $parser:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(raw: &str) -> Result<Self, ContractError> {
                $parser(raw).map(Self)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                $name::parse(&raw).map_err(DeError::custom)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_newtype!(
    EntityId,
    parse_entity_id,
    "Stable ASCII identifier. This is not a capability or secret."
);
string_newtype!(
    ItemLabel,
    parse_item_label,
    "Owner-facing label. This is metadata, not a provider secret."
);
string_newtype!(
    TimeZoneId,
    parse_time_zone,
    "UTC or Area/Location. This is a name, not a time-zone database."
);
string_newtype!(
    RuleText,
    parse_rule_text,
    "Original owner rule text. Bounded. Not a policy engine."
);
string_newtype!(
    ClauseText,
    parse_clause_text,
    "One clause from the original rule text."
);
string_newtype!(
    NoteText,
    parse_note_text,
    "Optional note metadata. Not a provider secret value."
);
string_newtype!(
    DiagnosticText,
    parse_diagnostic_text,
    "Bounded diagnostic text. Must not hold secrets or conversations."
);
string_newtype!(
    ParameterText,
    parse_parameter_text,
    "Bounded parameter text. Must not be a URL, SQL, credential, or conversation."
);

fn parse_item_label(raw: &str) -> Result<String, ContractError> {
    parse_free_text(raw, MAX_LABEL_LEN)
}
fn parse_rule_text(raw: &str) -> Result<String, ContractError> {
    parse_free_text(raw, MAX_RULE_TEXT_LEN)
}
fn parse_clause_text(raw: &str) -> Result<String, ContractError> {
    parse_free_text(raw, MAX_CLAUSE_TEXT_LEN)
}
fn parse_note_text(raw: &str) -> Result<String, ContractError> {
    parse_free_text(raw, MAX_NOTE_LEN)
}
fn parse_diagnostic_text(raw: &str) -> Result<String, ContractError> {
    parse_free_text(raw, MAX_DIAGNOSTIC_LEN)
}
fn parse_parameter_text(raw: &str) -> Result<String, ContractError> {
    parse_free_text(raw, MAX_PARAMETER_TEXT_LEN)
}

/// Non-zero schema or item version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Version(u32);

impl Version {
    pub fn new(value: u32) -> Result<Self, ContractError> {
        if value == 0 {
            Err(ContractError::new(
                ErrorCode::ZeroVersion,
                "version must be greater than zero",
            ))
        } else {
            Ok(Self(value))
        }
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        Version::new(value).map_err(DeError::custom)
    }
}

/// Restart generation. Backups must not restore a previous epoch as live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Epoch(u64);

impl Epoch {
    pub fn new(value: u64) -> Result<Self, ContractError> {
        if value == 0 {
            Err(ContractError::new(
                ErrorCode::ZeroVersion,
                "epoch must be greater than zero",
            ))
        } else {
            Ok(Self(value))
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Epoch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Epoch::new(value).map_err(DeError::custom)
    }
}

/// UTC unix seconds. Zero is rejected as unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct UnixTime(u64);

impl UnixTime {
    pub fn new(epoch_seconds: u64) -> Result<Self, ContractError> {
        if epoch_seconds == 0 {
            Err(ContractError::new(
                ErrorCode::InvalidTimeOrdering,
                "timestamp must be greater than zero",
            ))
        } else {
            Ok(Self(epoch_seconds))
        }
    }

    pub fn seconds(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for UnixTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        UnixTime::new(value).map_err(DeError::custom)
    }
}

/// Non-zero usage cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct UsageLimit(u32);

impl UsageLimit {
    pub fn new(value: u32) -> Result<Self, ContractError> {
        if value == 0 {
            Err(ContractError::new(
                ErrorCode::ZeroLimit,
                "usage limit must be greater than zero",
            ))
        } else if value > MAX_USAGE_LIMIT {
            Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                format!("usage limit {value} exceeds {MAX_USAGE_LIMIT}"),
            ))
        } else {
            Ok(Self(value))
        }
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for UsageLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        UsageLimit::new(value).map_err(DeError::custom)
    }
}

/// Named operation. Not a URL, SQL string, or shell command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OperationName(EntityId);

impl OperationName {
    pub fn parse(raw: &str) -> Result<Self, ContractError> {
        if looks_like_url(raw) || raw.contains('/') {
            return Err(ContractError::new(
                ErrorCode::UnsupportedOperation,
                "operation must not be a URL or path",
            ));
        }
        if UNSUPPORTED_OPERATION_NAMES.contains(&raw) {
            return Err(ContractError::new(
                ErrorCode::UnsupportedOperation,
                format!("{raw} is not a permitted named operation"),
            ));
        }
        Ok(Self(EntityId::parse(raw)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for OperationName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        OperationName::parse(&raw).map_err(DeError::custom)
    }
}

/// Parameter key. Reserved credential, SQL, URL, and conversation names are rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ParameterName(EntityId);

impl ParameterName {
    pub fn parse(raw: &str) -> Result<Self, ContractError> {
        if RESERVED_PARAMETER_NAMES.contains(&raw) {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                format!("{raw} is not a permitted parameter name"),
            ));
        }
        Ok(Self(EntityId::parse(raw)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for ParameterName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        ParameterName::parse(&raw).map_err(DeError::custom)
    }
}

/// Reason code identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ReasonCode(EntityId);

impl ReasonCode {
    pub fn parse(raw: &str) -> Result<Self, ContractError> {
        Ok(Self(EntityId::parse(raw)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for ReasonCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        ReasonCode::parse(&raw).map_err(DeError::custom)
    }
}

/// Kind-specific metadata. Values are references and names, not secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialDetails {
    ApiKey {
        service_id: EntityId,
    },
    Login {
        service_id: EntityId,
        username: ItemLabel,
    },
    SshKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<ItemLabel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_fingerprint_ref: Option<EntityId>,
    },
    Database {
        server_id: EntityId,
        database_name: EntityId,
    },
    Custom {
        fields: Vec<CustomField>,
    },
}

impl CredentialDetails {
    pub fn kind(&self) -> CredentialKind {
        match self {
            Self::ApiKey { .. } => CredentialKind::ApiKey,
            Self::Login { .. } => CredentialKind::Login,
            Self::SshKey { .. } => CredentialKind::SshKey,
            Self::Database { .. } => CredentialKind::Database,
            Self::Custom { .. } => CredentialKind::Custom,
        }
    }
}

/// Custom field name and secret flag. The field value is not in this contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CustomField {
    pub name: EntityId,
    pub secret: bool,
}

/// Credential metadata record. This is not a vault item and holds no provider secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CredentialMetadata {
    contract_version: u32,
    id: EntityId,
    kind: CredentialKind,
    revision: Version,
    label: ItemLabel,
    #[serde(default)]
    tags: Vec<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<NoteText>,
    details: CredentialDetails,
    created_at: UnixTime,
    updated_at: UnixTime,
}

impl CredentialMetadata {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn id(&self) -> &EntityId {
        &self.id
    }
    pub fn kind(&self) -> CredentialKind {
        self.kind
    }
    pub fn revision(&self) -> Version {
        self.revision
    }
    pub fn label(&self) -> &ItemLabel {
        &self.label
    }
    pub fn tags(&self) -> &[EntityId] {
        &self.tags
    }
    pub fn notes(&self) -> Option<&NoteText> {
        self.notes.as_ref()
    }
    pub fn details(&self) -> &CredentialDetails {
        &self.details
    }
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }
    pub fn updated_at(&self) -> UnixTime {
        self.updated_at
    }
}

impl Validate for CredentialMetadata {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)?;
        if self.kind != self.details.kind() {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "kind and details.type must match",
            ));
        }
        if self.tags.len() > MAX_TAG_COUNT {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                format!("tag count {} exceeds {MAX_TAG_COUNT}", self.tags.len()),
            ));
        }
        let mut seen = BTreeSet::new();
        for tag in &self.tags {
            if !seen.insert(tag.as_str()) {
                return Err(ContractError::new(
                    ErrorCode::InvalidRequestBounds,
                    format!("duplicate tag {}", tag.as_str()),
                ));
            }
        }
        if let Some(notes) = &self.notes
            && looks_like_secret(notes.as_str())
        {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "notes match a PEM-shaped pattern",
            ));
        }
        if let CredentialDetails::Custom { fields } = &self.details {
            if fields.is_empty() {
                return Err(ContractError::new(
                    ErrorCode::InvalidRequestBounds,
                    "custom credential must declare at least one field",
                ));
            }
            if fields.len() > MAX_CUSTOM_FIELD_COUNT {
                return Err(ContractError::new(
                    ErrorCode::InvalidRequestBounds,
                    format!(
                        "custom field count {} exceeds {MAX_CUSTOM_FIELD_COUNT}",
                        fields.len()
                    ),
                ));
            }
            let mut names = BTreeSet::new();
            for field in fields {
                if !names.insert(field.name.as_str()) {
                    return Err(ContractError::new(
                        ErrorCode::InvalidRequestBounds,
                        format!("duplicate custom field {}", field.name.as_str()),
                    ));
                }
            }
        }
        require_time_order(self.created_at, self.updated_at, true)
    }
}

/// How a rule clause is classified in a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClauseDisposition {
    EnforceableRestriction,
    ContextualCheck,
    UnresolvedIssue,
}

/// One clause from the original text with an explicit disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Clause {
    pub index: u32,
    pub text: ClauseText,
    pub disposition: ClauseDisposition,
}

impl Validate for Clause {
    fn validate(&self) -> Result<(), ContractError> {
        if self.index == 0 {
            Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "clause index must be greater than zero",
            ))
        } else {
            Ok(())
        }
    }
}

/// Deterministic restriction derived from a clause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "restriction", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnforceableRestriction {
    Agent {
        clause_index: u32,
        agent_id: EntityId,
    },
    Credential {
        clause_index: u32,
        credential_id: EntityId,
        revision: Version,
    },
    Destination {
        clause_index: u32,
        destination_id: EntityId,
    },
    Operation {
        clause_index: u32,
        operation: OperationName,
    },
    TimeWindow {
        clause_index: u32,
        not_before: UnixTime,
        not_after: UnixTime,
        time_zone: TimeZoneId,
    },
    UsageLimit {
        clause_index: u32,
        max_uses: UsageLimit,
    },
    ExplicitDenial {
        clause_index: u32,
        reason_code: ReasonCode,
    },
}

impl EnforceableRestriction {
    pub fn clause_index(&self) -> u32 {
        match self {
            Self::Agent { clause_index, .. }
            | Self::Credential { clause_index, .. }
            | Self::Destination { clause_index, .. }
            | Self::Operation { clause_index, .. }
            | Self::TimeWindow { clause_index, .. }
            | Self::UsageLimit { clause_index, .. }
            | Self::ExplicitDenial { clause_index, .. } => *clause_index,
        }
    }

    fn validate_fields(&self) -> Result<(), ContractError> {
        if self.clause_index() == 0 {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "clause_index must be greater than zero",
            ));
        }
        if let Self::TimeWindow {
            not_before,
            not_after,
            ..
        } = self
        {
            require_time_order(*not_before, *not_after, false)?;
        }
        Ok(())
    }
}

/// Planned contextual dimensions. These are Apassy names, not a verified Jev schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDimension {
    TaskAlignment,
    PromptInjection,
    DataDisclosure,
    PrivilegeEscalation,
    ResourceSensitivity,
    BehavioralAnomaly,
}

/// Visible contextual check. `on_failure` must not be [`Decision::Allow`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ContextualCheck {
    pub clause_index: u32,
    pub dimension: ContextDimension,
    pub on_failure: Decision,
}

impl Validate for ContextualCheck {
    fn validate(&self) -> Result<(), ContractError> {
        if self.clause_index == 0 {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "clause_index must be greater than zero",
            ));
        }
        if self.on_failure == Decision::Allow {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "contextual check must not fail open",
            ));
        }
        Ok(())
    }
}

/// Clause that the interpreter could not turn into a restriction or check.
///
/// `detail` uses the clause-text bound so it can quote the clause it covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct UnresolvedIssue {
    pub clause_index: u32,
    pub code: ReasonCode,
    pub detail: ClauseText,
}

impl Validate for UnresolvedIssue {
    fn validate(&self) -> Result<(), ContractError> {
        if self.clause_index == 0 {
            Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "clause_index must be greater than zero",
            ))
        } else {
            Ok(())
        }
    }
}

/// Derived draft status. Activation is a separate check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    NeedsClarification,
    ReadyForReview,
}

/// Enrolled agent reference. The record does not authenticate the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct AgentRef {
    pub id: EntityId,
    pub enrollment_revision: Version,
}

/// Session reference bound to an epoch. The record does not prove a live session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SessionRef {
    pub id: EntityId,
    pub agent_id: EntityId,
    pub epoch: Epoch,
    pub not_before: UnixTime,
    pub expires_at: UnixTime,
}

impl Validate for SessionRef {
    fn validate(&self) -> Result<(), ContractError> {
        require_time_order(self.not_before, self.expires_at, false)
    }
}

/// Credential identity and revision. This is not the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CredentialRef {
    pub id: EntityId,
    pub revision: Version,
    pub kind: CredentialKind,
}

/// Confirmed policy identity and version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct PolicyRef {
    pub id: EntityId,
    pub version: Version,
}

/// Registered destination. Arbitrary URLs are not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    RegisteredApiService,
    RegisteredDatabase,
}

impl DestinationKind {
    pub fn matches_credential(self, kind: CredentialKind) -> bool {
        matches!(
            (self, kind),
            (Self::RegisteredApiService, CredentialKind::ApiKey)
                | (Self::RegisteredDatabase, CredentialKind::Database)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DestinationRef {
    pub id: EntityId,
    pub kind: DestinationKind,
}

/// Reviewable rule draft. Unresolved issues are valid in a draft and block activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RuleDraft {
    contract_version: u32,
    id: EntityId,
    draft_version: Version,
    original_text: RuleText,
    clauses: Vec<Clause>,
    restrictions: Vec<EnforceableRestriction>,
    context_checks: Vec<ContextualCheck>,
    unresolved_issues: Vec<UnresolvedIssue>,
    agent: AgentRef,
    credential: CredentialRef,
    created_at: UnixTime,
}

impl RuleDraft {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn id(&self) -> &EntityId {
        &self.id
    }
    pub fn draft_version(&self) -> Version {
        self.draft_version
    }
    pub fn original_text(&self) -> &RuleText {
        &self.original_text
    }
    pub fn clauses(&self) -> &[Clause] {
        &self.clauses
    }
    pub fn restrictions(&self) -> &[EnforceableRestriction] {
        &self.restrictions
    }
    pub fn context_checks(&self) -> &[ContextualCheck] {
        &self.context_checks
    }
    pub fn unresolved_issues(&self) -> &[UnresolvedIssue] {
        &self.unresolved_issues
    }
    pub fn agent(&self) -> &AgentRef {
        &self.agent
    }
    pub fn credential(&self) -> &CredentialRef {
        &self.credential
    }
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }

    pub fn status(&self) -> DraftStatus {
        if self.unresolved_issues.is_empty()
            && !self
                .clauses
                .iter()
                .any(|clause| clause.disposition == ClauseDisposition::UnresolvedIssue)
        {
            DraftStatus::ReadyForReview
        } else {
            DraftStatus::NeedsClarification
        }
    }
}

impl Validate for RuleDraft {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)?;
        cover_clauses(
            &self.clauses,
            &self.restrictions,
            &self.context_checks,
            &self.unresolved_issues,
        )?;
        for restriction in &self.restrictions {
            match restriction {
                EnforceableRestriction::Agent { agent_id, .. } if agent_id != &self.agent.id => {
                    return Err(ContractError::new(
                        ErrorCode::InvalidRequestBounds,
                        "agent restriction must match the draft agent",
                    ));
                }
                EnforceableRestriction::Credential {
                    credential_id,
                    revision,
                    ..
                } if credential_id != &self.credential.id
                    || *revision != self.credential.revision =>
                {
                    return Err(ContractError::new(
                        ErrorCode::InvalidRequestBounds,
                        "credential restriction must match the draft credential revision",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn cover_clauses(
    clauses: &[Clause],
    restrictions: &[EnforceableRestriction],
    checks: &[ContextualCheck],
    issues: &[UnresolvedIssue],
) -> Result<(), ContractError> {
    if clauses.is_empty() {
        return Err(ContractError::new(
            ErrorCode::UncoveredClause,
            "rule draft has no clauses",
        ));
    }
    if clauses.len() > MAX_CLAUSE_COUNT {
        return Err(ContractError::new(
            ErrorCode::InvalidRequestBounds,
            format!("clause count {} exceeds {MAX_CLAUSE_COUNT}", clauses.len()),
        ));
    }
    for (i, clause) in clauses.iter().enumerate() {
        clause.validate()?;
        let expected = u32::try_from(i + 1).map_err(|_| {
            ContractError::new(ErrorCode::InvalidRequestBounds, "clause count is too large")
        })?;
        if clause.index != expected {
            return Err(ContractError::new(
                ErrorCode::UncoveredClause,
                "clause indices must be consecutive and start at 1",
            ));
        }
    }
    let mut covered = vec![false; clauses.len()];
    for restriction in restrictions {
        restriction.validate_fields()?;
        mark_coverage(
            &mut covered,
            clauses,
            restriction.clause_index(),
            ClauseDisposition::EnforceableRestriction,
        )?;
    }
    for check in checks {
        check.validate()?;
        mark_coverage(
            &mut covered,
            clauses,
            check.clause_index,
            ClauseDisposition::ContextualCheck,
        )?;
    }
    for issue in issues {
        issue.validate()?;
        mark_coverage(
            &mut covered,
            clauses,
            issue.clause_index,
            ClauseDisposition::UnresolvedIssue,
        )?;
    }
    for (i, is_covered) in covered.iter().enumerate() {
        if !is_covered {
            return Err(ContractError::new(
                ErrorCode::UncoveredClause,
                format!("clause {} is not covered", i + 1),
            ));
        }
    }
    Ok(())
}

fn mark_coverage(
    covered: &mut [bool],
    clauses: &[Clause],
    index: u32,
    expected: ClauseDisposition,
) -> Result<(), ContractError> {
    if index == 0 {
        return Err(ContractError::new(
            ErrorCode::InvalidRequestBounds,
            "clause_index must be greater than zero",
        ));
    }
    let Some(idx) = usize::try_from(index).ok().and_then(|n| n.checked_sub(1)) else {
        return Err(ContractError::new(
            ErrorCode::UncoveredClause,
            format!("clause_index {index} is out of range"),
        ));
    };
    let Some(slot) = covered.get_mut(idx) else {
        return Err(ContractError::new(
            ErrorCode::UncoveredClause,
            format!("clause_index {index} is out of range"),
        ));
    };
    if *slot {
        return Err(ContractError::new(
            ErrorCode::UncoveredClause,
            format!("clause {index} is covered more than once"),
        ));
    }
    let Some(clause) = clauses.get(idx) else {
        return Err(ContractError::new(
            ErrorCode::UncoveredClause,
            format!("clause_index {index} is out of range"),
        ));
    };
    if clause.disposition != expected {
        return Err(ContractError::new(
            ErrorCode::UncoveredClause,
            format!("clause {index} disposition does not match its coverage item"),
        ));
    }
    *slot = true;
    Ok(())
}

/// Owner confirmation bound to one draft version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct OwnerConfirmation {
    contract_version: u32,
    draft_id: EntityId,
    draft_version: Version,
    owner_id: EntityId,
    confirmed_at: UnixTime,
}

impl OwnerConfirmation {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn draft_id(&self) -> &EntityId {
        &self.draft_id
    }
    pub fn draft_version(&self) -> Version {
        self.draft_version
    }
    pub fn owner_id(&self) -> &EntityId {
        &self.owner_id
    }
    pub fn confirmed_at(&self) -> UnixTime {
        self.confirmed_at
    }
}

impl Validate for OwnerConfirmation {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)
    }
}

/// Confirmation bound to a draft. This record does not enable runtime authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ActiveRuleRecord {
    contract_version: u32,
    draft_id: EntityId,
    policy_version: Version,
    confirmation: OwnerConfirmation,
}

impl ActiveRuleRecord {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn draft_id(&self) -> &EntityId {
        &self.draft_id
    }
    pub fn policy_version(&self) -> Version {
        self.policy_version
    }
    pub fn confirmation(&self) -> &OwnerConfirmation {
        &self.confirmation
    }
}

impl Validate for ActiveRuleRecord {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)?;
        self.confirmation.validate()?;
        if self.draft_id != self.confirmation.draft_id
            || self.policy_version != self.confirmation.draft_version
        {
            return Err(ContractError::new(
                ErrorCode::ChangedDraftBinding,
                "active record must bind the confirmation draft version",
            ));
        }
        Ok(())
    }
}

/// Bind owner confirmation to a structurally valid draft.
///
/// This does not activate a runtime policy engine.
pub fn activate(
    draft: &RuleDraft,
    confirmation: Option<&OwnerConfirmation>,
) -> Result<ActiveRuleRecord, ContractError> {
    draft.validate()?;
    let Some(confirmation) = confirmation else {
        return Err(ContractError::new(
            ErrorCode::MissingConfirmation,
            "activation requires owner confirmation",
        ));
    };
    confirmation.validate()?;
    if draft.status() == DraftStatus::NeedsClarification || !draft.unresolved_issues.is_empty() {
        return Err(ContractError::new(
            ErrorCode::UnresolvedClause,
            "unresolved clauses block activation",
        ));
    }
    if confirmation.draft_id != draft.id || confirmation.draft_version != draft.draft_version {
        return Err(ContractError::new(
            ErrorCode::ChangedDraftBinding,
            "confirmation is bound to a different draft version",
        ));
    }
    if confirmation.confirmed_at.seconds() < draft.created_at.seconds() {
        return Err(ContractError::new(
            ErrorCode::InvalidTimeOrdering,
            "confirmation time must not precede draft creation",
        ));
    }
    let record = ActiveRuleRecord {
        contract_version: CONTRACT_VERSION,
        draft_id: draft.id.clone(),
        policy_version: draft.draft_version,
        confirmation: confirmation.clone(),
    };
    record.validate()?;
    Ok(record)
}

/// Typed parameter. Objects and arrays are not part of this schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ParameterValue {
    Text(ParameterText),
    Integer(i64),
    Boolean(bool),
    Identifier(EntityId),
}

impl ParameterValue {
    fn validate_request_value(&self) -> Result<(), ContractError> {
        let ParameterValue::Text(text) = self else {
            return Ok(());
        };
        let raw = text.as_str();
        if looks_like_url(raw) {
            return Err(ContractError::new(
                ErrorCode::UnsupportedDestination,
                "parameter text must not be a URL",
            ));
        }
        if looks_like_sql(raw) {
            return Err(ContractError::new(
                ErrorCode::UnsupportedOperation,
                "parameter text must not be SQL",
            ));
        }
        if looks_like_secret(raw) {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "parameter text matches a PEM-shaped pattern",
            ));
        }
        Ok(())
    }
}

/// Canonical named-operation request.
///
/// Field order is the canonical JSON key order. The schema has no URL, SQL,
/// credential, or conversation fields. Coarse parameter-text checks are not
/// secret detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct AgentRequest {
    contract_version: u32,
    request_id: EntityId,
    session: SessionRef,
    agent: AgentRef,
    credential: CredentialRef,
    policy: PolicyRef,
    connector_capability_version: Version,
    epoch: Epoch,
    operation: OperationName,
    destination: DestinationRef,
    parameters: BTreeMap<ParameterName, ParameterValue>,
    created_at: UnixTime,
}

impl AgentRequest {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn request_id(&self) -> &EntityId {
        &self.request_id
    }
    pub fn session(&self) -> &SessionRef {
        &self.session
    }
    pub fn agent(&self) -> &AgentRef {
        &self.agent
    }
    pub fn credential(&self) -> &CredentialRef {
        &self.credential
    }
    pub fn policy(&self) -> &PolicyRef {
        &self.policy
    }
    pub fn connector_capability_version(&self) -> Version {
        self.connector_capability_version
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn operation(&self) -> &OperationName {
        &self.operation
    }
    pub fn destination(&self) -> &DestinationRef {
        &self.destination
    }
    pub fn parameters(&self) -> &BTreeMap<ParameterName, ParameterValue> {
        &self.parameters
    }
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }

    /// Compact JSON in struct field order, with sorted parameter names.
    ///
    /// This is a canonical representation. It is not a cryptographic digest.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|err| ContractError::new(ErrorCode::InvalidJson, err.to_string()))
    }
}

impl Validate for AgentRequest {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)?;
        self.session.validate()?;
        if self.session.agent_id != self.agent.id {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "session agent_id must match agent.id",
            ));
        }
        if self.session.epoch != self.epoch {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "request epoch must match session epoch",
            ));
        }
        if self.created_at.seconds() < self.session.not_before.seconds()
            || self.created_at.seconds() >= self.session.expires_at.seconds()
        {
            return Err(ContractError::new(
                ErrorCode::InvalidTimeOrdering,
                "request time must fall in the session window",
            ));
        }
        if !self.credential.kind.supports_mediated_use() {
            return Err(ContractError::new(
                ErrorCode::UnsupportedOperation,
                format!(
                    "{} does not support mediated named operations",
                    self.credential.kind.label()
                ),
            ));
        }
        if !self
            .destination
            .kind
            .matches_credential(self.credential.kind)
        {
            return Err(ContractError::new(
                ErrorCode::UnsupportedDestination,
                "destination kind must match the credential kind",
            ));
        }
        if self.parameters.len() > MAX_PARAMETER_COUNT {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                format!(
                    "parameter count {} exceeds {MAX_PARAMETER_COUNT}",
                    self.parameters.len()
                ),
            ));
        }
        for value in self.parameters.values() {
            value.validate_request_value()?;
        }
        Ok(())
    }
}

/// Bouncer decision envelope with identifiers, a decision, and a reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DecisionEnvelope {
    contract_version: u32,
    request_id: EntityId,
    agent_id: EntityId,
    credential_id: EntityId,
    credential_revision: Version,
    policy_version: Version,
    decision: Decision,
    reason_code: ReasonCode,
    created_at: UnixTime,
}

impl DecisionEnvelope {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn request_id(&self) -> &EntityId {
        &self.request_id
    }
    pub fn agent_id(&self) -> &EntityId {
        &self.agent_id
    }
    pub fn credential_id(&self) -> &EntityId {
        &self.credential_id
    }
    pub fn credential_revision(&self) -> Version {
        self.credential_revision
    }
    pub fn policy_version(&self) -> Version {
        self.policy_version
    }
    pub fn decision(&self) -> Decision {
        self.decision
    }
    pub fn reason_code(&self) -> &ReasonCode {
        &self.reason_code
    }
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }
}

impl Validate for DecisionEnvelope {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)
    }
}

/// Audit or notification event. Diagnostic text is length-bounded.
/// The bound is not secret scrubbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    DecisionRecorded,
    ApprovalRequested,
    RequestDenied,
    NotificationQueued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct EventEnvelope {
    contract_version: u32,
    event_id: EntityId,
    kind: EventKind,
    severity: Severity,
    decision: DecisionEnvelope,
    occurred_at: UnixTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diagnostic: Option<DiagnosticText>,
}

impl EventEnvelope {
    pub fn contract_version(&self) -> u32 {
        self.contract_version
    }
    pub fn event_id(&self) -> &EntityId {
        &self.event_id
    }
    pub fn kind(&self) -> EventKind {
        self.kind
    }
    pub fn severity(&self) -> Severity {
        self.severity
    }
    pub fn decision(&self) -> &DecisionEnvelope {
        &self.decision
    }
    pub fn occurred_at(&self) -> UnixTime {
        self.occurred_at
    }
    pub fn diagnostic(&self) -> Option<&DiagnosticText> {
        self.diagnostic.as_ref()
    }
}

impl Validate for EventEnvelope {
    fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(self.contract_version)?;
        self.decision.validate()?;
        require_time_order(self.decision.created_at, self.occurred_at, true)?;
        match (self.kind, self.decision.decision) {
            (EventKind::RequestDenied, Decision::Deny)
            | (EventKind::ApprovalRequested, Decision::RequireApproval)
            | (EventKind::DecisionRecorded, _)
            | (EventKind::NotificationQueued, _) => Ok(()),
            (kind, decision) => Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                format!("{kind:?} cannot wrap {decision:?}"),
            )),
        }
    }
}

/// Opaque digest bytes and an algorithm **name**.
///
/// This crate does not hash, sign, or authenticate a request. A later component
/// that uses a reviewed cryptographic library may fill this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDigest {
    algorithm: EntityId,
    octets: Vec<u8>,
}

impl BoundDigest {
    pub fn bind(algorithm: &str, octets: &[u8]) -> Result<Self, ContractError> {
        if octets.len() < MIN_DIGEST_OCTETS || octets.len() > MAX_DIGEST_OCTETS {
            return Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                format!(
                    "digest length {} is outside {MIN_DIGEST_OCTETS}..={MAX_DIGEST_OCTETS}",
                    octets.len()
                ),
            ));
        }
        Ok(Self {
            algorithm: EntityId::parse(algorithm)?,
            octets: octets.to_vec(),
        })
    }

    pub fn algorithm(&self) -> &EntityId {
        &self.algorithm
    }

    pub fn octets(&self) -> &[u8] {
        &self.octets
    }

    pub fn octets_hex(&self) -> String {
        encode_hex(&self.octets)
    }
}

impl Validate for BoundDigest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.octets.len() < MIN_DIGEST_OCTETS || self.octets.len() > MAX_DIGEST_OCTETS {
            Err(ContractError::new(
                ErrorCode::InvalidRequestBounds,
                "digest length is outside the permitted bound",
            ))
        } else {
            Ok(())
        }
    }
}

impl Serialize for BoundDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BoundDigestWire {
            algorithm: self.algorithm.clone(),
            octets_hex: encode_hex(&self.octets),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BoundDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BoundDigestWire::deserialize(deserializer)?;
        let octets = decode_hex(&wire.octets_hex).map_err(DeError::custom)?;
        BoundDigest::bind(wire.algorithm.as_str(), &octets).map_err(DeError::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct BoundDigestWire {
    algorithm: EntityId,
    octets_hex: String,
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, ContractError> {
    if !raw.len().is_multiple_of(2) {
        return Err(ContractError::new(
            ErrorCode::InvalidRequestBounds,
            "digest hex length must be even",
        ));
    }
    if !raw.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ContractError::new(
            ErrorCode::InvalidRequestBounds,
            "digest hex must be hexadecimal",
        ));
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, ContractError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ContractError::new(
            ErrorCode::InvalidRequestBounds,
            "digest hex must be hexadecimal",
        )),
    }
}

/// Decode a JSON object for tests and callers that already have [`Value`].
pub fn parse_json_value<T>(value: &Value) -> Result<T, ContractError>
where
    T: for<'de> Deserialize<'de> + Validate,
{
    parse_json(&value.to_string())
}
