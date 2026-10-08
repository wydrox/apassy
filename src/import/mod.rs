//! Import from 1Password: the 1PUX export (1Password 8) and the CSV export.
//!
//! [`read_file`] reads an export file into an [`ImportPreview`]. The preview holds one
//! [`ImportItem`] for each 1Password item: the title, the 1Password vault, the Apassy
//! kind, warnings, and the item as a vault draft. The owner selects items, and the
//! desktop app adds each selected draft to the vault. Nothing is written until then.
//!
//! Mapping rules (see `docs/operations/import-1password.md`):
//!
//! - A secret goes into a secret field or a hidden custom detail. It never goes into the
//!   title, the notes, or the tags, because they are searchable metadata.
//! - Custom details follow the desktop layout: the field `x_` and the label in
//!   hexadecimal, at most 10 per item, labels of at most 31 bytes.
//! - A 1Password text field becomes a hidden detail unless it is a known plain field
//!   (username, host, port, URL, ...), because a text field can hold a secret. An agent
//!   that sees all credentials sees the visible details.
//!
//! Memory: the file bytes, the decompressed JSON, and each parsed value are in erasing
//! buffers (`Zeroizing`, [`SecretValue`]). This is best effort, as in the key-memory
//! review: `serde_json` keeps a scratch copy of a string with escapes, the deflate
//! window is not erased, and the allocator does not erase freed memory.

pub mod csv;
mod onepassword;
pub mod zip;

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use zeroize::Zeroizing;

use crate::contracts::CredentialKind;
use crate::vault::{Field, ItemDraft as VaultDraft, SecretValue};

pub use onepassword::{parse_1pux_json, parse_csv};
pub use zip::{ZipError, ZipLimits};

/// The name of the item data inside a 1PUX archive.
pub const EXPORT_DATA: &str = "export.data";
/// The largest CSV file, in bytes.
pub const MAX_CSV_BYTES: u64 = 32 * 1024 * 1024;
/// The tag that each imported item gets.
pub const IMPORT_TAG: &str = "1password";

/// Limits of the vault and of the desktop item layout.
const MAX_TITLE_BYTES: usize = 128;
const MAX_NOTES_BYTES: usize = 8192;
const MAX_TAGS: usize = 32;
const MAX_TAG_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 65_536;
/// The desktop app shows at most this many custom details
/// (`crate::desktop::owner_store::MAX_DETAILS`).
pub const MAX_DETAILS: usize = 10;
/// The longest custom detail label, in bytes
/// (`crate::desktop::owner_store::MAX_DETAIL_LABEL_BYTES`).
pub const MAX_DETAIL_LABEL_BYTES: usize = 31;
/// The name of the main field of an imported custom secret.
pub const CUSTOM_FIELD: &str = "secret";
/// The name of the main field of an imported secure note.
pub const NOTE_FIELD: &str = "note";

/// The field name of a custom detail: `x_` and the label in hexadecimal. The same rule
/// as `crate::desktop::owner_store::detail_field_name` and the inverse of
/// [`crate::vault::custom_detail_label`].
pub fn detail_field_name(label: &str) -> String {
    let mut name = String::with_capacity(2 + 2 * label.len());
    name.push_str("x_");
    for byte in label.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// The kind of export file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The 1Password 8 export: a zip archive with `export.data`.
    OnePux,
    /// The 1Password CSV export.
    Csv,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Self::OnePux => "1PUX export",
            Self::Csv => "CSV export",
        }
    }
}

/// The 1Password category of an item, as far as the import cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Login,
    Password,
    SecureNote,
    ApiCredential,
    Database,
    Server,
    SshKey,
    /// Another category that can hold a secret, such as an email account or a
    /// software license. It becomes a custom secret.
    Other,
    /// A personal or financial category, such as a credit card or a passport. Apassy
    /// does not import it.
    Personal,
    /// A row of the CSV export. The CSV export has no category.
    CsvRow,
}

impl Category {
    /// Selected by default in the preview. Apassy is for the credentials that agents
    /// use: API credentials, SSH keys, databases, and servers.
    pub fn selected_by_default(self) -> bool {
        matches!(
            self,
            Self::ApiCredential | Self::SshKey | Self::Database | Self::Server
        )
    }
}

/// An item as it goes into the vault. Debug redacts the notes and the values.
pub struct ImportDraft {
    title: String,
    kind: CredentialKind,
    notes: Zeroizing<String>,
    tags: Vec<String>,
    fields: Vec<Field>,
}

impl ImportDraft {
    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    pub fn notes(&self) -> &str {
        &self.notes
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// The field with `name`, a built-in field such as `token` or `username`.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// The custom detail with `label`.
    pub fn detail(&self, label: &str) -> Option<&Field> {
        self.field(&detail_field_name(label))
    }

    /// The labels of the custom details, in order.
    pub fn detail_labels(&self) -> Vec<String> {
        self.fields
            .iter()
            .filter_map(|field| crate::vault::custom_detail_label(&field.name))
            .collect()
    }

    /// The vault draft. The values move without a copy.
    pub fn into_vault_draft(mut self) -> VaultDraft {
        VaultDraft {
            title: std::mem::take(&mut self.title),
            kind: self.kind,
            notes: std::mem::take(&mut *self.notes),
            tags: std::mem::take(&mut self.tags),
            fields: std::mem::take(&mut self.fields),
        }
    }
}

impl fmt::Debug for ImportDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportDraft")
            .field("title", &self.title)
            .field("kind", &self.kind)
            .field("notes", &"[redacted]")
            .field("tags", &self.tags)
            .field("fields", &self.fields)
            .finish()
    }
}

/// What happens to an item.
#[derive(Debug)]
enum Outcome {
    Ready(ImportDraft),
    /// Apassy does not import the item, for this reason.
    Skipped(String),
}

/// One item of the export in the preview. Debug redacts every value.
#[derive(Debug)]
pub struct ImportItem {
    /// The title in 1Password.
    pub title: String,
    /// The name of the 1Password vault. Empty for the CSV export.
    pub source_vault: String,
    pub category: Category,
    /// The name of the 1Password category, such as "API Credential".
    pub category_label: String,
    /// Archived in 1Password.
    pub archived: bool,
    /// An item with the same title and kind is already in the vault.
    pub duplicate: bool,
    /// Notes for the owner: what did not fit or changed. They never hold a value.
    pub warnings: Vec<String>,
    outcome: Outcome,
}

impl ImportItem {
    /// The Apassy kind, when the item can be imported.
    pub fn kind(&self) -> Option<CredentialKind> {
        self.draft().map(ImportDraft::kind)
    }

    pub fn draft(&self) -> Option<&ImportDraft> {
        match &self.outcome {
            Outcome::Ready(draft) => Some(draft),
            Outcome::Skipped(_) => None,
        }
    }

    /// Why Apassy does not import the item. `None` when it can.
    pub fn skip_reason(&self) -> Option<&str> {
        match &self.outcome {
            Outcome::Ready(_) => None,
            Outcome::Skipped(reason) => Some(reason),
        }
    }

    pub fn can_import(&self) -> bool {
        matches!(self.outcome, Outcome::Ready(_))
    }

    /// The first selection of the item in the preview.
    pub fn selected_by_default(&self) -> bool {
        self.can_import()
            && !self.duplicate
            && !self.archived
            && self.category.selected_by_default()
    }

    /// The draft, for the import. The item keeps only its labels.
    pub fn take_draft(&mut self) -> Option<ImportDraft> {
        match std::mem::replace(&mut self.outcome, Outcome::Skipped(String::new())) {
            Outcome::Ready(draft) => Some(draft),
            skipped => {
                self.outcome = skipped;
                None
            }
        }
    }
}

/// The items of one export file.
#[derive(Debug)]
pub struct ImportPreview {
    pub format: Format,
    pub items: Vec<ImportItem>,
}

impl ImportPreview {
    /// Mark each item with the same title (trimmed, case-insensitive) and the same kind
    /// as an existing credential. A marked item is not selected by default.
    pub fn mark_existing<'a>(
        &mut self,
        existing: impl IntoIterator<Item = (&'a str, CredentialKind)>,
    ) {
        let known: BTreeSet<(String, &'static str)> = existing
            .into_iter()
            .map(|(title, kind)| (title.trim().to_lowercase(), kind.label()))
            .collect();
        for item in &mut self.items {
            if let Some(draft) = item.draft() {
                let key = (draft.title.trim().to_lowercase(), draft.kind.label());
                item.duplicate = known.contains(&key);
            }
        }
    }

    /// The first selection, one flag per item.
    pub fn default_selection(&self) -> Vec<bool> {
        self.items
            .iter()
            .map(ImportItem::selected_by_default)
            .collect()
    }

    /// The number of items that can be imported.
    pub fn importable(&self) -> usize {
        self.items.iter().filter(|item| item.can_import()).count()
    }
}

/// Why an export file cannot be read. The text never holds a value from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The path is empty.
    NoPath,
    /// The file cannot be opened or read.
    Io,
    /// The file is not a 1PUX or CSV export.
    UnknownFormat,
    /// A legacy 1PIF file.
    Legacy,
    Zip(ZipError),
    Csv(csv::CsvError),
    /// `export.data` is not the JSON that Apassy expects.
    Json {
        line: usize,
        column: usize,
    },
    /// The CSV file is larger than [`MAX_CSV_BYTES`].
    CsvTooLarge,
    /// The file is not UTF-8 text.
    NotText,
    /// The CSV header has no Title column.
    NoTitleColumn,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPath => f.write_str("Type the path of the export file."),
            Self::Io => f.write_str("Apassy cannot read the file. Check the path."),
            Self::UnknownFormat => f.write_str(
                "The file is not a 1Password export. Export from 1Password as 1PUX or CSV.",
            ),
            Self::Legacy => f.write_str(
                "Apassy does not read 1PIF files. Export from 1Password 8 as 1PUX or CSV.",
            ),
            Self::Zip(err) => write!(f, "{err}"),
            Self::Csv(err) => write!(f, "{err}"),
            Self::Json { line, column } => write!(
                f,
                "The export.data file is not valid 1PUX data (line {line}, column {column})."
            ),
            Self::CsvTooLarge => f.write_str("The CSV file is larger than 32 MB."),
            Self::NotText => f.write_str("The CSV file is not UTF-8 text."),
            Self::NoTitleColumn => f.write_str(
                "The CSV file has no Title column. Export from 1Password again, as CSV.",
            ),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<ZipError> for ImportError {
    fn from(err: ZipError) -> Self {
        Self::Zip(err)
    }
}

impl From<csv::CsvError> for ImportError {
    fn from(err: csv::CsvError) -> Self {
        Self::Csv(err)
    }
}

/// Read a 1PUX or CSV export file. A file that starts like a zip archive is a 1PUX
/// export. Otherwise the extension decides.
pub fn read_file(path: &Path) -> Result<ImportPreview, ImportError> {
    if path.as_os_str().is_empty() {
        return Err(ImportError::NoPath);
    }
    let mut file = File::open(path).map_err(|_| ImportError::Io)?;
    let meta = file.metadata().map_err(|_| ImportError::Io)?;
    if !meta.is_file() {
        return Err(ImportError::Io);
    }
    let mut magic = [0u8; 4];
    let read = read_prefix(&mut file, &mut magic)?;
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if read == 4 && (magic == *b"PK\x03\x04" || magic == *b"PK\x05\x06") {
        return read_1pux(&mut file);
    }
    match extension.as_str() {
        "1pux" => Err(ImportError::Zip(ZipError::NotZip)),
        "1pif" => Err(ImportError::Legacy),
        "csv" => {
            if meta.len() > MAX_CSV_BYTES {
                return Err(ImportError::CsvTooLarge);
            }
            file.rewind().map_err(|_| ImportError::Io)?;
            let bytes = read_limited(&mut file, meta.len(), MAX_CSV_BYTES)?;
            read_csv_bytes(&bytes)
        }
        _ => Err(ImportError::UnknownFormat),
    }
}

fn read_prefix(file: &mut File, buf: &mut [u8]) -> Result<usize, ImportError> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ImportError::Io),
        }
    }
    Ok(filled)
}

/// Read at most `limit` bytes into one erasing buffer of the file size, so the buffer
/// does not grow and leave copies.
fn read_limited(file: &mut File, len: u64, limit: u64) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let capacity = usize::try_from(len.min(limit)).map_err(|_| ImportError::CsvTooLarge)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity + 1));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ImportError::Io)?;
    if bytes.len() as u64 > limit {
        return Err(ImportError::CsvTooLarge);
    }
    Ok(bytes)
}

/// Read a 1PUX archive: `export.data` only. Attachments in `files/` are not read.
pub fn read_1pux<R: Read + Seek>(reader: &mut R) -> Result<ImportPreview, ImportError> {
    let data = zip::read_entry(reader, EXPORT_DATA, &ZipLimits::EXPORT)?;
    parse_1pux_json(&data)
}

/// Read the bytes of a CSV export.
pub fn read_csv_bytes(bytes: &[u8]) -> Result<ImportPreview, ImportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::NotText)?;
    parse_csv(text)
}

// ---- Mapping helpers shared by the 1PUX and the CSV mapping. ----

/// One value from a 1Password item before it gets its place.
struct Part {
    /// Lowercase keys to match: the field ID and the field title.
    keys: Vec<String>,
    label: String,
    value: Zeroizing<String>,
    hidden: bool,
}

impl Part {
    fn new(keys: &[&str], label: &str, value: Zeroizing<String>, hidden: bool) -> Self {
        Self {
            keys: keys
                .iter()
                .map(|key| key.trim().to_lowercase())
                .filter(|key| !key.is_empty())
                .collect(),
            label: label.to_owned(),
            value,
            hidden,
        }
    }

    fn matches(&self, keys: &[&str]) -> bool {
        self.keys.iter().any(|key| keys.contains(&key.as_str()))
    }

    fn is_blank(&self) -> bool {
        self.value.trim().is_empty()
    }
}

/// The values of one item, and what the mapping took from them.
struct Parts {
    parts: Vec<Part>,
}

impl Parts {
    fn new() -> Self {
        Self { parts: Vec::new() }
    }

    fn push(&mut self, part: Part) {
        if !part.is_blank() {
            self.parts.push(part);
        }
    }

    fn position(&self, keys: &[&str], hidden: Option<bool>) -> Option<usize> {
        self.parts
            .iter()
            .position(|part| part.matches(keys) && hidden.is_none_or(|h| part.hidden == h))
    }

    fn has(&self, keys: &[&str], hidden: Option<bool>) -> bool {
        self.position(keys, hidden).is_some()
    }

    fn take(&mut self, keys: &[&str], hidden: Option<bool>) -> Option<Part> {
        let index = self.position(keys, hidden)?;
        Some(self.parts.remove(index))
    }

    /// The first hidden value. A one-time password comes last.
    fn take_first_secret(&mut self) -> Option<Part> {
        let index = self
            .parts
            .iter()
            .position(|part| part.hidden && !part.matches(&[TOTP_KEY]))
            .or_else(|| self.parts.iter().position(|part| part.hidden))?;
        Some(self.parts.remove(index))
    }

    fn has_secret(&self) -> bool {
        self.parts.iter().any(|part| part.hidden)
    }

    /// The first website, for the `website` field of a login (ADR 0021). The other
    /// websites stay custom details "Website 2", "Website 3", and so on.
    /// A website that the field takes is a web address ([`crate::browser::site`]); another
    /// value, for example an app link, stays a detail, so the form can save the item.
    /// Only a part whose label is a website gets the label "Website N".
    fn take_website(&mut self) -> Option<Part> {
        let index = self.parts.iter().position(|part| {
            part.matches(&["website"])
                && !part.hidden
                && crate::browser::site::Website::parse(&part.value).is_some()
        })?;
        let first = self.parts.remove(index);
        for (number, part) in (2..).zip(self.parts.iter_mut().filter(|part| {
            part.matches(&["website"]) && part.label.trim().to_lowercase().starts_with("website")
        })) {
            part.label = format!("Website {number}");
        }
        Some(first)
    }
}

/// The key of a one-time password part.
const TOTP_KEY: &str = "totp";
const TOTP_LABEL: &str = "One-time password";

/// Builds one [`ImportItem`].
struct ItemBuilder {
    title: String,
    source_vault: String,
    category: Category,
    category_label: String,
    archived: bool,
    notes: Zeroizing<String>,
    tags: Vec<String>,
    warnings: Vec<String>,
}

impl ItemBuilder {
    fn new(title: &str, source_vault: &str, category: Category, category_label: &str) -> Self {
        let trimmed = title.trim();
        Self {
            title: if trimmed.is_empty() {
                "Untitled".to_owned()
            } else {
                trimmed.to_owned()
            },
            source_vault: source_vault.trim().to_owned(),
            category,
            category_label: category_label.to_owned(),
            archived: false,
            notes: Zeroizing::new(String::new()),
            tags: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn warn(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    fn skip(self, reason: impl Into<String>) -> ImportItem {
        ImportItem {
            title: self.title,
            source_vault: self.source_vault,
            category: self.category,
            category_label: self.category_label,
            archived: self.archived,
            duplicate: false,
            warnings: self.warnings,
            outcome: Outcome::Skipped(reason.into()),
        }
    }

    fn set_tags<'a>(&mut self, tags: impl IntoIterator<Item = &'a str>) {
        let mut out: Vec<String> = Vec::new();
        let mut long = false;
        for tag in tags {
            let tag = tag.trim();
            if tag.is_empty() || out.iter().any(|known| known == tag) {
                continue;
            }
            if tag.len() > MAX_TAG_BYTES {
                long = true;
                continue;
            }
            out.push(tag.to_owned());
        }
        out.retain(|tag| tag != IMPORT_TAG);
        if out.len() > MAX_TAGS - 1 {
            out.truncate(MAX_TAGS - 1);
            self.warn(format!(
                "The item has more than {} tags. Apassy keeps the first {}.",
                MAX_TAGS - 1,
                MAX_TAGS - 1
            ));
        }
        if long {
            self.warn("A tag is longer than 64 bytes. It is not imported.");
        }
        out.push(IMPORT_TAG.to_owned());
        self.tags = out;
    }

    /// The notes of the 1Password item. They stay notes, and they are searchable.
    fn set_notes(&mut self, notes: Zeroizing<String>) {
        let trimmed = notes.trim();
        if trimmed.len() > MAX_NOTES_BYTES {
            let cut = floor_char_boundary(trimmed, MAX_NOTES_BYTES);
            self.notes = Zeroizing::new(trimmed[..cut].to_owned());
            self.warn("The notes are longer than 8 KB. Apassy keeps the first 8 KB.");
        } else {
            self.notes = Zeroizing::new(trimmed.to_owned());
        }
    }

    /// Build the item from its built-in fields (name, value, secret) and the parts that
    /// are left. Each left part becomes a custom detail.
    fn finish(
        mut self,
        kind: CredentialKind,
        builtin: Vec<(&str, Part, bool)>,
        rest: Parts,
    ) -> ImportItem {
        let mut fields = Vec::new();
        for (name, part, secret) in builtin {
            if part.value.len() > MAX_VALUE_BYTES {
                let label = detail_label(&part.label);
                return self.skip(format!("“{label}” is larger than 64 KB."));
            }
            fields.push(field(name, part.value, secret));
        }
        if self.archived {
            self.warn("Archived in 1Password. Apassy archives it too.");
        }
        let details = self.fit_details(rest.parts);
        for (label, part) in details {
            fields.push(field(&detail_field_name(&label), part.value, part.hidden));
        }
        if self.title.len() > MAX_TITLE_BYTES {
            let cut = floor_char_boundary(&self.title, MAX_TITLE_BYTES);
            self.title.truncate(cut);
            self.warn("The title is longer than 128 bytes. Apassy shortens it.");
        }
        if self.tags.is_empty() {
            self.tags.push(IMPORT_TAG.to_owned());
        }
        let draft = ImportDraft {
            title: self.title.clone(),
            kind,
            notes: std::mem::take(&mut self.notes),
            tags: std::mem::take(&mut self.tags),
            fields,
        };
        ImportItem {
            title: self.title,
            source_vault: self.source_vault,
            category: self.category,
            category_label: self.category_label,
            archived: self.archived,
            duplicate: false,
            warnings: self.warnings,
            outcome: Outcome::Ready(draft),
        }
    }

    /// Give each part a unique label and keep at most [`MAX_DETAILS`]. When there are
    /// too many, visible details go first, from the end, then hidden ones.
    fn fit_details(&mut self, parts: Vec<Part>) -> Vec<(String, Part)> {
        let mut kept: Vec<Option<Part>> = Vec::with_capacity(parts.len());
        for part in parts {
            if part.value.len() > MAX_VALUE_BYTES {
                let label = detail_label(&part.label);
                self.warn(format!(
                    "“{label}” is larger than 64 KB. It is not imported."
                ));
                continue;
            }
            kept.push(Some(part));
        }
        let mut extra = kept.len().saturating_sub(MAX_DETAILS);
        for hidden in [false, true] {
            for slot in kept.iter_mut().rev() {
                if extra == 0 {
                    break;
                }
                if slot.as_ref().is_some_and(|part| part.hidden == hidden) {
                    let part = slot.take().expect("checked above");
                    let label = detail_label(&part.label);
                    self.warn(if hidden {
                        format!(
                            "The secret “{label}” did not fit: an item has at most {MAX_DETAILS} details. It is not imported."
                        )
                    } else {
                        format!(
                            "“{label}” did not fit: an item has at most {MAX_DETAILS} details. It is not imported."
                        )
                    });
                    extra -= 1;
                }
            }
        }
        let mut used = BTreeSet::new();
        kept.into_iter()
            .flatten()
            .map(|part| (unique_label(&part.label, &mut used), part))
            .collect()
    }
}

fn field(name: &str, mut value: Zeroizing<String>, secret: bool) -> Field {
    let text = if secret {
        std::mem::take(&mut *value)
    } else {
        value.trim().to_owned()
    };
    Field {
        name: name.to_owned(),
        value: SecretValue::new(text),
        secret,
    }
}

/// The largest index at or below `max` that is a character boundary of `text`.
fn floor_char_boundary(text: &str, max: usize) -> usize {
    let mut cut = max.min(text.len());
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

/// A detail label: one line, first letter in upper case, at most 31 bytes.
fn detail_label(raw: &str) -> String {
    let words: Vec<&str> = raw.split_whitespace().collect();
    let joined = words.join(" ");
    let mut chars = joined.chars();
    let mut label = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
        None => "Field".to_owned(),
    };
    let cut = floor_char_boundary(&label, MAX_DETAIL_LABEL_BYTES);
    label.truncate(cut);
    let trimmed = label.trim_end().len();
    label.truncate(trimmed);
    label
}

/// A label that no earlier detail of the item has (case-insensitive).
fn unique_label(raw: &str, used: &mut BTreeSet<String>) -> String {
    let base = detail_label(raw);
    if used.insert(base.to_lowercase()) {
        return base;
    }
    for number in 2.. {
        let suffix = format!(" {number}");
        let cut = floor_char_boundary(&base, MAX_DETAIL_LABEL_BYTES - suffix.len());
        let label = format!("{}{suffix}", base[..cut].trim_end());
        if used.insert(label.to_lowercase()) {
            return label;
        }
    }
    unreachable!("the numbers do not run out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_web_address_is_the_website_of_a_login() {
        let value = |text: &str| Zeroizing::new(text.to_owned());
        let mut parts = Parts::new();
        parts.push(Part::new(
            &["website"],
            "Website",
            value("android://com.example.app"),
            false,
        ));
        parts.push(Part::new(
            &["website"],
            "Website",
            value("https://example.com/login"),
            false,
        ));
        parts.push(Part::new(
            &["website"],
            "website",
            value("https://example.org"),
            false,
        ));
        parts.push(Part::new(
            &["website"],
            "Login page",
            value("https://example.net"),
            false,
        ));
        let first = parts.take_website().expect("a web address");
        assert_eq!(first.value.as_str(), "https://example.com/login");
        let labels: Vec<&str> = parts.parts.iter().map(|part| part.label.as_str()).collect();
        // An app link stays a detail. A part that is not labeled as a website keeps its
        // label.
        assert_eq!(labels, vec!["Website 2", "Website 3", "Login page"]);
        let mut none = Parts::new();
        none.push(Part::new(
            &["website"],
            "Website",
            value("android://x"),
            false,
        ));
        assert!(none.take_website().is_none());
    }

    #[test]
    fn detail_names_match_the_vault_rule() {
        for label in ["Port", "Région", "a b", "x"] {
            let name = detail_field_name(label);
            assert_eq!(
                crate::vault::custom_detail_label(&name).as_deref(),
                Some(label)
            );
            assert!(name.len() <= 64);
        }
    }

    #[test]
    fn labels_are_short_single_line_and_unique() {
        assert_eq!(detail_label("  admin\nconsole   url "), "Admin console url");
        assert_eq!(detail_label(""), "Field");
        let long = "ł".repeat(40);
        let label = detail_label(&long);
        assert!(label.len() <= MAX_DETAIL_LABEL_BYTES);
        assert!(label.is_char_boundary(label.len()));
        let mut used = BTreeSet::new();
        assert_eq!(unique_label("Port", &mut used), "Port");
        assert_eq!(unique_label("port", &mut used), "Port 2");
        assert_eq!(unique_label("PORT", &mut used), "PORT 3");
        let long = "a".repeat(31);
        assert_eq!(unique_label(&long, &mut used), format!("A{}", &long[1..]));
        let second = unique_label(&long, &mut used);
        assert_eq!(second.len(), 31);
        assert!(second.ends_with(" 2"));
    }
}
