//! The 1PUX data (`export.data`) and the CSV export of 1Password, mapped to Apassy
//! items.
//!
//! 1PUX: `accounts[].vaults[].items[]`. Each item has `categoryUuid`, `state`
//! (`active` or `archived`), `overview` (title, URLs, tags), and `details` (login
//! fields, `password`, `notesPlain`, and `sections[].fields[]` with a typed `value`).
//! The reader is lenient: a missing or `null` value is empty, and a value of an
//! unknown type is left out with a warning.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use super::csv::{self, Record};
use super::{
    Category, Format, ImportError, ImportItem, ImportPreview, ItemBuilder, NOTE_FIELD, Part, Parts,
    TOTP_KEY, TOTP_LABEL,
};
use crate::contracts::CredentialKind;

// ---- Lenient JSON values. ----

/// Any JSON scalar as text. `null`, an object, or a list is empty.
struct TextVisitor;

impl<'de> Visitor<'de> for TextVisitor {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
        Ok(value)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<String, E> {
        Ok(value.to_string())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<String, E> {
        Ok(value.to_string())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<String, E> {
        Ok(value.to_string())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<String, E> {
        Ok(value.to_string())
    }

    fn visit_unit<E: de::Error>(self) -> Result<String, E> {
        Ok(String::new())
    }

    fn visit_none<E: de::Error>(self) -> Result<String, E> {
        Ok(String::new())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<String, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(String::new())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<String, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(String::new())
    }
}

/// Text that is not a secret: a title, an ID, a label, a URL.
#[derive(Default)]
struct Text(String);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TextVisitor).map(Text)
    }
}

impl Text {
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A value that can be a secret. It erases itself on drop.
#[derive(Default)]
struct Secret(Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(TextVisitor)
            .map(|value| Secret(Zeroizing::new(value)))
    }
}

/// `null` becomes the default value.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

// ---- 1PUX structure. Unknown keys are ignored. ----

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ExportJson {
    #[serde(deserialize_with = "nullable")]
    accounts: Vec<AccountJson>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct AccountJson {
    #[serde(deserialize_with = "nullable")]
    vaults: Vec<VaultJson>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct VaultJson {
    #[serde(deserialize_with = "nullable")]
    attrs: VaultAttrs,
    #[serde(deserialize_with = "nullable")]
    items: Vec<ItemJson>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct VaultAttrs {
    name: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ItemJson {
    category_uuid: Text,
    state: Text,
    trashed: Text,
    #[serde(deserialize_with = "nullable")]
    overview: Overview,
    #[serde(deserialize_with = "nullable")]
    details: Details,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Overview {
    title: Text,
    url: Text,
    #[serde(deserialize_with = "nullable")]
    urls: Vec<UrlJson>,
    #[serde(deserialize_with = "nullable")]
    tags: Vec<Text>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct UrlJson {
    url: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Details {
    #[serde(deserialize_with = "nullable")]
    login_fields: Vec<LoginFieldJson>,
    notes_plain: Secret,
    password: Secret,
    #[serde(deserialize_with = "nullable")]
    sections: Vec<SectionJson>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LoginFieldJson {
    value: Secret,
    name: Text,
    field_type: Text,
    designation: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SectionJson {
    #[serde(deserialize_with = "nullable")]
    fields: Vec<FieldJson>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct FieldJson {
    title: Text,
    id: Text,
    value: FieldValue,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SshKeyJson {
    private_key: Secret,
    #[serde(deserialize_with = "nullable")]
    metadata: SshMetadata,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SshMetadata {
    private_key: Secret,
    public_key: Text,
    fingerprint: Text,
    key_type: Text,
}

/// An email value: a string, or `{"email_address": ..., "provider": ...}`.
#[derive(Default)]
struct EmailJson(Secret);

impl<'de> Deserialize<'de> for EmailJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EmailVisitor;
        impl<'de> Visitor<'de> for EmailVisitor {
            type Value = EmailJson;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an email address")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<EmailJson, E> {
                Ok(EmailJson(Secret(Zeroizing::new(value.to_owned()))))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<EmailJson, E> {
                Ok(EmailJson(Secret(Zeroizing::new(value))))
            }

            fn visit_unit<E: de::Error>(self) -> Result<EmailJson, E> {
                Ok(EmailJson::default())
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<EmailJson, A::Error> {
                let mut out = EmailJson::default();
                while let Some(key) = map.next_key::<Text>()? {
                    if matches!(key.as_str(), "email_address" | "emailAddress" | "address") {
                        out = EmailJson(map.next_value::<Secret>()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(EmailVisitor)
    }
}

/// The typed value of a section field: `{"concealed": "..."}`, `{"date": 1700000000}`,
/// `{"sshKey": {...}}`, and so on.
#[derive(Default)]
enum FieldValue {
    #[default]
    Empty,
    /// A text value and its type name.
    Text(&'static str, Secret),
    /// A date or month value and its type name.
    Number(&'static str, Text),
    SshKey(Box<SshKeyJson>),
    /// A type that Apassy does not import, with its name.
    Unsupported(String),
}

const TEXT_TYPES: [&str; 10] = [
    "concealed",
    "string",
    "totp",
    "url",
    "phone",
    "menu",
    "emailAddress",
    "creditCardNumber",
    "creditCardType",
    "gender",
];

impl<'de> Deserialize<'de> for FieldValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = FieldValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a field value")
            }

            fn visit_unit<E: de::Error>(self) -> Result<FieldValue, E> {
                Ok(FieldValue::Empty)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<FieldValue, E> {
                Ok(FieldValue::Text(
                    "string",
                    Secret(Zeroizing::new(value.to_owned())),
                ))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<FieldValue, E> {
                Ok(FieldValue::Text("string", Secret(Zeroizing::new(value))))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FieldValue, A::Error> {
                let mut out = FieldValue::Empty;
                while let Some(key) = map.next_key::<Text>()? {
                    let key = key.as_str();
                    if let Some(kind) = TEXT_TYPES.iter().find(|kind| **kind == key) {
                        out = FieldValue::Text(kind, map.next_value::<Secret>()?);
                    } else if key == "email" {
                        out = FieldValue::Text("email", map.next_value::<EmailJson>()?.0);
                    } else if key == "date" {
                        out = FieldValue::Number("date", map.next_value::<Text>()?);
                    } else if key == "monthYear" {
                        out = FieldValue::Number("monthYear", map.next_value::<Text>()?);
                    } else if key == "sshKey" {
                        out = FieldValue::SshKey(Box::new(map.next_value::<SshKeyJson>()?));
                    } else {
                        map.next_value::<IgnoredAny>()?;
                        out = FieldValue::Unsupported(key.to_owned());
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

// ---- 1PUX mapping. ----

/// Parse `export.data` and map every item. The input erases itself where the caller
/// keeps it; the parsed values move into erasing buffers.
pub fn parse_1pux_json(bytes: &[u8]) -> Result<ImportPreview, ImportError> {
    // serde_json error text can quote a value, so only the position is kept.
    let export: ExportJson = serde_json::from_slice(bytes).map_err(|err| ImportError::Json {
        line: err.line(),
        column: err.column(),
    })?;
    let mut items = Vec::new();
    for account in export.accounts {
        for vault in account.vaults {
            let vault_name = vault.attrs.name.0;
            for item in vault.items {
                items.push(map_item(item, &vault_name));
            }
        }
    }
    Ok(ImportPreview {
        format: Format::OnePux,
        items,
    })
}

fn category(uuid: &str) -> (Category, &'static str) {
    match uuid {
        "001" => (Category::Login, "Login"),
        "002" => (Category::Personal, "Credit Card"),
        "003" => (Category::SecureNote, "Secure Note"),
        "004" => (Category::Personal, "Identity"),
        "005" => (Category::Password, "Password"),
        "006" => (Category::Personal, "Document"),
        "100" => (Category::Other, "Software License"),
        "101" => (Category::Personal, "Bank Account"),
        "102" => (Category::Database, "Database"),
        "103" => (Category::Personal, "Driver License"),
        "104" => (Category::Personal, "Outdoor License"),
        "105" => (Category::Personal, "Membership"),
        "106" => (Category::Personal, "Passport"),
        "107" => (Category::Personal, "Reward Program"),
        "108" => (Category::Personal, "Social Security Number"),
        "109" => (Category::Other, "Wireless Router"),
        "110" => (Category::Server, "Server"),
        "111" => (Category::Other, "Email Account"),
        "112" => (Category::ApiCredential, "API Credential"),
        "113" => (Category::Personal, "Medical Record"),
        "114" => (Category::SshKey, "SSH Key"),
        "115" => (Category::Personal, "Crypto Wallet"),
        _ => (Category::Other, "Other"),
    }
}

const USERNAME: &[&str] = &["username"];
const PASSWORD: &[&str] = &["password"];
const HOST: &[&str] = &["hostname", "host", "server"];
const DATABASE: &[&str] = &["database"];
const TOKEN: &[&str] = &["credential", "token", "api key", "api_key", "secret", "key"];
const PRIVATE_KEY: &[&str] = &["private_key"];
const PUBLIC_KEY: &[&str] = &["public_key"];

/// Text fields that stay visible. Any other text field becomes a hidden detail.
const PLAIN_KEYS: &[&str] = &[
    "username",
    "hostname",
    "host",
    "server",
    "port",
    "database",
    "database_type",
    "sid",
    "alias",
    "url",
    "website",
    "type",
    "filename",
    "name",
    "admin_console_url",
    "admin_console_username",
    "support_contact_url",
    "support_contact_phone",
    "region",
    "project",
    "service",
    "environment",
];

fn map_item(item: ItemJson, vault: &str) -> ImportItem {
    let ItemJson {
        category_uuid,
        state,
        trashed,
        overview,
        details,
    } = item;
    let (category, label) = category(category_uuid.as_str().trim());
    let mut builder = ItemBuilder::new(overview.title.as_str(), vault, category, label);
    let state = state.as_str().trim().to_ascii_lowercase();
    builder.archived = state == "archived";
    builder.set_tags(overview.tags.iter().map(Text::as_str));
    if matches!(state.as_str(), "trashed" | "deleted") || trashed.as_str() == "true" {
        return builder.skip("In the 1Password trash.");
    }
    if category == Category::Personal {
        return builder.skip(if label == "Document" {
            "A document is a file. Apassy does not import files.".to_owned()
        } else {
            format!("Apassy does not import {label} items. They are not credentials for agents.")
        });
    }

    let Details {
        login_fields,
        notes_plain,
        password,
        sections,
    } = details;
    let mut parts = Parts::new();
    for login in login_fields {
        let designation = login.designation.as_str().trim().to_ascii_lowercase();
        let name = login.name.as_str().trim();
        match designation.as_str() {
            "username" => parts.push(Part::new(USERNAME, "Username", login.value.0, false)),
            "password" => parts.push(Part::new(PASSWORD, "Password", login.value.0, true)),
            _ if login.field_type.as_str() == "P" => {
                parts.push(Part::new(&[name], name, login.value.0, true));
            }
            // Other web form fields (check boxes, buttons, search fields) are not
            // credentials.
            _ => {}
        }
    }
    parts.push(Part::new(PASSWORD, "Password", password.0, true));
    let mut urls: Vec<String> = Vec::new();
    for url in std::iter::once(overview.url.0).chain(overview.urls.into_iter().map(|u| u.url.0)) {
        let url = url.trim();
        if !url.is_empty() && !urls.iter().any(|known| known == url) {
            urls.push(url.to_owned());
        }
    }
    for url in urls {
        parts.push(Part::new(
            &["website"],
            "Website",
            Zeroizing::new(url),
            false,
        ));
    }
    for section in sections {
        for field in section.fields {
            push_section_field(&mut builder, &mut parts, field);
        }
    }

    if category == Category::SecureNote {
        let note = Part::new(&[NOTE_FIELD], "Note", notes_plain.0, true);
        if note.is_blank() {
            return custom(builder, parts, None);
        }
        return builder.finish(
            CredentialKind::Custom,
            vec![(NOTE_FIELD, note, true)],
            parts,
        );
    }
    builder.set_notes(notes_plain.0);

    match category {
        Category::Login | Category::Server | Category::Password => {
            if parts.has(USERNAME, Some(false)) && parts.has(PASSWORD, Some(true)) {
                let username = parts.take(USERNAME, Some(false)).expect("checked");
                let password = parts.take(PASSWORD, Some(true)).expect("checked");
                return builder.finish(
                    CredentialKind::Login,
                    vec![("username", username, false), ("password", password, true)],
                    parts,
                );
            }
            let why = (category != Category::Password).then_some(
                "Apassy needs a username and a password for a login. It imports the item as a custom secret.",
            );
            custom(builder, parts, why)
        }
        Category::Database => {
            if parts.has(HOST, Some(false))
                && parts.has(DATABASE, Some(false))
                && parts.has(USERNAME, Some(false))
                && parts.has(PASSWORD, Some(true))
            {
                let host = parts.take(HOST, Some(false)).expect("checked");
                let database = parts.take(DATABASE, Some(false)).expect("checked");
                let username = parts.take(USERNAME, Some(false)).expect("checked");
                let password = parts.take(PASSWORD, Some(true)).expect("checked");
                return builder.finish(
                    CredentialKind::Database,
                    vec![
                        ("host", host, false),
                        ("database", database, false),
                        ("username", username, false),
                        ("password", password, true),
                    ],
                    parts,
                );
            }
            custom(
                builder,
                parts,
                Some(
                    "Apassy needs a host, a database name, a username, and a password for a database. It imports the item as a custom secret.",
                ),
            )
        }
        Category::ApiCredential => {
            let Some(token) = parts
                .take(TOKEN, Some(true))
                .or_else(|| parts.take_first_secret())
            else {
                return builder.skip("The API credential has no secret value.");
            };
            builder.finish(CredentialKind::ApiKey, vec![("token", token, true)], parts)
        }
        Category::SshKey => {
            let Some(private) = parts.take(PRIVATE_KEY, Some(true)) else {
                return custom(
                    builder,
                    parts,
                    Some("The SSH key has no private key. Apassy imports it as a custom secret."),
                );
            };
            let mut builtin = vec![("private_key", private, true)];
            if let Some(public) = parts.take(PUBLIC_KEY, Some(false)) {
                builtin.push(("public_key", public, false));
            }
            builder.finish(CredentialKind::SshKey, builtin, parts)
        }
        _ => {
            let why = format!(
                "1Password category “{label}” has no Apassy kind. Apassy imports it as a custom secret."
            );
            custom(builder, parts, Some(&why))
        }
    }
}

/// A custom secret: the password, or else the first hidden value, is the main field.
fn custom(mut builder: ItemBuilder, mut parts: Parts, why: Option<&str>) -> ImportItem {
    let Some(main) = parts
        .take(PASSWORD, Some(true))
        .or_else(|| parts.take_first_secret())
    else {
        return builder.skip("The item has no password or other secret value.");
    };
    if let Some(why) = why {
        builder.warn(why);
    }
    builder.finish(
        CredentialKind::Custom,
        vec![(super::CUSTOM_FIELD, main, true)],
        parts,
    )
}

fn push_section_field(builder: &mut ItemBuilder, parts: &mut Parts, field: FieldJson) {
    let FieldJson { title, id, value } = field;
    let id = id.as_str().trim();
    let title = title.as_str().trim();
    let label = if title.is_empty() { id } else { title };
    let keys = [id, title];
    let plain_key = keys
        .iter()
        .any(|key| PLAIN_KEYS.contains(&key.to_lowercase().as_str()));
    match value {
        FieldValue::Empty => {}
        FieldValue::Text(kind, value) => {
            let hidden = match kind {
                "concealed" | "totp" | "creditCardNumber" => true,
                "string" => !plain_key,
                _ => false,
            };
            if kind == "totp" {
                let label = if label.is_empty() { TOTP_LABEL } else { label };
                parts.push(Part::new(&[TOTP_KEY, id, title], label, value.0, true));
            } else {
                parts.push(Part::new(&keys, label, value.0, hidden));
            }
        }
        FieldValue::Number(kind, value) => {
            let text = if kind == "date" {
                format_date(value.as_str())
            } else {
                format_month(value.as_str())
            };
            parts.push(Part::new(&keys, label, Zeroizing::new(text), false));
        }
        FieldValue::SshKey(key) => {
            let SshKeyJson {
                private_key,
                metadata,
            } = *key;
            // The OpenSSH form in the metadata works with `ssh` and Git. The top-level
            // value is the PKCS #8 form.
            let private = if metadata.private_key.0.trim().is_empty() {
                private_key.0
            } else {
                metadata.private_key.0
            };
            parts.push(Part::new(
                &["private_key", id],
                "Private key",
                private,
                true,
            ));
            parts.push(Part::new(
                PUBLIC_KEY,
                "Public key",
                Zeroizing::new(metadata.public_key.0),
                false,
            ));
            parts.push(Part::new(
                &["fingerprint"],
                "Fingerprint",
                Zeroizing::new(metadata.fingerprint.0),
                false,
            ));
            parts.push(Part::new(
                &["key_type"],
                "Key type",
                Zeroizing::new(metadata.key_type.0),
                false,
            ));
        }
        FieldValue::Unsupported(kind) => {
            let label = super::detail_label(label);
            builder.warn(match kind.as_str() {
                "file" => format!("“{label}” is an attachment. Apassy does not import files."),
                "reference" => format!(
                    "“{label}” links to another 1Password item. Apassy does not import links."
                ),
                _ => format!("“{label}” is a field of a type that Apassy does not import."),
            });
        }
    }
}

/// A 1Password date (Unix seconds) as `YYYY-MM-DD`.
fn format_date(raw: &str) -> String {
    match raw.trim().parse::<i64>() {
        Ok(seconds) if seconds >= 0 => {
            let text = crate::vault::format_utc(seconds.unsigned_abs());
            text.get(..10).unwrap_or(&text).to_owned()
        }
        _ => raw.trim().to_owned(),
    }
}

/// A 1Password month (`YYYYMM`) as `YYYY-MM`.
fn format_month(raw: &str) -> String {
    match raw.trim().parse::<u32>() {
        Ok(value) if (1..=12).contains(&(value % 100)) && value >= 100 => {
            format!("{:04}-{:02}", value / 100, value % 100)
        }
        _ => raw.trim().to_owned(),
    }
}

// ---- CSV mapping. ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Column {
    Title,
    Url,
    Username,
    Password,
    Otp,
    Archived,
    Tags,
    Notes,
    Vault,
    /// A known column without a credential value, such as Favorite.
    Ignored,
    /// Another column. A value in it becomes a hidden detail.
    Other,
}

fn column(header: &str) -> Column {
    match header.trim().to_lowercase().as_str() {
        "title" | "name" => Column::Title,
        "url" | "urls" | "website" | "login_uri" => Column::Url,
        "username" | "user name" | "login_username" => Column::Username,
        "password" | "login_password" => Column::Password,
        "otpauth" | "otp" | "totp" | "one-time password" | "login_totp" => Column::Otp,
        "archived" => Column::Archived,
        "tags" => Column::Tags,
        "notes" | "notesplain" => Column::Notes,
        "vault" => Column::Vault,
        "favorite" | "favourite" | "type" | "category" | "uuid" | "created" | "modified"
        | "created at" | "updated at" => Column::Ignored,
        _ => Column::Other,
    }
}

/// Parse the CSV export. The header row names the columns, in any order and case.
pub fn parse_csv(text: &str) -> Result<ImportPreview, ImportError> {
    let records = csv::parse(text)?;
    let mut rows = records.into_iter();
    let Some(header) = rows.next() else {
        return Err(ImportError::NoTitleColumn);
    };
    // A known column counts once. A second column with the same name is "other".
    let mut columns: Vec<Column> = Vec::with_capacity(header.len());
    for name in &header {
        let kind = column(name);
        let repeated = !matches!(kind, Column::Other | Column::Ignored) && columns.contains(&kind);
        columns.push(if repeated { Column::Other } else { kind });
    }
    if !columns.contains(&Column::Title) {
        return Err(ImportError::NoTitleColumn);
    }
    let labels: Vec<String> = header
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let name = name.trim();
            if name.is_empty() {
                format!("Column {}", index + 1)
            } else {
                name.to_owned()
            }
        })
        .collect();
    let items = rows.map(|row| map_row(&columns, &labels, row)).collect();
    Ok(ImportPreview {
        format: Format::Csv,
        items,
    })
}

fn map_row(columns: &[Column], labels: &[String], row: Record) -> ImportItem {
    let value = |kind: Column| -> Option<&str> {
        let index = columns.iter().position(|column| *column == kind)?;
        row.get(index).map(|value| value.as_str())
    };
    let title = value(Column::Title).unwrap_or_default().to_owned();
    let vault = value(Column::Vault).unwrap_or_default().to_owned();
    let archived = value(Column::Archived)
        .is_some_and(|flag| matches!(flag.trim().to_lowercase().as_str(), "true" | "1" | "yes"));
    let tags = value(Column::Tags).unwrap_or_default().to_owned();
    let mut builder = ItemBuilder::new(&title, &vault, Category::CsvRow, "CSV row");
    builder.archived = archived;
    builder.set_tags(tags.split(','));
    if row.len() > columns.len() {
        builder.warn("The row has more values than the header has columns. Apassy leaves out the extra values.");
    }

    let mut parts = Parts::new();
    let mut notes = Zeroizing::new(String::new());
    for (index, mut cell) in row.into_iter().enumerate() {
        let Some(kind) = columns.get(index) else {
            break;
        };
        let taken = std::mem::take(&mut cell);
        match kind {
            Column::Username => parts.push(Part::new(USERNAME, "Username", taken, false)),
            Column::Password => parts.push(Part::new(PASSWORD, "Password", taken, true)),
            Column::Url => parts.push(Part::new(&["website"], "Website", taken, false)),
            Column::Otp => parts.push(Part::new(&[TOTP_KEY], TOTP_LABEL, taken, true)),
            Column::Notes => notes = taken,
            Column::Other => parts.push(Part::new(&[], &labels[index], taken, true)),
            Column::Title | Column::Archived | Column::Tags | Column::Vault | Column::Ignored => {}
        }
    }
    builder.set_notes(notes);
    if parts.has(USERNAME, Some(false)) && parts.has(PASSWORD, Some(true)) {
        let username = parts.take(USERNAME, Some(false)).expect("checked");
        let password = parts.take(PASSWORD, Some(true)).expect("checked");
        return builder.finish(
            CredentialKind::Login,
            vec![("username", username, false), ("password", password, true)],
            parts,
        );
    }
    if !parts.has_secret() {
        return builder.skip("The row has no password or other secret value.");
    }
    let why = parts
        .has(PASSWORD, Some(true))
        .then_some("The row has no username. Apassy imports it as a custom secret.");
    custom(builder, parts, why)
}
