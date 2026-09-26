//! Built-in provider data and suggested declarations (goal item B4, ADR 0009).
//!
//! The files in `packs/providers/` describe common credential providers: how to
//! recognize a credential of the provider (signals), the declaration fields that such
//! a credential usually has, with a reason, and the known API hosts of the provider.
//! One file (`general.json`) has general signals, such as "prod" in a host or a name.
//! The build embeds the files, so only an app release changes them. The loader rejects
//! unknown fields at every level.
//!
//! - [`Vault::suggest_declaration`](super::Vault::suggest_declaration) reads one item of
//!   the unlocked vault and gives a [`Suggestion`]. Only the owner flow calls it. The
//!   broker never runs the detection. A suggestion has no secret value: only a provider
//!   name, declaration fields, and reasons from the data files.
//! - The broker reads the provider of a stored declaration and gives its known hosts
//!   ([`known_hosts`]) to the command analysis.
//!
//! When two signals suggest different values for one field, the suggestion takes the
//! more sensitive value and says so. A field without a signal keeps the most sensitive
//! value of the declaration form (ADR 0008).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use zeroize::Zeroizing;

use super::agents::{Environment, Reversibility, RiskLevel, Scope};
use super::suggestions::{DeclarationField, SuggestedDeclaration};

/// The provider file format that this version of Apassy reads.
pub const SCHEMA_VERSION: u64 = 1;

/// Built-in provider files, embedded at build time. Only an app release changes them.
const BUILTIN: &[(&str, &str)] = &[
    (
        "anthropic.json",
        include_str!("../../packs/providers/anthropic.json"),
    ),
    ("aws.json", include_str!("../../packs/providers/aws.json")),
    (
        "cloudflare.json",
        include_str!("../../packs/providers/cloudflare.json"),
    ),
    (
        "datadog.json",
        include_str!("../../packs/providers/datadog.json"),
    ),
    ("gcp.json", include_str!("../../packs/providers/gcp.json")),
    (
        "general.json",
        include_str!("../../packs/providers/general.json"),
    ),
    (
        "github.json",
        include_str!("../../packs/providers/github.json"),
    ),
    ("neon.json", include_str!("../../packs/providers/neon.json")),
    (
        "netlify.json",
        include_str!("../../packs/providers/netlify.json"),
    ),
    (
        "openai.json",
        include_str!("../../packs/providers/openai.json"),
    ),
    (
        "planetscale.json",
        include_str!("../../packs/providers/planetscale.json"),
    ),
    (
        "postgres.json",
        include_str!("../../packs/providers/postgres.json"),
    ),
    (
        "resend.json",
        include_str!("../../packs/providers/resend.json"),
    ),
    (
        "sendgrid.json",
        include_str!("../../packs/providers/sendgrid.json"),
    ),
    (
        "sentry.json",
        include_str!("../../packs/providers/sentry.json"),
    ),
    (
        "stripe.json",
        include_str!("../../packs/providers/stripe.json"),
    ),
    (
        "supabase.json",
        include_str!("../../packs/providers/supabase.json"),
    ),
    (
        "twilio.json",
        include_str!("../../packs/providers/twilio.json"),
    ),
    (
        "vercel.json",
        include_str!("../../packs/providers/vercel.json"),
    ),
];

/// File names of the built-in provider files in `packs/providers/`.
pub fn builtin_files() -> Vec<&'static str> {
    BUILTIN.iter().map(|(name, _)| *name).collect()
}

/// A provider file that does not load. `source` is the file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub source: String,
    pub message: String,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.source, self.message)
    }
}

impl std::error::Error for ProviderError {}

// ---- Schema ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileKind {
    /// A provider: signals, suggested fields, and known hosts.
    Provider,
    /// General signals for every credential. They name no provider.
    General,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFile {
    schema_version: u64,
    provider_version: u64,
    id: String,
    kind: FileKind,
    label: String,
    description: String,
    /// A generic provider, such as a PostgreSQL URL of any host. A specific provider
    /// wins over it.
    #[serde(default)]
    generic: bool,
    #[serde(default)]
    known_hosts: Vec<String>,
    signals: Vec<SignalFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalFile {
    id: String,
    when: Conditions,
    #[serde(default)]
    suggest: FieldsFile,
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldsFile {
    environment: Option<String>,
    risk: Option<String>,
    scope: Option<String>,
    reversibility: Option<String>,
}

/// All conditions of a signal must hold. A list means "one of the items".
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Conditions {
    /// A field value starts with a text. Case matters.
    value_starts: Option<Vec<String>>,
    /// A field value contains a text. Case matters.
    value_contains: Option<Vec<String>>,
    /// A field value is a prefix and a rest of a fixed form.
    value_shape: Option<Shape>,
    /// A field value is a JWT, and each claim is one of the texts.
    jwt_claims: Option<BTreeMap<String, Vec<String>>>,
    /// A field value is a JSON object, and each field is one of the texts.
    json_fields: Option<BTreeMap<String, Vec<String>>>,
    /// The variable name or a field name is one of the names, in lowercase.
    env_names: Option<Vec<String>>,
    /// The variable name or a field name contains a text, in lowercase.
    env_name_contains: Option<Vec<String>>,
    /// A host of the item is a host of the list or a subdomain of it.
    hosts: Option<Vec<String>>,
    /// A word or a phrase of the names and labels, in lowercase.
    words: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Shape {
    starts: Vec<String>,
    min_len: usize,
    max_len: usize,
    chars: Charset,
}

/// The characters of the rest of a value after its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Charset {
    LowerHex,
    UpperAlnum,
    Alnum,
    /// ASCII letters, digits, `-`, `_`, and `.`.
    Token,
}

impl Charset {
    fn accepts(self, c: char) -> bool {
        match self {
            Self::LowerHex => c.is_ascii_digit() || ('a'..='f').contains(&c),
            Self::UpperAlnum => c.is_ascii_uppercase() || c.is_ascii_digit(),
            Self::Alnum => c.is_ascii_alphanumeric(),
            Self::Token => c.is_ascii_alphanumeric() || "-_.".contains(c),
        }
    }
}

// ---- Loaded data ----

/// Declaration fields that one signal suggests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Fields {
    environment: Option<Environment>,
    risk: Option<RiskLevel>,
    scope: Option<Scope>,
    reversibility: Option<Reversibility>,
}

impl Fields {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Signal {
    id: String,
    when: Conditions,
    suggest: Fields,
    reason: String,
    /// How much the signal says about the provider: 3 for a value, 2 for a host, 1 for a
    /// variable name, and 0 for a word.
    strength: u8,
}

/// One built-in provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub id: String,
    pub label: String,
    pub description: String,
    pub version: u64,
    /// Provider API hosts. A host also covers its subdomains.
    pub known_hosts: Vec<String>,
    generic: bool,
    signals: Vec<Signal>,
}

/// All provider files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    providers: Vec<Provider>,
    general: Vec<Signal>,
}

static BUILTIN_CATALOG: LazyLock<Result<Catalog, ProviderError>> =
    LazyLock::new(|| Catalog::from_files(BUILTIN));

/// The built-in catalog. A load error only comes from a broken release. Then there are
/// no suggestions, and a stored provider has no known hosts.
pub fn builtin() -> Result<&'static Catalog, &'static ProviderError> {
    BUILTIN_CATALOG.as_ref()
}

/// A built-in provider by its ID.
pub fn find(id: &str) -> Option<&'static Provider> {
    builtin().ok()?.find(id)
}

/// The known API hosts of a built-in provider. Empty for an unknown ID.
pub fn known_hosts(id: &str) -> &'static [String] {
    find(id).map_or(&[], |provider| provider.known_hosts.as_slice())
}

/// Suggest a declaration with the built-in catalog.
pub fn suggest(facts: &ItemFacts) -> Suggestion {
    builtin().map_or_else(|_| Suggestion::default(), |catalog| catalog.suggest(facts))
}

impl Catalog {
    /// Load provider files: `(file name, JSON text)`. One bad file fails the whole load.
    pub fn from_files(files: &[(&str, &str)]) -> Result<Self, ProviderError> {
        let mut catalog = Self::default();
        for (name, text) in files {
            catalog.add(name, text).map_err(|message| ProviderError {
                source: (*name).to_owned(),
                message,
            })?;
        }
        catalog.providers.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(catalog)
    }

    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    pub fn find(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|provider| provider.id == id)
    }

    fn add(&mut self, name: &str, text: &str) -> Result<(), String> {
        let file: ProviderFile = serde_json::from_str(text).map_err(|error| error.to_string())?;
        if file.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "`schema_version` is {}; this version of Apassy reads version {SCHEMA_VERSION} only",
                file.schema_version
            ));
        }
        if file.provider_version == 0 {
            return Err("`provider_version` starts at 1".to_owned());
        }
        check_id(&file.id, "id")?;
        if name != format!("{}.json", file.id) {
            return Err(format!("the file name must be `{}.json`", file.id));
        }
        let taken = self.providers.iter().any(|p| p.id == file.id)
            || (file.kind == FileKind::General && !self.general.is_empty());
        if taken {
            return Err(format!("`{}` is already loaded", file.id));
        }
        if file.label.trim().is_empty() || file.description.trim().is_empty() {
            return Err("`label` and `description` must have text".to_owned());
        }
        for host in &file.known_hosts {
            check_host(host).map_err(|message| format!("`known_hosts`: {message}"))?;
        }
        match file.kind {
            FileKind::General if file.generic || !file.known_hosts.is_empty() => {
                return Err(
                    "a general file has no provider, so it has no `known_hosts` and no `generic`"
                        .to_owned(),
                );
            }
            FileKind::Provider if !file.generic && file.known_hosts.is_empty() => {
                return Err("a provider needs `known_hosts`, or `generic: true`".to_owned());
            }
            _ => {}
        }
        if file.signals.is_empty() {
            return Err("`signals` is an empty list".to_owned());
        }
        let mut signals: Vec<Signal> = Vec::new();
        for signal in file.signals {
            check_id(&signal.id, "signal id")?;
            if signals.iter().any(|s| s.id == signal.id) {
                return Err(format!("signal `{}` is not unique", signal.id));
            }
            let fail = |message: String| format!("signal `{}`: {message}", signal.id);
            let strength = signal.when.validate().map_err(fail)?;
            let suggest = parse_fields(&signal.suggest).map_err(fail)?;
            if file.kind == FileKind::General && suggest.is_empty() {
                return Err(fail(
                    "a general signal must suggest a field; it names no provider".to_owned(),
                ));
            }
            if signal.reason.trim().is_empty() {
                return Err(fail("`reason` is empty".to_owned()));
            }
            signals.push(Signal {
                id: signal.id,
                when: signal.when,
                suggest,
                reason: signal.reason.trim().to_owned(),
                strength,
            });
        }
        match file.kind {
            FileKind::General => self.general = signals,
            FileKind::Provider => self.providers.push(Provider {
                id: file.id,
                label: file.label,
                description: file.description,
                version: file.provider_version,
                known_hosts: file.known_hosts,
                generic: file.generic,
                signals,
            }),
        }
        Ok(())
    }

    /// Suggest a declaration for one item. Every matching signal adds its fields. The
    /// provider comes from the strongest signal of a specific provider.
    pub fn suggest(&self, facts: &ItemFacts) -> Suggestion {
        let view = FactsView::new(facts);
        let mut suggestion = Suggestion::default();
        let mut votes = Votes::default();
        // (specific, strength) of the best provider so far, its index, and its reason.
        let mut best: Option<((bool, u8), usize, &str)> = None;
        for (index, provider) in self.providers.iter().enumerate() {
            for signal in &provider.signals {
                if !signal.when.matches(&view) {
                    continue;
                }
                suggestion
                    .signals
                    .push(format!("{}/{}", provider.id, signal.id));
                votes.add(&signal.suggest, &signal.reason);
                let rank = (!provider.generic, signal.strength);
                if best.is_none_or(|(current, _, _)| rank > current) {
                    best = Some((rank, index, &signal.reason));
                }
            }
        }
        for signal in &self.general {
            if signal.when.matches(&view) {
                suggestion.signals.push(format!("general/{}", signal.id));
                votes.add(&signal.suggest, &signal.reason);
            }
        }
        if let Some((_, index, reason)) = best {
            suggestion.provider = Some(self.providers[index].id.clone());
            reason.clone_into(&mut suggestion.provider_reason);
        }
        suggestion.environment = merge(votes.environment);
        suggestion.risk = merge(votes.risk);
        suggestion.scope = merge(votes.scope);
        suggestion.reversibility = merge(votes.reversibility);
        suggestion
    }
}

fn check_id(id: &str, field: &str) -> Result<(), String> {
    let good = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if good {
        Ok(())
    } else {
        Err(format!(
            "`{field}` `{id}` must use lowercase letters, digits, `-`, and `_`"
        ))
    }
}

/// A host name in lowercase, such as `api.stripe.com` or `localhost`.
fn check_host(host: &str) -> Result<(), String> {
    let good = !host.is_empty()
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if good {
        Ok(())
    } else {
        Err(format!("`{host}` is not a lowercase host name"))
    }
}

fn check_texts(list: &[String], field: &str, lowercase: bool) -> Result<(), String> {
    if list.is_empty() {
        return Err(format!("`{field}` is an empty list"));
    }
    for text in list {
        if text.trim().is_empty() {
            return Err(format!("`{field}` has an empty text"));
        }
        if lowercase && text.to_lowercase() != *text {
            return Err(format!(
                "`{field}` has `{text}`: the detection compares lowercase text, so use lowercase"
            ));
        }
    }
    Ok(())
}

fn check_claims(map: &BTreeMap<String, Vec<String>>, field: &str) -> Result<(), String> {
    if map.is_empty() {
        return Err(format!("`{field}` is empty"));
    }
    for (name, values) in map {
        if name.is_empty() {
            return Err(format!("`{field}` has an empty name"));
        }
        check_texts(values, &format!("{field}.{name}"), false)?;
    }
    Ok(())
}

impl Conditions {
    /// Check the conditions. Gives the strength of the signal.
    fn validate(&self) -> Result<u8, String> {
        let mut strength = None;
        let mut raise = |level: u8| strength = Some(strength.map_or(level, |s: u8| s.max(level)));
        if let Some(list) = &self.value_starts {
            check_texts(list, "value_starts", false)?;
            raise(3);
        }
        if let Some(list) = &self.value_contains {
            check_texts(list, "value_contains", false)?;
            raise(3);
        }
        if let Some(shape) = &self.value_shape {
            check_texts(&shape.starts, "value_shape.starts", false)?;
            if shape.max_len == 0 || shape.min_len > shape.max_len {
                return Err("`value_shape` needs 0 < `max_len` and `min_len` <= `max_len`".into());
            }
            raise(3);
        }
        if let Some(map) = &self.jwt_claims {
            check_claims(map, "jwt_claims")?;
            raise(3);
        }
        if let Some(map) = &self.json_fields {
            check_claims(map, "json_fields")?;
            raise(3);
        }
        if let Some(list) = &self.hosts {
            check_texts(list, "hosts", true)?;
            for host in list {
                check_host(host).map_err(|message| format!("`hosts`: {message}"))?;
            }
            raise(2);
        }
        if let Some(list) = &self.env_names {
            check_texts(list, "env_names", true)?;
            raise(1);
        }
        if let Some(list) = &self.env_name_contains {
            check_texts(list, "env_name_contains", true)?;
            raise(1);
        }
        if let Some(list) = &self.words {
            check_texts(list, "words", true)?;
            raise(0);
        }
        strength.ok_or_else(|| "`when` has no condition".to_owned())
    }

    fn matches(&self, view: &FactsView<'_>) -> bool {
        let values = || view.values.iter().map(|value| value.as_str());
        let any = |list: &Option<Vec<String>>, test: &dyn Fn(&str) -> bool| {
            list.as_ref()
                .is_none_or(|list| list.iter().any(|t| test(t)))
        };
        any(&self.value_starts, &|prefix| {
            values().any(|v| v.starts_with(prefix))
        }) && any(&self.value_contains, &|part| {
            values().any(|v| v.contains(part))
        }) && self
            .value_shape
            .as_ref()
            .is_none_or(|shape| values().any(|v| shape.matches(v)))
            && self
                .jwt_claims
                .as_ref()
                .is_none_or(|claims| values().any(|v| jwt_claims_match(v, claims)))
            && self
                .json_fields
                .as_ref()
                .is_none_or(|fields| values().any(|v| json_fields_match(v, fields)))
            && any(&self.env_names, &|name| {
                view.env_names.iter().any(|n| n == name)
            })
            && any(&self.env_name_contains, &|part| {
                view.env_names.iter().any(|n| n.contains(part))
            })
            && any(&self.hosts, &|known| {
                view.hosts.iter().any(|h| host_matches(h, known))
            })
            && any(&self.words, &|phrase| view.has_phrase(phrase))
    }
}

impl Shape {
    fn matches(&self, value: &str) -> bool {
        self.starts.iter().any(|prefix| {
            value.strip_prefix(prefix.as_str()).is_some_and(|rest| {
                (self.min_len..=self.max_len).contains(&rest.len())
                    && rest.chars().all(|c| self.chars.accepts(c))
            })
        })
    }
}

fn host_matches(host: &str, known: &str) -> bool {
    host == known
        || host
            .strip_suffix(known)
            .is_some_and(|head| head.ends_with('.'))
}

fn parse_fields(file: &FieldsFile) -> Result<Fields, String> {
    fn one<T>(
        text: Option<&String>,
        field: &str,
        parse: fn(&str) -> super::types::VaultResult<T>,
    ) -> Result<Option<T>, String> {
        text.map(|text| parse(text).map_err(|_| format!("`suggest.{field}` has `{text}`")))
            .transpose()
    }
    Ok(Fields {
        environment: one(file.environment.as_ref(), "environment", Environment::parse)?,
        risk: one(file.risk.as_ref(), "risk", RiskLevel::parse)?,
        scope: one(file.scope.as_ref(), "scope", Scope::parse)?,
        reversibility: one(
            file.reversibility.as_ref(),
            "reversibility",
            Reversibility::parse,
        )?,
    })
}

// ---- Item facts ----

/// One field of an item for the detection. Drop erases the value. Debug hides it.
pub struct FactField {
    pub name: String,
    pub value: Zeroizing<String>,
    pub secret: bool,
}

impl fmt::Debug for FactField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FactField")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("secret", &self.secret)
            .finish()
    }
}

/// What the detection reads from one item: the labels, the variable name, and the
/// field values. Only the owner flow builds it, from the unlocked vault.
#[derive(Debug, Default)]
pub struct ItemFacts {
    pub title: String,
    pub notes: String,
    pub tags: Vec<String>,
    /// The environment variable of the item for agent processes.
    pub env_name: Option<String>,
    pub fields: Vec<FactField>,
}

/// Plain fields whose values are not names or labels.
const NOT_LABEL_FIELDS: &[&str] = &["public_key"];

/// The facts in the forms that the conditions compare.
struct FactsView<'a> {
    values: Vec<&'a Zeroizing<String>>,
    /// The variable name and the field names, in lowercase.
    env_names: Vec<String>,
    /// URL hosts of the values and the notes, and the `host` field.
    hosts: Vec<String>,
    /// Lowercase words of each name or label. A phrase does not cross two labels.
    labels: Vec<Vec<String>>,
}

impl<'a> FactsView<'a> {
    fn new(facts: &'a ItemFacts) -> Self {
        let mut view = Self {
            values: facts.fields.iter().map(|field| &field.value).collect(),
            env_names: Vec::new(),
            hosts: url_hosts(&facts.notes),
            labels: Vec::new(),
        };
        if let Some(name) = &facts.env_name {
            view.env_names.push(name.to_lowercase());
        }
        view.labels.push(words(&facts.title));
        for tag in &facts.tags {
            view.labels.push(words(tag));
        }
        if let Some(name) = &facts.env_name {
            view.labels.push(words(name));
        }
        for field in &facts.fields {
            view.env_names.push(field.name.to_lowercase());
            view.labels.push(words(&field.name));
            let value = field.value.as_str();
            view.hosts.extend(url_hosts(value));
            if field.secret || value.contains("://") || NOT_LABEL_FIELDS.contains(&&*field.name) {
                continue;
            }
            if field.name == "host" {
                let host = value.trim().split(':').next().unwrap_or_default();
                if check_host(&host.to_lowercase()).is_ok() {
                    view.hosts.push(host.to_lowercase());
                }
            } else {
                view.labels.push(words(value));
            }
        }
        view.hosts.sort();
        view.hosts.dedup();
        // The labels of a host are words too: `db.prod.example.com` says prod.
        let host_words: Vec<Vec<String>> = view.hosts.iter().map(|host| words(host)).collect();
        view.labels.extend(host_words);
        view
    }

    fn has_phrase(&self, phrase: &str) -> bool {
        let wanted: Vec<&str> = phrase.split_whitespace().collect();
        self.labels.iter().any(|label| {
            label
                .windows(wanted.len())
                .any(|window| window.iter().zip(&wanted).all(|(a, b)| a == b))
        })
    }
}

/// Lowercase words, split at every character that is not a letter or a digit.
fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The hosts of `scheme://` URLs anywhere in the text. User info and the port go.
pub(crate) fn url_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("://") {
        let has_scheme = rest[..pos]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        let after = &rest[pos + 3..];
        let authority = after
            .split(|c: char| c.is_whitespace() || "/?#\"'`<>(),;|\\".contains(c))
            .next()
            .unwrap_or_default();
        let host = authority
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_end_matches('.')
            .to_lowercase();
        if has_scheme && check_host(&host).is_ok() {
            hosts.push(host);
        }
        rest = after;
    }
    hosts
}

/// The value is a JWT (`header.payload.signature`), and each claim of the payload is a
/// text of its list. The payload of a JWT is not secret. Only the signature is.
fn jwt_claims_match(value: &str, claims: &BTreeMap<String, Vec<String>>) -> bool {
    let mut parts = value.trim().split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(bytes) = base64url_decode(payload) else {
        return false;
    };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(&bytes) else {
        return false;
    };
    claims.iter().all(|(name, allowed)| {
        map.get(name)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| allowed.iter().any(|a| a == text))
    })
}

/// The value is a JSON object, and each named field is a text of its list. The parser
/// keeps only the named fields. It skips the other values, such as a private key.
fn json_fields_match(value: &str, fields: &BTreeMap<String, Vec<String>>) -> bool {
    if !value.trim_start().starts_with('{') {
        return false;
    }
    let wanted: Vec<&str> = fields.keys().map(String::as_str).collect();
    let mut deserializer = serde_json::Deserializer::from_str(value);
    let Ok(found) = (NamedFields { wanted: &wanted }).deserialize(&mut deserializer) else {
        return false;
    };
    fields.iter().all(|(name, allowed)| {
        found
            .get(name)
            .is_some_and(|text| allowed.iter().any(|a| a == text))
    })
}

/// A JSON object reader that keeps the text values of some fields only.
struct NamedFields<'a> {
    wanted: &'a [&'a str],
}

impl<'de> DeserializeSeed<'de> for NamedFields<'_> {
    type Value = BTreeMap<String, String>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for NamedFields<'_> {
    type Value = BTreeMap<String, String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if self.wanted.contains(&key.as_str()) {
                if let serde_json::Value::String(text) = map.next_value()? {
                    found.insert(key, text);
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

/// Base64 with the URL alphabet (RFC 4648 section 5), with or without padding.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ---- Suggestion ----

/// One suggested field and its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggested<T> {
    pub value: T,
    /// Why Apassy suggests the value. With a conflict, it names the other values too.
    pub reason: String,
    /// Signals suggested different values. The value is the most sensitive of them.
    pub conflict: bool,
}

/// A suggested declaration (goal item B4). It has no secret value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Suggestion {
    /// The provider ID, such as `stripe`.
    pub provider: Option<String>,
    /// Why Apassy names the provider.
    pub provider_reason: String,
    pub environment: Option<Suggested<Environment>>,
    pub risk: Option<Suggested<RiskLevel>>,
    pub scope: Option<Suggested<Scope>>,
    pub reversibility: Option<Suggested<Reversibility>>,
    /// The signals that matched, as `file/signal`.
    pub signals: Vec<String>,
}

/// The most sensitive values: the defaults of the declaration form (ADR 0008).
pub const DEFAULT_ENVIRONMENT: Environment = Environment::Production;
pub const DEFAULT_RISK: RiskLevel = RiskLevel::High;
pub const DEFAULT_SCOPE: Scope = Scope::Admin;
pub const DEFAULT_REVERSIBILITY: Reversibility = Reversibility::Irreversible;

impl Suggestion {
    /// No provider and no field.
    pub fn is_empty(&self) -> bool {
        self.provider.is_none()
            && self.environment.is_none()
            && self.risk.is_none()
            && self.scope.is_none()
            && self.reversibility.is_none()
    }

    /// The form that the owner sees: each suggested value, and the most sensitive
    /// default for a field without a suggestion.
    pub fn prefilled(&self) -> SuggestedDeclaration {
        let mut from_signals = Vec::new();
        let mut take = |field: DeclarationField, present: bool| {
            if present {
                from_signals.push(field);
            }
        };
        take(DeclarationField::Provider, self.provider.is_some());
        take(DeclarationField::Environment, self.environment.is_some());
        take(DeclarationField::Risk, self.risk.is_some());
        take(DeclarationField::Scope, self.scope.is_some());
        take(
            DeclarationField::Reversibility,
            self.reversibility.is_some(),
        );
        SuggestedDeclaration {
            provider: self.provider.clone(),
            environment: self
                .environment
                .as_ref()
                .map_or(DEFAULT_ENVIRONMENT, |s| s.value),
            risk: self.risk.as_ref().map_or(DEFAULT_RISK, |s| s.value),
            scope: self.scope.as_ref().map_or(DEFAULT_SCOPE, |s| s.value),
            reversibility: self
                .reversibility
                .as_ref()
                .map_or(DEFAULT_REVERSIBILITY, |s| s.value),
            from_signals,
        }
    }
}

/// The values that the matching signals suggest for each field, with their reasons.
#[derive(Default)]
struct Votes<'a> {
    environment: Vec<(Environment, &'a str)>,
    risk: Vec<(RiskLevel, &'a str)>,
    scope: Vec<(Scope, &'a str)>,
    reversibility: Vec<(Reversibility, &'a str)>,
}

impl<'a> Votes<'a> {
    fn add(&mut self, fields: &Fields, reason: &'a str) {
        if let Some(value) = fields.environment {
            self.environment.push((value, reason));
        }
        if let Some(value) = fields.risk {
            self.risk.push((value, reason));
        }
        if let Some(value) = fields.scope {
            self.scope.push((value, reason));
        }
        if let Some(value) = fields.reversibility {
            self.reversibility.push((value, reason));
        }
    }
}

/// A declaration value with its text. The declaration enums order their values from
/// the least to the most sensitive.
trait FieldValue: Copy + Ord {
    fn text(self) -> &'static str;
}

macro_rules! field_value {
    ($($name:ident),+) => {
        $(impl FieldValue for $name {
            fn text(self) -> &'static str {
                self.as_str()
            }
        })+
    };
}

field_value!(Environment, RiskLevel, Scope, Reversibility);

/// Join the votes for one field. Different values: the most sensitive value wins, and
/// the reason says so.
fn merge<T: FieldValue>(votes: Vec<(T, &str)>) -> Option<Suggested<T>> {
    let chosen = votes.iter().map(|(value, _)| *value).max()?;
    let reasons_for = |value: T| {
        let mut reasons: Vec<&str> = Vec::new();
        for (v, reason) in &votes {
            if *v == value && !reasons.contains(reason) {
                reasons.push(reason);
            }
        }
        reasons.join(" ")
    };
    let mut others: Vec<T> = votes
        .iter()
        .map(|(value, _)| *value)
        .filter(|value| *value != chosen)
        .collect();
    others.sort();
    others.dedup();
    let mut reason = reasons_for(chosen);
    for other in others.iter().rev() {
        reason.push_str(&format!(
            " Another signal suggests {}: {}",
            other.text(),
            reasons_for(*other)
        ));
    }
    if !others.is_empty() {
        reason.push_str(&format!(
            " The signals disagree, so Apassy chose the more sensitive value, {}.",
            chosen.text()
        ));
    }
    Some(Suggested {
        value: chosen,
        reason,
        conflict: !others.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str, secret: bool) -> FactField {
        FactField {
            name: name.to_owned(),
            value: Zeroizing::new(value.to_owned()),
            secret,
        }
    }

    fn key_item(title: &str, value: &str) -> ItemFacts {
        ItemFacts {
            title: title.to_owned(),
            fields: vec![field("token", value, true)],
            ..ItemFacts::default()
        }
    }

    /// A fake value: a public prefix and filler text. Never a real key.
    fn fake(prefix: &str, len: usize) -> String {
        format!(
            "{prefix}{}",
            "EXAMPLE0".repeat(len / 8 + 1)[..len].to_owned()
        )
    }

    #[test]
    fn every_built_in_file_loads() {
        let catalog = builtin().expect("built-in provider files");
        assert!(catalog.providers().len() >= 18);
        assert!(!catalog.general.is_empty());
        for provider in catalog.providers() {
            assert!(
                provider.generic || !provider.known_hosts.is_empty(),
                "{}",
                provider.id
            );
        }
        assert!(known_hosts("stripe").contains(&"api.stripe.com".to_owned()));
        assert!(known_hosts("no-such-provider").is_empty());
    }

    #[test]
    fn live_and_test_keys_suggest_their_environment() {
        let live = suggest(&key_item("Payments", &fake("sk_live_", 24)));
        assert_eq!(live.provider.as_deref(), Some("stripe"));
        assert_eq!(
            live.prefilled(),
            SuggestedDeclaration {
                provider: Some("stripe".to_owned()),
                environment: Environment::Production,
                risk: RiskLevel::High,
                scope: Scope::Admin,
                reversibility: Reversibility::Irreversible,
                from_signals: DeclarationField::ALL.to_vec(),
            }
        );
        let test = suggest(&key_item("Payments", &fake("sk_test_", 24)));
        let environment = test.environment.expect("environment");
        assert_eq!(environment.value, Environment::Staging);
        assert!(!environment.conflict);
        assert_eq!(test.risk.expect("risk").value, RiskLevel::Low);
    }

    /// The example of the goal: a `sk_test_` value, but "prod" in a URL of the item.
    #[test]
    fn conflicting_signals_choose_the_more_sensitive_value_and_say_so() {
        let mut item = key_item("Billing", &fake("sk_test_", 24));
        item.notes = "Used by https://billing.prod.example.com/api".to_owned();
        let suggestion = suggest(&item);
        let environment = suggestion.environment.expect("environment");
        assert_eq!(environment.value, Environment::Production);
        assert!(environment.conflict);
        assert!(
            environment.reason.contains("staging") && environment.reason.contains("more sensitive"),
            "{}",
            environment.reason
        );
        // The other fields have one value each.
        assert_eq!(suggestion.risk.expect("risk").value, RiskLevel::Low);
    }

    #[test]
    fn an_item_without_a_signal_has_no_suggestion() {
        let suggestion = suggest(&key_item("Something", "plain-value-0000"));
        assert!(suggestion.is_empty(), "{suggestion:?}");
        let form = suggestion.prefilled();
        assert!(form.from_signals.is_empty());
        assert_eq!(form.environment, DEFAULT_ENVIRONMENT);
        assert_eq!(form.risk, DEFAULT_RISK);
        assert_eq!(form.scope, DEFAULT_SCOPE);
        assert_eq!(form.reversibility, DEFAULT_REVERSIBILITY);
    }

    /// Base64 with the URL alphabet and no padding, for fake JWTs.
    fn b64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            }
        }
        out
    }

    #[test]
    fn base64url_round_trip() {
        for text in [
            "",
            "f",
            "fo",
            "foo",
            "foob",
            "fooba",
            "foobar",
            "\u{ff}\u{fe}?>",
        ] {
            assert_eq!(
                base64url_decode(&b64url(text.as_bytes())).as_deref(),
                Some(text.as_bytes())
            );
        }
        assert_eq!(base64url_decode("Zm9v!"), None);
    }

    #[test]
    fn supabase_jwt_roles_and_hosts() {
        let jwt = |role: &str| {
            format!(
                "{}.{}.fake-signature",
                b64url(br#"{"alg":"HS256","typ":"JWT"}"#),
                b64url(
                    format!(r#"{{"iss":"supabase","ref":"exampleref","role":"{role}"}}"#)
                        .as_bytes()
                )
            )
        };
        let admin = suggest(&key_item("Backend", &jwt("service_role")));
        assert_eq!(admin.provider.as_deref(), Some("supabase"));
        assert_eq!(admin.scope.expect("scope").value, Scope::Admin);
        let anon = suggest(&key_item("Frontend", &jwt("anon")));
        assert_eq!(anon.scope.expect("scope").value, Scope::ReadOnly);
        // A database host of a hosted provider wins over the generic PostgreSQL URL.
        let url = suggest(&key_item(
            "Database",
            "postgresql://postgres:filler@db.exampleref.supabase.co:5432/postgres",
        ));
        assert_eq!(url.provider.as_deref(), Some("supabase"));
        assert!(url.signals.contains(&"postgres/connection-url".to_owned()));
    }

    #[test]
    fn a_service_account_key_is_read_without_its_other_fields() {
        let value = r#"{"type":"service_account","private_key":"EXAMPLE-NOT-A-KEY","token_uri":"https://oauth2.googleapis.com/token"}"#;
        let suggestion = suggest(&key_item("Terraform", value));
        assert_eq!(suggestion.provider.as_deref(), Some("gcp"));
        assert!(!json_fields_match(
            r#"{"type":"authorized_user"}"#,
            &BTreeMap::from([("type".to_owned(), vec!["service_account".to_owned()])])
        ));
        assert!(!json_fields_match("not json", &BTreeMap::new()));
    }

    #[test]
    fn words_hosts_and_phrases() {
        let mut item = ItemFacts {
            title: "Reporting (read-only)".to_owned(),
            ..ItemFacts::default()
        };
        item.fields
            .push(field("host", "replica.db.internal.example:5432", false));
        item.fields
            .push(field("password", "db.prod.example.com", true));
        let view = FactsView::new(&item);
        assert!(view.has_phrase("read only"));
        assert!(!view.has_phrase("only read"));
        assert_eq!(view.hosts, vec!["replica.db.internal.example".to_owned()]);
        // A secret value gives no words.
        assert!(!view.has_phrase("prod"));
        assert_eq!(
            url_hosts("x https://user:$KEY@evil.example:8443/a and ftp://files.example.org"),
            vec!["evil.example".to_owned(), "files.example.org".to_owned()]
        );
        assert!(url_hosts("https://${HOST}/v1 and ://nothing").is_empty());
        assert!(host_matches("o1.ingest.sentry.io", "sentry.io"));
        assert!(!host_matches("notsentry.io", "sentry.io"));
    }

    #[test]
    fn debug_output_hides_the_values() {
        let secret = fake("sk_live_", 24);
        let item = key_item("Payments", &secret);
        let suggestion = suggest(&item);
        assert!(!format!("{item:?}").contains(&secret));
        assert!(!format!("{suggestion:?}").contains(&secret));
    }

    fn load_one(text: &str) -> Result<Catalog, ProviderError> {
        Catalog::from_files(&[("demo.json", text)])
    }

    const GOOD: &str = r#"{
      "schema_version": 1, "provider_version": 1, "id": "demo", "kind": "provider",
      "label": "Demo", "description": "A demo provider.", "known_hosts": ["api.demo.example"],
      "signals": [ { "id": "key", "when": { "value_starts": ["demo_"] },
                     "suggest": { "risk": "low" }, "reason": "A demo key." } ]
    }"#;

    #[test]
    fn the_loader_rejects_unknown_fields_and_bad_values() {
        load_one(GOOD).expect("the good file loads");
        let bad = [
            GOOD.replace(r#""kind": "provider""#, r#""kind": "provider", "extra": 1"#),
            GOOD.replace(r#""reason": "A demo key.""#, r#""reason": "A demo key.", "allow": true"#),
            GOOD.replace(r#""value_starts""#, r#""value_starts_with""#),
            GOOD.replace(r#""risk": "low""#, r#""risk": "low", "trust": "full""#),
            GOOD.replace(r#""risk": "low""#, r#""risk": "none""#),
            GOOD.replace(r#""schema_version": 1"#, r#""schema_version": 2"#),
            GOOD.replace(r#""provider_version": 1"#, r#""provider_version": 0"#),
            GOOD.replace(r#""id": "demo""#, r#""id": "other""#),
            GOOD.replace("api.demo.example", "API.demo.example"),
            GOOD.replace(r#"["api.demo.example"]"#, "[]"),
            GOOD.replace(r#""kind": "provider""#, r#""kind": "general""#),
            GOOD.replace(r#"{ "value_starts": ["demo_"] }"#, "{}"),
            GOOD.replace(r#"["demo_"]"#, "[]"),
            GOOD.replace(r#""A demo key.""#, r#""""#),
            GOOD.replace(
                r#""value_starts": ["demo_"]"#,
                r#""value_shape": { "starts": ["demo_"], "min_len": 9, "max_len": 3, "chars": "alnum" }"#,
            ),
            GOOD.replace(r#""value_starts": ["demo_"]"#, r#""words": ["Demo"]"#),
        ];
        for text in &bad {
            assert!(load_one(text).is_err(), "must be rejected: {text}");
        }
        let twice = Catalog::from_files(&[("demo.json", GOOD), ("demo.json", GOOD)]);
        assert!(twice.is_err());
    }
}
