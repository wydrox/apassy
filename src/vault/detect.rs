//! Paste detection: "two steps to add" (ADR 0025 §4, ADR 0026 §4).
//!
//! [`detect`] reads what the owner pasted into one field: a secret, a `KEY=value`
//! line, a whole `.env` file, a URL with credentials (`postgres://`, `mysql://`,
//! `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://`), or an `otpauth://` link. It
//! gives one [`Detected`] for each credential, with everything that a new item needs:
//! the title, the kind, the provider, the environment variable, the provider hosts,
//! the fields, and a declaration with the source of each value.
//!
//! The detection is pure and runs on this Mac only. It reads the built-in provider
//! catalog ([`super::providers`]): the value prefixes (`sk-ant-`, `ghp_`, `sk_live_`,
//! `AKIA`, ...), the signals, the default variable, and the known hosts. It sends
//! nothing anywhere and touches no vault.
//!
//! Rules:
//!
//! - The provider of a value comes from a value signal of the catalog (a prefix, a
//!   shape, a JWT, a JSON key file), then from the longest value prefix, then from a
//!   host or the variable name.
//! - Each declaration field comes from the catalog signals ([`super::providers`]). Two
//!   signals that disagree give the more sensitive value. A field without a signal
//!   gets the most sensitive default (ADR 0008) with the source [`Source::Default`].
//! - "live", "prod", or "production" as a word of the value or of the variable name
//!   makes the environment production. A word never makes a production value lower.
//! - A value without a provider becomes a Custom item. Its title comes from the
//!   variable name ("Database Password"), or it is "Credential". Without a variable
//!   name it has no variable: the vault then uses `APASSY_ITEM_<id>`.

use crate::contracts::CredentialKind;

use super::agents::{Environment, Reversibility, RiskLevel, Scope, checked_env_name};
use super::providers::{self, Catalog, FactField, ItemFacts, Provider, Suggestion};
use super::suggestions::{DeclarationField, SuggestedDeclaration};
use super::types::{Field, MAX_FIELD_NAME_BYTES, MAX_TITLE_BYTES, SecretValue};

pub mod dotenv;

/// The largest text that the detection reads: the largest item payload of the vault.
pub const MAX_INPUT_BYTES: usize = 1_048_576;

/// The title of a value without a provider and without a variable name.
pub const FALLBACK_TITLE: &str = "Credential";

/// The field of the whole URL of a database URL. The environment variable delivers it.
pub const URL_FIELD: &str = "url";

/// Where a declaration value comes from. The vault stores the text
/// (`declaration_source`, schema 18): `signal` or `default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A signal of the provider catalog, or a production word.
    Signal,
    /// No signal: the most sensitive value of the declaration form (ADR 0008).
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signal => "signal",
            Self::Default => "default",
        }
    }
}

/// The source of each declaration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sources {
    pub environment: Source,
    pub risk: Source,
    pub scope: Source,
    pub reversibility: Source,
}

impl Sources {
    /// Every value is a default.
    pub const DEFAULT: Self = Self {
        environment: Source::Default,
        risk: Source::Default,
        scope: Source::Default,
        reversibility: Source::Default,
    };
}

/// One credential that the detection found. The secret values are in [`Field`]s, which
/// erase them on drop. Debug shows no value.
#[derive(Debug, Clone)]
pub struct Detected {
    /// The item title, such as "Anthropic API key" or "Stripe live".
    pub title: String,
    pub kind: CredentialKind,
    /// The provider ID of the catalog, such as `stripe`.
    pub provider: Option<String>,
    /// The environment variable for agent processes, such as `ANTHROPIC_API_KEY`.
    /// `None`: the vault gives `APASSY_ITEM_<id>` (and a one-time password never goes to
    /// a process).
    pub env_name: Option<String>,
    /// The field that the variable delivers. `None`: the default field of the kind.
    pub env_field: Option<String>,
    /// The known API hosts of the provider: the hosts of a placeholder delivery. Empty
    /// when the value must reach the process as it is (a database URL, an unknown value).
    pub hosts: Vec<String>,
    /// The fields of the item, in order. A secret field has `secret: true`.
    pub fields: Vec<Field>,
    pub environment: Environment,
    pub risk: RiskLevel,
    pub scope: Scope,
    pub reversibility: Reversibility,
    pub sources: Sources,
    /// The line of a `.env` entry, from 1. `None` for a single value.
    pub line: Option<usize>,
}

impl Detected {
    /// A field by its name.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// The main secret: the password of a URL, the token of an API key, the private key
    /// of an SSH key, the setup key of a one-time password, or the value of a Custom
    /// item.
    pub fn secret(&self) -> Option<&SecretValue> {
        let main = match self.kind {
            CredentialKind::ApiKey => Some("token"),
            CredentialKind::Login | CredentialKind::Database => Some("password"),
            CredentialKind::SshKey => Some("private_key"),
            CredentialKind::Custom => None,
        };
        main.and_then(|name| self.field(name))
            .or_else(|| self.fields.iter().find(|field| field.secret))
            .map(|field| &field.value)
    }

    /// The declaration as a suggestion form, for the suggestion record.
    pub fn suggested(&self) -> SuggestedDeclaration {
        let mut from_signals = Vec::new();
        if self.provider.is_some() {
            from_signals.push(DeclarationField::Provider);
        }
        for (field, source) in [
            (DeclarationField::Environment, self.sources.environment),
            (DeclarationField::Risk, self.sources.risk),
            (DeclarationField::Scope, self.sources.scope),
            (DeclarationField::Reversibility, self.sources.reversibility),
        ] {
            if source == Source::Signal {
                from_signals.push(field);
            }
        }
        SuggestedDeclaration {
            provider: self.provider.clone(),
            environment: self.environment,
            risk: self.risk,
            scope: self.scope,
            reversibility: self.reversibility,
            from_signals,
        }
    }
}

/// The result in one line, such as "Anthropic API key · ANTHROPIC_API_KEY ·
/// development". Without a variable: "Credential · production".
pub fn summary_line(detected: &Detected) -> String {
    let mut parts = vec![detected.title.as_str()];
    if let Some(name) = &detected.env_name {
        parts.push(name);
    }
    parts.push(detected.environment.as_str());
    parts.join(" · ")
}

/// Detect the credentials of a pasted text with the built-in catalog. An empty text,
/// a text over [`MAX_INPUT_BYTES`], or an `otpauth://` link that is not a valid TOTP
/// setting gives nothing.
pub fn detect(text: &str) -> Vec<Detected> {
    match providers::builtin() {
        Ok(catalog) => detect_with(catalog, text),
        Err(_) => detect_with(&Catalog::default(), text),
    }
}

/// [`detect`] with a given catalog.
pub fn detect_with(catalog: &Catalog, text: &str) -> Vec<Detected> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_INPUT_BYTES {
        return Vec::new();
    }
    if !is_private_key(text)
        && let Some(lines) = env_lines(text)
    {
        return lines
            .iter()
            .filter_map(|line| {
                one_value(
                    catalog,
                    &line.value,
                    Some(line.key.as_str()),
                    Some(line.line),
                )
            })
            .collect();
    }
    one_value(catalog, text, None, None).into_iter().collect()
}

/// The entries of a `.env` text, or `None` when the text is not one.
///
/// A text with two or more entries is a `.env` file when its entries outnumber its
/// other lines. A single line needs `export`, or a key in uppercase (`API_KEY`) or in
/// lowercase with `_` (`api_key`), so that a password with `=` stays one value. A value
/// that starts with `=` is Base64 padding, not a `.env` entry.
fn env_lines(text: &str) -> Option<Vec<dotenv::Line>> {
    let (lines, skipped) = dotenv::parse(text);
    if lines.is_empty() || lines.iter().any(|line| line.value.starts_with('=')) {
        return None;
    }
    let other = skipped.iter().filter(|skip| skip.not_env).count();
    let file = if lines.len() + skipped.len() >= 2 || text.contains('\n') {
        other == 0 || (lines.len() >= 2 && lines.len() > other)
    } else {
        let exported = text.starts_with("export ");
        let key = &lines[0].key;
        let upper = key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        let lower = key.contains('_')
            && key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        exported || upper || lower
    };
    file.then_some(lines)
}

/// One value, with the variable name of its `.env` line.
fn one_value(
    catalog: &Catalog,
    value: &str,
    key: Option<&str>,
    line: Option<usize>,
) -> Option<Detected> {
    if has_prefix_ignore_case(value, OTP_SCHEME) {
        return one_time_password(value, line);
    }
    if let Some(url) = DbUrl::parse(value) {
        return Some(database_url(catalog, value, &url, key, line));
    }
    if is_private_key(value) {
        return Some(private_key(catalog, value, key, line));
    }
    Some(plain_value(catalog, value, key, line))
}

// ---- Plain values ----

fn plain_value(catalog: &Catalog, value: &str, key: Option<&str>, line: Option<usize>) -> Detected {
    let env_key = key.map(str::to_ascii_uppercase);
    let mut fact_name = key.map_or_else(|| "secret".to_owned(), dotenv::custom_field);
    // The name is ASCII: letters, digits, and `_`.
    fact_name.truncate(MAX_FIELD_NAME_BYTES);
    let facts = ItemFacts {
        env_name: env_key.clone(),
        fields: vec![fact(&fact_name, value, true)],
        ..ItemFacts::default()
    };
    let suggestion = catalog.suggest(&facts);
    let prefix = catalog.prefix_match(value);
    let named = suggestion
        .provider
        .as_deref()
        .and_then(|id| catalog.find(id));
    // A value signal of the catalog wins, then the longest prefix, then a host or the
    // variable name.
    let (provider, by_value) = match (named, prefix) {
        (Some(provider), _) if suggestion.provider_strength >= 3 => (Some(provider), true),
        (_, Some((provider, _))) => (Some(provider), true),
        (named, None) => (named, false),
    };
    let matched_prefix = prefix
        .filter(|(p, _)| provider.is_some_and(|provider| provider.id == p.id))
        .map(|(_, at)| at);
    let title = match (provider, env_key.as_deref()) {
        (Some(provider), _) if by_value => provider_title(provider, matched_prefix),
        (Some(provider), Some(name)) if name == provider.variable => provider_title(provider, None),
        (_, Some(_)) => title_case(key.unwrap_or_default()),
        (Some(provider), None) => provider_title(provider, None),
        (None, None) => FALLBACK_TITLE.to_owned(),
    };
    let env_name = match &env_key {
        Some(name) => valid_env_name(name),
        None => provider.and_then(|provider| valid_env_name(&provider.variable)),
    };
    let (kind, field_name) = match provider {
        Some(_) => (CredentialKind::ApiKey, "token".to_owned()),
        None => (CredentialKind::Custom, fact_name),
    };
    let production = says_production(value);
    let mut detected = declared(&suggestion, production);
    detected.title = clip_title(title);
    detected.kind = kind;
    detected.provider = provider.map(|provider| provider.id.clone());
    detected.env_name = env_name;
    detected.hosts = provider.map_or_else(Vec::new, |provider| provider.known_hosts.clone());
    detected.fields = vec![secret_field(&field_name, value)];
    detected.line = line;
    detected
}

/// The title of a credential of a provider. A prefix with a mode names the mode:
/// `sk_live_` gives "Stripe live", `sk_test_` gives "Stripe test".
fn provider_title(provider: &Provider, prefix: Option<&str>) -> String {
    match prefix {
        Some(prefix) if prefix.contains("_live_") => format!("{} live", provider.label),
        Some(prefix) if prefix.contains("_test_") => format!("{} test", provider.label),
        _ => provider.title.clone(),
    }
}

// ---- Private keys ----

fn is_private_key(value: &str) -> bool {
    value.starts_with("-----BEGIN ") && value.contains("PRIVATE KEY-----")
}

fn private_key(catalog: &Catalog, value: &str, key: Option<&str>, line: Option<usize>) -> Detected {
    let env_key = key.map(str::to_ascii_uppercase);
    let facts = ItemFacts {
        env_name: env_key.clone(),
        fields: vec![fact("private_key", value, true)],
        ..ItemFacts::default()
    };
    let mut detected = declared(&catalog.suggest(&facts), false);
    detected.title = clip_title(key.map_or_else(|| "SSH key".to_owned(), title_case));
    detected.kind = CredentialKind::SshKey;
    detected.env_name = env_key.as_deref().and_then(valid_env_name);
    detected.fields = vec![secret_field("private_key", value)];
    detected.line = line;
    detected
}

// ---- Database URLs ----

/// A URL scheme with credentials: its name, the label for a title, the default
/// variable, and the noun of the title.
struct DbScheme {
    names: &'static [&'static str],
    label: &'static str,
    variable: &'static str,
    noun: &'static str,
}

const DB_SCHEMES: &[DbScheme] = &[
    DbScheme {
        names: &["postgres", "postgresql"],
        label: "PostgreSQL",
        variable: "DATABASE_URL",
        noun: "database",
    },
    DbScheme {
        names: &["mysql"],
        label: "MySQL",
        variable: "DATABASE_URL",
        noun: "database",
    },
    DbScheme {
        names: &["mongodb", "mongodb+srv"],
        label: "MongoDB",
        variable: "MONGODB_URI",
        noun: "database",
    },
    DbScheme {
        names: &["redis", "rediss"],
        label: "Redis",
        variable: "REDIS_URL",
        noun: "database",
    },
    DbScheme {
        names: &["amqp", "amqps"],
        label: "RabbitMQ",
        variable: "AMQP_URL",
        noun: "broker",
    },
];

/// Database names that say nothing about the use, so the title does not use them.
const PLAIN_DATABASE_NAMES: &[&str] = &["postgres", "defaultdb", "admin", "mysql", "default"];

/// The parts of a URL with credentials. The texts are as written (percent-encoded).
struct DbUrl<'a> {
    scheme: &'static DbScheme,
    user: &'a str,
    password: Option<&'a str>,
    /// The host and the port, or several of them (`h1:27017,h2:27017`).
    host: &'a str,
    database: &'a str,
}

impl<'a> DbUrl<'a> {
    fn parse(text: &'a str) -> Option<Self> {
        if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        let (name, rest) = text.split_once("://")?;
        let scheme = DB_SCHEMES
            .iter()
            .find(|scheme| scheme.names.iter().any(|n| n.eq_ignore_ascii_case(name)))?;
        // A password may hold `/` that is not encoded: the last `@` before the query
        // ends the user part.
        let head = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
        let at = head.rfind('@');
        let host_start = at.map_or(0, |at| at + 1);
        let host_end = head[host_start..]
            .find('/')
            .map_or(head.len(), |end| host_start + end);
        let host = &head[host_start..host_end];
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:,[]%".contains(&b));
        if !host_ok {
            return None;
        }
        let (user, password) = match at.map(|at| &head[..at]) {
            Some(info) => match info.split_once(':') {
                Some((user, password)) => (user, Some(password)),
                None => (info, None),
            },
            None => ("", None),
        };
        Some(Self {
            scheme,
            user,
            password,
            host,
            database: head[host_end..].trim_start_matches('/'),
        })
    }
}

fn database_url(
    catalog: &Catalog,
    value: &str,
    url: &DbUrl<'_>,
    key: Option<&str>,
    line: Option<usize>,
) -> Detected {
    let user = decode(url.user);
    let database = decode(url.database);
    let password = url.password.map(decode).filter(|p| !p.is_empty());
    let complete = !user.is_empty() && !database.is_empty() && password.is_some();
    let mut fields = vec![plain_field("host", url.host)];
    if !database.is_empty() {
        fields.push(plain_field("database", &database));
    }
    if !user.is_empty() {
        fields.push(plain_field("username", &user));
    }
    if let Some(password) = &password {
        fields.push(secret_field("password", password));
    }
    fields.push(secret_field(URL_FIELD, value));

    let env_key = key.map(str::to_ascii_uppercase);
    let facts = ItemFacts {
        env_name: env_key.clone(),
        fields: fields
            .iter()
            .map(|field| fact(&field.name, field.value.expose(), field.secret))
            .collect(),
        ..ItemFacts::default()
    };
    let suggestion = catalog.suggest(&facts);
    let provider = suggestion
        .provider
        .as_deref()
        .and_then(|id| catalog.find(id));
    let scheme = url.scheme;
    let named_database = database.chars().any(char::is_alphanumeric)
        && !database.bytes().all(|b| b.is_ascii_digit())
        && !PLAIN_DATABASE_NAMES.contains(&database.to_ascii_lowercase().as_str());
    let title = if named_database {
        format!("{} {}", title_case(&database), scheme.noun)
    } else {
        match provider {
            Some(provider) if !provider.is_generic() => {
                format!("{} {}", provider.label, scheme.noun)
            }
            _ => format!("{} {}", scheme.label, scheme.noun),
        }
    };
    let mut detected = declared(&suggestion, false);
    detected.title = clip_title(title);
    // The kind needs a host, a database, a user, and a password. Without one of them,
    // the URL is a Custom item.
    detected.kind = if complete {
        CredentialKind::Database
    } else {
        CredentialKind::Custom
    };
    detected.provider = provider.map(|provider| provider.id.clone());
    detected.env_name = match &env_key {
        Some(name) => valid_env_name(name),
        None => valid_env_name(scheme.variable),
    };
    detected.env_field = Some(URL_FIELD.to_owned());
    detected.fields = fields;
    detected.line = line;
    detected
}

// ---- One-time passwords ----

const OTP_SCHEME: &str = "otpauth://";

fn one_time_password(value: &str, line: Option<usize>) -> Option<Detected> {
    let value = value.trim();
    crate::otp::Totp::parse(value).ok()?;
    let mut detected = declared(&Suggestion::default(), false);
    detected.title = clip_title(otp_title(value));
    detected.kind = CredentialKind::Custom;
    detected.fields = vec![secret_field(
        &crate::import::detail_field_name(crate::otp::LABEL),
        value,
    )];
    detected.line = line;
    Some(detected)
}

/// "Issuer (account)" from the label and the `issuer` parameter of an `otpauth://`
/// link, or "One-time password".
fn otp_title(uri: &str) -> String {
    let rest = &uri[OTP_SCHEME.len()..];
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = path.split_once('/').map_or("", |(_, label)| label);
    let label = decode(label);
    let (mut issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (issuer.trim().to_owned(), account.trim().to_owned()),
        None => (String::new(), label.trim().to_owned()),
    };
    for pair in query.split('#').next().unwrap_or_default().split('&') {
        if let Some(("issuer", raw)) = pair.split_once('=') {
            let named = decode(&raw.replace('+', " ")).trim().to_owned();
            if !named.is_empty() {
                issuer = named;
            }
        }
    }
    match (issuer.is_empty(), account.is_empty()) {
        (false, false) => format!("{issuer} ({account})"),
        (false, true) => issuer,
        (true, false) => account,
        (true, true) => crate::otp::LABEL.to_owned(),
    }
}

// ---- Declaration ----

/// A detection with the declaration of a suggestion and no item data yet. A field
/// without a signal gets the most sensitive default. `production`: a production word
/// of the value.
fn declared(suggestion: &Suggestion, production: bool) -> Detected {
    let source = |found: bool| {
        if found {
            Source::Signal
        } else {
            Source::Default
        }
    };
    let mut environment = suggestion.environment.as_ref().map(|s| s.value);
    if production {
        environment = Some(Environment::Production);
    }
    let risk = suggestion.risk.as_ref().map(|s| s.value);
    let scope = suggestion.scope.as_ref().map(|s| s.value);
    let reversibility = suggestion.reversibility.as_ref().map(|s| s.value);
    Detected {
        title: String::new(),
        kind: CredentialKind::Custom,
        provider: None,
        env_name: None,
        env_field: None,
        hosts: Vec::new(),
        fields: Vec::new(),
        environment: environment.unwrap_or(providers::DEFAULT_ENVIRONMENT),
        risk: risk.unwrap_or(providers::DEFAULT_RISK),
        scope: scope.unwrap_or(providers::DEFAULT_SCOPE),
        reversibility: reversibility.unwrap_or(providers::DEFAULT_REVERSIBILITY),
        sources: Sources {
            environment: source(environment.is_some()),
            risk: source(risk.is_some()),
            scope: source(scope.is_some()),
            reversibility: source(reversibility.is_some()),
        },
        line: None,
    }
}

/// "live", "prod", or "production" is a word of the value (`acme_live_...`). The
/// catalog reads no words from a secret value, so this rule can only raise the
/// environment to production, never lower it.
fn says_production(value: &str) -> bool {
    value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| {
            ["live", "prod", "production"]
                .iter()
                .any(|w| word.eq_ignore_ascii_case(w))
        })
}

// ---- Helpers ----

fn fact(name: &str, value: &str, secret: bool) -> FactField {
    FactField {
        name: name.to_owned(),
        value: zeroize::Zeroizing::new(value.to_owned()),
        secret,
    }
}

fn secret_field(name: &str, value: &str) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret: true,
    }
}

fn plain_field(name: &str, value: &str) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret: false,
    }
}

/// A variable name that the vault accepts, or `None`.
fn valid_env_name(name: &str) -> Option<String> {
    checked_env_name(name).ok().map(str::to_owned)
}

/// "Database Password" from `DATABASE_PASSWORD`, `database-password`, or `database password`.
fn title_case(text: &str) -> String {
    text.split(|c: char| c == '_' || c == '-' || c.is_whitespace())
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A title of at most [`MAX_TITLE_BYTES`], without control characters.
fn clip_title(title: String) -> String {
    let clean: String = title.chars().filter(|c| !c.is_control()).collect();
    let clean = clean.trim();
    let mut end = clean.len().min(MAX_TITLE_BYTES);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    let clipped = clean[..end].trim_end();
    if clipped.is_empty() {
        FALLBACK_TITLE.to_owned()
    } else {
        clipped.to_owned()
    }
}

fn has_prefix_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// `%XX` of a URL part. A part with a bad escape stays as written.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            match hex {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                None => return text.to_owned(),
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_case_and_clip() {
        assert_eq!(title_case("DATABASE_PASSWORD"), "Database Password");
        assert_eq!(title_case("api-key"), "Api Key");
        assert_eq!(title_case("__X__"), "X");
        assert_eq!(clip_title("a\u{7}b".to_owned()), "ab");
        assert_eq!(clip_title("  ".to_owned()), FALLBACK_TITLE);
        assert_eq!(clip_title("é".repeat(100)).len(), MAX_TITLE_BYTES);
    }

    #[test]
    fn decode_keeps_a_bad_escape() {
        assert_eq!(decode("p%40ss%2Fw"), "p@ss/w");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
    }

    #[test]
    fn production_words_of_a_value() {
        assert!(says_production("acme_live_0000"));
        assert!(says_production("x-PROD-y"));
        assert!(!says_production("delivery0000"));
        assert!(!says_production("productive"));
    }
}
