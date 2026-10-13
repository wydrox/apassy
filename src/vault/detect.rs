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
//! - Each declaration field comes from the strong catalog signals
//!   ([`super::providers::Suggestion::strong`]): a value signal (`sk_live_`, `sk_test_`,
//!   a shape, a JWT, a JSON key file), or an environment word of the variable name
//!   (`STRIPE_LIVE_KEY`, `DEV_API_TOKEN`). Only these have the source [`Source::Signal`].
//!   Two signals that disagree give the more sensitive value.
//! - A weak signal (a host, a field name, a word of a plain field or of the value) never
//!   lowers a value: it can only raise a strong value, and the raised value has the source
//!   [`Source::Default`]. A field without a strong signal gets the most sensitive default
//!   (ADR 0008) with the source [`Source::Default`]. So `localhost` or `127.0.0.1` never
//!   makes a credential local, low-risk, or reversible: a tunnel or a proxy to a
//!   production database has the same URL.
//! - "live", "prod", or "production" as a word of the value is a weak production signal.
//! - A URL is split only when the split is certain (`providers::split_url`): the
//!   user part ends at the last `@` before the host, and an `@` after the first `/`, `?`,
//!   or `#` keeps the whole URL as one secret, with no plain field and a title from the
//!   scheme. A user part without `:` is a token for Redis and RabbitMQ, and for any
//!   scheme when it looks random; then it is secret, not a plain user name.
//! - A title and the result line never have a part of a secret value: they come from the
//!   provider, the scheme, the variable name, or the database name.
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
    /// A strong signal: a value signal of the provider catalog, or an environment word
    /// of the variable name.
    Signal,
    /// No strong signal: the most sensitive value of the declaration form (ADR 0008), or
    /// a value that a weak signal raised above a strong one.
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
        && let Some(lines) = env_lines(catalog, text)
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
/// Two or more entries are a `.env` file when every non-comment line is an assignment
/// (lowercase keys are fine). A single entry is `KEY=value` only when it has `export`,
/// a key like `API_KEY` ([`is_variable_style`]), or the `variable` of a provider. Else
/// the whole text is one raw secret, so that `AB12=xyz` does not make `AB12` a title or
/// a variable. A value that starts with `=` is Base64 padding, not a `.env` entry.
fn env_lines(catalog: &Catalog, text: &str) -> Option<Vec<dotenv::Line>> {
    let (lines, skipped) = dotenv::parse(text);
    if lines.is_empty() || lines.iter().any(|line| line.value.starts_with('=')) {
        return None;
    }
    if skipped.iter().any(|skip| skip.not_env) {
        return None;
    }
    // An empty value or an open quote is still an assignment.
    if lines.len() + skipped.len() >= 2 {
        return Some(lines);
    }
    let exported = text
        .lines()
        .map(str::trim_start)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .is_some_and(|line| line.starts_with("export "));
    let key = lines[0].key.as_str();
    let known = catalog
        .providers()
        .iter()
        .any(|provider| provider.variable == key);
    (exported || is_variable_style(key) || known).then_some(lines)
}

/// A key like `API_KEY`: `^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`, four characters or more.
fn is_variable_style(key: &str) -> bool {
    let mut parts = key.split('_');
    let head = parts.next().unwrap_or_default();
    let valid = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    };
    key.len() >= 4
        && head.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && valid(head)
        && parts.clone().next().is_some()
        && parts.all(valid)
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
    if let Some(scheme) = db_scheme(value) {
        return Some(match DbUrl::parse(value) {
            Some(url) => database_url(catalog, value, &url, key, line),
            None => opaque_url(catalog, value, scheme, key, line),
        });
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
    /// A user part without `:` is a token or a password (`rediss://TOKEN@host`), not a
    /// user name.
    lone_user_is_secret: bool,
}

const DB_SCHEMES: &[DbScheme] = &[
    DbScheme {
        names: &["postgres", "postgresql"],
        label: "PostgreSQL",
        variable: "DATABASE_URL",
        noun: "database",
        lone_user_is_secret: false,
    },
    DbScheme {
        names: &["mysql"],
        label: "MySQL",
        variable: "DATABASE_URL",
        noun: "database",
        lone_user_is_secret: false,
    },
    DbScheme {
        names: &["mongodb", "mongodb+srv"],
        label: "MongoDB",
        variable: "MONGODB_URI",
        noun: "database",
        lone_user_is_secret: false,
    },
    DbScheme {
        names: &["redis", "rediss"],
        label: "Redis",
        variable: "REDIS_URL",
        noun: "database",
        lone_user_is_secret: true,
    },
    DbScheme {
        names: &["amqp", "amqps"],
        label: "RabbitMQ",
        variable: "AMQP_URL",
        noun: "broker",
        lone_user_is_secret: true,
    },
];

/// The scheme of a value that starts with a URL with credentials, as one word without
/// spaces.
fn db_scheme(value: &str) -> Option<&'static DbScheme> {
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let (name, _) = value.split_once("://")?;
    DB_SCHEMES
        .iter()
        .find(|scheme| scheme.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
}

/// A user part (as written) that looks like a token: an escape (`%2F`), long, or mixed
/// case with digits.
fn looks_random(text: &str) -> bool {
    let has = |test: fn(&u8) -> bool| text.bytes().any(|b| test(&b));
    text.contains('%')
        || text.len() >= 24
        || (text.len() >= 12
            && has(u8::is_ascii_uppercase)
            && has(u8::is_ascii_lowercase)
            && has(u8::is_ascii_digit))
}

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
    /// `None` when the split is not certain ([`providers::split_url`]) or the host is
    /// not a host: the caller keeps the whole URL as one secret.
    fn parse(text: &'a str) -> Option<Self> {
        let scheme = db_scheme(text)?;
        let parts = providers::split_url(text)?;
        let host = parts.host;
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:,[]%".contains(&b));
        if !host_ok {
            return None;
        }
        let (user, password) = match parts.user_info {
            Some(info) => match info.split_once(':') {
                Some((user, password)) if !password.is_empty() => (user, Some(password)),
                // A user part without a password may be a token.
                _ => {
                    let lone = info.strip_suffix(':').unwrap_or(info);
                    if scheme.lone_user_is_secret || looks_random(lone) {
                        ("", Some(lone))
                    } else {
                        (lone, None)
                    }
                }
            },
            None => ("", None),
        };
        let database = parts.rest.strip_prefix('/').map_or("", |path| {
            &path[..path.find(['?', '#']).unwrap_or(path.len())]
        });
        Some(Self {
            scheme,
            user,
            password,
            host,
            database,
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
    let mut user = decode(url.user);
    // A user name with `:` or `@` after decoding may hold a part of the password.
    if user.contains([':', '@']) {
        user.clear();
    }
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

/// A URL with credentials whose split is not certain: one secret field with the whole
/// URL, no plain field, and a title from the scheme or a hosted provider.
fn opaque_url(
    catalog: &Catalog,
    value: &str,
    scheme: &DbScheme,
    key: Option<&str>,
    line: Option<usize>,
) -> Detected {
    let env_key = key.map(str::to_ascii_uppercase);
    let facts = ItemFacts {
        env_name: env_key.clone(),
        fields: vec![fact(URL_FIELD, value, true)],
        ..ItemFacts::default()
    };
    let suggestion = catalog.suggest(&facts);
    let provider = suggestion
        .provider
        .as_deref()
        .and_then(|id| catalog.find(id));
    let title = match provider {
        Some(provider) if !provider.is_generic() => format!("{} {}", provider.label, scheme.noun),
        _ => format!("{} {}", scheme.label, scheme.noun),
    };
    let mut detected = declared(&suggestion, false);
    detected.title = clip_title(title);
    detected.kind = CredentialKind::Custom;
    detected.provider = provider.map(|provider| provider.id.clone());
    detected.env_name = match &env_key {
        Some(name) => valid_env_name(name),
        None => valid_env_name(scheme.variable),
    };
    detected.env_field = Some(URL_FIELD.to_owned());
    detected.fields = vec![secret_field(URL_FIELD, value)];
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

/// A detection with the declaration of a suggestion and no item data yet. Only a strong
/// signal sets a value; a weak signal can only raise it. A field without a strong
/// signal gets the most sensitive default. `production`: a production word of the value
/// (a weak signal).
fn declared(suggestion: &Suggestion, production: bool) -> Detected {
    let weak_environment = suggestion
        .environment
        .as_ref()
        .map(|s| s.value)
        .max(production.then_some(Environment::Production));
    let (environment, environment_source) = pick(
        suggestion.strong.environment,
        weak_environment,
        providers::DEFAULT_ENVIRONMENT,
    );
    let (risk, risk_source) = pick(
        suggestion.strong.risk,
        suggestion.risk.as_ref().map(|s| s.value),
        providers::DEFAULT_RISK,
    );
    let (scope, scope_source) = pick(
        suggestion.strong.scope,
        suggestion.scope.as_ref().map(|s| s.value),
        providers::DEFAULT_SCOPE,
    );
    let (reversibility, reversibility_source) = pick(
        suggestion.strong.reversibility,
        suggestion.reversibility.as_ref().map(|s| s.value),
        providers::DEFAULT_REVERSIBILITY,
    );
    Detected {
        title: String::new(),
        kind: CredentialKind::Custom,
        provider: None,
        env_name: None,
        env_field: None,
        hosts: Vec::new(),
        fields: Vec::new(),
        environment,
        risk,
        scope,
        reversibility,
        sources: Sources {
            environment: environment_source,
            risk: risk_source,
            scope: scope_source,
            reversibility: reversibility_source,
        },
        line: None,
    }
}

/// One declaration value. A strong value is a signal. A weak value only raises it, and
/// a raised value is not a signal. Without a strong value: the most sensitive default.
/// `weak` is the most sensitive value of all matching signals, strong and weak.
fn pick<T: Ord + Copy>(strong: Option<T>, weak: Option<T>, default: T) -> (T, Source) {
    match strong {
        Some(strong) => match weak {
            Some(weak) if weak > strong => (weak, Source::Default),
            _ => (strong, Source::Signal),
        },
        None => (default, Source::Default),
    }
}

/// "live", "prod", or "production" is a word of the value (`acme_live_...`). The
/// catalog reads no words from a secret value. This weak rule can only raise the
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
    fn a_weak_value_only_raises_a_strong_value() {
        use RiskLevel::{High, Low, Medium};
        assert_eq!(pick(Some(Low), Some(Low), High), (Low, Source::Signal));
        assert_eq!(
            pick(Some(Medium), Some(Low), High),
            (Medium, Source::Signal)
        );
        assert_eq!(
            pick(Some(Low), Some(Medium), High),
            (Medium, Source::Default)
        );
        assert_eq!(pick(None, Some(Low), High), (High, Source::Default));
        assert_eq!(pick(None::<RiskLevel>, None, High), (High, Source::Default));
    }

    #[test]
    fn a_lone_user_part_is_secret_when_it_looks_random() {
        assert!(looks_random("Rk7Vb2Mn9Qx4Lp3W"));
        assert!(looks_random("0123456789abcdef01234567"));
        assert!(looks_random("a%2Fb"));
        assert!(!looks_random("billing_rw"));
        assert!(!looks_random("app_user_2024"));
        let redis = DbUrl::parse("rediss://tokenvalue@cache.example.com").expect("url");
        assert_eq!((redis.user, redis.password), ("", Some("tokenvalue")));
        let user = DbUrl::parse("postgres://billing_rw:@db.example.com/x").expect("url");
        assert_eq!((user.user, user.password), ("billing_rw", None));
        assert!(DbUrl::parse("postgres://app:a#b@db.example.com/x").is_none());
        assert!(DbUrl::parse("postgres://app:a/b@db.example.com/x").is_none());
    }

    #[test]
    fn production_words_of_a_value() {
        assert!(says_production("acme_live_0000"));
        assert!(says_production("x-PROD-y"));
        assert!(!says_production("delivery0000"));
        assert!(!says_production("productive"));
    }
}
