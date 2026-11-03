//! Short-lived credentials ("way C") and keys per member in the vault (ADR 0037 stage 6,
//! plan unit D, contract docs/contracts/private-sharing-v1.md sections 3 and 8). The
//! tables are in `schema32.rs`.
//!
//! A source is an item with a `short_lived` row. The row names the kind of the provider
//! call and its settings; the item's own fields hold the long-lived secret. The vault
//! checks the form of a row (the strict settings of section 3.2 and the fields of section
//! 3.1) when it is written, and again when a key holder reads the source for a lease
//! ([`Vault::short_lived_source`]), because the fields can change after the row.
//!
//! Way C is on when the row is `enabled`. Only the owner turns it off or on again
//! (`OwnerAction::ChangeDelivery`); the vault does not check that proof, the caller does,
//! as for the bouncer host. A row that is off keeps its kind and its settings, so a
//! signer item still reads its `region` and `services` ([`ShortLived::settings`]).
//!
//! Nothing here holds a secret: the settings refuse no secret by content, but none of
//! their fields is a secret field of the contract, and [`ShortLivedSource`] is the only
//! type that carries field values, redacted in `Debug`.

use std::collections::BTreeSet;
use std::fmt;

use rusqlite::{OptionalExtension, TransactionBehavior};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::agents::{ActivityDecision, MAX_ACTIVITY_ROWS, from_sql_time, to_sql_time};
use super::types::{Field, SecretValue, VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// The longest settings text that the vault stores.
pub const MAX_SETTINGS_BYTES: usize = 16_384;

fn storage<E>(_: E) -> super::types::VaultError {
    err(VaultErrorKind::Storage)
}

fn invalid() -> super::types::VaultError {
    err(VaultErrorKind::InvalidInput)
}

// ----- kinds -------------------------------------------------------------------------

/// The kinds of a source (contract section 3). The last three are reserved for unit K:
/// a row of a reserved kind is refused until the contract defines its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShortLivedKind {
    AwsSts,
    GithubApp,
    GoogleServiceAccount,
    OauthRefresh,
    CloudflareToken,
    PlanetscalePassword,
    NeonRole,
}

/// One field that a kind reads from its item (contract section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindField {
    pub name: &'static str,
    pub secret: bool,
    pub required: bool,
}

const AWS_FIELDS: [KindField; 2] = [
    KindField {
        name: "access_key_id",
        secret: false,
        required: true,
    },
    KindField {
        name: "secret_access_key",
        secret: true,
        required: true,
    },
];
const GITHUB_FIELDS: [KindField; 3] = [
    KindField {
        name: "app_id",
        secret: false,
        required: true,
    },
    KindField {
        name: "installation_id",
        secret: false,
        required: true,
    },
    KindField {
        name: "private_key",
        secret: true,
        required: true,
    },
];
const GOOGLE_FIELDS: [KindField; 1] = [KindField {
    name: "key_json",
    secret: true,
    required: true,
}];
const OAUTH_FIELDS: [KindField; 3] = [
    KindField {
        name: "client_id",
        secret: false,
        required: true,
    },
    KindField {
        name: "client_secret",
        secret: true,
        required: false,
    },
    KindField {
        name: "refresh_token",
        secret: true,
        required: true,
    },
];

impl ShortLivedKind {
    /// Every kind of the table's `CHECK`, in the order of the contract.
    pub const ALL: [Self; 7] = [
        Self::AwsSts,
        Self::GithubApp,
        Self::GoogleServiceAccount,
        Self::OauthRefresh,
        Self::CloudflareToken,
        Self::PlanetscalePassword,
        Self::NeonRole,
    ];
    /// The kinds that a row may have in contract v1.
    pub const ACTIVE: [Self; 4] = [
        Self::AwsSts,
        Self::GithubApp,
        Self::GoogleServiceAccount,
        Self::OauthRefresh,
    ];

    /// The stored and wire name (snake_case).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwsSts => "aws_sts",
            Self::GithubApp => "github_app",
            Self::GoogleServiceAccount => "google_service_account",
            Self::OauthRefresh => "oauth_refresh",
            Self::CloudflareToken => "cloudflare_token",
            Self::PlanetscalePassword => "planetscale_password",
            Self::NeonRole => "neon_role",
        }
    }

    /// The kind of a stored or wire name.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    fn from_db(text: &str) -> VaultResult<Self> {
        Self::parse(text).ok_or_else(|| err(VaultErrorKind::Storage))
    }

    /// Reserved for unit K: no fields and no settings yet.
    pub fn is_reserved(self) -> bool {
        !Self::ACTIVE.contains(&self)
    }

    /// The owner's name of the kind.
    pub fn label(self) -> &'static str {
        match self {
            Self::AwsSts => "AWS temporary credentials (STS)",
            Self::GithubApp => "GitHub App installation token",
            Self::GoogleServiceAccount => "Google service account access token",
            Self::OauthRefresh => "OAuth access token from a refresh token",
            Self::CloudflareToken => "Cloudflare token for one run",
            Self::PlanetscalePassword => "PlanetScale password for one run",
            Self::NeonRole => "Neon role for one run",
        }
    }

    /// The fields that the key holder reads (contract section 3.1). Empty for a reserved
    /// kind.
    pub fn fields(self) -> &'static [KindField] {
        match self {
            Self::AwsSts => &AWS_FIELDS,
            Self::GithubApp => &GITHUB_FIELDS,
            Self::GoogleServiceAccount => &GOOGLE_FIELDS,
            Self::OauthRefresh => &OAUTH_FIELDS,
            Self::CloudflareToken | Self::PlanetscalePassword | Self::NeonRole => &[],
        }
    }

    /// The variable that detection binds a source of this kind to (S6-14, contract
    /// section 4.1). `None`: the owner chooses the variable.
    pub fn detected_variable(self) -> Option<&'static str> {
        match self {
            Self::AwsSts => Some("AWS_ACCESS_KEY_ID"),
            Self::GoogleServiceAccount => Some("CLOUDSDK_AUTH_ACCESS_TOKEN"),
            _ => None,
        }
    }

    /// The lifetime of a lease of this kind as the catalog shows it, in seconds
    /// (`lease_secs` of `apassy_list_access`, contract section 5.1): 900, or 3600 for a
    /// GitHub installation token. It is not a limit: see [`ShortLivedKind::max_secs`].
    /// The OAuth lease lives as long as the answer's `expires_in` says (section 3.3).
    pub fn lease_secs(self) -> u64 {
        match self {
            Self::GithubApp => 3600,
            _ => 900,
        }
    }

    /// The longest lease of the kind in seconds (`expires_at - made_at`), when the
    /// contract fixes one (section 4): 900 for AWS and Google, 3600 for GitHub. `None`
    /// for OAuth, whose lease lives as long as the provider's `expires_in` says (at most
    /// one hour unless it is revoked at run end, `lease::oauth::MAX_UNREVOKED_SECS`),
    /// and for the reserved kinds.
    pub fn max_secs(self) -> Option<u64> {
        match self {
            Self::AwsSts | Self::GoogleServiceAccount => Some(900),
            Self::GithubApp => Some(3600),
            Self::OauthRefresh
            | Self::CloudflareToken
            | Self::PlanetscalePassword
            | Self::NeonRole => None,
        }
    }

    /// The provider as the lease messages name it ("AWS STS answered 403. ...").
    pub fn provider_label(self) -> &'static str {
        match self {
            Self::AwsSts => "AWS STS",
            Self::GithubApp => "GitHub",
            Self::GoogleServiceAccount => "Google",
            Self::OauthRefresh => "The OAuth token endpoint",
            Self::CloudflareToken => "Cloudflare",
            Self::PlanetscalePassword => "PlanetScale",
            Self::NeonRole => "Neon",
        }
    }
}

impl fmt::Display for ShortLivedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ShortLivedKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ShortLivedKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| de::Error::custom("unknown short-lived kind"))
    }
}

// ----- settings (contract section 3.2) -------------------------------------------------

/// The settings of an `aws_sts` source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsStsSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
}

impl AwsStsSettings {
    /// The default region of the contract.
    pub const DEFAULT_REGION: &'static str = "us-east-1";

    /// The region, or the default `us-east-1`.
    pub fn region(&self) -> &str {
        self.region.as_deref().unwrap_or(Self::DEFAULT_REGION)
    }
}

/// A GitHub permission level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubPermission {
    Read,
    Write,
    Admin,
}

/// The permissions of a GitHub App token: a strict map, in key order, that refuses a
/// duplicate key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GithubPermissions(pub Vec<(String, GithubPermission)>);

impl Serialize for GithubPermissions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, level) in &self.0 {
            map.serialize_entry(name, level)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for GithubPermissions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = GithubPermissions;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of GitHub permissions")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                let mut entries = Vec::new();
                while let Some((name, level)) = map.next_entry::<String, GithubPermission>()? {
                    if !seen.insert(name.clone()) {
                        return Err(de::Error::custom("duplicate permission"));
                    }
                    entries.push((name, level));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(GithubPermissions(entries))
            }
        }
        deserializer.deserialize_map(Strict)
    }
}

/// The settings of a `github_app` source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubAppSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<GithubPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
}

impl GithubAppSettings {
    pub const DEFAULT_API_URL: &'static str = "https://api.github.com";

    pub fn api_url(&self) -> &str {
        self.api_url.as_deref().unwrap_or(Self::DEFAULT_API_URL)
    }
}

/// The settings of a `google_service_account` source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonate: Option<String>,
}

impl GoogleSettings {
    pub const DEFAULT_SCOPE: &'static str = "https://www.googleapis.com/auth/cloud-platform";
}

/// How an OAuth client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OauthClientAuth {
    /// HTTP Basic (RFC 6749 section 2.3.1).
    Basic,
    /// `client_id` and `client_secret` in the form.
    Body,
}

/// The settings of an `oauth_refresh` source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthSettings {
    pub token_url: String,
    pub client_auth: OauthClientAuth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// The settings of a source, by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortLivedSettings {
    AwsSts(AwsStsSettings),
    GithubApp(GithubAppSettings),
    GoogleServiceAccount(GoogleSettings),
    OauthRefresh(OauthSettings),
}

/// The refusal of a reserved kind (unit K defines its fields and settings later).
const RESERVED: &str = "this kind is reserved for a later version of Apassy.";

impl ShortLivedSettings {
    /// Parse and check the settings text of `kind` (contract section 3.2): strict (an
    /// unknown field, a duplicate field, or a wrong type is refused), and each value in
    /// its form. `InvalidInput` for a reserved kind, a text over
    /// [`MAX_SETTINGS_BYTES`], or any refusal.
    pub fn parse(kind: ShortLivedKind, text: &str) -> VaultResult<Self> {
        Self::parse_checked(kind, text).map_err(|_| invalid())
    }

    /// [`ShortLivedSettings::parse`] with the reason of a refusal. The reason names the
    /// setting, never its value.
    pub fn parse_checked(kind: ShortLivedKind, text: &str) -> Result<Self, &'static str> {
        if text.len() > MAX_SETTINGS_BYTES {
            return Err("the settings are longer than 16384 bytes.");
        }
        let settings = match kind {
            ShortLivedKind::AwsSts => Self::AwsSts(strict(text)?),
            ShortLivedKind::GithubApp => Self::GithubApp(strict(text)?),
            ShortLivedKind::GoogleServiceAccount => Self::GoogleServiceAccount(strict(text)?),
            ShortLivedKind::OauthRefresh => Self::OauthRefresh(strict(text)?),
            ShortLivedKind::CloudflareToken
            | ShortLivedKind::PlanetscalePassword
            | ShortLivedKind::NeonRole => return Err(RESERVED),
        };
        settings.check()?;
        Ok(settings)
    }

    /// The kind of these settings.
    pub fn kind(&self) -> ShortLivedKind {
        match self {
            Self::AwsSts(_) => ShortLivedKind::AwsSts,
            Self::GithubApp(_) => ShortLivedKind::GithubApp,
            Self::GoogleServiceAccount(_) => ShortLivedKind::GoogleServiceAccount,
            Self::OauthRefresh(_) => ShortLivedKind::OauthRefresh,
        }
    }

    /// The canonical text that the vault stores: the fields in declaration order, the
    /// unset ones left out, and the GitHub permissions in name order.
    pub fn to_json(&self) -> String {
        let text = match self {
            Self::AwsSts(settings) => serde_json::to_string(settings),
            Self::GithubApp(settings) => serde_json::to_string(settings),
            Self::GoogleServiceAccount(settings) => serde_json::to_string(settings),
            Self::OauthRefresh(settings) => serde_json::to_string(settings),
        };
        // The types serialize only strings, lists, and maps of strings.
        text.unwrap_or_else(|_| "{}".to_owned())
    }

    /// Check each value of the settings against its rule of contract section 3.2. The
    /// parsers call it; a key holder calls it again for settings that it did not parse
    /// (the fields of the types are public). The reason names the setting, never its
    /// value.
    pub fn check(&self) -> Result<(), &'static str> {
        match self {
            Self::AwsSts(settings) => check_aws_settings(settings),
            Self::GithubApp(settings) => check_github_settings(settings),
            Self::GoogleServiceAccount(settings) => check_google_settings(settings),
            Self::OauthRefresh(settings) => check_oauth_settings(settings),
        }
    }
}

fn strict<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, &'static str> {
    const BAD: &str =
        "the settings are not a JSON object of known, distinct fields of the right types.";
    // serde refuses an unknown field (`deny_unknown_fields`), a duplicate field of a
    // struct, and a wrong type; trailing text is refused by `from_str`. A struct also
    // reads from a JSON array, so the settings must be an object.
    if !text.trim_start().starts_with('{') {
        return Err(BAD);
    }
    serde_json::from_str(text).map_err(|_| BAD)
}

fn distinct(list: &[String]) -> bool {
    list.iter().collect::<BTreeSet<_>>().len() == list.len()
}

fn all_chars(text: &str, allowed: impl Fn(char) -> bool) -> bool {
    !text.is_empty() && text.chars().all(allowed)
}

/// Contract section 3.2: `https://` with a host, without userinfo, query, or fragment.
pub fn is_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    url.len() <= 2048
        && !host.is_empty()
        && !rest.contains(['@', '?', '#'])
        && rest.chars().all(|c| c.is_ascii_graphic())
}

/// `[a-z]{2}(-[a-z]+)+-[0-9]+`, for example `eu-central-1`, at most 32 bytes (the
/// region of a SigV4 scope, contract section 7.2).
pub fn is_aws_region(region: &str) -> bool {
    let parts: Vec<&str> = region.split('-').collect();
    region.len() <= 32
        && parts.len() >= 3
        && parts[0].len() == 2
        && all_chars(parts[0], |c| c.is_ascii_lowercase())
        && all_chars(parts[parts.len() - 1], |c| c.is_ascii_digit())
        && parts[1..parts.len() - 1]
            .iter()
            .all(|part| all_chars(part, |c| c.is_ascii_lowercase()))
}

/// `[a-z0-9-]{1,32}`: an AWS service name.
pub fn is_aws_service(name: &str) -> bool {
    name.len() <= 32
        && all_chars(name, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
        })
}

/// `arn:aws:iam::<12 digits>:role/<path and name>`, at most 2048 bytes; the role part
/// is printable ASCII without spaces.
pub fn is_aws_role_arn(arn: &str) -> bool {
    let rest = arn.strip_prefix("arn:aws:iam::").unwrap_or("");
    let (account, role) = rest.split_once(":role/").unwrap_or(("", ""));
    arn.len() <= 2048
        && account.len() == 12
        && all_chars(account, |c| c.is_ascii_digit())
        && all_chars(role, |c| c.is_ascii_graphic())
}

fn check_aws_settings(settings: &AwsStsSettings) -> Result<(), &'static str> {
    let policy_ok = |policy: &String| {
        matches!(
            serde_json::from_str::<serde_json::Value>(policy),
            Ok(serde_json::Value::Object(_))
        )
    };
    let services_ok = |services: &Vec<String>| {
        (1..=16).contains(&services.len())
            && distinct(services)
            && services.iter().all(|service| is_aws_service(service))
    };
    if !settings.role_arn.as_deref().is_none_or(is_aws_role_arn) {
        return Err("the role_arn setting is not arn:aws:iam::<12 digits>:role/<name>.");
    }
    if settings
        .policy
        .as_ref()
        .is_some_and(|policy| policy.len() > 2048)
    {
        return Err("the policy setting is longer than 2048 bytes.");
    }
    if !settings.policy.as_ref().is_none_or(policy_ok) {
        return Err("the policy setting is not the JSON text of a policy object.");
    }
    if !settings.region.as_deref().is_none_or(is_aws_region) {
        return Err("the region setting is not an AWS region such as eu-central-1.");
    }
    if !settings.services.as_ref().is_none_or(services_ok) {
        return Err("the services setting is not 1 to 16 distinct AWS service names.");
    }
    Ok(())
}

fn check_github_settings(settings: &GithubAppSettings) -> Result<(), &'static str> {
    let repositories_ok = |repositories: &Vec<String>| {
        (1..=500).contains(&repositories.len())
            && distinct(repositories)
            && repositories.iter().all(|name| {
                name.len() <= 100
                    && all_chars(name, |c| {
                        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
                    })
            })
    };
    let permissions_ok = |GithubPermissions(permissions): &GithubPermissions| {
        (1..=64).contains(&permissions.len())
            && permissions.iter().all(|(name, _)| {
                name.len() <= 64 && all_chars(name, |c| c.is_ascii_lowercase() || c == '_')
            })
            && permissions
                .iter()
                .enumerate()
                .all(|(index, (name, _))| !permissions[..index].iter().any(|(n, _)| n == name))
    };
    if !settings.repositories.as_ref().is_none_or(repositories_ok) {
        return Err("the repositories setting is not 1 to 500 distinct repository names.");
    }
    if !settings.permissions.as_ref().is_none_or(permissions_ok) {
        return Err("the permissions setting is not 1 to 64 distinct GitHub permission names.");
    }
    if !settings.api_url.as_deref().is_none_or(is_https_url) {
        return Err(
            "the api_url setting is not an https:// URL without userinfo, query, or fragment.",
        );
    }
    Ok(())
}

/// `<name>@<project>.iam.gserviceaccount.com`, at most 254 bytes, without white space.
pub fn is_service_account_email(email: &str) -> bool {
    let (name, domain) = email.split_once('@').unwrap_or(("", ""));
    let project = domain
        .strip_suffix(".iam.gserviceaccount.com")
        .unwrap_or("");
    email.len() <= 254
        && !name.is_empty()
        && !project.is_empty()
        && !email.contains(char::is_whitespace)
        && !project.contains('@')
}

fn check_google_settings(settings: &GoogleSettings) -> Result<(), &'static str> {
    let scopes_ok = |scopes: &Vec<String>| {
        (1..=16).contains(&scopes.len())
            && distinct(scopes)
            && scopes.iter().all(|scope| is_https_url(scope))
    };
    if !settings.scopes.as_ref().is_none_or(scopes_ok) {
        return Err("the scopes setting is not 1 to 16 distinct https:// scope URLs.");
    }
    if !settings
        .impersonate
        .as_deref()
        .is_none_or(is_service_account_email)
    {
        return Err(
            "the impersonate setting is not a service-account email (<name>@<project>.iam.gserviceaccount.com).",
        );
    }
    Ok(())
}

fn check_oauth_settings(settings: &OauthSettings) -> Result<(), &'static str> {
    if !is_https_url(&settings.token_url) {
        return Err(
            "the token_url setting is not an https:// URL without userinfo, query, or fragment.",
        );
    }
    if !settings.revoke_url.as_deref().is_none_or(is_https_url) {
        return Err(
            "the revoke_url setting is not an https:// URL without userinfo, query, or fragment.",
        );
    }
    if !settings
        .scope
        .as_ref()
        .is_none_or(|scope| (1..=1024).contains(&scope.len()))
    {
        return Err("the scope setting is not 1 to 1024 bytes.");
    }
    Ok(())
}

// ----- fields (contract section 3.1) ----------------------------------------------------

/// Whether `value` has the form of the field `name` of `kind` (contract section 3.1).
pub fn field_value_ok(kind: ShortLivedKind, name: &str, value: &str) -> bool {
    field_value_problem(kind, name, value).is_none()
}

/// Why `value` does not have the form of the field `name` of `kind` (contract section
/// 3.1), or `None` when it has. The reason names the field, never its value.
pub fn field_value_problem(kind: ShortLivedKind, name: &str, value: &str) -> Option<String> {
    let problem = |ok: bool, why: &str| (!ok).then(|| why.to_owned());
    match (kind, name) {
        (ShortLivedKind::AwsSts, "access_key_id") if value.starts_with("ASIA") => Some(
            "the access key id is already temporary (ASIA). Use the IAM user's long-lived AKIA key."
                .to_owned(),
        ),
        (ShortLivedKind::AwsSts, "access_key_id") => problem(
            is_aws_access_key_id(value),
            "the field access_key_id is not an IAM user key (AKIA and 16 characters A-Z, 0-9).",
        ),
        (ShortLivedKind::AwsSts, "secret_access_key") => problem(
            is_aws_secret_access_key(value),
            "the field secret_access_key is not 40 characters of A-Z, a-z, 0-9, / and +.",
        ),
        (ShortLivedKind::GithubApp, "app_id" | "installation_id") => {
            (!is_positive_decimal(value))
                .then(|| format!("the field {name} is not a decimal number of at least 1."))
        }
        (ShortLivedKind::GithubApp, "private_key") => problem(
            is_private_key_pem(value),
            "the field private_key is not a PEM RSA PRIVATE KEY or PRIVATE KEY.",
        ),
        (ShortLivedKind::GoogleServiceAccount, "key_json") => {
            crate::lease::google::ServiceAccountKey::read(value)
                .err()
                .map(|why| format!("the field key_json is not a service-account key: {why}"))
        }
        (ShortLivedKind::OauthRefresh, "client_id" | "client_secret") => {
            (!(1..=512).contains(&value.len()))
                .then(|| format!("the field {name} is not 1 to 512 bytes."))
        }
        (ShortLivedKind::OauthRefresh, "refresh_token") => problem(
            (1..=4096).contains(&value.len()),
            "the field refresh_token is not 1 to 4096 bytes.",
        ),
        _ => Some(format!(
            "the field {name} is not a field of the kind {kind}."
        )),
    }
}

/// `AKIA` and 16 characters `A-Z0-9`: a long-lived IAM user key. An `ASIA` key is
/// temporary already and is refused.
pub fn is_aws_access_key_id(value: &str) -> bool {
    value.len() == 20
        && value.starts_with("AKIA")
        && value[4..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// 40 characters `A-Za-z0-9/+`.
pub fn is_aws_secret_access_key(value: &str) -> bool {
    value.len() == 40
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+')
}

fn is_positive_decimal(value: &str) -> bool {
    value.len() <= 20
        && all_chars(value, |c| c.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|n| n >= 1)
}

/// A PEM `RSA PRIVATE KEY` (PKCS#1) or `PRIVATE KEY` (PKCS#8). Only the armor is checked
/// here; the key holder parses the key (`lease::jwt::RsaKey::from_pem`).
pub fn is_private_key_pem(value: &str) -> bool {
    let text = value.trim();
    ["RSA PRIVATE KEY", "PRIVATE KEY"].iter().any(|label| {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        text.starts_with(&begin) && text.ends_with(&end) && text.len() > begin.len() + end.len()
    })
}

/// A service-account key JSON: an object with `"type": "service_account"` and the text
/// fields `client_email`, `private_key` (PEM), and `token_uri` (`https://`) (contract
/// section 3.1). It is read by `lease::google::ServiceAccountKey::read`, which copies
/// the private key only into an erased buffer.
pub fn is_service_account_key(value: &str) -> bool {
    crate::lease::google::ServiceAccountKey::read(value).is_ok()
}

/// Check that `fields` hold what `kind` reads (contract section 3.1): each field of the
/// kind at most once, each required field present, each field with its `secret` flag,
/// and each value in its form. Other fields are ignored. The first problem names a field,
/// never a value. The vault (when a row is written and when a source is read) and the
/// key holder (before a lease) use this one check.
pub fn check_kind_fields<'a>(
    kind: ShortLivedKind,
    fields: impl Iterator<Item = (&'a str, &'a str, bool)> + Clone,
) -> Result<(), String> {
    if kind.is_reserved() {
        return Err(RESERVED.to_owned());
    }
    for rule in kind.fields() {
        let mut matching = fields.clone().filter(|(name, _, _)| *name == rule.name);
        match (matching.next(), matching.next()) {
            (Some(_), Some(_)) => {
                return Err(format!("the item has two fields named {}.", rule.name));
            }
            (None, _) if rule.required => {
                return Err(format!("the item has no field {}.", rule.name));
            }
            (None, _) => {}
            (Some((_, value, secret)), None) => {
                if secret != rule.secret {
                    return Err(if rule.secret {
                        format!("the field {} must be secret.", rule.name)
                    } else {
                        format!("the field {} must not be secret.", rule.name)
                    });
                }
                if let Some(problem) = field_value_problem(kind, rule.name, value) {
                    return Err(problem);
                }
            }
        }
    }
    Ok(())
}

fn check_fields<'a>(
    kind: ShortLivedKind,
    fields: impl Iterator<Item = (&'a str, &'a str, bool)> + Clone,
) -> VaultResult<()> {
    check_kind_fields(kind, fields).map_err(|_| invalid())
}

/// Check the fields of a draft for `kind`: what detection and the new-credential sheet
/// call before they add an item with a source row.
pub fn check_draft_fields(kind: ShortLivedKind, fields: &[Field]) -> VaultResult<()> {
    check_fields(
        kind,
        fields
            .iter()
            .map(|field| (field.name.as_str(), field.value.expose(), field.secret)),
    )
}

// ----- rows ---------------------------------------------------------------------------

/// The `short_lived` row of an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortLived {
    pub item_id: u64,
    pub kind: ShortLivedKind,
    /// The canonical settings text (contract section 3.2). Shown to the owner only.
    pub settings_json: String,
    /// Way C on. A row that is off keeps its kind and settings.
    pub enabled: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl ShortLived {
    /// The parsed settings. `Storage` when the stored text no longer parses (a row
    /// written by a later build).
    pub fn settings(&self) -> VaultResult<ShortLivedSettings> {
        ShortLivedSettings::parse(self.kind, &self.settings_json).map_err(storage)
    }
}

/// What a key holder reads to make a lease: the kind, the settings, and only the fields
/// that the kind names. The values are secret text (`Debug` is redacted, drop erases).
#[derive(Clone)]
pub struct ShortLivedSource {
    pub item_id: u64,
    pub kind: ShortLivedKind,
    pub settings: ShortLivedSettings,
    pub enabled: bool,
    /// The fields of [`ShortLivedKind::fields`] that the item has, in that order.
    pub fields: Vec<Field>,
}

impl ShortLivedSource {
    /// The value of the field `name`, when the item has it.
    pub fn field(&self, name: &str) -> Option<&SecretValue> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| &field.value)
    }
}

impl fmt::Debug for ShortLivedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShortLivedSource")
            .field("item_id", &self.item_id)
            .field("kind", &self.kind)
            .field("settings", &self.settings)
            .field("enabled", &self.enabled)
            .field(
                "fields",
                &self
                    .fields
                    .iter()
                    .map(|field| field.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// What [`Vault::swap_secret_field`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSwap {
    /// The field held the expected value and now holds the new one.
    Stored,
    /// The field no longer held the expected value; nothing was written.
    Changed,
}

/// The provider API that made a member key (contract section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyManagerKind {
    CloudflareToken,
    AwsIam,
}

impl KeyManagerKind {
    pub const ALL: [Self; 2] = [Self::CloudflareToken, Self::AwsIam];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CloudflareToken => "cloudflare_token",
            Self::AwsIam => "aws_iam",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }
}

/// A member key row (contract section 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKey {
    /// The member key item.
    pub item_id: u64,
    /// The team item that the key was made from. `None`: that item is not in this vault
    /// (deleted, or not synced here), but the remote key may still exist.
    pub source_item_id: Option<u64>,
    /// The sync UUID of the team item.
    pub source_uuid: String,
    pub team_id: String,
    pub member_id: u64,
    pub manager: KeyManagerKind,
    /// The provider's id of the key. Not a secret.
    pub remote_id: String,
    pub created_at: u64,
}

/// A member key to record for the item `item_id`, made from `source_item_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMemberKey {
    pub item_id: u64,
    pub source_item_id: u64,
    pub team_id: String,
    pub member_id: u64,
    pub manager: KeyManagerKind,
    pub remote_id: String,
}

fn text_ok(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len()) && text.chars().all(|c| c.is_ascii_graphic())
}

type ShortLivedSql = (i64, String, String, i64, i64, i64);

fn short_lived_from_row(row: ShortLivedSql) -> VaultResult<ShortLived> {
    let (item, kind, settings_json, enabled, created_at, updated_at) = row;
    Ok(ShortLived {
        item_id: to_public_id(item)?,
        kind: ShortLivedKind::from_db(&kind)?,
        settings_json,
        enabled: enabled == 1,
        created_at: from_sql_time(created_at)?,
        updated_at: from_sql_time(updated_at)?,
    })
}

const SHORT_LIVED_SELECT: &str =
    "SELECT item_id, kind, settings, enabled, created_at, updated_at FROM short_lived";

const MEMBER_KEY_SELECT: &str =
    "SELECT m.item_id, s.id, m.source_uuid, m.team_id, m.member_id, m.manager, m.remote_id,
            m.created_at
     FROM member_key m LEFT JOIN item s ON s.uuid = m.source_uuid";

fn member_key_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemberKeySql> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

type MemberKeySql = (i64, Option<i64>, String, String, i64, String, String, i64);

fn member_key_from_sql(row: MemberKeySql) -> VaultResult<MemberKey> {
    let (item, source, source_uuid, team_id, member_id, manager, remote_id, created_at) = row;
    Ok(MemberKey {
        item_id: to_public_id(item)?,
        source_item_id: source.map(to_public_id).transpose()?,
        source_uuid,
        team_id,
        member_id: u64::try_from(member_id).map_err(storage)?,
        manager: KeyManagerKind::parse(&manager).ok_or_else(|| err(VaultErrorKind::Storage))?,
        remote_id,
        created_at: from_sql_time(created_at)?,
    })
}

/// The fields of the item `item` as `(name, value, secret)`, in position order.
fn item_fields(
    conn: &rusqlite::Connection,
    item: i64,
) -> VaultResult<Vec<(String, SecretValue, bool)>> {
    let mut stmt = conn
        .prepare(
            "SELECT name, value, secret FROM item_field WHERE item_id = ?1
             ORDER BY position, rowid",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([item], |row| {
            Ok((
                row.get::<_, String>(0)?,
                SecretValue::new(row.get::<_, String>(1)?),
                row.get::<_, i64>(2)? == 1,
            ))
        })
        .map_err(storage)?;
    rows.collect::<Result<_, _>>().map_err(storage)
}

fn item_exists(conn: &rusqlite::Connection, item: i64) -> VaultResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM item WHERE id = ?1)",
        [item],
        |row| row.get(0),
    )
    .map_err(storage)
}

fn owner_activity(
    tx: &rusqlite::Transaction<'_>,
    at: i64,
    item: i64,
    reason: &str,
) -> VaultResult<()> {
    tx.execute(
        "INSERT INTO activity (at, agent_id, agent_name, item_id, operation, decision, reason)
         VALUES (?1, NULL, 'Owner', ?2, 'change delivery', ?3, ?4)",
        rusqlite::params![at, item, ActivityDecision::Allow.as_str(), reason],
    )
    .map_err(storage)?;
    tx.execute(
        "DELETE FROM activity WHERE id NOT IN
         (SELECT id FROM activity ORDER BY id DESC LIMIT ?1)",
        [i64::try_from(MAX_ACTIVITY_ROWS).map_err(storage)?],
    )
    .map_err(storage)?;
    Ok(())
}

impl Vault {
    /// The source row of `item`. `None`: the item is a static key.
    pub fn short_lived(&self, item: u64) -> VaultResult<Option<ShortLived>> {
        let conn = self.conn_ref()?;
        let row: Option<ShortLivedSql> = conn
            .query_row(
                &format!("{SHORT_LIVED_SELECT} WHERE item_id = ?1"),
                [to_sql_id(item)?],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        row.map(short_lived_from_row).transpose()
    }

    /// Every source row, on or off, in item order (the catalog of the node, the badges
    /// of the item list).
    pub fn short_lived_items(&self) -> VaultResult<Vec<ShortLived>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!("{SHORT_LIVED_SELECT} ORDER BY item_id"))
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(storage)?;
        let rows: Vec<ShortLivedSql> = rows.collect::<Result<_, _>>().map_err(storage)?;
        rows.into_iter().map(short_lived_from_row).collect()
    }

    /// Make `item` a source of `kind` with `settings` (JSON text), or change the kind and
    /// the settings of its row, at `now`. A new row is on; a changed row keeps its
    /// switch (only [`Vault::set_short_lived_enabled`] flips it). Returns the stored row.
    ///
    /// `NotFound`: no such item. `InvalidInput`: a reserved kind, settings that are not
    /// the strict settings of the kind, or fields of the item that are not the fields of
    /// the kind (a missing required field, a wrong `secret` flag, a value in another
    /// form, or a field twice).
    pub fn set_short_lived(
        &mut self,
        item: u64,
        kind: ShortLivedKind,
        settings: &str,
        now: u64,
    ) -> VaultResult<ShortLived> {
        let parsed = ShortLivedSettings::parse(kind, settings)?;
        let canonical = parsed.to_json();
        let sql_id = to_sql_id(item)?;
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if !item_exists(&tx, sql_id)? {
            return Err(err(VaultErrorKind::NotFound));
        }
        let fields = item_fields(&tx, sql_id)?;
        check_fields(
            kind,
            fields
                .iter()
                .map(|(name, value, secret)| (name.as_str(), value.expose(), *secret)),
        )?;
        drop(fields);
        tx.execute(
            "INSERT INTO short_lived (item_id, kind, settings, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?4)
             ON CONFLICT(item_id) DO UPDATE SET kind = excluded.kind,
                 settings = excluded.settings, updated_at = excluded.updated_at",
            rusqlite::params![sql_id, kind.as_str(), canonical, at],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        self.short_lived(item)?
            .ok_or_else(|| err(VaultErrorKind::Storage))
    }

    /// Turn way C on or off for `item` at `now`, with an activity entry, in one
    /// transaction. The kind and the settings stay as they are. The caller has checked
    /// the fresh owner proof of `OwnerAction::ChangeDelivery { item, kind, on }`.
    /// `NotFound`: the item has no source row.
    pub fn set_short_lived_enabled(&mut self, item: u64, on: bool, now: u64) -> VaultResult<()> {
        let sql_id = to_sql_id(item)?;
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let kind: Option<String> = tx
            .query_row(
                "SELECT kind FROM short_lived WHERE item_id = ?1",
                [sql_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(kind) = kind else {
            return Err(err(VaultErrorKind::NotFound));
        };
        let kind = ShortLivedKind::from_db(&kind)?;
        tx.execute(
            "UPDATE short_lived SET enabled = ?1, updated_at = ?2 WHERE item_id = ?3",
            rusqlite::params![i64::from(on), at, sql_id],
        )
        .map_err(storage)?;
        let reason = if on {
            format!("Temporary credentials on ({}).", kind.label())
        } else {
            format!(
                "Temporary credentials off ({}): the item is a static key.",
                kind.label()
            )
        };
        owner_activity(&tx, at, sql_id, &reason)?;
        tx.commit().map_err(storage)
    }

    /// Remove the source row of `item`: the item is a static key again. Returns whether
    /// there was a row. As turning way C off, this needs the owner check of
    /// `OwnerAction::ChangeDelivery { item, kind, on: false }` in the caller.
    pub fn remove_short_lived(&mut self, item: u64, now: u64) -> VaultResult<bool> {
        let sql_id = to_sql_id(item)?;
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let removed = tx
            .execute("DELETE FROM short_lived WHERE item_id = ?1", [sql_id])
            .map_err(storage)?
            > 0;
        if removed {
            owner_activity(
                &tx,
                at,
                sql_id,
                "Temporary credentials removed: the item is a static key.",
            )?;
        }
        tx.commit().map_err(storage)?;
        Ok(removed)
    }

    /// The source of `item` for a lease: its kind, its parsed settings, its switch, and
    /// only the fields that the kind reads, checked again. The caller (the key holder)
    /// makes the lease only when `enabled` and maps an error to `lease_failed`; a signer
    /// may read the settings of a row that is off.
    ///
    /// `NotFound`: no item or no source row. `InvalidInput`: the fields of the item no
    /// longer are the fields of the kind (contract section 3.1), or a reserved kind.
    pub fn short_lived_source(&self, item: u64) -> VaultResult<ShortLivedSource> {
        let row = self
            .short_lived(item)?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        if row.kind.is_reserved() {
            return Err(invalid());
        }
        let settings = row.settings()?;
        let conn = self.conn_ref()?;
        let all = item_fields(conn, to_sql_id(item)?)?;
        check_fields(
            row.kind,
            all.iter()
                .map(|(name, value, secret)| (name.as_str(), value.expose(), *secret)),
        )?;
        let fields = row
            .kind
            .fields()
            .iter()
            .filter_map(|rule| {
                all.iter()
                    .find(|(name, _, _)| name == rule.name)
                    .map(|(name, value, secret)| Field {
                        name: name.clone(),
                        value: value.clone(),
                        secret: *secret,
                    })
            })
            .collect();
        Ok(ShortLivedSource {
            item_id: row.item_id,
            kind: row.kind,
            settings,
            enabled: row.enabled,
            fields,
        })
    }

    /// Store `new` in the secret field `field` of `item` only while the field still holds
    /// `expected`: the compare-and-swap of a rotated OAuth refresh token (contract
    /// private-sharing-v1 section 4.2). One transaction: the value, a new item revision
    /// (so that a synced copy converges on it), and an edit event that names the field,
    /// never a value. [`FieldSwap::Changed`] writes nothing: another run, another Mac
    /// (through sync), or the owner changed the field after the key holder read it.
    ///
    /// `NotFound`: no item or no such field. `InvalidInput`: the field is not secret, is a
    /// passkey field, or `new` is empty or over the field limit.
    pub fn swap_secret_field(
        &mut self,
        item: u64,
        field: &str,
        expected: &SecretValue,
        new: &SecretValue,
    ) -> VaultResult<FieldSwap> {
        if super::is_passkey_field(field)
            || new.expose().is_empty()
            || new.expose().len() > super::types::MAX_FIELD_VALUE_BYTES
        {
            return Err(invalid());
        }
        let sql_id = to_sql_id(item)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row: Option<(i64, SecretValue, bool)> = tx
            .query_row(
                "SELECT rowid, value, secret FROM item_field WHERE item_id = ?1 AND name = ?2",
                rusqlite::params![sql_id, field],
                |row| {
                    Ok((
                        row.get(0)?,
                        SecretValue::new(row.get::<_, String>(1)?),
                        row.get::<_, i64>(2)? == 1,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((rowid, current, secret)) = row else {
            return Err(err(VaultErrorKind::NotFound));
        };
        if !secret {
            return Err(invalid());
        }
        if current != *expected {
            return Ok(FieldSwap::Changed);
        }
        drop(current);
        tx.execute(
            "UPDATE item_field SET value = ?1 WHERE rowid = ?2",
            rusqlite::params![new.expose(), rowid],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE item SET revision = revision + 1 WHERE id = ?1",
            [sql_id],
        )
        .map_err(storage)?;
        super::history::record(
            &tx,
            sql_id,
            super::ItemEventKind::Edited,
            &super::EditChange::detail(&[super::EditChange::Secret(field.to_owned())]),
        )?;
        tx.commit().map_err(storage)?;
        Ok(FieldSwap::Stored)
    }

    /// Record a member key at `now` (unit J2): the item `key.item_id` is the key of one
    /// member, made from the team item `key.source_item_id`.
    ///
    /// `NotFound`: either item is missing. `AlreadyExists`: the item has a member key row.
    /// `InvalidInput`: the same item as source, a team id or remote id outside 1 to 128
    /// and 1 to 256 printable ASCII characters, or member 0.
    pub fn add_member_key(&mut self, key: &NewMemberKey, now: u64) -> VaultResult<MemberKey> {
        if key.item_id == key.source_item_id
            || key.member_id == 0
            || !text_ok(&key.team_id, 128)
            || !text_ok(&key.remote_id, 256)
        {
            return Err(invalid());
        }
        let item = to_sql_id(key.item_id)?;
        let source = to_sql_id(key.source_item_id)?;
        let member = i64::try_from(key.member_id).map_err(|_| invalid())?;
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if !item_exists(&tx, item)? {
            return Err(err(VaultErrorKind::NotFound));
        }
        let source_uuid: Option<Option<String>> = tx
            .query_row("SELECT uuid FROM item WHERE id = ?1", [source], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        let Some(Some(source_uuid)) = source_uuid else {
            return Err(err(VaultErrorKind::NotFound));
        };
        let taken: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM member_key WHERE item_id = ?1)",
                [item],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if taken {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        tx.execute(
            "INSERT INTO member_key
                 (item_id, source_uuid, team_id, member_id, manager, remote_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                item,
                source_uuid,
                key.team_id,
                member,
                key.manager.as_str(),
                key.remote_id,
                at
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        self.member_key(key.item_id)?
            .ok_or_else(|| err(VaultErrorKind::Storage))
    }

    /// The member key row of `item`. `None`: the item is not a member key.
    pub fn member_key(&self, item: u64) -> VaultResult<Option<MemberKey>> {
        let conn = self.conn_ref()?;
        let row = conn
            .query_row(
                &format!("{MEMBER_KEY_SELECT} WHERE m.item_id = ?1"),
                [to_sql_id(item)?],
                member_key_from_row,
            )
            .optional()
            .map_err(storage)?;
        row.map(member_key_from_sql).transpose()
    }

    /// Every member key row, in item order.
    pub fn member_keys(&self) -> VaultResult<Vec<MemberKey>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!("{MEMBER_KEY_SELECT} ORDER BY m.item_id"))
            .map_err(storage)?;
        let rows = stmt.query_map([], member_key_from_row).map_err(storage)?;
        let rows: Vec<MemberKeySql> = rows.collect::<Result<_, _>>().map_err(storage)?;
        rows.into_iter().map(member_key_from_sql).collect()
    }

    /// The member keys of one member of `team_id`, in item order (removal of a member).
    pub fn member_keys_of_member(
        &self,
        team_id: &str,
        member_id: u64,
    ) -> VaultResult<Vec<MemberKey>> {
        Ok(self
            .member_keys()?
            .into_iter()
            .filter(|key| key.team_id == team_id && key.member_id == member_id)
            .collect())
    }

    /// The member keys made from the team item `source`, in item order (archiving the
    /// source).
    pub fn member_keys_of_source(&self, source: u64) -> VaultResult<Vec<MemberKey>> {
        Ok(self
            .member_keys()?
            .into_iter()
            .filter(|key| key.source_item_id == Some(source))
            .collect())
    }

    /// Remove the member key row of `item` (after the remote key was deleted). Returns
    /// whether there was a row.
    pub fn remove_member_key(&mut self, item: u64) -> VaultResult<bool> {
        let sql_id = to_sql_id(item)?;
        let conn = self.conn_mut()?;
        let removed = conn
            .execute("DELETE FROM member_key WHERE item_id = ?1", [sql_id])
            .map_err(storage)?;
        Ok(removed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::ItemDraft;

    const PASS: &str = "synthetic-short-lived-pass";
    const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("v.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    fn field(name: &str, value: &str, secret: bool) -> Field {
        Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        }
    }

    fn item(vault: &mut Vault, fields: Vec<Field>) -> u64 {
        vault
            .add(ItemDraft {
                title: "Synthetic source".to_owned(),
                kind: CredentialKind::Custom,
                notes: String::new(),
                tags: Vec::new(),
                fields,
            })
            .unwrap()
            .id
    }

    fn aws(vault: &mut Vault) -> u64 {
        item(
            vault,
            vec![
                field("access_key_id", KEY_ID, false),
                field("secret_access_key", SECRET, true),
            ],
        )
    }

    #[test]
    fn a_disabled_aws_source_keeps_its_settings_for_a_signer() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let id = aws(&mut vault);
        let settings = r#"{"region":"eu-central-1","services":["s3","dynamodb"],
            "role_arn":"arn:aws:iam::123456789012:role/apassy-test"}"#;
        let row = vault
            .set_short_lived(id, ShortLivedKind::AwsSts, settings, 1_700_000_000)
            .unwrap();
        assert!(row.enabled, "a new source is on");
        vault
            .set_short_lived_enabled(id, false, 1_700_000_100)
            .unwrap();
        let off = vault.short_lived(id).unwrap().expect("the row stays");
        assert!(!off.enabled);
        assert_eq!(off.kind, ShortLivedKind::AwsSts);
        assert_eq!(off.settings_json, row.settings_json);
        assert_eq!(off.created_at, 1_700_000_000);
        assert_eq!(off.updated_at, 1_700_000_100);
        let ShortLivedSettings::AwsSts(aws) = off.settings().unwrap() else {
            panic!("aws settings");
        };
        assert_eq!(aws.region(), "eu-central-1");
        assert_eq!(
            aws.services.as_deref(),
            Some(&["s3".to_owned(), "dynamodb".to_owned()][..])
        );
        // The source still reads, with its switch off: a signer uses the settings and
        // the key holder makes no lease.
        let source = vault.short_lived_source(id).unwrap();
        assert!(!source.enabled);
        assert_eq!(source.settings, ShortLivedSettings::AwsSts(aws.clone()));
        // A change of the settings of a row that is off keeps it off.
        vault
            .set_short_lived(
                id,
                ShortLivedKind::AwsSts,
                r#"{"region":"us-west-2"}"#,
                1_700_000_200,
            )
            .unwrap();
        assert!(!vault.short_lived(id).unwrap().unwrap().enabled);
        // On again: the same row.
        vault
            .set_short_lived_enabled(id, true, 1_700_000_300)
            .unwrap();
        let on = vault.short_lived(id).unwrap().unwrap();
        assert!(on.enabled);
        assert_eq!(on.settings_json, r#"{"region":"us-west-2"}"#);
        // The owner's switch is in the activity log, without a value.
        let reasons: Vec<String> = vault
            .conn_ref()
            .unwrap()
            .prepare("SELECT reason FROM activity WHERE operation = 'change delivery'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(reasons.len(), 2);
        for reason in &reasons {
            assert!(
                !reason.contains(SECRET) && !reason.contains(KEY_ID),
                "{reason}"
            );
        }
    }

    #[test]
    fn the_source_holds_only_the_fields_of_its_kind() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let id = item(
            &mut vault,
            vec![
                field("note", "SYNTH-other-field", true),
                field("secret_access_key", SECRET, true),
                field("access_key_id", KEY_ID, false),
            ],
        );
        vault
            .set_short_lived(id, ShortLivedKind::AwsSts, "{}", 1)
            .unwrap();
        let source = vault.short_lived_source(id).unwrap();
        let names: Vec<&str> = source.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["access_key_id", "secret_access_key"]);
        assert_eq!(source.field("secret_access_key").unwrap().expose(), SECRET);
        assert_eq!(
            source.settings,
            ShortLivedSettings::AwsSts(AwsStsSettings::default())
        );
        let debug = format!("{source:?}");
        assert!(
            !debug.contains(SECRET) && !debug.contains("SYNTH-other-field"),
            "{debug}"
        );
    }

    #[test]
    fn a_row_needs_the_fields_and_strict_settings_of_its_kind() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let id = aws(&mut vault);
        let kind = ShortLivedKind::AwsSts;
        for settings in [
            r#"{"region":"eu-central-1","extra":1}"#,
            r#"{"region":"eu-central-1","region":"us-east-1"}"#,
            r#"{"region":7}"#,
            r#"{"region":"EU"}"#,
            r#"{"services":[]}"#,
            r#"{"services":["s3","s3"]}"#,
            r#"{"role_arn":"arn:aws:iam::12:role/x"}"#,
            r#"{"policy":"[]"}"#,
            "[]",
            "{} trailing",
        ] {
            assert_eq!(
                vault
                    .set_short_lived(id, kind, settings, 1)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput,
                "{settings}"
            );
        }
        // A reserved kind is refused until unit K defines it.
        assert_eq!(
            vault
                .set_short_lived(id, ShortLivedKind::CloudflareToken, "{}", 1)
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        // Fields of another kind, a temporary key, a secret flag that differs.
        for fields in [
            vec![field("access_key_id", KEY_ID, false)],
            vec![
                field("access_key_id", "ASIAIOSFODNN7EXAMPLE", false),
                field("secret_access_key", SECRET, true),
            ],
            vec![
                field("access_key_id", KEY_ID, true),
                field("secret_access_key", SECRET, true),
            ],
            vec![
                field("access_key_id", KEY_ID, false),
                field("secret_access_key", SECRET, false),
            ],
            vec![
                field("access_key_id", KEY_ID, false),
                field("secret_access_key", "short", true),
            ],
        ] {
            let other = item(&mut vault, fields);
            assert_eq!(
                vault
                    .set_short_lived(other, kind, "{}", 1)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput
            );
            assert_eq!(vault.short_lived(other).unwrap(), None);
        }
        assert_eq!(
            vault
                .set_short_lived(999, kind, "{}", 1)
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            vault
                .set_short_lived_enabled(id, false, 1)
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound,
            "no row yet"
        );
    }

    #[test]
    fn a_source_whose_fields_changed_is_refused_at_lease_time() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let id = aws(&mut vault);
        vault
            .set_short_lived(id, ShortLivedKind::AwsSts, "{}", 1)
            .unwrap();
        let revision = vault.details(id).unwrap().summary.revision;
        vault
            .update(
                id,
                revision,
                ItemDraft {
                    title: "Synthetic source".to_owned(),
                    kind: CredentialKind::Custom,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![field("access_key_id", KEY_ID, false)],
                },
            )
            .unwrap();
        assert_eq!(
            vault.short_lived_source(id).unwrap_err().kind(),
            VaultErrorKind::InvalidInput,
            "no fallback to a partial source"
        );
    }

    #[test]
    fn each_active_kind_takes_the_fields_and_settings_of_the_contract() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElD\n-----END RSA PRIVATE KEY-----\n";
        let key_json = r#"{"type":"service_account","client_email":"a@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}"#;
        let cases: Vec<(ShortLivedKind, Vec<Field>, &str)> = vec![
            (
                ShortLivedKind::GithubApp,
                vec![
                    field("app_id", "123456", false),
                    field("installation_id", "7654321", false),
                    field("private_key", pem, true),
                ],
                r#"{"repositories":["apassy"],"permissions":{"contents":"read","metadata":"read"}}"#,
            ),
            (
                ShortLivedKind::GoogleServiceAccount,
                vec![field("key_json", key_json, true)],
                r#"{"scopes":["https://www.googleapis.com/auth/cloud-platform"]}"#,
            ),
            (
                ShortLivedKind::OauthRefresh,
                vec![
                    field("client_id", "synthetic-client", false),
                    field("refresh_token", "SYNTH-refresh", true),
                ],
                r#"{"token_url":"https://auth.example.com/token","client_auth":"body"}"#,
            ),
        ];
        for (kind, fields, settings) in cases {
            let id = item(&mut vault, fields);
            let row = vault.set_short_lived(id, kind, settings, 5).unwrap();
            assert_eq!(row.kind, kind);
            assert_eq!(row.settings().unwrap().kind(), kind);
            assert_eq!(vault.short_lived_source(id).unwrap().kind, kind);
        }
        // Duplicate GitHub permissions and an OAuth source without its required settings
        // are refused.
        assert!(
            ShortLivedSettings::parse(
                ShortLivedKind::GithubApp,
                r#"{"permissions":{"contents":"read","contents":"write"}}"#
            )
            .is_err()
        );
        assert!(ShortLivedSettings::parse(ShortLivedKind::OauthRefresh, "{}").is_err());
        assert!(
            ShortLivedSettings::parse(
                ShortLivedKind::OauthRefresh,
                r#"{"token_url":"http://auth.example.com/token","client_auth":"basic"}"#
            )
            .is_err(),
            "a stored URL is https"
        );
        assert_eq!(vault.short_lived_items().unwrap().len(), 3);
    }

    #[test]
    fn a_member_key_links_two_items_by_uuid_and_goes_with_its_item() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let source = aws(&mut vault);
        let key = aws(&mut vault);
        let new = NewMemberKey {
            item_id: key,
            source_item_id: source,
            team_id: "team-synthetic".to_owned(),
            member_id: 4,
            manager: KeyManagerKind::AwsIam,
            remote_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
        };
        let row = vault.add_member_key(&new, 1_700_000_000).unwrap();
        assert_eq!(row.source_item_id, Some(source));
        assert_eq!(row.member_id, 4);
        assert_eq!(
            vault.add_member_key(&new, 1).unwrap_err().kind(),
            VaultErrorKind::AlreadyExists
        );
        assert_eq!(
            vault.member_keys_of_member("team-synthetic", 4).unwrap(),
            std::slice::from_ref(&row)
        );
        assert_eq!(
            vault.member_keys_of_source(source).unwrap(),
            std::slice::from_ref(&row)
        );
        assert!(
            vault
                .member_keys_of_member("team-synthetic", 5)
                .unwrap()
                .is_empty()
        );
        for bad in [
            NewMemberKey {
                source_item_id: key,
                ..new.clone()
            },
            NewMemberKey {
                member_id: 0,
                ..new.clone()
            },
            NewMemberKey {
                remote_id: String::new(),
                ..new.clone()
            },
            NewMemberKey {
                team_id: "with space".to_owned(),
                ..new.clone()
            },
        ] {
            assert_eq!(
                vault.add_member_key(&bad, 1).unwrap_err().kind(),
                VaultErrorKind::InvalidInput
            );
        }
        // Deleting the source keeps the row of the key: the remote key still exists.
        let revision = vault.details(source).unwrap().summary.revision;
        vault.delete(source, revision).unwrap();
        let kept = vault.member_key(key).unwrap().expect("kept");
        assert_eq!(kept.source_item_id, None);
        assert_eq!(kept.source_uuid, row.source_uuid);
        // Deleting the key item removes its row.
        let revision = vault.details(key).unwrap().summary.revision;
        vault.delete(key, revision).unwrap();
        assert!(vault.member_keys().unwrap().is_empty());
    }

    #[test]
    fn a_rotated_refresh_token_is_stored_by_compare_and_swap() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let oauth_fields = |refresh: &str| {
            vec![
                field("client_id", "synthetic-client", false),
                field("refresh_token", refresh, true),
            ]
        };
        let id = item(&mut vault, oauth_fields("SYNTH-refresh-1"));
        vault
            .set_short_lived(
                id,
                ShortLivedKind::OauthRefresh,
                r#"{"token_url":"https://auth.example.com/token","client_auth":"body"}"#,
                1,
            )
            .unwrap();
        let secret = |text: &str| SecretValue::new(text.to_owned());
        let revision = vault.details(id).unwrap().summary.revision;
        // The field still holds the token that was sent: stored, with a new revision.
        assert_eq!(
            vault
                .swap_secret_field(
                    id,
                    "refresh_token",
                    &secret("SYNTH-refresh-1"),
                    &secret("SYNTH-refresh-2")
                )
                .unwrap(),
            FieldSwap::Stored
        );
        assert_eq!(
            vault.reveal(id, "refresh_token").unwrap().expose(),
            "SYNTH-refresh-2"
        );
        assert_eq!(vault.details(id).unwrap().summary.revision, revision + 1);
        assert_eq!(
            vault
                .short_lived_source(id)
                .unwrap()
                .field("refresh_token")
                .unwrap()
                .expose(),
            "SYNTH-refresh-2"
        );
        // A stale expected token writes nothing.
        assert_eq!(
            vault
                .swap_secret_field(
                    id,
                    "refresh_token",
                    &secret("SYNTH-refresh-1"),
                    &secret("SYNTH-refresh-3")
                )
                .unwrap(),
            FieldSwap::Changed
        );
        assert_eq!(
            vault.reveal(id, "refresh_token").unwrap().expose(),
            "SYNTH-refresh-2"
        );
        assert_eq!(vault.details(id).unwrap().summary.revision, revision + 1);
        // Only a secret field that exists, and never an empty value.
        for (name, new, kind) in [
            ("client_id", "SYNTH-x", VaultErrorKind::InvalidInput),
            ("missing", "SYNTH-x", VaultErrorKind::NotFound),
            ("refresh_token", "", VaultErrorKind::InvalidInput),
        ] {
            assert_eq!(
                vault
                    .swap_secret_field(id, name, &secret("synthetic-client"), &secret(new))
                    .unwrap_err()
                    .kind(),
                kind,
                "{name}"
            );
        }
        // `Vault::update` edits the Custom source item too.
        let revision = vault.details(id).unwrap().summary.revision;
        vault
            .update(
                id,
                revision,
                ItemDraft {
                    title: "Synthetic source".to_owned(),
                    kind: CredentialKind::Custom,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: oauth_fields("SYNTH-refresh-4"),
                },
            )
            .unwrap();
        assert_eq!(
            vault.reveal(id, "refresh_token").unwrap().expose(),
            "SYNTH-refresh-4"
        );
        // The history names the field, never a value.
        let details: Vec<String> = vault
            .conn_ref()
            .unwrap()
            .prepare("SELECT detail FROM item_event WHERE item_id = ?1")
            .unwrap()
            .query_map([i64::try_from(id).unwrap()], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(details.iter().any(|detail| detail == "secret:refresh_token"));
        assert!(details.iter().all(|detail| !detail.contains("SYNTH-refresh")));
    }

    #[test]
    fn deleting_a_source_removes_its_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let id = aws(&mut vault);
        vault
            .set_short_lived(id, ShortLivedKind::AwsSts, "{}", 1)
            .unwrap();
        let revision = vault.details(id).unwrap().summary.revision;
        vault.delete(id, revision).unwrap();
        assert!(vault.short_lived_items().unwrap().is_empty());
        assert!(
            vault
                .remove_short_lived(id, 2)
                .is_ok_and(|removed| !removed)
        );
    }
}
