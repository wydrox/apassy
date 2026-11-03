//! Short-lived credentials, "way C" (ADR 0037 stage 6, contract
//! [`private-sharing-v1`](../../docs/contracts/private-sharing-v1.md), plan s6 units C1,
//! C2, and K).
//!
//! The key holder (the owner's app, its node, or the team host) calls the provider with
//! the long-lived secret of a source item and hands out only the [`Lease`]: a credential
//! for one run that lives at most 15 minutes for AWS and Google and one hour for GitHub.
//! The long-lived secret never leaves this process (contract section 2, rule 1).
//!
//! - [`acquire`] makes a lease from a [`LeaseSource`] after the owner's decision
//!   (rule 5). It has one deadline of 20 seconds for the whole exchange
//!   ([`LEASE_DEADLINE`]). A lease that cannot be made is a [`LeaseError`] with the code
//!   `lease_failed`; the caller MUST NOT fall back to the long-lived value (rule 4).
//! - [`revoke`] ends a lease that has a [`Revoke`] when the run ends (section 4.2).
//! - [`check_source`] runs every check that [`acquire`] runs before its first provider
//!   call.
//! - [`LeaseSource::from_vault`] is the one mapping of a vault source
//!   ([`crate::vault::ShortLivedSource`]) to a lease source.
//! - [`sigv4`] is the AWS Signature Version 4 code that the STS call, the signing
//!   proxies (E1, E2), and the sign endpoint (H) share.
//! - [`scan`] is the no-secret scan of every test of the plan (section 11).
//!
//! The kinds, their fields, and their settings are the vault's types
//! ([`crate::vault::ShortLivedKind`], re-exported here as [`LeaseKind`], and
//! [`crate::vault::ShortLivedSettings`]); the vault and the key holder use one check of
//! the fields ([`crate::vault::check_kind_fields`]) and of the settings
//! ([`crate::vault::ShortLivedSettings::check`]). The providers: [`aws`] (`aws_sts`,
//! unit C1), [`github`] (`github_app`), [`google`] (`google_service_account`), and
//! [`oauth`] (`oauth_refresh`) of unit C2, with [`jwt`] for RS256. Unit K adds
//! `cloudflare`, `planetscale`, and `neon` for the reserved kinds, with their settings
//! variants.
//!
//! Every secret is held in a [`SecretValue`] or a `Zeroizing` buffer, and the provider's
//! answer is erased after it is read (JSON answers through [`json`], which copies a
//! string only into an erased buffer). No error, `Debug` output, or message holds a
//! secret, a lease value, or a provider body (rule 6).

pub mod aws;
pub mod github;
pub mod google;
pub mod holder;
pub(crate) mod json;
pub mod jwt;
pub mod oauth;
pub mod scan;
pub mod sigv4;
#[cfg(test)]
pub(crate) mod testing;

use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::broker::http::{DestinationUrl, HttpFailure, TlsClient, parse_destination};
use crate::vault::{Field, SecretValue, ShortLivedSettings, ShortLivedSource, is_https_url};

/// One row of the field table of contract section 3.1 (the vault's type).
pub use crate::vault::KindField;
/// The kind of a source and of its lease: the vault's [`crate::vault::ShortLivedKind`]
/// (contract section 3), the one definition of the kinds, their fields
/// ([`LeaseKind::fields`]), and their lifetimes ([`LeaseKind::max_secs`],
/// [`LeaseKind::lease_secs`]).
pub use crate::vault::ShortLivedKind as LeaseKind;
/// Check the item's fields against the table of contract section 3.1 (the vault's
/// check): each field of the kind at most once, a required one present, its `secret`
/// flag as in the table, and its value in its form. The text names the field, never a
/// value.
pub use crate::vault::check_kind_fields;

/// The deadline of one lease: name lookup, connect, TLS, and every provider call of the
/// kind (contract section 3.3).
pub const LEASE_DEADLINE: Duration = Duration::from_secs(20);
/// Most `secrets` of one lease (contract section 4).
pub const MAX_LEASE_SECRETS: usize = 4;
/// Most `plain` variables of one lease.
pub const MAX_LEASE_PLAIN: usize = 4;
/// The longest lease value: `check_value` of the relay.
pub const MAX_LEASE_VALUE_BYTES: usize = 4096;
/// The longest variable name: `[A-Z_][A-Z0-9_]{0,127}`.
pub const MAX_VARIABLE_NAME_BYTES: usize = 128;
/// A lease with less time than this left is useless to a run (the relay refuses a
/// lease with less than 60 seconds left, contract section 5.2).
pub const MIN_LEASE_SECS: u64 = 60;
/// The end of every `lease_failed` message (contract section 9).
pub const NOT_RUN: &str = "No temporary credentials were made, so the command did not run.";

/// How far a provider's expiry may be past `made_at + max_secs` before the answer is
/// refused (AWS and Google: 900 s, GitHub: 3600 s). A provider refuses a request whose
/// time is far from its clock (STS: 5 minutes), so a provider that honours the lifetime
/// stays inside this window, while one that ignores it (longer defaults) is refused. The
/// lease never claims more than its kind allows: `expires_at = min(expiry, made_at +
/// max_secs)`.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// A source item as the key holder reads it for one lease ([`LeaseSource::from_vault`]
/// builds it from the vault). `fields` hold the long-lived secret; `Debug` shows their
/// names only. The kind is the kind of the settings, so the two cannot differ.
#[derive(Debug)]
pub struct LeaseSource {
    /// The item's bound variable (`env_binding.env_name`): the name of the lease's first
    /// secret (contract section 4.1).
    pub env_name: String,
    /// The item's fields. Only the fields of [`LeaseKind::fields`] are read.
    pub fields: Vec<Field>,
    /// The `short_lived.settings` of the source (contract section 3.2).
    pub settings: ShortLivedSettings,
}

impl LeaseSource {
    /// The kind of the source: the kind of its settings.
    pub fn kind(&self) -> LeaseKind {
        self.settings.kind()
    }

    /// The lease source of a vault source whose item is bound to `env_name`: the one
    /// mapping of [`ShortLivedSource`] to [`LeaseSource`]. The fields move; no value is
    /// copied. A source whose way C is off is refused (`lease_failed`): its item is a
    /// static key, and a caller that asks for a lease of it has a fault.
    pub fn from_vault(source: ShortLivedSource, env_name: &str) -> Result<Self, LeaseError> {
        let ShortLivedSource {
            kind,
            settings,
            enabled,
            fields,
            ..
        } = source;
        if settings.kind() != kind {
            return Err(LeaseError::invalid_source(
                kind,
                "its settings are of another kind.",
            ));
        }
        if !enabled {
            return Err(LeaseError::invalid_source(
                kind,
                "temporary credentials are off for this item.",
            ));
        }
        Ok(Self {
            env_name: env_name.to_owned(),
            fields,
            settings,
        })
    }
}

/// The run that a lease is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunScope {
    /// The run id or another short label of the run. AWS names the session
    /// `apassy-<label>` (S6-4); a byte outside `[A-Za-z0-9+=,.@_-]` becomes `-`, and the
    /// label is cut to 25 characters (the `GetFederationToken` name has at most 32).
    pub run_label: String,
    /// The lifetime that the caller would like, in seconds. A kind with a fixed lifetime
    /// ignores it: AWS always asks for 900 seconds, its minimum.
    pub ttl_wanted: u64,
}

/// One secret variable of a lease. Masked in the run output and replaced in relay
/// answers (contract section 4).
#[derive(Debug)]
pub struct LeaseSecret {
    pub name: String,
    pub value: SecretValue,
}

/// One variable of a lease that is not a secret (`AWS_CREDENTIAL_EXPIRATION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasePlain {
    pub name: String,
    pub text: String,
}

/// How a lease is ended when the run ends (contract section 4.2). The token to revoke is
/// the lease's first secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revoke {
    /// `DELETE <api_url>/installation/token` with the token as bearer.
    Github { url: String },
    /// RFC 7009 `POST <revoke_url>` with `token` and `token_type_hint=access_token`.
    Oauth { url: String },
}

/// A rotated OAuth refresh token that the caller MUST store before it delivers the lease
/// or fails the run (contract section 4.2): [`holder::KeyHolder`] stores it with a
/// compare-and-swap (`Vault::swap_secret_field`). `Debug` redacts the value; drop erases
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateField {
    pub field: String,
    pub value: SecretValue,
}

/// A short-lived credential for one run (contract section 4). It exists only in this
/// process and on its way to the agent's side; it MUST NOT be written to a file, a
/// database, a log, or an audit row. It has no `Serialize` and no `Clone`, and `Debug`
/// redacts every value.
#[derive(Debug)]
pub struct Lease {
    pub kind: LeaseKind,
    /// 1 to 4 variables; the first is the item's bound variable.
    pub secrets: Vec<LeaseSecret>,
    /// 0 to 4 variables that are not secrets.
    pub plain: Vec<LeasePlain>,
    /// Unix seconds when the key holder sent the provider request.
    pub made_at: u64,
    /// Unix seconds, after `made_at`, at most `made_at + kind.max_secs()`.
    pub expires_at: u64,
    pub revoke: Option<Revoke>,
    pub update_field: Option<UpdateField>,
    /// The provider did not say when the credential expires (an OAuth answer without
    /// `expires_in`, contract section 3.3). Only a lease that is revoked at run end may
    /// have it; its `expires_at` is `made_at + 3600` ([`oauth::MAX_UNREVOKED_SECS`]), not
    /// the provider's expiry. The caller's activity row says so ([`UNKNOWN_EXPIRY_NOTE`]).
    pub expiry_unknown: bool,
}

/// The words of the activity row of a lease whose expiry is unknown.
pub const UNKNOWN_EXPIRY_NOTE: &str = "The token endpoint did not say when the access token expires. Apassy revokes it when the run ends.";

impl Lease {
    /// The variable names: the secrets, then the plain variables, in lease order (the
    /// `env_names` of a `LeaseView`, contract section 5.2).
    pub fn env_names(&self) -> Vec<String> {
        self.secrets
            .iter()
            .map(|secret| secret.name.clone())
            .chain(self.plain.iter().map(|plain| plain.name.clone()))
            .collect()
    }

    /// The value of the secret variable `name`.
    pub fn secret(&self, name: &str) -> Option<&SecretValue> {
        self.secrets
            .iter()
            .find(|secret| secret.name == name)
            .map(|secret| &secret.value)
    }

    /// The lifetime that the lease claims, in seconds.
    pub fn lifetime_secs(&self) -> u64 {
        self.expires_at.saturating_sub(self.made_at)
    }

    /// Check the rules of contract section 4 and the fixed names of section 4.1. A lease
    /// that fails this is never delivered.
    pub fn check(&self) -> Result<(), &'static str> {
        if !(1..=MAX_LEASE_SECRETS).contains(&self.secrets.len()) {
            return Err("A lease has 1 to 4 secret variables.");
        }
        if self.plain.len() > MAX_LEASE_PLAIN {
            return Err("A lease has at most 4 plain variables.");
        }
        let names = self.env_names();
        if !names.iter().all(|name| is_variable_name(name)) {
            return Err("A lease variable name is not valid.");
        }
        if names
            .iter()
            .enumerate()
            .any(|(index, name)| names[..index].contains(name))
        {
            return Err("A lease variable name is used twice.");
        }
        if !self
            .secrets
            .iter()
            .all(|secret| is_lease_value(secret.value.expose()))
        {
            return Err(
                "A lease value is not 1 to 4096 bytes of printable ASCII without quotes and backslashes.",
            );
        }
        if !self.plain.iter().all(|plain| is_plain_text(&plain.text)) {
            return Err("A plain lease variable is not 1 to 4096 bytes of printable ASCII.");
        }
        if self.made_at >= self.expires_at {
            return Err("A lease must expire after it was made.");
        }
        if self
            .kind
            .max_secs()
            .is_some_and(|max| self.lifetime_secs() > max)
        {
            return Err("The lease lives longer than its kind allows.");
        }
        if self.expiry_unknown
            && (self.kind != LeaseKind::OauthRefresh
                || self.revoke.is_none()
                || self.lifetime_secs() != oauth::MAX_UNREVOKED_SECS)
        {
            return Err("Only a revoked OAuth lease has an unknown expiry, shown as one hour.");
        }
        if self.kind == LeaseKind::OauthRefresh
            && self.revoke.is_none()
            && self.lifetime_secs() > oauth::MAX_UNREVOKED_SECS
        {
            return Err("An OAuth lease that is not revoked lives at most one hour.");
        }
        let revoke_ok = match (&self.revoke, self.kind) {
            (None, _) => true,
            (Some(Revoke::Github { url }), LeaseKind::GithubApp) => url
                .strip_suffix(github::REVOKE_PATH)
                .is_some_and(is_https_url),
            (Some(Revoke::Oauth { url }), LeaseKind::OauthRefresh) => is_https_url(url),
            (Some(_), _) => false,
        };
        if !revoke_ok {
            return Err("The revocation does not fit the kind of the lease.");
        }
        if let Some(update) = &self.update_field {
            let value = update.value.expose();
            if self.kind != LeaseKind::OauthRefresh
                || update.field != "refresh_token"
                || value.is_empty()
                || value.len() > MAX_LEASE_VALUE_BYTES
            {
                return Err("Only an OAuth lease rotates its refresh token.");
            }
        }
        match self.kind {
            LeaseKind::AwsSts => {
                let fixed = self.secrets.len() == 3
                    && self.secrets[1].name == aws::SECRET_ACCESS_KEY
                    && self.secrets[2].name == aws::SESSION_TOKEN
                    && self.plain.len() == 1
                    && self.plain[0].name == aws::CREDENTIAL_EXPIRATION
                    && rfc3339(self.expires_at).as_deref() == Some(self.plain[0].text.as_str());
                if !fixed {
                    return Err(
                        "An AWS lease has the bound variable, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, and AWS_CREDENTIAL_EXPIRATION.",
                    );
                }
            }
            LeaseKind::GithubApp | LeaseKind::GoogleServiceAccount | LeaseKind::OauthRefresh => {
                if self.secrets.len() != 1 || !self.plain.is_empty() {
                    return Err("This kind of lease has one secret variable.");
                }
            }
            LeaseKind::CloudflareToken | LeaseKind::PlanetscalePassword | LeaseKind::NeonRole => {}
        }
        Ok(())
    }
}

/// The code of a [`LeaseError`] (contract section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCode {
    /// The lease could not be made: the run does not start, nothing is delivered.
    LeaseFailed,
    /// A revocation at run end failed: an activity or audit row only.
    LeaseRevokeFailed,
}

impl LeaseCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeaseFailed => "lease_failed",
            Self::LeaseRevokeFailed => "lease_revoke_failed",
        }
    }
}

/// What the provider did, for the message and the audit `status` (contract section 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseStatus {
    /// The provider answered with this HTTP status (not a success).
    Http(u16),
    /// No answer before the deadline.
    Timeout,
    /// No connection or no TLS session.
    Unreachable,
    /// An answer that is not the documented form, or a lease that breaks the contract
    /// (a longer lifetime than asked).
    InvalidAnswer,
    /// The source item or its settings are not valid; no provider call was made.
    InvalidSource,
}

impl LeaseStatus {
    /// The audit `status` text: the HTTP status in decimal, `timeout`, `unreachable`,
    /// `invalid_answer`, or `invalid_source`.
    pub fn detail(self) -> String {
        match self {
            Self::Http(status) => status.to_string(),
            Self::Timeout => "timeout".to_owned(),
            Self::Unreachable => "unreachable".to_owned(),
            Self::InvalidAnswer => "invalid_answer".to_owned(),
            Self::InvalidSource => "invalid_source".to_owned(),
        }
    }
}

/// A lease that could not be made or revoked. The message names the provider and its
/// status, never a provider body or a value (contract section 9).
///
/// `update_field` is the one secret that an error may carry: a refresh token that the
/// token endpoint rotated in an answer that was otherwise unusable. The old token may be
/// dead already, so the caller MUST store it (as for a lease) before it fails the run.
/// `Debug` redacts it, and the message never holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseError {
    pub code: LeaseCode,
    pub kind: LeaseKind,
    pub status: LeaseStatus,
    pub message: String,
    pub update_field: Option<UpdateField>,
}

impl LeaseError {
    /// This error with the rotated refresh token `update` to store.
    pub fn with_update_field(mut self, update: Option<UpdateField>) -> Self {
        self.update_field = update;
        self
    }

    /// `lease_failed` with the provider's HTTP status: "AWS STS answered 403. No
    /// temporary credentials were made, so the command did not run."
    pub fn http_status(kind: LeaseKind, status: u16) -> Self {
        Self {
            code: LeaseCode::LeaseFailed,
            kind,
            status: LeaseStatus::Http(status),
            message: format!("{} answered {status}. {NOT_RUN}", kind.provider_label()),
            update_field: None,
        }
    }

    /// `lease_failed` with the provider's HTTP status and a hint for the owner that holds
    /// no value: "Google answered 403. The service account needs … No temporary
    /// credentials were made, so the command did not run."
    pub fn http_status_because(kind: LeaseKind, status: u16, hint: &str) -> Self {
        Self {
            message: format!(
                "{} answered {status}. {hint} {NOT_RUN}",
                kind.provider_label()
            ),
            ..Self::http_status(kind, status)
        }
    }

    /// `lease_failed` for a request that did not get an answer.
    pub fn from_http(kind: LeaseKind, failure: HttpFailure) -> Self {
        let label = kind.provider_label();
        let (status, message) = match failure {
            HttpFailure::Timeout => (
                LeaseStatus::Timeout,
                format!(
                    "{label} did not answer within {} seconds (timeout). {NOT_RUN}",
                    LEASE_DEADLINE.as_secs()
                ),
            ),
            HttpFailure::Connect | HttpFailure::Tls => (
                LeaseStatus::Unreachable,
                format!("{label} could not be reached (unreachable). {NOT_RUN}"),
            ),
            HttpFailure::Protocol | HttpFailure::TooLarge => (
                LeaseStatus::InvalidAnswer,
                format!("{label} gave an invalid answer. {NOT_RUN}"),
            ),
        };
        Self {
            code: LeaseCode::LeaseFailed,
            kind,
            status,
            message,
            update_field: None,
        }
    }

    /// `lease_failed` for an answer that is not the documented form.
    pub fn invalid_answer(kind: LeaseKind) -> Self {
        Self::invalid_answer_because(kind, "")
    }

    /// `lease_failed` for an answer that is not usable, with a reason that holds no value.
    pub fn invalid_answer_because(kind: LeaseKind, reason: &str) -> Self {
        let label = kind.provider_label();
        let message = if reason.is_empty() {
            format!("{label} gave an invalid answer. {NOT_RUN}")
        } else {
            format!("{label} gave an invalid answer: {reason} {NOT_RUN}")
        };
        Self {
            code: LeaseCode::LeaseFailed,
            kind,
            status: LeaseStatus::InvalidAnswer,
            message,
            update_field: None,
        }
    }

    /// `lease_failed` before any provider call: the source or its settings are not
    /// valid. `why` names the field or the setting, never a value.
    pub fn invalid_source(kind: LeaseKind, why: &str) -> Self {
        Self {
            code: LeaseCode::LeaseFailed,
            kind,
            status: LeaseStatus::InvalidSource,
            message: format!(
                "The {} item cannot make temporary credentials: {why} {NOT_RUN}",
                kind.as_str()
            ),
            update_field: None,
        }
    }

    /// `lease_revoke_failed` for a request that did not get an answer.
    pub fn revoke_failed_http(kind: LeaseKind, failure: HttpFailure) -> Self {
        Self::revoke_failed(kind, Self::from_http(kind, failure).status)
    }

    /// `lease_revoke_failed` (an activity or audit row only, never a run error).
    pub fn revoke_failed(kind: LeaseKind, status: LeaseStatus) -> Self {
        Self {
            code: LeaseCode::LeaseRevokeFailed,
            kind,
            status,
            message: format!(
                "{} did not revoke the temporary credentials ({}). They end when they expire.",
                kind.provider_label(),
                status.detail()
            ),
            update_field: None,
        }
    }
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LeaseError {}

/// Where the provider calls go. Production has the real hosts over platform TLS; a test
/// points every provider at a loopback fake (`http://127.0.0.1:<port>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoints {
    /// `None`: `https://sts.<region>.amazonaws.com`, the region of the item's settings.
    /// A test sets one destination for every region.
    pub sts: Option<DestinationUrl>,
    /// The default `api_url` of a GitHub App (`https://api.github.com`).
    pub github: DestinationUrl,
    /// `oauth2.googleapis.com`, for a key whose `token_uri` is the default one.
    pub google_token: DestinationUrl,
    /// `iamcredentials.googleapis.com` (`generateAccessToken`).
    pub google_iam: DestinationUrl,
    /// `api.cloudflare.com` (units J1 and K).
    pub cloudflare: DestinationUrl,
    /// `iam.amazonaws.com`, the global IAM endpoint (unit J1).
    pub aws_iam: DestinationUrl,
    /// `api.planetscale.com` (unit K).
    pub planetscale: DestinationUrl,
    /// `console.neon.tech` (unit K).
    pub neon: DestinationUrl,
    /// `None`: the `token_url` and `revoke_url` hosts of each OAuth source. A test sends
    /// every OAuth call to one destination, with the path of the URL.
    pub oauth: Option<DestinationUrl>,
}

impl ProviderEndpoints {
    /// The real provider hosts on port 443.
    pub fn production() -> Self {
        let https = |host: &str| DestinationUrl::Https {
            host: host.to_owned(),
            port: 443,
        };
        Self {
            sts: None,
            github: https("api.github.com"),
            google_token: https("oauth2.googleapis.com"),
            google_iam: https("iamcredentials.googleapis.com"),
            cloudflare: https("api.cloudflare.com"),
            aws_iam: https("iam.amazonaws.com"),
            planetscale: https("api.planetscale.com"),
            neon: https("console.neon.tech"),
            oauth: None,
        }
    }

    /// Every provider at `destination`: the one loopback fake of a test.
    pub fn all_at(destination: DestinationUrl) -> Self {
        Self {
            sts: Some(destination.clone()),
            github: destination.clone(),
            google_token: destination.clone(),
            google_iam: destination.clone(),
            cloudflare: destination.clone(),
            aws_iam: destination.clone(),
            planetscale: destination.clone(),
            neon: destination.clone(),
            oauth: Some(destination),
        }
    }

    /// The destination and the path prefix (no trailing `/`) of a GitHub `api_url`: the
    /// default `https://api.github.com` is [`ProviderEndpoints::github`]; another URL (a
    /// GitHub Enterprise Server, `https://ghe.example.com/api/v3`) is its own host.
    pub fn github_api(&self, api_url: &str) -> Result<(DestinationUrl, String), &'static str> {
        let api_url = api_url.trim_end_matches('/');
        if api_url == github::DEFAULT_API_URL {
            return Ok((self.github.clone(), String::new()));
        }
        let (destination, path) = https_target(api_url)?;
        Ok((destination, path.trim_end_matches('/').to_owned()))
    }

    /// The destination and the path of a service-account key's `token_uri`: the default
    /// `https://oauth2.googleapis.com/token` is [`ProviderEndpoints::google_token`].
    pub fn google_token_for(
        &self,
        token_uri: &str,
    ) -> Result<(DestinationUrl, String), &'static str> {
        if token_uri == google::DEFAULT_TOKEN_URI {
            return Ok((self.google_token.clone(), google::TOKEN_PATH.to_owned()));
        }
        https_target(token_uri)
    }

    /// The destination and the path of an OAuth `token_url` or `revoke_url`.
    pub fn oauth_for(&self, url: &str) -> Result<(DestinationUrl, String), &'static str> {
        let (destination, path) = https_target(url)?;
        Ok((self.oauth.clone().unwrap_or(destination), path))
    }

    /// The STS destination for `region` (already checked by the settings).
    pub fn sts_for(&self, region: &str) -> Result<DestinationUrl, &'static str> {
        match &self.sts {
            Some(fixed) => Ok(fixed.clone()),
            None => parse_destination(&format!("https://sts.{region}.amazonaws.com")),
        }
    }
}

impl Default for ProviderEndpoints {
    fn default() -> Self {
        Self::production()
    }
}

/// Make the lease of `source` for one run. Call it only after the owner's decision and
/// the broker's second check (contract section 2, rule 5). One deadline of
/// [`LEASE_DEADLINE`] covers the whole exchange. On an error, deliver nothing: no
/// long-lived value, no placeholder, no older lease (rule 4).
pub fn acquire(
    source: &LeaseSource,
    scope: &RunScope,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
) -> Result<Lease, LeaseError> {
    acquire_at(
        source,
        scope,
        endpoints,
        tls,
        Instant::now() + LEASE_DEADLINE,
        unix_now(),
    )
}

/// [`acquire`] with the deadline and the clock given: `now` is the Unix time of the
/// provider request (`made_at`).
pub(crate) fn acquire_at(
    source: &LeaseSource,
    scope: &RunScope,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
    now: u64,
) -> Result<Lease, LeaseError> {
    check_common(source)?;
    let lease = match &source.settings {
        ShortLivedSettings::AwsSts(settings) => {
            aws::acquire(source, settings, scope, endpoints, tls, deadline, now)?
        }
        ShortLivedSettings::GithubApp(settings) => {
            github::acquire(source, settings, endpoints, tls, deadline, now)?
        }
        ShortLivedSettings::GoogleServiceAccount(settings) => {
            google::acquire(source, settings, endpoints, tls, deadline, now)?
        }
        ShortLivedSettings::OauthRefresh(settings) => {
            oauth::acquire(source, settings, endpoints, tls, deadline, now)?
        }
    };
    if lease.kind != source.kind()
        || lease.check().is_err()
        || lease.secrets.first().map(|secret| secret.name.as_str())
            != Some(source.env_name.as_str())
    {
        // A rotated refresh token goes with the error: the caller still stores it.
        let mut lease = lease;
        return Err(LeaseError::invalid_answer(source.kind())
            .with_update_field(lease.update_field.take()));
    }
    Ok(lease)
}

/// End a lease that has a [`Revoke`] (contract section 4.2), best effort, within
/// [`LEASE_DEADLINE`]. A lease without one ends when it expires: `Ok`. An error is
/// `lease_revoke_failed`, for an activity or audit row only.
///
/// `source` is the lease's source, read again from the vault at run end (the key holder
/// drops it before the process spawns). GitHub needs none: the token revokes itself. An
/// RFC 7009 revocation authenticates a confidential client as the token request did
/// (`client_auth`); without the source it sends the token alone, which is enough for a
/// public client and for a provider that does not authenticate revocations.
pub fn revoke(
    lease: &Lease,
    source: Option<&LeaseSource>,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
) -> Result<(), LeaseError> {
    revoke_at(
        lease,
        source,
        endpoints,
        tls,
        Instant::now() + LEASE_DEADLINE,
    )
}

/// [`revoke`] with the deadline given.
pub(crate) fn revoke_at(
    lease: &Lease,
    source: Option<&LeaseSource>,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
) -> Result<(), LeaseError> {
    let Some(revoke) = &lease.revoke else {
        return Ok(());
    };
    let refused = || LeaseError::revoke_failed(lease.kind, LeaseStatus::InvalidSource);
    let token = lease.secrets.first().ok_or_else(refused)?;
    match (revoke, lease.kind) {
        (Revoke::Github { url }, LeaseKind::GithubApp) => {
            github::revoke(url, &token.value, endpoints, tls, deadline)
        }
        (Revoke::Oauth { url }, LeaseKind::OauthRefresh) => {
            let source = match source {
                Some(source) => match &source.settings {
                    ShortLivedSettings::OauthRefresh(settings) => Some((source, settings)),
                    _ => return Err(refused()),
                },
                None => None,
            };
            oauth::revoke(url, &token.value, source, endpoints, tls, deadline)
        }
        _ => Err(refused()),
    }
}

/// Run every check that [`acquire`] runs before its first provider call: the variable
/// name, the settings, the fields of the kind, and the kind's own checks (the AWS fixed
/// names, the RSA key of a GitHub App, the service-account key and the account it acts
/// as). An error is `lease_failed` with [`LeaseStatus::InvalidSource`]; its text names
/// the field or the setting, never a value. The vault checks the form when a row is
/// written (`Vault::set_short_lived`); this also parses the keys.
pub fn check_source(source: &LeaseSource) -> Result<(), LeaseError> {
    check_common(source)?;
    match &source.settings {
        ShortLivedSettings::AwsSts(_) => aws::check_names(source),
        ShortLivedSettings::GithubApp(_) => github::prepare(source).map(drop),
        ShortLivedSettings::GoogleServiceAccount(settings) => {
            google::prepare(source, settings).map(drop)
        }
        ShortLivedSettings::OauthRefresh(_) => oauth::prepare(source).map(drop),
    }
}

/// The checks of every kind: the variable name, the settings, and the fields.
fn check_common(source: &LeaseSource) -> Result<(), LeaseError> {
    let kind = source.kind();
    let invalid = |why: &str| LeaseError::invalid_source(kind, why);
    if !is_variable_name(&source.env_name) {
        return Err(invalid("its variable name is not valid."));
    }
    source.settings.check().map_err(invalid)?;
    check_fields(kind, &source.fields).map_err(|why| invalid(&why))
}

/// [`check_kind_fields`] for a list of fields.
pub fn check_fields(kind: LeaseKind, fields: &[Field]) -> Result<(), String> {
    check_kind_fields(
        kind,
        fields
            .iter()
            .map(|field| (field.name.as_str(), field.value.expose(), field.secret)),
    )
}

/// The one field `name` of `fields`, after [`check_fields`].
pub fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|field| field.name == name)
}

/// The destination and the path of an `https://` URL of a source (contract section
/// 3.2: a host, no userinfo, query, or fragment). The path is `/` when the URL has none.
pub fn https_target(url: &str) -> Result<(DestinationUrl, String), &'static str> {
    const BAD: &str = "the URL is not an https:// URL without userinfo, query, or fragment.";
    if !is_https_url(url) {
        return Err(BAD);
    }
    let rest = &url["https://".len()..];
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let destination = parse_destination(&format!("https://{authority}")).map_err(|_| BAD)?;
    Ok((destination, path.to_owned()))
}

/// The lease's `expires_at` for a provider expiry `expiry` (its clock) of a request sent
/// at `made_at` (this clock), for a kind whose lease lives at most `max_secs`: refused
/// when more than [`MAX_CLOCK_SKEW_SECS`] past `made_at + max_secs` (a provider that
/// ignores the asked lifetime), capped at `made_at + max_secs`, and refused when less
/// than [`MIN_LEASE_SECS`] remain.
pub(crate) fn capped_expiry(
    kind: LeaseKind,
    expiry: u64,
    made_at: u64,
    max_secs: u64,
) -> Result<u64, LeaseError> {
    if expiry > made_at + max_secs + MAX_CLOCK_SKEW_SECS {
        return Err(LeaseError::invalid_answer_because(
            kind,
            &format!(
                "the credentials would live longer than {} minutes.",
                max_secs / 60
            ),
        ));
    }
    let expires_at = expiry.min(made_at + max_secs);
    if expires_at < made_at + MIN_LEASE_SECS {
        return Err(LeaseError::invalid_answer_because(
            kind,
            "the credentials expire in less than a minute.",
        ));
    }
    Ok(expires_at)
}

/// A token of a provider answer: a lease value ([`is_lease_value`]) without spaces.
pub(crate) fn is_token(value: &str) -> bool {
    is_lease_value(value) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Whether a `token_type` of an answer is `Bearer` (any case, RFC 6749 section 7.1).
pub(crate) fn is_bearer_type(token_type: &str) -> bool {
    token_type.eq_ignore_ascii_case("bearer")
}

/// `[A-Z_][A-Z0-9_]{0,127}` (contract section 4).
pub fn is_variable_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_VARIABLE_NAME_BYTES
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// A lease secret value: printable ASCII (space to `~`) without `"` and `\`, 1 to 4096
/// bytes (the relay's `check_value`, without its placeholder rule).
pub fn is_lease_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LEASE_VALUE_BYTES
        && value
            .bytes()
            .all(|byte| (b' '..=b'~').contains(&byte) && byte != b'"' && byte != b'\\')
}

fn is_plain_text(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_LEASE_VALUE_BYTES
        && text.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}

/// The Unix time now, in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `YYYY-MM-DDTHH:MM:SSZ` of Unix seconds (UTC), or `None` outside the years 1970 to
/// 9999. `AWS_CREDENTIAL_EXPIRATION` has this form (contract section 4.1).
pub fn rfc3339(unix: u64) -> Option<String> {
    let (year, month, day, hour, minute, second) = utc_parts(unix)?;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Unix seconds of `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (a fraction of 1 to 9 digits is
/// dropped). Any other form, an offset other than `Z` included, is `None`.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || bytes.len() < 20 || bytes[bytes.len() - 1] != b'Z' {
        return None;
    }
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators.iter().any(|(at, byte)| bytes[*at] != *byte) {
        return None;
    }
    let tail = &text[19..text.len() - 1];
    if !tail.is_empty() {
        let fraction = tail.strip_prefix('.')?;
        if fraction.is_empty()
            || fraction.len() > 9
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = text.get(range)?;
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    unix_from_parts(
        i32::try_from(number(0..4)?).ok()?,
        u8::try_from(number(5..7)?).ok()?,
        u8::try_from(number(8..10)?).ok()?,
        u8::try_from(number(11..13)?).ok()?,
        u8::try_from(number(14..16)?).ok()?,
        u8::try_from(number(17..19)?).ok()?,
    )
}

/// Year, month, day, hour, minute, and second (UTC) of Unix seconds, for the years 1970
/// to 9999.
pub(crate) fn utc_parts(unix: u64) -> Option<(i32, u8, u8, u8, u8, u8)> {
    let at = time::OffsetDateTime::from_unix_timestamp(i64::try_from(unix).ok()?).ok()?;
    if at.year() > 9999 {
        return None;
    }
    Some((
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
    ))
}

/// Unix seconds of a UTC time, or `None` for a time that does not exist or is before
/// 1970.
pub(crate) fn unix_from_parts(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<u64> {
    let month = time::Month::try_from(month).ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let at = date.with_hms(hour, minute, second).ok()?.assume_utc();
    u64::try_from(at.unix_timestamp()).ok()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const KINDS: &str = include_str!("../../tests/fixtures/private-sharing-v1/kinds.json");
    const LEASE_AWS: &str =
        include_str!("../../tests/fixtures/private-sharing-v1/lease-aws-sts.json");
    const LEASE_GITHUB: &str =
        include_str!("../../tests/fixtures/private-sharing-v1/lease-github-app.json");
    const LEASE_OAUTH: &str =
        include_str!("../../tests/fixtures/private-sharing-v1/lease-oauth-refresh.json");
    const LEASE_GOOGLE: &str =
        include_str!("../../tests/fixtures/private-sharing-v1/lease-google-service-account.json");
    const ERROR_LEASE_FAILED: &str =
        include_str!("../../tests/fixtures/private-sharing-v1/error-lease-failed.json");
    const RUN_LEASE_FAILED: &str =
        include_str!("../../tests/fixtures/private-sharing-v1/run-lease-failed.json");
    const SOURCES: &str = include_str!("../../tests/fixtures/private-sharing-v1/sources.json");

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture JSON")
    }

    /// A lease from its contract JSON form (test only: the product never reads or
    /// writes a lease as JSON).
    fn lease_from(value: &Value) -> Lease {
        let text = |value: &Value| value.as_str().expect("text").to_owned();
        Lease {
            kind: LeaseKind::parse(value["kind"].as_str().expect("kind")).expect("known kind"),
            secrets: value["secrets"]
                .as_array()
                .expect("secrets")
                .iter()
                .map(|secret| LeaseSecret {
                    name: text(&secret["name"]),
                    value: SecretValue::new(text(&secret["value"])),
                })
                .collect(),
            plain: value["plain"]
                .as_array()
                .expect("plain")
                .iter()
                .map(|plain| LeasePlain {
                    name: text(&plain["name"]),
                    text: text(&plain["text"]),
                })
                .collect(),
            made_at: value["made_at"].as_u64().expect("made_at"),
            expires_at: value["expires_at"].as_u64().expect("expires_at"),
            revoke: match value["revoke"]["type"].as_str() {
                None => None,
                Some("github") => Some(Revoke::Github {
                    url: text(&value["revoke"]["url"]),
                }),
                Some("oauth") => Some(Revoke::Oauth {
                    url: text(&value["revoke"]["url"]),
                }),
                Some(other) => panic!("unknown revoke type {other}"),
            },
            update_field: value["update_field"]["field"]
                .as_str()
                .map(|field| UpdateField {
                    field: field.to_owned(),
                    value: SecretValue::new(text(&value["update_field"]["value"])),
                }),
            expiry_unknown: false,
        }
    }

    fn fixture_fields(kind: &str) -> Vec<Field> {
        let sources = json(SOURCES);
        sources[kind]["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|field| Field {
                name: field["name"].as_str().expect("name").to_owned(),
                value: SecretValue::new(field["value"].as_str().expect("value").to_owned()),
                secret: field["secret"].as_bool().expect("secret"),
            })
            .collect()
    }

    #[test]
    fn kinds_fields_and_lifetimes_match_the_contract_fixture() {
        let kinds = json(KINDS);
        let names: Vec<&str> = kinds["kinds"]
            .as_array()
            .expect("kinds")
            .iter()
            .map(|kind| kind.as_str().expect("kind"))
            .collect();
        let ours: Vec<&str> = LeaseKind::ALL.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(names, ours);
        for kind in LeaseKind::ALL {
            assert_eq!(LeaseKind::parse(kind.as_str()), Some(kind));
            assert_eq!(
                serde_json::to_value(kind).expect("serialize"),
                Value::String(kind.as_str().to_owned())
            );
            let reserved = kinds["reserved"]
                .as_array()
                .expect("reserved")
                .iter()
                .any(|name| name == kind.as_str());
            assert_eq!(kind.is_reserved(), reserved, "{kind}");
            if reserved {
                assert!(kind.fields().is_empty());
                continue;
            }
            let fixture: Vec<(&str, bool, bool)> = kinds["fields"][kind.as_str()]
                .as_array()
                .expect("fields")
                .iter()
                .map(|rule| {
                    (
                        rule["name"].as_str().expect("name"),
                        rule["secret"].as_bool().expect("secret"),
                        rule["required"].as_bool().expect("required"),
                    )
                })
                .collect();
            let ours: Vec<(&str, bool, bool)> = kind
                .fields()
                .iter()
                .map(|rule| (rule.name, rule.secret, rule.required))
                .collect();
            assert_eq!(ours, fixture, "{kind}");
            assert_eq!(
                kinds["lease"][kind.as_str()]["max_secs"].as_u64(),
                kind.max_secs(),
                "{kind}"
            );
        }
        assert_eq!(LeaseKind::parse("aws"), None);
        let aws_names = &kinds["lease"]["aws_sts"];
        assert_eq!(aws_names["secrets"][1], aws::SECRET_ACCESS_KEY);
        assert_eq!(aws_names["secrets"][2], aws::SESSION_TOKEN);
        assert_eq!(aws_names["plain"][0], aws::CREDENTIAL_EXPIRATION);
        assert_eq!(kinds["codes"][0], LeaseCode::LeaseFailed.as_str());
        assert_eq!(kinds["codes"][1], LeaseCode::LeaseRevokeFailed.as_str());
    }

    #[test]
    fn the_fixture_leases_pass_the_lease_check() {
        for text in [LEASE_AWS, LEASE_GITHUB, LEASE_OAUTH, LEASE_GOOGLE] {
            let lease = lease_from(&json(text));
            lease
                .check()
                .unwrap_or_else(|why| panic!("{}: {why}", lease.kind));
            // Debug never shows a value.
            let debug = format!("{lease:?}");
            for secret in &lease.secrets {
                assert!(!debug.contains(secret.value.expose()));
            }
        }
        let aws = lease_from(&json(LEASE_AWS));
        assert_eq!(
            aws.env_names(),
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_CREDENTIAL_EXPIRATION"
            ]
        );
        assert_eq!(aws.lifetime_secs(), 900);
        assert!(aws.secret("AWS_SESSION_TOKEN").is_some());
        assert!(aws.secret("AWS_CREDENTIAL_EXPIRATION").is_none());
    }

    #[test]
    fn a_lease_that_breaks_the_contract_is_refused() {
        type Change = fn(&mut Lease);
        let aws_changes: [Change; 10] = [
            |lease| lease.expires_at = lease.made_at + 901,
            |lease| lease.expires_at = lease.made_at,
            |lease| lease.secrets[1].name = "AWS_ACCESS_KEY_ID".to_owned(),
            |lease| lease.secrets[0].name = "aws_access_key_id".to_owned(),
            |lease| lease.secrets[2].value = SecretValue::new("with \"quote\"".to_owned()),
            |lease| lease.secrets[2].value = SecretValue::new("a".repeat(4097)),
            |lease| lease.secrets[2].value = SecretValue::new(String::new()),
            |lease| lease.plain[0].text = "2026-11-03T10:15:01Z".to_owned(),
            |lease| {
                lease.revoke = Some(Revoke::Github {
                    url: "https://api.github.com/installation/token".to_owned(),
                })
            },
            |lease| {
                lease.update_field = Some(UpdateField {
                    field: "refresh_token".to_owned(),
                    value: SecretValue::new("x".to_owned()),
                })
            },
        ];
        for (index, change) in aws_changes.iter().enumerate() {
            let mut lease = lease_from(&json(LEASE_AWS));
            change(&mut lease);
            assert!(lease.check().is_err(), "AWS change {index}");
        }
        let mut github = lease_from(&json(LEASE_GITHUB));
        github.expires_at = github.made_at + 3601;
        assert!(github.check().is_err());
        let mut github = lease_from(&json(LEASE_GITHUB));
        github.revoke = Some(Revoke::Oauth {
            url: "https://auth.example.test/revoke".to_owned(),
        });
        assert!(github.check().is_err());
        let mut many = lease_from(&json(LEASE_OAUTH));
        many.kind = LeaseKind::NeonRole;
        many.revoke = None;
        many.update_field = None;
        for index in 0..4 {
            many.secrets.push(LeaseSecret {
                name: format!("EXTRA_{index}"),
                value: SecretValue::new("value".to_owned()),
            });
        }
        assert!(many.check().is_err(), "five secrets");
    }

    #[test]
    fn error_messages_match_the_contract_fixtures() {
        let error = json(ERROR_LEASE_FAILED);
        let failed = LeaseError::http_status(LeaseKind::AwsSts, 403);
        assert_eq!(error["error"]["code"], failed.code.as_str());
        assert_eq!(error["error"]["message"], failed.message.as_str());
        assert_eq!(failed.status.detail(), "403");
        let run = json(RUN_LEASE_FAILED);
        assert_eq!(
            run["note"],
            LeaseError::http_status(LeaseKind::GithubApp, 404).to_string()
        );
        let timeout = LeaseError::from_http(LeaseKind::AwsSts, HttpFailure::Timeout);
        assert_eq!(timeout.status.detail(), "timeout");
        assert!(
            timeout
                .message
                .starts_with("AWS STS did not answer within 20 seconds")
        );
        assert!(timeout.message.ends_with(NOT_RUN));
        let unreachable = LeaseError::from_http(LeaseKind::AwsSts, HttpFailure::Tls);
        assert_eq!(unreachable.status, LeaseStatus::Unreachable);
        assert_eq!(unreachable.status.detail(), "unreachable");
        let revoke = LeaseError::revoke_failed(LeaseKind::OauthRefresh, LeaseStatus::Http(503));
        assert_eq!(revoke.code.as_str(), "lease_revoke_failed");
        assert_eq!(revoke.status.detail(), "503");
    }

    #[test]
    fn the_production_endpoints_are_the_provider_hosts() {
        let production = ProviderEndpoints::production();
        assert_eq!(production, ProviderEndpoints::default());
        assert_eq!(
            production.sts_for("eu-central-1"),
            Ok(DestinationUrl::Https {
                host: "sts.eu-central-1.amazonaws.com".to_owned(),
                port: 443
            })
        );
        assert_eq!(
            production.github.host_header(),
            "api.github.com",
            "a stored api_url is https and the default is GitHub's"
        );
        let fake = parse_destination("http://127.0.0.1:4555").expect("loopback");
        let tests = ProviderEndpoints::all_at(fake.clone());
        assert_eq!(tests.sts_for("us-east-1"), Ok(fake.clone()));
        assert_eq!(tests.neon, fake);
        assert_eq!(
            production.oauth, None,
            "each OAuth source names its own hosts"
        );
        assert_eq!(tests.oauth, Some(fake));
    }

    fn fixture_source(kind: &str, settings: &str) -> LeaseSource {
        let sources = json(SOURCES);
        LeaseSource {
            env_name: sources[kind]["env_name"]
                .as_str()
                .expect("env_name")
                .to_owned(),
            fields: fixture_fields(kind),
            settings: ShortLivedSettings::parse_checked(
                LeaseKind::parse(kind).expect("kind"),
                settings,
            )
            .expect("settings"),
        }
    }

    #[test]
    fn the_field_table_is_enforced() {
        let aws = fixture_fields("aws_sts");
        check_fields(LeaseKind::AwsSts, &aws).expect("fixture fields");
        let settings =
            include_str!("../../tests/fixtures/private-sharing-v1/settings-aws-sts.json");
        check_source(&fixture_source("aws_sts", settings)).expect("fixture source");
        check_source(&fixture_source("aws_sts", "{}")).expect("no settings");
        let missing: Vec<Field> = aws.iter().take(1).cloned().collect();
        assert!(check_fields(LeaseKind::AwsSts, &missing).is_err());
        let mut flipped = aws.clone();
        flipped[1].secret = false;
        let why = check_fields(LeaseKind::AwsSts, &flipped).unwrap_err();
        assert_eq!(why, "the field secret_access_key must be secret.");
        let mut twice = aws.clone();
        twice.push(aws[0].clone());
        assert!(check_fields(LeaseKind::AwsSts, &twice).is_err());
        // An optional field may be missing; the other kinds' required ones may not.
        let mut oauth = fixture_fields("oauth_refresh");
        oauth.retain(|field| field.name != "client_secret");
        check_fields(LeaseKind::OauthRefresh, &oauth).expect("public client");
        oauth.retain(|field| field.name != "refresh_token");
        assert!(check_fields(LeaseKind::OauthRefresh, &oauth).is_err());
        // A reserved kind has no fields and no settings yet.
        assert!(check_fields(LeaseKind::NeonRole, &[]).is_err());
        assert!(ShortLivedSettings::parse_checked(LeaseKind::NeonRole, "{}").is_err());
        assert!(ShortLivedSettings::parse_checked(LeaseKind::GithubApp, "[]").is_err());
        // No error text holds a field value.
        let secret = aws[1].value.expose();
        let mut bad_region = fixture_source("aws_sts", "{}");
        bad_region.settings = ShortLivedSettings::AwsSts(crate::vault::AwsStsSettings {
            region: Some("x".to_owned()),
            ..crate::vault::AwsStsSettings::default()
        });
        for why in [
            check_fields(LeaseKind::AwsSts, &flipped).unwrap_err(),
            check_source(&bad_region).unwrap_err().message,
        ] {
            assert!(!why.contains(secret));
        }
    }

    #[test]
    fn a_vault_source_maps_to_a_lease_source_only_when_on() {
        let on = ShortLivedSource {
            item_id: 4,
            kind: LeaseKind::GithubApp,
            settings: ShortLivedSettings::parse_checked(LeaseKind::GithubApp, "{}")
                .expect("settings"),
            enabled: true,
            fields: fixture_fields("github_app"),
        };
        let off = ShortLivedSource {
            enabled: false,
            ..on.clone()
        };
        let mixed = ShortLivedSource {
            kind: LeaseKind::AwsSts,
            ..on.clone()
        };
        let source = LeaseSource::from_vault(on, "GITHUB_TOKEN").expect("on");
        assert_eq!(source.kind(), LeaseKind::GithubApp);
        assert_eq!(source.env_name, "GITHUB_TOKEN");
        let names: Vec<&str> = source.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["app_id", "installation_id", "private_key"]);
        for refused in [off, mixed] {
            let error = LeaseSource::from_vault(refused, "GITHUB_TOKEN").unwrap_err();
            assert_eq!(error.code, LeaseCode::LeaseFailed);
            assert_eq!(error.status, LeaseStatus::InvalidSource);
        }
    }

    #[test]
    fn variable_names_and_values_follow_the_contract() {
        let longest = "A".repeat(MAX_VARIABLE_NAME_BYTES);
        let too_long = "A".repeat(MAX_VARIABLE_NAME_BYTES + 1);
        for good in ["AWS_ACCESS_KEY_ID", "_X", "A", longest.as_str()] {
            assert!(is_variable_name(good), "{good}");
        }
        for bad in ["", "1A", "aws", "A-B", "A B", too_long.as_str()] {
            assert!(!is_variable_name(bad), "{bad}");
        }
        assert!(is_lease_value("ASIA0123 /+=~"));
        for bad in ["", "a\"b", "a\\b", "a\nb", "\u{e9}"] {
            assert!(!is_lease_value(bad), "{bad:?}");
        }
        assert!(!is_lease_value(&"a".repeat(4097)));
    }

    #[test]
    fn rfc3339_times_round_trip() {
        assert_eq!(
            rfc3339(1_793_700_900).as_deref(),
            Some("2026-11-03T10:15:00Z")
        );
        assert_eq!(parse_rfc3339("2026-11-03T10:15:00Z"), Some(1_793_700_900));
        assert_eq!(
            parse_rfc3339("2026-11-03T10:15:00.359Z"),
            Some(1_793_700_900)
        );
        assert_eq!(rfc3339(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        for bad in [
            "",
            "2026-11-03T10:15:00",
            "2026-11-03T10:15:00+00:00",
            "2026-11-03 10:15:00Z",
            "2026-11-03T10:15:00.Z",
            "2026-11-03T10:15:00.0123456789Z",
            "2026-02-30T10:15:00Z",
            "2026-11-03T24:15:00Z",
            "+026-11-03T10:15:00Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_fixture_sources_of_unit_c2_are_checked_before_any_call() {
        // The fixture keys are synthetic armor, not RSA keys: the checks stop them
        // before any connection, with a reason that names the key and holds no value.
        let (endpoints, listener) = testing::untouched();
        let scope = RunScope {
            run_label: "7".to_owned(),
            ttl_wanted: 900,
        };
        for (kind, settings) in [
            (
                "github_app",
                include_str!("../../tests/fixtures/private-sharing-v1/settings-github-app.json"),
            ),
            (
                "google_service_account",
                include_str!(
                    "../../tests/fixtures/private-sharing-v1/settings-google-service-account.json"
                ),
            ),
        ] {
            let source = fixture_source(kind, settings);
            let error = acquire(&source, &scope, &endpoints, None).unwrap_err();
            assert_eq!(error.code, LeaseCode::LeaseFailed, "{kind}");
            assert_eq!(error.status, LeaseStatus::InvalidSource, "{kind}");
            assert!(
                error.message.contains("RSA key"),
                "{kind}: {}",
                error.message
            );
            assert_eq!(check_source(&source).unwrap_err(), error);
        }
        let oauth = fixture_source(
            "oauth_refresh",
            include_str!("../../tests/fixtures/private-sharing-v1/settings-oauth-refresh.json"),
        );
        check_source(&oauth).expect("the OAuth fixture is a valid source");
        assert!(listener.accept().is_err(), "no provider call");
        // A lease without a revocation ends when it expires.
        let aws = lease_from(&json(LEASE_AWS));
        assert_eq!(revoke(&aws, None, &endpoints, None), Ok(()));
        // A lease whose revocation does not fit its kind is refused without a call.
        let mut odd = lease_from(&json(LEASE_GITHUB));
        odd.kind = LeaseKind::GoogleServiceAccount;
        let error = revoke(&odd, None, &endpoints, None).unwrap_err();
        assert_eq!(error.code, LeaseCode::LeaseRevokeFailed);
        assert!(listener.accept().is_err(), "no provider call");
    }

    #[test]
    fn https_targets_split_the_host_and_the_path() {
        let (destination, path) =
            https_target("https://auth.example.test/oauth/token").expect("target");
        assert_eq!(destination.host_header(), "auth.example.test");
        assert_eq!(path, "/oauth/token");
        let (destination, path) = https_target("https://auth.example.test:8443").expect("target");
        assert_eq!(destination.host_header(), "auth.example.test:8443");
        assert_eq!(path, "/");
        for refused in [
            "http://auth.example.test/token",
            "https://user@auth.example.test/token",
            "https://auth.example.test/token?x=1",
            "https://auth.example.test/token#f",
            "https://",
        ] {
            assert!(https_target(refused).is_err(), "{refused}");
        }
        let production = ProviderEndpoints::production();
        assert_eq!(
            production.google_token_for(google::DEFAULT_TOKEN_URI),
            Ok((production.google_token.clone(), "/token".to_owned()))
        );
        assert_eq!(
            production.oauth_for("https://auth.example.test/oauth/revoke"),
            https_target("https://auth.example.test/oauth/revoke")
        );
        let fake = parse_destination("http://127.0.0.1:4555").expect("loopback");
        assert_eq!(
            ProviderEndpoints::all_at(fake.clone())
                .oauth_for("https://auth.example.test/oauth/revoke"),
            Ok((fake, "/oauth/revoke".to_owned()))
        );
    }

    #[test]
    fn an_unknown_expiry_is_only_a_revoked_oauth_lease_of_one_hour() {
        let mut oauth = lease_from(&json(LEASE_OAUTH));
        oauth.expiry_unknown = true;
        oauth.check().expect("revoked, shown as one hour");
        oauth.expires_at = oauth.made_at + 900;
        assert!(oauth.check().is_err(), "an unknown expiry is shown as one hour");
        oauth.expires_at = oauth.made_at + 3600;
        let revoke = oauth.revoke.take();
        assert!(oauth.check().is_err(), "an unknown expiry needs the revocation");
        // Without a revocation, an OAuth lease lives at most one hour; with one, the
        // provider's longer expiry is reported as it is.
        oauth.expiry_unknown = false;
        oauth.check().expect("one hour");
        oauth.expires_at = oauth.made_at + 3601;
        assert!(oauth.check().is_err(), "longer than one hour without revocation");
        oauth.revoke = revoke;
        oauth.check().expect("revoked at run end");
        let mut google = lease_from(&json(LEASE_GOOGLE));
        google.expiry_unknown = true;
        assert!(google.check().is_err());
        // The two lifetimes of a kind: the catalog's (5.1) and the limit (4).
        assert_eq!(LeaseKind::OauthRefresh.lease_secs(), 900);
        assert_eq!(LeaseKind::OauthRefresh.max_secs(), None);
        assert_eq!(LeaseKind::GithubApp.lease_secs(), 3600);
        assert_eq!(LeaseKind::GithubApp.max_secs(), Some(3600));
        // A GitHub revocation is `<api_url>/installation/token` over https.
        let mut github = lease_from(&json(LEASE_GITHUB));
        github.revoke = Some(Revoke::Github {
            url: "https://api.github.com/installation".to_owned(),
        });
        assert!(github.check().is_err());
    }

    /// The no-secret scan over the three kinds of unit C2 (contract sections 2 rule 6
    /// and 11): what the agent's side gets of a lease (its variables and values) and
    /// every `Debug` and error text hold no long-lived value, no bootstrap token, and no
    /// JWT; the long-lived key never goes over the wire.
    #[test]
    fn no_long_lived_secret_in_any_lease_or_error() {
        use serde_json::json;

        use crate::lease::jwt::tests::pkcs1_pem;
        use crate::lease::testing::{Reply, Seen, deadline, endpoints, fake};

        const BOOTSTRAP: &str = "ya29.FakeBootstrapTokenThatNeverLeaves0002";
        const CLIENT_SECRET: &str = "synthetic-oauth-client-secret-scan-0002";
        const REFRESH: &str = "synthetic-refresh-token-long-lived-scan-0002";
        const ROTATED: &str = "synthetic-refresh-token-rotated-scan-0003";
        let pem = pkcs1_pem();
        let mut long_lived: Vec<String> = pem
            .lines()
            .filter(|line| !line.starts_with("-----") && line.len() >= 16)
            .map(str::to_owned)
            .collect();
        long_lived.extend([CLIENT_SECRET, REFRESH, ROTATED].map(str::to_owned));
        let pkcs8 = crate::lease::jwt::tests::pkcs8_pem();
        long_lived.extend(
            pkcs8
                .lines()
                .filter(|line| !line.starts_with("-----") && line.len() >= 16)
                .map(str::to_owned),
        );
        let field = |name: &str, value: &str, secret: bool| Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        };
        let settings = |kind: LeaseKind, text: &str| {
            ShortLivedSettings::parse_checked(kind, text).expect("settings")
        };
        let key_json = json!({
            "type": "service_account",
            "private_key": pkcs8,
            "client_email": "scan@synthetic-project.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token"
        })
        .to_string();
        let sources = [
            LeaseSource {
                env_name: "GITHUB_TOKEN".to_owned(),
                fields: vec![
                    field("app_id", "123456", false),
                    field("installation_id", "7654321", false),
                    field("private_key", &pem, true),
                ],
                settings: settings(LeaseKind::GithubApp, "{}"),
            },
            LeaseSource {
                env_name: "CLOUDSDK_AUTH_ACCESS_TOKEN".to_owned(),
                fields: vec![field("key_json", &key_json, true)],
                settings: settings(LeaseKind::GoogleServiceAccount, "{}"),
            },
            LeaseSource {
                env_name: "EXAMPLE_ACCESS_TOKEN".to_owned(),
                fields: vec![
                    field("client_id", "synthetic-client-id", false),
                    field("client_secret", CLIENT_SECRET, true),
                    field("refresh_token", REFRESH, true),
                ],
                settings: settings(
                    LeaseKind::OauthRefresh,
                    r#"{"token_url":"https://auth.example.test/token","client_auth":"basic","revoke_url":"https://auth.example.test/revoke"}"#,
                ),
            },
        ];
        // Each provider echoes every secret it was sent in its error bodies.
        let echo = |seen: &Seen| -> String { String::from_utf8_lossy(&seen.raw).into_owned() };
        let scope = RunScope {
            run_label: "7".to_owned(),
            ttl_wanted: 900,
        };
        let mut texts = Vec::new();
        for source in &sources {
            let kind = source.kind();
            // A lease: one call, or two for Google.
            let calls = if kind == LeaseKind::GoogleServiceAccount {
                2
            } else {
                1
            };
            let (destination, server) = fake(calls, move |index, _: &Seen| match (kind, index) {
                (LeaseKind::GithubApp, _) => Reply::json(
                    201,
                    &json!({"token": "ghs_ScanInstallationToken00000000000001", "expires_at": "2026-11-03T11:00:00Z"}),
                ),
                (LeaseKind::GoogleServiceAccount, 0) => {
                    Reply::json(200, &json!({"access_token": BOOTSTRAP, "expires_in": 3599}))
                }
                (LeaseKind::GoogleServiceAccount, _) => Reply::json(
                    200,
                    &json!({"accessToken": "ya29.ScanShortLivedToken0001", "expireTime": "2026-11-03T10:15:00Z"}),
                ),
                _ => Reply::json(
                    200,
                    &json!({"access_token": "scan-access-token-0001", "refresh_token": ROTATED}),
                ),
            });
            let lease = acquire_at(
                source,
                &scope,
                &endpoints(destination),
                None,
                deadline(),
                1_793_700_000,
            )
            .expect("lease");
            let seen = server.join().expect("fake provider");
            assert_eq!(seen.len(), calls);
            for request in &seen {
                // The private key and the client secret in the clear never go out;
                // the refresh token goes only to the token endpoint, in the form.
                for secret in long_lived.iter().filter(|secret| {
                    !(kind == LeaseKind::OauthRefresh
                        && (secret.as_str() == REFRESH || secret.as_str() == CLIENT_SECRET))
                }) {
                    scan::assert_no_secret(&request.raw, secret);
                }
                if kind == LeaseKind::GoogleServiceAccount
                    && request.path.contains("generateAccessToken")
                {
                    assert_eq!(request.bearer(), Some(BOOTSTRAP));
                }
            }
            let mut agent_side = String::new();
            for secret in &lease.secrets {
                agent_side.push_str(&format!("{}={}\n", secret.name, secret.value.expose()));
            }
            for plain in &lease.plain {
                agent_side.push_str(&format!("{}={}\n", plain.name, plain.text));
            }
            texts.push(agent_side);
            texts.push(format!("{lease:?} {source:?}"));
            for secret in &lease.secrets {
                assert!(!format!("{lease:?}").contains(secret.value.expose()));
            }
            if kind == LeaseKind::OauthRefresh {
                assert_eq!(
                    lease
                        .update_field
                        .as_ref()
                        .map(|update| update.value.expose()),
                    Some(ROTATED),
                    "the rotation is for the caller, not the agent's side"
                );
            }
            // An error whose body echoes the request.
            let (destination, server) =
                fake(1, move |_, seen: &Seen| Reply::text(400, &echo(seen)));
            let error = acquire_at(
                source,
                &scope,
                &endpoints(destination),
                None,
                deadline(),
                1_793_700_000,
            )
            .unwrap_err();
            server.join().expect("fake provider");
            texts.push(format!("{error} {error:?}"));
            // A revocation that fails with an echoing body.
            if lease.revoke.is_some() {
                let (destination, server) =
                    fake(1, move |_, seen: &Seen| Reply::text(500, &echo(seen)));
                let error = revoke_at(
                    &lease,
                    Some(source),
                    &endpoints(destination),
                    None,
                    deadline(),
                )
                .unwrap_err();
                server.join().expect("fake provider");
                assert_eq!(error.code, LeaseCode::LeaseRevokeFailed);
                texts.push(format!("{error} {error:?}"));
            }
        }
        for text in &texts {
            for secret in &long_lived {
                scan::assert_no_secret(text, secret);
            }
            scan::assert_no_secret(text, BOOTSTRAP);
        }
    }
}
