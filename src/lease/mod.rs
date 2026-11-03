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
//! - [`check_source`] checks the fields and the settings of a source when its
//!   `short_lived` row is written (unit D): a problem there is `invalid_request`.
//! - [`sigv4`] is the AWS Signature Version 4 code that the STS call, the signing
//!   proxies (E1, E2), and the sign endpoint (H) share.
//! - [`scan`] is the no-secret scan of every test of the plan (section 11).
//!
//! The kinds: [`aws`] (`aws_sts`, unit C1). Unit C2 adds `jwt`, `github`, `google`, and
//! `oauth` next to it and fills the `github_app`, `google_service_account`, and
//! `oauth_refresh` arms of [`acquire`], [`revoke`], and [`check_source`]; unit K adds
//! `cloudflare`, `planetscale`, and `neon` for the reserved kinds.
//!
//! Every secret is held in a [`SecretValue`] or a `Zeroizing` buffer, and the provider's
//! answer is erased after it is read. No error, `Debug` output, or message holds a
//! secret, a lease value, or a provider body (rule 6).

pub mod aws;
pub mod scan;
pub mod sigv4;

use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::broker::http::{DestinationUrl, HttpFailure, TlsClient, parse_destination};
use crate::vault::{Field, SecretValue};

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

/// The way C kinds of contract section 3. The last three are reserved for unit K.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    AwsSts,
    GithubApp,
    GoogleServiceAccount,
    OauthRefresh,
    CloudflareToken,
    PlanetscalePassword,
    NeonRole,
}

impl LeaseKind {
    /// Every kind, in the order of contract section 3.
    pub const ALL: [Self; 7] = [
        Self::AwsSts,
        Self::GithubApp,
        Self::GoogleServiceAccount,
        Self::OauthRefresh,
        Self::CloudflareToken,
        Self::PlanetscalePassword,
        Self::NeonRole,
    ];

    /// The stored and wire name (`aws_sts`, …).
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
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }

    /// Reserved for unit K: until its contract section exists, writing a row of such a
    /// kind is `invalid_request` (contract section 3).
    pub fn is_reserved(self) -> bool {
        matches!(
            self,
            Self::CloudflareToken | Self::PlanetscalePassword | Self::NeonRole
        )
    }

    /// The longest lease of the kind in seconds (`expires_at - made_at`), when the
    /// contract fixes one: 900 for AWS and Google, 3600 for GitHub.
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

    /// The provider as the messages name it ("AWS STS answered 403. …").
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

    /// The fields that the key holder reads (contract section 3.1). Empty for a
    /// reserved kind.
    pub fn fields(self) -> &'static [FieldRule] {
        const fn rule(name: &'static str, secret: bool, required: bool) -> FieldRule {
            FieldRule {
                name,
                secret,
                required,
            }
        }
        const AWS: [FieldRule; 2] = [
            rule(aws::ACCESS_KEY_ID_FIELD, false, true),
            rule(aws::SECRET_ACCESS_KEY_FIELD, true, true),
        ];
        const GITHUB: [FieldRule; 3] = [
            rule("app_id", false, true),
            rule("installation_id", false, true),
            rule("private_key", true, true),
        ];
        const GOOGLE: [FieldRule; 1] = [rule("key_json", true, true)];
        const OAUTH: [FieldRule; 3] = [
            rule("client_id", false, true),
            rule("client_secret", true, false),
            rule("refresh_token", true, true),
        ];
        match self {
            Self::AwsSts => &AWS,
            Self::GithubApp => &GITHUB,
            Self::GoogleServiceAccount => &GOOGLE,
            Self::OauthRefresh => &OAUTH,
            Self::CloudflareToken | Self::PlanetscalePassword | Self::NeonRole => &[],
        }
    }
}

impl fmt::Display for LeaseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of the field table of contract section 3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRule {
    pub name: &'static str,
    /// The `secret` flag that the item's field must have.
    pub secret: bool,
    pub required: bool,
}

/// A source item as the key holder reads it for one lease (plan unit D builds it from
/// the vault: `short_lived_source(item)`). `fields` hold the long-lived secret; `Debug`
/// shows their names only.
#[derive(Debug)]
pub struct LeaseSource {
    pub kind: LeaseKind,
    /// The item's bound variable (`env_binding.env_name`): the name of the lease's first
    /// secret (contract section 4.1).
    pub env_name: String,
    /// The item's fields. Only the fields of [`LeaseKind::fields`] are read.
    pub fields: Vec<Field>,
    /// The `short_lived.settings` object of the kind (contract section 3.2).
    pub settings: Value,
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

/// A rotated OAuth refresh token that the caller MUST store with `Vault::update` before
/// it delivers the lease (contract section 4.2).
#[derive(Debug)]
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
}

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
        let revoke_ok = match (&self.revoke, self.kind) {
            (None, _) => true,
            (Some(Revoke::Github { url }), LeaseKind::GithubApp)
            | (Some(Revoke::Oauth { url }), LeaseKind::OauthRefresh) => !url.is_empty(),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseError {
    pub code: LeaseCode,
    pub kind: LeaseKind,
    pub status: LeaseStatus,
    pub message: String,
}

impl LeaseError {
    /// `lease_failed` with the provider's HTTP status: "AWS STS answered 403. No
    /// temporary credentials were made, so the command did not run."
    pub fn http_status(kind: LeaseKind, status: u16) -> Self {
        Self {
            code: LeaseCode::LeaseFailed,
            kind,
            status: LeaseStatus::Http(status),
            message: format!("{} answered {status}. {NOT_RUN}", kind.provider_label()),
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
        }
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
            neon: destination,
        }
    }

    /// The STS destination for `region` (already checked by [`aws::AwsSettings`]).
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
    if !is_variable_name(&source.env_name) {
        return Err(LeaseError::invalid_source(
            source.kind,
            "its variable name is not valid.",
        ));
    }
    let lease = match source.kind {
        LeaseKind::AwsSts => aws::acquire(source, scope, endpoints, tls, deadline, now)?,
        // Unit C2 replaces this arm with GitHub, Google, and OAuth refresh; unit K adds
        // the reserved kinds.
        kind => {
            return Err(LeaseError::invalid_source(
                kind,
                "this kind of temporary credentials is not available in this version.",
            ));
        }
    };
    if lease.kind != source.kind
        || lease.check().is_err()
        || lease.secrets.first().map(|secret| secret.name.as_str())
            != Some(source.env_name.as_str())
    {
        return Err(LeaseError::invalid_answer(source.kind));
    }
    Ok(lease)
}

/// End a lease that has a [`Revoke`] (contract section 4.2), best effort. A lease
/// without one ends when it expires: `Ok`. An error is `lease_revoke_failed`, for an
/// activity or audit row only.
pub fn revoke(
    lease: &Lease,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
) -> Result<(), LeaseError> {
    match &lease.revoke {
        None => Ok(()),
        // Unit C2 replaces this arm with the GitHub and OAuth revocations, which use the
        // endpoints, the TLS client, and a deadline of `LEASE_DEADLINE`.
        Some(Revoke::Github { .. } | Revoke::Oauth { .. }) => {
            let _ = (endpoints, tls);
            Err(LeaseError::revoke_failed(
                lease.kind,
                LeaseStatus::InvalidSource,
            ))
        }
    }
}

/// Check the fields and the settings of a source when its `short_lived` row is written
/// (plan unit D). An error is `invalid_request`; its text names the field or the setting,
/// never a value.
pub fn check_source(kind: LeaseKind, fields: &[Field], settings: &Value) -> Result<(), String> {
    if kind.is_reserved() {
        return Err(format!(
            "the kind {kind} is reserved for a later version of Apassy."
        ));
    }
    check_fields(kind, fields)?;
    check_settings(kind, settings)?;
    match kind {
        LeaseKind::AwsSts => aws::check_key(fields),
        // Unit C2 adds the value checks of its kinds (the PEM key, the key JSON).
        _ => Ok(()),
    }
}

/// Check a settings object of `kind` (contract section 3.2): strict, no secret.
pub fn check_settings(kind: LeaseKind, settings: &Value) -> Result<(), String> {
    match kind {
        LeaseKind::AwsSts => aws::AwsSettings::parse(settings)
            .map(drop)
            .map_err(str::to_owned),
        _ if kind.is_reserved() => Err(format!(
            "the kind {kind} is reserved for a later version of Apassy."
        )),
        // Until unit C2 adds the strict readers of its kinds, their settings are checked
        // only as a JSON object here; C2 replaces this arm, and its `acquire` refuses a
        // settings object that breaks the contract.
        _ if settings.is_object() => Ok(()),
        _ => Err("the settings must be a JSON object.".to_owned()),
    }
}

/// Check the item's fields against the table of contract section 3.1: each field of the
/// kind at most once, a required one present, and its `secret` flag as in the table.
pub fn check_fields(kind: LeaseKind, fields: &[Field]) -> Result<(), String> {
    for rule in kind.fields() {
        let mut found = fields.iter().filter(|field| field.name == rule.name);
        match (found.next(), found.next()) {
            (Some(_), Some(_)) => {
                return Err(format!("the item has two fields named {}.", rule.name));
            }
            (None, _) if rule.required => {
                return Err(format!("the item has no field {}.", rule.name));
            }
            (Some(field), None) if field.secret != rule.secret => {
                return Err(if rule.secret {
                    format!("the field {} must be secret.", rule.name)
                } else {
                    format!("the field {} must not be secret.", rule.name)
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// The one field `name` of `fields`, after [`check_fields`].
pub fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|field| field.name == name)
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
    }

    #[test]
    fn the_field_table_is_enforced() {
        let aws = fixture_fields("aws_sts");
        check_fields(LeaseKind::AwsSts, &aws).expect("fixture fields");
        let settings = json(include_str!(
            "../../tests/fixtures/private-sharing-v1/settings-aws-sts.json"
        ));
        check_source(LeaseKind::AwsSts, &aws, &settings).expect("fixture source");
        check_source(LeaseKind::AwsSts, &aws, &json("{}")).expect("no settings");
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
        assert!(check_source(LeaseKind::NeonRole, &[], &json("{}")).is_err());
        assert!(check_settings(LeaseKind::GithubApp, &json("[]")).is_err());
        // No error text holds a field value.
        let secret = aws[1].value.expose();
        for why in [
            check_fields(LeaseKind::AwsSts, &flipped).unwrap_err(),
            check_source(LeaseKind::AwsSts, &aws, &json(r#"{"region": "x"}"#)).unwrap_err(),
        ] {
            assert!(!why.contains(secret));
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
    fn the_kinds_of_unit_c2_and_k_fail_without_a_provider_call() {
        // Until C2 and K land, `acquire` refuses their kinds before any connection.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let fake = parse_destination(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        ))
        .expect("loopback");
        let endpoints = ProviderEndpoints::all_at(fake);
        for kind in [
            LeaseKind::GithubApp,
            LeaseKind::GoogleServiceAccount,
            LeaseKind::OauthRefresh,
            LeaseKind::CloudflareToken,
        ] {
            let source = LeaseSource {
                kind,
                env_name: "SOME_TOKEN".to_owned(),
                fields: Vec::new(),
                settings: json("{}"),
            };
            let scope = RunScope {
                run_label: "7".to_owned(),
                ttl_wanted: 900,
            };
            let error = acquire(&source, &scope, &endpoints, None).unwrap_err();
            assert_eq!(error.code, LeaseCode::LeaseFailed);
            assert_eq!(error.status, LeaseStatus::InvalidSource);
        }
        assert!(listener.accept().is_err(), "no provider call");
        let lease = lease_from(&json(LEASE_GITHUB));
        let error = revoke(&lease, &endpoints, None).unwrap_err();
        assert_eq!(error.code, LeaseCode::LeaseRevokeFailed);
        let aws = lease_from(&json(LEASE_AWS));
        assert_eq!(revoke(&aws, &endpoints, None), Ok(()));
    }
}
