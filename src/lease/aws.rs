//! AWS STS leases: the kind `aws_sts` (contract private-sharing-v1 sections 3 and 4,
//! plan s6 decision S6-4).
//!
//! With a `role_arn` the key holder calls `AssumeRole` (recommended: the role narrows
//! the permissions), else `GetFederationToken` with the item's session policy, or with
//! an allow-all policy when the item has none (the result is still the intersection with
//! the IAM user's own permissions; without a policy `GetFederationToken` grants nothing).
//! `DurationSeconds` is 900, the AWS minimum, and the session is `apassy-<run label>`.
//! `GetSessionToken` is never used: it cannot be narrowed.
//!
//! The request is a form `POST /` to `sts.<region>.amazonaws.com`, SigV4-signed with the
//! long-lived key (service `sts`). It asks for XML with `Accept: text/xml`, because the
//! HTTP client's default `Accept: application/json` can make STS answer JSON. A strict
//! scanner reads the four elements `AccessKeyId`, `SecretAccessKey`, `SessionToken`, and
//! `Expiration` of the answer; there is no XML parser. The answer is erased after it is
//! read. An `ASIA…` key is already temporary and is refused as a source.

use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use super::sigv4::{self, ClientRequest};
use super::{
    Lease, LeaseError, LeaseKind, LeasePlain, LeaseSecret, LeaseSource, MIN_LEASE_SECS,
    ProviderEndpoints, RunScope,
};
use crate::broker::http::{self, Body, HttpRequest, Method, TlsClient};
use crate::vault::{Field, SecretValue};

/// The plain field with the IAM user's key id (`AKIA…`).
pub const ACCESS_KEY_ID_FIELD: &str = "access_key_id";
/// The secret field with the IAM user's secret access key.
pub const SECRET_ACCESS_KEY_FIELD: &str = "secret_access_key";
/// The fixed lease names after the bound variable (contract section 4.1).
pub const SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
pub const SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
/// The plain lease variable: `expires_at` as `YYYY-MM-DDTHH:MM:SSZ`.
pub const CREDENTIAL_EXPIRATION: &str = "AWS_CREDENTIAL_EXPIRATION";
/// The STS API version of the request.
pub const STS_VERSION: &str = "2011-06-15";
/// `DurationSeconds` of every call: the AWS minimum, the 15 minutes of the ADR.
pub const DURATION_SECS: u64 = 900;
/// How far the answer's `Expiration` may be past `made_at + 900` before the answer is
/// refused. STS refuses a request whose `X-Amz-Date` is more than 5 minutes from its
/// clock, so a provider that honours `DurationSeconds` stays inside this window, while
/// one that ignores it (the defaults are 1 and 12 hours) is refused. The lease never
/// claims more than 900 seconds: `expires_at = min(Expiration, made_at + 900)`.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// The STS limit of a session policy (contract section 3.2).
pub const MAX_POLICY_BYTES: usize = 2048;
pub const MAX_ROLE_ARN_BYTES: usize = 2048;
/// Most entries of the `services` setting.
pub const MAX_SERVICES: usize = 16;
/// The region when the settings name none.
pub const DEFAULT_REGION: &str = "us-east-1";
/// The session policy of `GetFederationToken` for an item without a policy (S6-4).
pub const ALLOW_ALL_POLICY: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

const KIND: LeaseKind = LeaseKind::AwsSts;
const SERVICE: &str = "sts";
const ACCEPT: &str = "text/xml";
const SESSION_PREFIX: &str = "apassy-";
/// `GetFederationToken`'s `Name` has at most 32 characters: 7 for `apassy-`, 25 for the
/// label. `AssumeRole`'s `RoleSessionName` (64) gets the same name.
const MAX_SESSION_LABEL_CHARS: usize = 25;
const MAX_REGION_BYTES: usize = 32;
const MAX_SERVICE_NAME_BYTES: usize = 32;
const ASIA_REFUSED: &str =
    "the access key id is already temporary (ASIA). Use the IAM user's long-lived AKIA key.";

/// The settings of an `aws_sts` source (contract section 3.2). Strict: an unknown field,
/// a duplicate field (in [`AwsSettings::parse_text`]), or a wrong type is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AwsSettings {
    /// `arn:aws:iam::<12 digits>:role/<path and name>`: `AssumeRole`.
    pub role_arn: Option<String>,
    /// The JSON text of an IAM session policy object, at most 2048 bytes.
    pub policy: Option<String>,
    /// `[a-z]{2}(-[a-z]+)+-[0-9]+`; [`DEFAULT_REGION`] when missing.
    pub region: Option<String>,
    /// 1 to 16 distinct service names (`[a-z0-9-]{1,32}`), for signed requests.
    pub services: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsWire {
    #[serde(default)]
    role_arn: Option<String>,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    services: Option<Vec<String>>,
}

impl AwsSettings {
    /// Read a settings object (the `LeaseSource.settings` value).
    pub fn parse(settings: &Value) -> Result<Self, &'static str> {
        if !settings.is_object() {
            return Err("the AWS settings are not a JSON object.");
        }
        let wire = SettingsWire::deserialize(settings)
            .map_err(|_| "the AWS settings have an unknown field or a field of the wrong type.")?;
        Self::checked(wire)
    }

    /// Read the stored settings text; a duplicate field is refused here too.
    pub fn parse_text(text: &str) -> Result<Self, &'static str> {
        const BAD: &str =
            "the AWS settings are not a JSON object of known, distinct fields of the right types.";
        let value: Value = serde_json::from_str(text).map_err(|_| BAD)?;
        if !value.is_object() {
            return Err(BAD);
        }
        let wire: SettingsWire = serde_json::from_str(text).map_err(|_| BAD)?;
        Self::checked(wire)
    }

    fn checked(wire: SettingsWire) -> Result<Self, &'static str> {
        if wire
            .role_arn
            .as_deref()
            .is_some_and(|arn| !is_role_arn(arn))
        {
            return Err("the role_arn setting is not arn:aws:iam::<12 digits>:role/<name>.");
        }
        if let Some(policy) = &wire.policy {
            if policy.len() > MAX_POLICY_BYTES {
                return Err("the policy setting is longer than 2048 bytes.");
            }
            if !matches!(serde_json::from_str::<Value>(policy), Ok(Value::Object(_))) {
                return Err("the policy setting is not the JSON text of a policy object.");
            }
        }
        if wire
            .region
            .as_deref()
            .is_some_and(|region| !is_region(region))
        {
            return Err("the region setting is not an AWS region such as eu-central-1.");
        }
        if let Some(services) = &wire.services {
            let distinct = services
                .iter()
                .enumerate()
                .all(|(index, name)| !services[..index].contains(name));
            if !(1..=MAX_SERVICES).contains(&services.len())
                || !distinct
                || !services.iter().all(|name| is_service_name(name))
            {
                return Err("the services setting is not 1 to 16 distinct AWS service names.");
            }
        }
        Ok(Self {
            role_arn: wire.role_arn,
            policy: wire.policy,
            region: wire.region,
            services: wire.services,
        })
    }

    /// The region of the STS endpoint and of the signing scope.
    pub fn region(&self) -> &str {
        self.region.as_deref().unwrap_or(DEFAULT_REGION)
    }
}

/// Check the values of the two fields (after [`super::check_fields`]): an `AKIA` key id
/// of 20 characters and a 40-character secret access key. An `ASIA` key is refused.
/// The text names the field, never its value.
pub fn check_key(fields: &[Field]) -> Result<(), String> {
    let id = super::field(fields, ACCESS_KEY_ID_FIELD)
        .ok_or_else(|| format!("the item has no field {ACCESS_KEY_ID_FIELD}."))?;
    let secret = super::field(fields, SECRET_ACCESS_KEY_FIELD)
        .ok_or_else(|| format!("the item has no field {SECRET_ACCESS_KEY_FIELD}."))?;
    check_access_key_id(id.value.expose()).map_err(str::to_owned)?;
    if !is_secret_access_key(secret.value.expose()) {
        return Err(format!(
            "the field {SECRET_ACCESS_KEY_FIELD} is not 40 characters of A-Z, a-z, 0-9, / and +."
        ));
    }
    Ok(())
}

/// The two STS actions of S6-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call<'a> {
    AssumeRole { role_arn: &'a str },
    GetFederationToken,
}

impl Call<'_> {
    fn action(self) -> &'static str {
        match self {
            Self::AssumeRole { .. } => "AssumeRole",
            Self::GetFederationToken => "GetFederationToken",
        }
    }

    fn response_element(self) -> &'static str {
        match self {
            Self::AssumeRole { .. } => "AssumeRoleResponse",
            Self::GetFederationToken => "GetFederationTokenResponse",
        }
    }

    fn result_element(self) -> &'static str {
        match self {
            Self::AssumeRole { .. } => "AssumeRoleResult",
            Self::GetFederationToken => "GetFederationTokenResult",
        }
    }
}

/// Make an `aws_sts` lease: check the source, sign and send the STS call, read the
/// answer, and check the lifetime. `now` is the Unix time of the request (`made_at`).
pub(super) fn acquire(
    source: &LeaseSource,
    scope: &RunScope,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
    now: u64,
) -> Result<Lease, LeaseError> {
    let invalid = |why: &str| LeaseError::invalid_source(KIND, why);
    let settings = AwsSettings::parse(&source.settings).map_err(invalid)?;
    super::check_fields(KIND, &source.fields).map_err(|why| invalid(why.as_str()))?;
    check_key(&source.fields).map_err(|why| invalid(why.as_str()))?;
    if [SECRET_ACCESS_KEY, SESSION_TOKEN, CREDENTIAL_EXPIRATION].contains(&source.env_name.as_str())
    {
        return Err(invalid(
            "its variable is one of the fixed names AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, and AWS_CREDENTIAL_EXPIRATION.",
        ));
    }
    let (Some(id), Some(secret)) = (
        super::field(&source.fields, ACCESS_KEY_ID_FIELD),
        super::field(&source.fields, SECRET_ACCESS_KEY_FIELD),
    ) else {
        return Err(invalid("the item has no access key."));
    };
    let region = settings.region();
    let destination = endpoints.sts_for(region).map_err(invalid)?;
    let call = match settings.role_arn.as_deref() {
        Some(role_arn) => Call::AssumeRole { role_arn },
        None => Call::GetFederationToken,
    };
    let session = session_name(&scope.run_label);
    let body = request_body(call, &settings, &session);
    let host = destination.host_header();
    let request = ClientRequest {
        method: "POST",
        host: &host,
        path: "/",
        query: "",
        headers: &[],
        payload: &body,
    };
    // The long-lived secret is used here only, to derive the signing key.
    let signed = sigv4::sign_request(
        id.value.expose(),
        secret.value.expose(),
        region,
        SERVICE,
        &request,
        now,
    )
    .map_err(|_| invalid("its key cannot sign the request."))?;
    let headers = [
        ("X-Amz-Date", signed.amz_date.as_str()),
        ("Authorization", signed.authorization.as_str()),
        ("Accept", ACCEPT),
    ];
    let request = HttpRequest {
        headers: &headers,
        body: Some(Body::Form(&body)),
        ..HttpRequest::new(Method::Post, "/")
    };
    let mut response = http::send(&destination, &request, deadline, tls)
        .map_err(|failure| LeaseError::from_http(KIND, failure))?;
    // The answer holds the lease (or a provider message): erased when this returns.
    let answer = Zeroizing::new(std::mem::take(&mut response.body));
    if response.status != 200 {
        return Err(LeaseError::http_status(KIND, response.status));
    }
    let credentials =
        scan_credentials(&answer, call).ok_or_else(|| LeaseError::invalid_answer(KIND))?;
    let expires_at = lease_expiry(credentials.expiration, now)?;
    let expiration = super::rfc3339(expires_at).ok_or_else(|| LeaseError::invalid_answer(KIND))?;
    let lease = Lease {
        kind: KIND,
        secrets: vec![
            LeaseSecret {
                name: source.env_name.clone(),
                value: SecretValue::new(credentials.access_key_id.to_owned()),
            },
            LeaseSecret {
                name: SECRET_ACCESS_KEY.to_owned(),
                value: SecretValue::new(credentials.secret_access_key.to_owned()),
            },
            LeaseSecret {
                name: SESSION_TOKEN.to_owned(),
                value: SecretValue::new(credentials.session_token.to_owned()),
            },
        ],
        plain: vec![LeasePlain {
            name: CREDENTIAL_EXPIRATION.to_owned(),
            text: expiration,
        }],
        made_at: now,
        expires_at,
        revoke: None,
        update_field: None,
    };
    drop(answer);
    lease
        .check()
        .map_err(|_| LeaseError::invalid_answer(KIND))?;
    Ok(lease)
}

/// The form body of the call: `Action`, `Version`, then the call's own parameters.
fn request_body(call: Call<'_>, settings: &AwsSettings, session: &str) -> Zeroizing<Vec<u8>> {
    let duration = DURATION_SECS.to_string();
    let mut pairs: Vec<(&str, &str)> = vec![("Action", call.action()), ("Version", STS_VERSION)];
    match call {
        Call::AssumeRole { role_arn } => {
            pairs.push(("RoleArn", role_arn));
            pairs.push(("RoleSessionName", session));
            pairs.push(("DurationSeconds", duration.as_str()));
            if let Some(policy) = settings.policy.as_deref() {
                pairs.push(("Policy", policy));
            }
        }
        Call::GetFederationToken => {
            pairs.push(("Name", session));
            pairs.push(("DurationSeconds", duration.as_str()));
            pairs.push((
                "Policy",
                settings.policy.as_deref().unwrap_or(ALLOW_ALL_POLICY),
            ));
        }
    }
    http::form_body(&pairs)
}

/// `apassy-<label>`: at most 25 label characters, each outside `[A-Za-z0-9+=,.@_-]`
/// replaced with `-`; `apassy-run` for an empty label.
fn session_name(label: &str) -> String {
    let mut name = String::from(SESSION_PREFIX);
    if label.is_empty() {
        name.push_str("run");
        return name;
    }
    for c in label.chars().take(MAX_SESSION_LABEL_CHARS) {
        name.push(if c.is_ascii_alphanumeric() || "+=,.@_-".contains(c) {
            c
        } else {
            '-'
        });
    }
    name
}

/// The lease's `expires_at` for an answer that expires at `expiration` (STS clock) for a
/// request sent at `made_at` (this clock). See [`MAX_CLOCK_SKEW_SECS`].
fn lease_expiry(expiration: u64, made_at: u64) -> Result<u64, LeaseError> {
    if expiration > made_at + DURATION_SECS + MAX_CLOCK_SKEW_SECS {
        return Err(LeaseError::invalid_answer_because(
            KIND,
            "the credentials would live longer than 15 minutes.",
        ));
    }
    let expires_at = expiration.min(made_at + DURATION_SECS);
    if expires_at < made_at + MIN_LEASE_SECS {
        return Err(LeaseError::invalid_answer_because(
            KIND,
            "the credentials expire in less than a minute.",
        ));
    }
    Ok(expires_at)
}

/// The four values of an STS answer. The slices point into the erased answer buffer.
struct StsCredentials<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a str,
    expiration: u64,
}

/// Read the credentials of the answer of `call`, or `None` when the answer is not the
/// documented form: an optional XML declaration, the call's response element once (as
/// the whole document), its result element once, one `Credentials` element in it, and
/// in that each of `AccessKeyId` (`ASIA…`), `SecretAccessKey`, `SessionToken`, and
/// `Expiration` (RFC 3339 UTC) once, without attributes, markup, or entities.
fn scan_credentials<'a>(answer: &'a [u8], call: Call<'_>) -> Option<StsCredentials<'a>> {
    let text = std::str::from_utf8(answer).ok()?.trim();
    let text = match text.strip_prefix("<?xml") {
        Some(rest) => rest.split_once("?>")?.1.trim_start(),
        None => text,
    };
    let root = call.response_element();
    let close = format!("</{root}>");
    if !text.starts_with(&format!("<{root}"))
        || !text.ends_with(&close)
        || start_tags(text, root) != 1
        || text.matches(&close).count() != 1
    {
        return None;
    }
    let result = element(text, call.result_element())?;
    let credentials = element(result, "Credentials")?;
    let access_key_id = leaf(credentials, "AccessKeyId")?;
    let secret_access_key = leaf(credentials, "SecretAccessKey")?;
    let session_token = leaf(credentials, "SessionToken")?;
    let expiration = super::parse_rfc3339(leaf(credentials, "Expiration")?)?;
    let token_like = |value: &str| {
        super::is_lease_value(value) && value.bytes().all(|byte| byte.is_ascii_graphic())
    };
    if !is_session_key_id(access_key_id)
        || !token_like(secret_access_key)
        || !token_like(session_token)
    {
        return None;
    }
    Some(StsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

/// How many start tags of the element `name` `text` has: `<name>`, `<name …>`, or
/// `<name/>`, not `<nameOther>`.
fn start_tags(text: &str, name: &str) -> usize {
    let open = format!("<{name}");
    text.match_indices(&open)
        .filter(|(at, _)| {
            matches!(
                text.as_bytes().get(at + open.len()),
                Some(b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r')
            )
        })
        .count()
}

/// The content of the one element `<name>…</name>` in `text`: one start tag of that name
/// and it has no attributes, one end tag, after it.
fn element<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    if start_tags(text, name) != 1
        || text.matches(&open).count() != 1
        || text.matches(&close).count() != 1
    {
        return None;
    }
    let start = text.find(&open)? + open.len();
    let end = text.find(&close)?;
    if start > end {
        return None;
    }
    Some(&text[start..end])
}

/// An [`element`] whose content is text only (no `<`, `>`, or `&`), without the white
/// space around it.
fn leaf<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let content = element(text, name)?.trim_matches(|c: char| c.is_ascii_whitespace());
    (!content.is_empty() && !content.contains(['<', '>', '&'])).then_some(content)
}

fn check_access_key_id(id: &str) -> Result<(), &'static str> {
    if id.starts_with("ASIA") {
        return Err(ASIA_REFUSED);
    }
    let body_ok = id.len() == 20
        && id.starts_with("AKIA")
        && id[4..]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
    if body_ok {
        Ok(())
    } else {
        Err("the field access_key_id is not an IAM user key (AKIA and 16 characters A-Z, 0-9).")
    }
}

fn is_secret_access_key(secret: &str) -> bool {
    secret.len() == 40
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'/' || byte == b'+')
}

/// `ASIA` and 12 to 124 characters `A-Z0-9`: a temporary key id of an STS answer.
fn is_session_key_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id.starts_with("ASIA")
        && id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// `arn:aws:iam::<12 digits>:role/<path and name>`, at most 2048 bytes; the role part is
/// printable ASCII without spaces.
fn is_role_arn(arn: &str) -> bool {
    let Some(rest) = arn.strip_prefix("arn:aws:iam::") else {
        return false;
    };
    let Some((account, role)) = rest.split_once(":role/") else {
        return false;
    };
    arn.len() <= MAX_ROLE_ARN_BYTES
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && !role.is_empty()
        && role.bytes().all(|byte| byte.is_ascii_graphic())
}

/// `[a-z]{2}(-[a-z]+)+-[0-9]+`, at most 32 bytes.
fn is_region(region: &str) -> bool {
    let parts: Vec<&str> = region.split('-').collect();
    let letters =
        |part: &&str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase());
    region.len() <= MAX_REGION_BYTES
        && parts.len() >= 3
        && parts[0].len() == 2
        && letters(&parts[0])
        && parts[1..parts.len() - 1].iter().all(letters)
        && parts
            .last()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// `[a-z0-9-]{1,32}`.
fn is_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SERVICE_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use ring::{digest, hmac};
    use serde_json::json;

    use super::*;
    use crate::broker::http::parse_destination;
    use crate::lease::{LeaseCode, LeaseStatus, acquire_at, check_source, scan};

    /// The long-lived key of the source: the published example key of the AWS
    /// documentation, also the canary of `sources.json`. Not a real key.
    const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /// What the fake STS hands out.
    const LEASE_KEY_ID: &str = "ASIAFAKESTSLEASE0001";
    const LEASE_SECRET: &str = "FakeStsLeaseSecretKey/0000000000000000001";
    const LEASE_TOKEN: &str = "FwoGZXIvYXdzEFakeStsSessionToken/+=0001";
    const BODY_CANARY: &str = "FAKE-STS-ERROR-BODY-CANARY-0001";
    const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/apassy/agent-read";
    const NOW: u64 = 1_793_700_000;

    /// What the fake STS saw of the one request.
    struct Seen {
        raw: Vec<u8>,
        signature_ok: bool,
        scope_region: String,
        accept: Option<String>,
        form: Vec<(String, String)>,
        amz_unix: Option<u64>,
    }

    #[derive(Clone)]
    enum Answer {
        /// 200 with credentials that expire `lifetime` seconds after `X-Amz-Date`.
        Credentials { lifetime: u64 },
        /// This status with an STS error body that holds [`BODY_CANARY`].
        Status(u16),
        /// 200 with this body.
        Body(String),
        /// Read the request and never answer.
        Silent,
    }

    fn fake_sts(answer: Answer) -> (ProviderEndpoints, JoinHandle<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("loopback");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let raw = read_request(&mut stream);
            let seen = inspect(raw);
            let (status, body) = match &answer {
                Answer::Credentials { lifetime } => {
                    let action = form_value(&seen.form, "Action").unwrap_or_default();
                    let expiration =
                        crate::lease::rfc3339(seen.amz_unix.expect("x-amz-date") + lifetime)
                            .expect("expiration");
                    (200, credentials_xml(&action, &expiration))
                }
                Answer::Status(status) => (*status, error_xml()),
                Answer::Body(body) => (200, body.clone()),
                Answer::Silent => {
                    // Wait until the client gives up and closes.
                    let _ = stream.read(&mut [0u8; 1]);
                    return seen;
                }
            };
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nx-amzn-RequestId: c6104cbe\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("write");
            seen
        });
        (ProviderEndpoints::all_at(destination), handle)
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).expect("read");
            raw.extend_from_slice(&chunk[..read]);
            if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
                if raw.len() >= end + 4 + length {
                    return raw;
                }
            }
            assert!(read > 0, "the request ended early");
        }
    }

    fn inspect(raw: Vec<u8>) -> Seen {
        let end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("head");
        let head = String::from_utf8(raw[..end].to_vec()).expect("ASCII head");
        let body = raw[end + 4..].to_vec();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().expect("request line").to_owned();
        let headers: Vec<(String, String)> = lines
            .map(|line| {
                let (name, value) = line.split_once(':').expect("header");
                (name.trim().to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let header = |name: &str| {
            headers
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| value.clone())
        };
        let (signature_ok, scope_region) = independent_check(&request_line, &header, &body);
        let form = String::from_utf8(body.clone())
            .expect("form")
            .split('&')
            .map(|pair| {
                let (name, value) = pair.split_once('=').expect("pair");
                (percent_decode(name), percent_decode(value))
            })
            .collect();
        Seen {
            amz_unix: header("x-amz-date").and_then(|date| sigv4::parse_amz_date(&date)),
            accept: header("accept"),
            raw,
            signature_ok,
            scope_region,
            form,
        }
    }

    /// Verify the SigV4 signature of a form `POST /` with the test secret, written out
    /// here with `ring` and string formatting (not with `sigv4`), as AWS would check it.
    fn independent_check(
        request_line: &str,
        header: &dyn Fn(&str) -> Option<String>,
        body: &[u8],
    ) -> (bool, String) {
        fn mac(key: &[u8], data: &str) -> Vec<u8> {
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
                .as_ref()
                .to_vec()
        }
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        let Some(authorization) = header("authorization") else {
            return (false, String::new());
        };
        let Some(rest) = authorization.strip_prefix("AWS4-HMAC-SHA256 Credential=") else {
            return (false, String::new());
        };
        let (credential, rest) = rest.split_once(", SignedHeaders=").expect("signed headers");
        let (signed, signature) = rest.split_once(", Signature=").expect("signature");
        let parts: Vec<&str> = credential.split('/').collect();
        assert_eq!(parts.len(), 5, "credential scope");
        assert_eq!(parts[0], KEY_ID);
        assert_eq!(parts[3], "sts");
        assert_eq!(parts[4], "aws4_request");
        let (method, path) = request_line
            .strip_suffix(" HTTP/1.1")
            .and_then(|line| line.split_once(' '))
            .expect("request line");
        let mut canonical = format!("{method}\n{path}\n\n");
        for name in signed.split(';') {
            let value = header(name).expect("signed header present");
            canonical.push_str(&format!("{name}:{value}\n"));
        }
        canonical.push_str(&format!(
            "\n{signed}\n{}",
            hex(digest::digest(&digest::SHA256, body).as_ref())
        ));
        let amz = header("x-amz-date").expect("x-amz-date");
        let scope = format!("{}/{}/{}/aws4_request", parts[1], parts[2], parts[3]);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
            hex(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref())
        );
        let mut key = mac(format!("AWS4{SECRET}").as_bytes(), parts[1]);
        for step in [parts[2], parts[3], "aws4_request"] {
            key = mac(&key, step);
        }
        let ok = amz.starts_with(parts[1])
            && signed.split(';').any(|name| name == "host")
            && hex(&mac(&key, &to_sign)) == signature;
        (ok, parts[2].to_owned())
    }

    fn percent_decode(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(out).expect("UTF-8")
    }

    fn form_value(form: &[(String, String)], name: &str) -> Option<String> {
        form.iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
    }

    fn credentials_xml(action: &str, expiration: &str) -> String {
        let user = if action == "AssumeRole" {
            "<AssumedRoleUser>\n      <Arn>arn:aws:sts::123456789012:assumed-role/agent-read/apassy-run-7</Arn>\n      <AssumedRoleId>AROA3XFRBF535PLBIFPI4:apassy-run-7</AssumedRoleId>\n    </AssumedRoleUser>"
        } else {
            "<FederatedUser>\n      <Arn>arn:aws:sts::123456789012:federated-user/apassy-run-7</Arn>\n      <FederatedUserId>123456789012:apassy-run-7</FederatedUserId>\n    </FederatedUser>"
        };
        format!(
            "<{action}Response xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\n  <{action}Result>\n    {user}\n    <Credentials>\n      <AccessKeyId>{LEASE_KEY_ID}</AccessKeyId>\n      <SecretAccessKey>{LEASE_SECRET}</SecretAccessKey>\n      <SessionToken>{LEASE_TOKEN}</SessionToken>\n      <Expiration>{expiration}</Expiration>\n    </Credentials>\n    <PackedPolicySize>6</PackedPolicySize>\n  </{action}Result>\n  <ResponseMetadata>\n    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>\n  </ResponseMetadata>\n</{action}Response>\n"
        )
    }

    fn error_xml() -> String {
        format!(
            "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>{BODY_CANARY}: {SECRET} is not authorized</Message></Error><RequestId>c6104cbe</RequestId></ErrorResponse>"
        )
    }

    fn fields(id: &str, secret: &str) -> Vec<Field> {
        vec![
            Field {
                name: ACCESS_KEY_ID_FIELD.to_owned(),
                value: SecretValue::new(id.to_owned()),
                secret: false,
            },
            Field {
                name: SECRET_ACCESS_KEY_FIELD.to_owned(),
                value: SecretValue::new(secret.to_owned()),
                secret: true,
            },
        ]
    }

    fn source(settings: Value) -> LeaseSource {
        LeaseSource {
            kind: LeaseKind::AwsSts,
            env_name: "AWS_ACCESS_KEY_ID".to_owned(),
            fields: fields(KEY_ID, SECRET),
            settings,
        }
    }

    fn scope() -> RunScope {
        RunScope {
            run_label: "run-7".to_owned(),
            ttl_wanted: 900,
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    fn pairs(form: &[(&str, &str)]) -> Vec<(String, String)> {
        form.iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// An endpoint that must not be called: a listener that is never accepted.
    fn untouched() -> (ProviderEndpoints, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("loopback");
        (ProviderEndpoints::all_at(destination), listener)
    }

    #[test]
    fn assume_role_gives_asia_credentials_that_expire_in_900s() {
        let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime: 900 });
        let source = source(json!({"role_arn": ROLE_ARN, "region": "eu-central-1"}));
        let lease =
            acquire_at(&source, &scope(), &endpoints, None, deadline(), NOW).expect("lease");
        let seen = fake.join().expect("fake STS");
        assert!(
            seen.signature_ok,
            "the request is SigV4-signed with the long-lived key"
        );
        assert_eq!(seen.scope_region, "eu-central-1");
        assert_eq!(seen.accept.as_deref(), Some("text/xml"));
        assert_eq!(seen.amz_unix, Some(NOW));
        assert_eq!(
            seen.form,
            pairs(&[
                ("Action", "AssumeRole"),
                ("Version", STS_VERSION),
                ("RoleArn", ROLE_ARN),
                ("RoleSessionName", "apassy-run-7"),
                ("DurationSeconds", "900"),
            ])
        );
        assert_eq!(lease.kind, LeaseKind::AwsSts);
        assert_eq!(
            lease.env_names(),
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_CREDENTIAL_EXPIRATION"
            ]
        );
        let key = lease.secret("AWS_ACCESS_KEY_ID").expect("key id");
        assert!(key.expose().starts_with("ASIA"));
        assert_eq!(key.expose(), LEASE_KEY_ID);
        assert_eq!(
            lease.secret(SECRET_ACCESS_KEY).expect("secret").expose(),
            LEASE_SECRET
        );
        assert_eq!(
            lease.secret(SESSION_TOKEN).expect("token").expose(),
            LEASE_TOKEN
        );
        assert_eq!(lease.made_at, NOW);
        assert_eq!(lease.expires_at, NOW + 900);
        assert_eq!(lease.lifetime_secs(), 900);
        assert_eq!(lease.plain[0].text, "2026-11-03T10:15:00Z");
        assert!(lease.revoke.is_none());
        assert!(lease.update_field.is_none());
        lease.check().expect("contract");
    }

    #[test]
    fn get_federation_token_sends_an_allow_all_policy_when_the_item_has_none() {
        let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime: 900 });
        let lease = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .expect("lease");
        let seen = fake.join().expect("fake STS");
        assert!(seen.signature_ok);
        assert_eq!(seen.scope_region, DEFAULT_REGION);
        assert_eq!(
            seen.form,
            pairs(&[
                ("Action", "GetFederationToken"),
                ("Version", STS_VERSION),
                ("Name", "apassy-run-7"),
                ("DurationSeconds", "900"),
                ("Policy", ALLOW_ALL_POLICY),
            ])
        );
        assert_eq!(lease.expires_at, NOW + 900);

        // The item's own policy replaces the allow-all policy.
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;
        let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime: 900 });
        acquire_at(
            &source(json!({"policy": policy})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .expect("lease");
        let seen = fake.join().expect("fake STS");
        assert_eq!(form_value(&seen.form, "Policy").as_deref(), Some(policy));

        // AssumeRole sends the policy only when the item has one.
        let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime: 900 });
        acquire_at(
            &source(json!({"role_arn": ROLE_ARN, "policy": policy})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .expect("lease");
        let seen = fake.join().expect("fake STS");
        assert_eq!(
            form_value(&seen.form, "Action").as_deref(),
            Some("AssumeRole")
        );
        assert_eq!(form_value(&seen.form, "Policy").as_deref(), Some(policy));
        // GetSessionToken is never used.
        assert!(
            !seen
                .form
                .iter()
                .any(|(_, value)| value == "GetSessionToken")
        );
    }

    #[test]
    fn a_longer_expiration_than_asked_is_refused() {
        for lifetime in [3600, 43_200, DURATION_SECS + MAX_CLOCK_SKEW_SECS + 1] {
            let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime });
            let error = acquire_at(
                &source(json!({})),
                &scope(),
                &endpoints,
                None,
                deadline(),
                NOW,
            )
            .unwrap_err();
            fake.join().expect("fake STS");
            assert_eq!(error.code, LeaseCode::LeaseFailed, "{lifetime}");
            assert_eq!(error.status, LeaseStatus::InvalidAnswer, "{lifetime}");
            assert!(
                error.message.contains("longer than 15 minutes"),
                "{lifetime}"
            );
            scan::assert_no_secret(error.message.as_bytes(), LEASE_SECRET);
            scan::assert_no_secret(error.message.as_bytes(), LEASE_TOKEN);
        }
        // Within the clock window the lease is accepted and never claims more than 900 s.
        let (endpoints, fake) = fake_sts(Answer::Credentials {
            lifetime: DURATION_SECS + MAX_CLOCK_SKEW_SECS,
        });
        let lease = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .expect("lease within the skew window");
        fake.join().expect("fake STS");
        assert_eq!(lease.expires_at, NOW + DURATION_SECS);
        // A lease that is nearly over is no lease.
        let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime: 30 });
        let error = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .unwrap_err();
        fake.join().expect("fake STS");
        assert_eq!(error.status, LeaseStatus::InvalidAnswer);
    }

    #[test]
    fn a_4xx_from_sts_is_lease_failed_without_the_body() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/private-sharing-v1/error-lease-failed.json"
        ))
        .expect("fixture");
        let (endpoints, fake) = fake_sts(Answer::Status(403));
        let error = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .unwrap_err();
        fake.join().expect("fake STS");
        assert_eq!(error, LeaseError::http_status(LeaseKind::AwsSts, 403));
        assert_eq!(error.code.as_str(), "lease_failed");
        assert_eq!(error.status.detail(), "403");
        assert_eq!(fixture["error"]["message"], error.message.as_str());
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(BODY_CANARY));
            assert!(!text.contains("AccessDenied"));
        }
        // A 200 whose body is not the documented answer is an invalid answer, also
        // without the body.
        let (endpoints, fake) = fake_sts(Answer::Body(error_xml()));
        let error = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .unwrap_err();
        fake.join().expect("fake STS");
        assert_eq!(error, LeaseError::invalid_answer(LeaseKind::AwsSts));
        assert!(!format!("{error:?}").contains(BODY_CANARY));
    }

    #[test]
    fn the_long_lived_secret_is_not_in_the_lease_or_the_error() {
        let (endpoints, fake) = fake_sts(Answer::Credentials { lifetime: 900 });
        let lease = acquire_at(
            &source(json!({"role_arn": ROLE_ARN})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .expect("lease");
        let seen = fake.join().expect("fake STS");
        // What the agent's side gets: every variable and value of the lease.
        let mut agent_side = String::new();
        for secret in &lease.secrets {
            agent_side.push_str(&format!("{}={}\n", secret.name, secret.value.expose()));
        }
        for plain in &lease.plain {
            agent_side.push_str(&format!("{}={}\n", plain.name, plain.text));
        }
        agent_side.push_str(&format!("{lease:?}"));
        scan::assert_no_secret(agent_side.as_bytes(), SECRET);
        // The secret never went over the wire either: only its signature did.
        scan::assert_no_secret(seen.raw.as_slice(), SECRET);
        // Debug of the lease shows no lease value.
        for value in [LEASE_KEY_ID, LEASE_SECRET, LEASE_TOKEN] {
            assert!(!format!("{lease:?}").contains(value));
        }
        // No error text holds it: a provider error whose body echoes the secret, a bad
        // source, and an unreachable endpoint.
        let (endpoints, fake) = fake_sts(Answer::Status(403));
        let failed = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        )
        .unwrap_err();
        fake.join().expect("fake STS");
        let (idle, _listener) = untouched();
        let bad_source = acquire_at(
            &source(json!({"region": "Mars"})),
            &scope(),
            &idle,
            None,
            deadline(),
            NOW,
        )
        .unwrap_err();
        let mut short = source(json!({}));
        short.fields = fields(KEY_ID, "too-short-secret-value");
        let bad_key = acquire_at(&short, &scope(), &idle, None, deadline(), NOW).unwrap_err();
        for error in [&failed, &bad_source, &bad_key] {
            scan::assert_no_secret(format!("{error} {error:?}").as_bytes(), SECRET);
            assert!(!error.message.contains("too-short-secret-value"));
        }
        assert_eq!(bad_source.status, LeaseStatus::InvalidSource);
    }

    #[test]
    fn an_asia_key_is_refused_before_any_call() {
        let (endpoints, listener) = untouched();
        let mut asia = source(json!({}));
        asia.fields = fields("ASIAIOSFODNN7EXAMPLE", SECRET);
        let error = acquire_at(&asia, &scope(), &endpoints, None, deadline(), NOW).unwrap_err();
        assert_eq!(error.code, LeaseCode::LeaseFailed);
        assert_eq!(error.status, LeaseStatus::InvalidSource);
        assert!(error.message.contains("already temporary"));
        assert!(!error.message.contains("ASIAIOSFODNN7EXAMPLE"));
        let why = check_source(LeaseKind::AwsSts, &asia.fields, &json!({})).unwrap_err();
        assert!(why.contains("already temporary"));
        // Other bad sources also stop before the call.
        let mut cases = Vec::new();
        let mut not_akia = source(json!({}));
        not_akia.fields = fields("AKIDEXAMPLE", SECRET);
        cases.push(not_akia);
        let mut flipped = source(json!({}));
        flipped.fields[1].secret = false;
        cases.push(flipped);
        let mut fixed_name = source(json!({}));
        fixed_name.env_name = SESSION_TOKEN.to_owned();
        cases.push(fixed_name);
        let mut bad_name = source(json!({}));
        bad_name.env_name = "aws key".to_owned();
        cases.push(bad_name);
        cases.push(source(json!({"policy": "not json"})));
        cases.push(source(json!({"unknown": 1})));
        for case in &cases {
            let error = acquire_at(case, &scope(), &endpoints, None, deadline(), NOW).unwrap_err();
            assert_eq!(error.status, LeaseStatus::InvalidSource, "{case:?}");
        }
        assert!(listener.accept().is_err(), "no provider call was made");
    }

    #[test]
    fn aws_settings_are_strict() {
        let fixture = include_str!("../../tests/fixtures/private-sharing-v1/settings-aws-sts.json");
        let parsed = AwsSettings::parse_text(fixture).expect("fixture");
        assert_eq!(parsed.region(), "eu-central-1");
        assert_eq!(parsed.services.as_deref(), Some(&["s3".to_owned()][..]));
        assert_eq!(
            AwsSettings::parse(&serde_json::from_str(fixture).expect("JSON")),
            Ok(parsed)
        );
        assert_eq!(
            AwsSettings::parse(&json!({})).expect("empty").region(),
            DEFAULT_REGION
        );
        let long_policy = format!(
            r#"{{"Version":"2012-10-17","Statement":[],"Pad":"{}"}}"#,
            "x".repeat(MAX_POLICY_BYTES)
        );
        let refused = [
            json!([]),
            json!("text"),
            json!({"role": ROLE_ARN}),
            json!({"role_arn": 7}),
            json!({"role_arn": "arn:aws:iam::12345678901:role/x"}),
            json!({"role_arn": "arn:aws:iam::123456789012:user/x"}),
            json!({"role_arn": "arn:aws-cn:iam::123456789012:role/x"}),
            json!({"role_arn": "arn:aws:iam::123456789012:role/"}),
            json!({"role_arn": "arn:aws:iam::123456789012:role/a b"}),
            json!({"policy": "[1]"}),
            json!({"policy": "not json"}),
            json!({"policy": long_policy}),
            json!({"region": "eu-central"}),
            json!({"region": "EU-central-1"}),
            json!({"region": "eu--1"}),
            json!({"region": "e-central-1"}),
            json!({"services": []}),
            json!({"services": ["s3", "s3"]}),
            json!({"services": ["S3"]}),
            json!({"services": (0..17).map(|index| format!("s{index}")).collect::<Vec<_>>()}),
            json!({"services": "s3"}),
        ];
        for settings in &refused {
            assert!(AwsSettings::parse(settings).is_err(), "{settings}");
        }
        assert!(
            AwsSettings::parse_text(r#"{"region":"eu-central-1","region":"us-east-1"}"#).is_err()
        );
        assert!(AwsSettings::parse_text(r#"["arn"]"#).is_err());
        assert!(AwsSettings::parse_text(r#"{"region":"eu-central-1"} x"#).is_err());
        // A 2048-byte policy is the limit, not over it.
        let mut exact = String::from(r#"{"Version":"2012-10-17","Pad":""#);
        exact.push_str(&"x".repeat(MAX_POLICY_BYTES - exact.len() - 2));
        exact.push_str(r#""}"#);
        assert_eq!(exact.len(), MAX_POLICY_BYTES);
        AwsSettings::parse(&json!({"policy": exact})).expect("2048 bytes");
    }

    #[test]
    fn the_scanner_reads_only_the_documented_answer() {
        let assume = Call::AssumeRole { role_arn: ROLE_ARN };
        let good = credentials_xml("AssumeRole", "2026-11-03T10:15:00Z");
        let read = scan_credentials(good.as_bytes(), assume).expect("documented answer");
        assert_eq!(read.access_key_id, LEASE_KEY_ID);
        assert_eq!(read.secret_access_key, LEASE_SECRET);
        assert_eq!(read.session_token, LEASE_TOKEN);
        assert_eq!(read.expiration, NOW + 900);
        let declared = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{good}");
        assert!(scan_credentials(declared.as_bytes(), assume).is_some());
        let fractional = credentials_xml("AssumeRole", "2026-11-03T10:15:00.359Z");
        assert_eq!(
            scan_credentials(fractional.as_bytes(), assume).map(|read| read.expiration),
            Some(NOW + 900)
        );
        let key = format!("<AccessKeyId>{LEASE_KEY_ID}</AccessKeyId>");
        let token = format!("<SessionToken>{LEASE_TOKEN}</SessionToken>");
        let refused = [
            // The other call's answer.
            credentials_xml("GetFederationToken", "2026-11-03T10:15:00Z"),
            good.replace(&key, &format!("{key}{key}")),
            good.replace(&token, ""),
            good.replace(&token, "<SessionToken>a&amp;b</SessionToken>"),
            good.replace(&token, "<SessionToken><![CDATA[x]]></SessionToken>"),
            good.replace(&token, "<SessionToken>a b</SessionToken>"),
            good.replace(&token, "<SessionToken></SessionToken>"),
            good.replace("<AccessKeyId>", "<AccessKeyId id=\"1\">"),
            good.replace(&key, "<AccessKeyId/>"),
            good.replace(LEASE_KEY_ID, "AKIAFAKESTSLEASE0001"),
            good.replace(LEASE_KEY_ID, "ASIA"),
            good.replace("2026-11-03T10:15:00Z", "2026-11-03T10:15:00+00:00"),
            good.replace("<Credentials>", "<Credentials><Credentials>"),
            format!("{good}<AssumeRoleResponse></AssumeRoleResponse>"),
            format!("x{good}"),
            good.replace("AssumeRoleResult", "AssumeRoleResults"),
            "{\"AssumeRoleResponse\":{}}".to_owned(),
            String::new(),
        ];
        for (index, answer) in refused.iter().enumerate() {
            assert!(
                scan_credentials(answer.as_bytes(), assume).is_none(),
                "answer {index}"
            );
        }
        assert!(scan_credentials(&[0xff, 0xfe], assume).is_none());
    }

    #[test]
    fn an_unreachable_or_silent_sts_is_lease_failed() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let closed = ProviderEndpoints::all_at(
            parse_destination(&format!("http://127.0.0.1:{port}")).expect("loopback"),
        );
        let error =
            acquire_at(&source(json!({})), &scope(), &closed, None, deadline(), NOW).unwrap_err();
        assert_eq!(error.code, LeaseCode::LeaseFailed);
        assert_eq!(error.status, LeaseStatus::Unreachable);
        assert_eq!(error.status.detail(), "unreachable");

        let (endpoints, fake) = fake_sts(Answer::Silent);
        let started = Instant::now();
        let error = acquire_at(
            &source(json!({})),
            &scope(),
            &endpoints,
            None,
            Instant::now() + Duration::from_millis(300),
            NOW,
        )
        .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline holds"
        );
        assert_eq!(error.status, LeaseStatus::Timeout);
        assert_eq!(error.status.detail(), "timeout");
        fake.join().expect("fake STS");
    }

    #[test]
    fn the_session_name_fits_both_calls() {
        assert_eq!(session_name("run-7"), "apassy-run-7");
        assert_eq!(session_name(""), "apassy-run");
        assert_eq!(session_name("a b/c:d"), "apassy-a-b-c-d");
        assert_eq!(session_name("r\u{e9}n"), "apassy-r-n");
        let long = session_name(&"9".repeat(100));
        assert_eq!(
            long.len(),
            32,
            "GetFederationToken's Name has at most 32 characters"
        );
        assert!(long.starts_with("apassy-999"));
    }

    #[test]
    fn the_production_endpoint_is_the_regional_sts_host() {
        let endpoints = ProviderEndpoints::production();
        let settings = AwsSettings::parse(&json!({"region": "ap-southeast-2"})).expect("settings");
        assert_eq!(
            endpoints
                .sts_for(settings.region())
                .map(|url| url.host_header()),
            Ok("sts.ap-southeast-2.amazonaws.com".to_owned())
        );
    }
}
