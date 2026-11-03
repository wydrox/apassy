//! Google service-account access tokens: the kind `google_service_account` (contract
//! private-sharing-v1 sections 3 and 4, plan s6 decision S6-5).
//!
//! Two calls on the key holder:
//!
//! 1. A JWT-bearer exchange (RFC 7523): an RS256 assertion signed with the key's private
//!    key (`iss` = the key's `client_email`, `aud` = its `token_uri`, scope
//!    `cloud-platform`) → `POST token_uri` gives a bootstrap token. The bootstrap token
//!    never leaves this module and is erased after the second call.
//! 2. `POST iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{account}:generateAccessToken`
//!    with the bootstrap token as bearer, the item's `scopes`, and `lifetime: "900s"`, for
//!    the item's `impersonate` account or the key's own `client_email`
//!    (self-impersonation). That needs `roles/iam.serviceAccountTokenCreator` on the
//!    account and the IAM Service Account Credentials API in its project (an owner step;
//!    the error text names both).
//!
//! The answer's `expireTime` must be at most 900 seconds ahead (with the clock window of
//! [`super::MAX_CLOCK_SKEW_SECS`]); the lease holds only the short token.
//!
//! The key JSON is read by [`ServiceAccountKey::read`] with the reader of
//! [`super::json`], so its private key is copied only into an erased buffer (the vault's
//! check of the field uses the same reader).

use std::fmt;
use std::time::Instant;

use zeroize::Zeroizing;

use super::json::Object;
use super::jwt::{self, RsaKey};
use super::{Lease, LeaseError, LeaseKind, LeaseSecret, LeaseSource, ProviderEndpoints};
use crate::broker::http::{self, Body, HttpRequest, Method, TlsClient};
use crate::vault::{GoogleSettings, SecretValue, is_https_url, is_private_key_pem};

/// The `token_uri` of a Google key: [`ProviderEndpoints::google_token`].
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// The path of [`DEFAULT_TOKEN_URI`].
pub const TOKEN_PATH: &str = "/token";
/// The grant type of the bootstrap exchange (RFC 7523 section 2.1).
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The scope of the bootstrap token: enough for `generateAccessToken`.
pub const BOOTSTRAP_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// The default scopes of the lease (contract section 3.2).
pub const DEFAULT_SCOPE: &str = GoogleSettings::DEFAULT_SCOPE;
/// The `lifetime` of `generateAccessToken`: the 15 minutes of the ADR.
pub const LIFETIME: &str = "900s";
/// The lifetime of the lease in seconds.
pub const LIFETIME_SECS: u64 = 900;

const KIND: LeaseKind = LeaseKind::GoogleServiceAccount;
const ROLE_HINT: &str = "The service account needs roles/iam.serviceAccountTokenCreator on the account it acts as, and the IAM Service Account Credentials API must be on in its project.";
const KEY_HINT: &str = "The token endpoint refused the service-account key: check that the key is not deleted or disabled, and the clock of this computer.";

/// The parts of a service-account key JSON that the key holder uses. `Debug` redacts the
/// private key.
pub struct ServiceAccountKey {
    pub client_email: String,
    /// The PEM private key, in an erased buffer.
    pub private_key: Zeroizing<String>,
    pub token_uri: String,
    /// The key id for the JWT header (`kid`), when the key has one of the usual form.
    pub private_key_id: Option<String>,
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key", &"[redacted]")
            .field("token_uri", &self.token_uri)
            .field("private_key_id", &self.private_key_id.is_some())
            .finish()
    }
}

impl ServiceAccountKey {
    /// Read a service-account key JSON (contract section 3.1): one JSON object with
    /// distinct keys, `"type": "service_account"`, a `client_email` that can be a path
    /// segment, a PEM `private_key`, and an `https://` `token_uri`. Other members are
    /// ignored. The reason of a refusal names a member, never a value.
    pub fn read(text: &str) -> Result<Self, &'static str> {
        let object = Object::parse(text).ok_or("it is not one JSON object with distinct keys.")?;
        if object
            .text("type")
            .is_none_or(|kind| kind.as_str() != "service_account")
        {
            return Err("its type is not service_account.");
        }
        let client_email = object
            .text("client_email")
            .filter(|email| is_account_email(email))
            .ok_or("its client_email is not a service-account email.")?
            .as_str()
            .to_owned();
        let private_key = object
            .text("private_key")
            .filter(|key| is_private_key_pem(key))
            .ok_or("its private_key is not a PEM private key.")?;
        let token_uri = object
            .text("token_uri")
            .filter(|uri| is_https_url(uri))
            .ok_or("its token_uri is not an https:// URL.")?
            .as_str()
            .to_owned();
        let private_key_id = object
            .text("private_key_id")
            .filter(|id| {
                (1..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .map(|id| id.as_str().to_owned());
        Ok(Self {
            client_email,
            private_key,
            token_uri,
            private_key_id,
        })
    }
}

/// An account email that is safe as a path segment: `<name>@<domain>`, each part of
/// `[A-Za-z0-9._-]`, at most 254 bytes.
fn is_account_email(email: &str) -> bool {
    let part = |text: &str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    email.len() <= 254
        && email
            .split_once('@')
            .is_some_and(|(name, domain)| part(name) && part(domain))
}

/// What a source gives for the calls, after every check. `Debug` redacts the key.
pub(super) struct Prepared {
    key: ServiceAccountKey,
    rsa: RsaKey,
    /// The account that the lease acts as: `impersonate`, or the key's own account.
    account: String,
    scopes: Vec<String>,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("key", &self.key)
            .field("rsa", &self.rsa)
            .field("account", &self.account)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Read the key of a `google_service_account` source and parse its RSA key. No call.
pub(super) fn prepare(
    source: &LeaseSource,
    settings: &GoogleSettings,
) -> Result<Prepared, LeaseError> {
    let invalid = |why: &str| LeaseError::invalid_source(KIND, why);
    let field = super::field(&source.fields, "key_json")
        .ok_or_else(|| invalid("the item has no field key_json."))?;
    let key = ServiceAccountKey::read(field.value.expose()).map_err(|why| {
        invalid(&format!(
            "the field key_json is not a service-account key: {why}"
        ))
    })?;
    let rsa = RsaKey::from_pem(&key.private_key).map_err(invalid)?;
    let account = settings
        .impersonate
        .clone()
        .unwrap_or_else(|| key.client_email.clone());
    if !is_account_email(&account) {
        return Err(invalid(
            "the account to act as is not a service-account email.",
        ));
    }
    let scopes = settings
        .scopes
        .clone()
        .unwrap_or_else(|| vec![DEFAULT_SCOPE.to_owned()]);
    Ok(Prepared {
        key,
        rsa,
        account,
        scopes,
    })
}

/// Make a `google_service_account` lease. `now` is the Unix time of the first request
/// (`made_at`).
pub(super) fn acquire(
    source: &LeaseSource,
    settings: &GoogleSettings,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
    now: u64,
) -> Result<Lease, LeaseError> {
    let prepared = prepare(source, settings)?;
    let bootstrap = bootstrap_token(&prepared, endpoints, tls, deadline, now)?;
    let account = prepared.account.clone();
    let scopes = prepared.scopes.clone();
    // The long-lived key is not needed after the first call.
    drop(prepared);
    let path = format!("/v1/projects/-/serviceAccounts/{account}:generateAccessToken");
    let body = serde_json::to_vec(&serde_json::json!({"scope": scopes, "lifetime": LIFETIME}))
        .map_err(|_| LeaseError::invalid_source(KIND, "its scopes cannot be written."))?;
    let request = HttpRequest {
        bearer: Some(bootstrap.as_str()),
        body: Some(Body::Json(&body)),
        ..HttpRequest::new(Method::Post, &path)
    };
    let sent = http::send(&endpoints.google_iam, &request, deadline, tls);
    // The bootstrap token is dropped after the second call, whatever its result.
    drop(bootstrap);
    let mut response = sent.map_err(|failure| LeaseError::from_http(KIND, failure))?;
    let answer = Zeroizing::new(std::mem::take(&mut response.body));
    if response.status != 200 {
        let hint = if matches!(response.status, 403 | 404) {
            ROLE_HINT
        } else {
            ""
        };
        return Err(LeaseError::http_status_because(KIND, response.status, hint));
    }
    let text = std::str::from_utf8(&answer).map_err(|_| LeaseError::invalid_answer(KIND))?;
    let object = Object::parse(text).ok_or_else(|| LeaseError::invalid_answer(KIND))?;
    let token = object
        .text("accessToken")
        .filter(|token| super::is_token(token))
        .ok_or_else(|| {
            LeaseError::invalid_answer_because(KIND, "the answer has no access token.")
        })?;
    let expiry = object
        .text("expireTime")
        .and_then(|text| super::parse_rfc3339(&text))
        .ok_or_else(|| {
            LeaseError::invalid_answer_because(KIND, "the answer has no expiry time.")
        })?;
    let expires_at = super::capped_expiry(KIND, expiry, now, LIFETIME_SECS)?;
    let lease = Lease {
        kind: KIND,
        secrets: vec![LeaseSecret {
            name: source.env_name.clone(),
            value: SecretValue::new(token.as_str().to_owned()),
        }],
        plain: Vec::new(),
        made_at: now,
        expires_at,
        revoke: None,
        update_field: None,
        expiry_unknown: false,
    };
    drop(token);
    drop(object);
    drop(answer);
    lease
        .check()
        .map_err(|_| LeaseError::invalid_answer(KIND))?;
    Ok(lease)
}

/// The bootstrap token of the key: the JWT-bearer exchange at the key's `token_uri`.
fn bootstrap_token(
    prepared: &Prepared,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
    now: u64,
) -> Result<Zeroizing<String>, LeaseError> {
    let key = &prepared.key;
    let (destination, path) = endpoints
        .google_token_for(&key.token_uri)
        .map_err(|why| LeaseError::invalid_source(KIND, why))?;
    let claims = serde_json::json!({
        "iss": key.client_email,
        "scope": BOOTSTRAP_SCOPE,
        "aud": key.token_uri,
        "iat": now.saturating_sub(jwt::BACKDATE_SECS),
        "exp": now + jwt::LIFETIME_SECS,
    });
    let assertion = jwt::rs256(&prepared.rsa, key.private_key_id.as_deref(), &claims)
        .map_err(|why| LeaseError::invalid_source(KIND, why))?;
    let form = http::form_body(&[
        ("grant_type", JWT_BEARER),
        ("assertion", assertion.as_str()),
    ]);
    drop(assertion);
    let request = HttpRequest {
        body: Some(Body::Form(&form)),
        ..HttpRequest::new(Method::Post, &path)
    };
    let mut response = http::send(&destination, &request, deadline, tls)
        .map_err(|failure| LeaseError::from_http(KIND, failure))?;
    drop(form);
    let answer = Zeroizing::new(std::mem::take(&mut response.body));
    if response.status != 200 {
        return Err(LeaseError::http_status_because(
            KIND,
            response.status,
            KEY_HINT,
        ));
    }
    let text = std::str::from_utf8(&answer).map_err(|_| LeaseError::invalid_answer(KIND))?;
    let object = Object::parse(text).ok_or_else(|| LeaseError::invalid_answer(KIND))?;
    if object
        .text("token_type")
        .is_some_and(|kind| !super::is_bearer_type(&kind))
    {
        return Err(LeaseError::invalid_answer_because(
            KIND,
            "the bootstrap token is not a bearer token.",
        ));
    }
    object
        .text("access_token")
        .filter(|token| super::is_token(token))
        .ok_or_else(|| {
            LeaseError::invalid_answer_because(KIND, "the token endpoint gave no access token.")
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};

    use super::*;
    use crate::lease::jwt::tests::{pkcs1_pem, pkcs8_pem, verify};
    use crate::lease::testing::{Reply, Seen, deadline, endpoints, fake, untouched};
    use crate::lease::{LeaseCode, LeaseStatus, RunScope, acquire_at, check_source, scan};
    use crate::vault::{Field, ShortLivedSettings};

    const NOW: u64 = 1_793_700_000;
    const EMAIL: &str = "apassy-test@synthetic-project.iam.gserviceaccount.com";
    const BOOTSTRAP: &str = "ya29.FakeBootstrapTokenThatNeverLeaves0001";
    const LEASE_TOKEN: &str = "ya29.FakeShortLivedAccessToken0000000001";
    const BODY_CANARY: &str = "FAKE-GOOGLE-ERROR-BODY-CANARY-0001";

    fn key_json(pem: &str) -> String {
        json!({
            "type": "service_account",
            "project_id": "synthetic-project",
            "private_key_id": "0123456789abcdef0123456789abcdef01234567",
            "private_key": pem,
            "client_email": EMAIL,
            "client_id": "100000000000000000001",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": DEFAULT_TOKEN_URI,
            "universe_domain": "googleapis.com"
        })
        .to_string()
    }

    fn source(settings: &Value, key_json: &str) -> LeaseSource {
        LeaseSource {
            env_name: "CLOUDSDK_AUTH_ACCESS_TOKEN".to_owned(),
            fields: vec![Field {
                name: "key_json".to_owned(),
                value: SecretValue::new(key_json.to_owned()),
                secret: true,
            }],
            settings: ShortLivedSettings::parse_checked(KIND, &settings.to_string())
                .expect("Google settings"),
        }
    }

    fn scope() -> RunScope {
        RunScope {
            run_label: "7".to_owned(),
            ttl_wanted: 900,
        }
    }

    /// The fake token endpoint (first request) and IAM Credentials (second request).
    fn google(iam: Reply) -> (ProviderEndpoints, std::thread::JoinHandle<Vec<Seen>>) {
        let iam = Arc::new(Mutex::new(Some(iam)));
        let (destination, fake) = fake(2, move |index, seen: &Seen| match index {
            0 => Reply::json(
                200,
                &json!({"access_token": BOOTSTRAP, "expires_in": 3599, "token_type": "Bearer"}),
            ),
            _ => {
                assert_eq!(
                    seen.bearer(),
                    Some(BOOTSTRAP),
                    "IAM sees the bootstrap bearer"
                );
                iam.lock().expect("lock").take().expect("one IAM reply")
            }
        });
        (endpoints(destination), fake)
    }

    fn expire_reply(expire_time: &str) -> Reply {
        Reply::json(
            200,
            &json!({"accessToken": LEASE_TOKEN, "expireTime": expire_time}),
        )
    }

    fn key_canaries(pem: &str) -> Vec<String> {
        pem.lines()
            .filter(|line| !line.starts_with("-----") && line.len() >= 16)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_google_lease_asks_for_900s_and_drops_the_bootstrap_token() {
        let (endpoints, fake) = google(expire_reply("2026-11-03T10:15:00.512Z"));
        let source = source(&json!({}), &key_json(&pkcs8_pem()));
        check_source(&source).expect("a valid source");
        let result = acquire_at(&source, &scope(), &endpoints, None, deadline(), NOW);
        let seen = fake.join().expect("fake Google");
        let lease = result.expect("lease");
        // 1. The JWT-bearer exchange at the key's token_uri.
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, TOKEN_PATH);
        assert_eq!(
            seen[0].header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            seen[0].form_value("grant_type").as_deref(),
            Some(JWT_BEARER)
        );
        let (header, claims) = verify(&seen[0].form_value("assertion").expect("assertion"));
        assert_eq!(header["kid"], "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(claims["iss"], EMAIL);
        assert_eq!(claims["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(claims["scope"], BOOTSTRAP_SCOPE);
        assert!(
            claims["exp"].as_u64().expect("exp") - claims["iat"].as_u64().expect("iat") <= 3600
        );
        assert!(seen[0].bearer().is_none());
        // 2. generateAccessToken for the key's own account (self-impersonation).
        assert_eq!(seen[1].method, "POST");
        assert_eq!(
            seen[1].path,
            format!("/v1/projects/-/serviceAccounts/{EMAIL}:generateAccessToken")
        );
        assert_eq!(
            seen[1].json(),
            json!({"scope": [DEFAULT_SCOPE], "lifetime": "900s"})
        );
        // The lease holds only the short token, for 900 seconds at most.
        assert_eq!(lease.env_names(), ["CLOUDSDK_AUTH_ACCESS_TOKEN"]);
        assert_eq!(
            lease
                .secret("CLOUDSDK_AUTH_ACCESS_TOKEN")
                .expect("token")
                .expose(),
            LEASE_TOKEN
        );
        assert_eq!(lease.expires_at, NOW + 900);
        assert!(lease.revoke.is_none() && lease.update_field.is_none());
        let agent_side = format!(
            "{}={}\n{lease:?}",
            lease.secrets[0].name,
            lease.secrets[0].value.expose()
        );
        scan::assert_no_secret(&agent_side, BOOTSTRAP);
        // The private key went over neither request.
        for canary in key_canaries(&pkcs8_pem()) {
            scan::assert_no_secret(&agent_side, &canary);
            scan::assert_no_secret(&seen[0].raw, &canary);
            scan::assert_no_secret(&seen[1].raw, &canary);
        }
    }

    #[test]
    fn the_impersonated_account_and_the_scopes_of_the_item_are_asked_for() {
        let other = "reader@other-project.iam.gserviceaccount.com";
        let scopes = [
            "https://www.googleapis.com/auth/devstorage.read_only",
            "https://www.googleapis.com/auth/bigquery.readonly",
        ];
        let (endpoints, fake) = google(expire_reply("2026-11-03T10:15:00Z"));
        let result = acquire_at(
            &source(
                &json!({"impersonate": other, "scopes": scopes}),
                &key_json(&pkcs1_pem()),
            ),
            &scope(),
            &endpoints,
            None,
            deadline(),
            NOW,
        );
        let seen = fake.join().expect("fake Google");
        result.expect("lease");
        assert_eq!(
            seen[1].path,
            format!("/v1/projects/-/serviceAccounts/{other}:generateAccessToken")
        );
        assert_eq!(seen[1].json()["scope"], json!(scopes));
        // The assertion is still the key's own account.
        let (_, claims) = verify(&seen[0].form_value("assertion").expect("assertion"));
        assert_eq!(claims["iss"], EMAIL);
    }

    #[test]
    fn a_longer_google_token_or_an_iam_refusal_is_lease_failed() {
        let cases: Vec<(Reply, LeaseStatus, &str)> = vec![
            (
                expire_reply("2026-11-03T11:00:00Z"),
                LeaseStatus::InvalidAnswer,
                "longer than 15 minutes",
            ),
            (
                Reply::json(200, &json!({"expireTime": "2026-11-03T10:15:00Z"})),
                LeaseStatus::InvalidAnswer,
                "no access token",
            ),
            (
                Reply::text(
                    403,
                    &format!(r#"{{"error": {{"message": "{BODY_CANARY}"}}}}"#),
                ),
                LeaseStatus::Http(403),
                "roles/iam.serviceAccountTokenCreator",
            ),
            (
                Reply::text(500, BODY_CANARY),
                LeaseStatus::Http(500),
                "Google answered 500.",
            ),
        ];
        for (reply, status, words) in cases {
            let (endpoints, fake) = google(reply);
            let error = acquire_at(
                &source(&json!({}), &key_json(&pkcs8_pem())),
                &scope(),
                &endpoints,
                None,
                deadline(),
                NOW,
            )
            .unwrap_err();
            fake.join().expect("fake Google");
            assert_eq!(error.code, LeaseCode::LeaseFailed, "{words}");
            assert_eq!(error.status, status, "{words}");
            assert!(error.message.contains(words), "{words}: {}", error.message);
            let text = format!("{error} {error:?}");
            assert!(!text.contains(BODY_CANARY));
            scan::assert_no_secret(&text, BOOTSTRAP);
            scan::assert_no_secret(&text, LEASE_TOKEN);
        }
        // A token endpoint that refuses the key: one call, a hint, no IAM call.
        let (destination, fake) = fake(1, |_, _: &Seen| Reply::text(400, BODY_CANARY));
        let error = acquire_at(
            &source(&json!({}), &key_json(&pkcs8_pem())),
            &scope(),
            &endpoints(destination),
            None,
            deadline(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(fake.join().expect("fake").len(), 1);
        assert_eq!(error.status, LeaseStatus::Http(400));
        assert!(error.message.contains("not deleted or disabled"));
        assert!(!error.message.contains(BODY_CANARY));
    }

    #[test]
    fn the_key_json_is_read_strictly_and_never_echoed() {
        let pem = pkcs8_pem();
        let good = key_json(&pem);
        let key = ServiceAccountKey::read(&good).expect("key");
        assert_eq!(key.client_email, EMAIL);
        assert_eq!(key.private_key.as_str(), pem);
        assert_eq!(key.token_uri, DEFAULT_TOKEN_URI);
        let debug = format!("{key:?}");
        for canary in key_canaries(&pem) {
            scan::assert_no_secret(&debug, &canary);
        }
        let value: Value = serde_json::from_str(&good).expect("JSON");
        let with = |name: &str, member: Value| {
            let mut changed = value.clone();
            changed[name] = member;
            changed.to_string()
        };
        let refused = [
            with("type", json!("authorized_user")),
            with("client_email", json!("not an email")),
            with("client_email", json!("a/b@c.iam.gserviceaccount.com")),
            with("private_key", json!("not a pem")),
            with("token_uri", json!("http://oauth2.googleapis.com/token")),
            with("token_uri", json!(7)),
            good.replacen('{', r#"{"type": "service_account", "#, 1),
            format!("{good} trailing"),
            "[]".to_owned(),
        ];
        for (index, text) in refused.iter().enumerate() {
            let why = ServiceAccountKey::read(text).unwrap_err();
            for canary in key_canaries(&pem) {
                assert!(!why.contains(&canary), "case {index}");
            }
            assert!(!crate::vault::is_service_account_key(text), "case {index}");
        }
        assert!(crate::vault::is_service_account_key(&good));
        // A key without a key id of the usual form signs without `kid`.
        let odd = with("private_key_id", json!("not/a-kid"));
        assert_eq!(
            ServiceAccountKey::read(&odd).expect("key").private_key_id,
            None
        );
    }

    #[test]
    fn a_bad_google_source_makes_no_call() {
        let (endpoints, listener) = untouched();
        let pem = pkcs8_pem();
        let fixture_key = r#"{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n","client_email":"a@p.iam.gserviceaccount.com","token_uri":"https://oauth2.googleapis.com/token"}"#;
        let cases = [
            (source(&json!({}), fixture_key), "not an RSA key"),
            (source(&json!({}), "{}"), "key_json"),
            (
                LeaseSource {
                    settings: ShortLivedSettings::GoogleServiceAccount(GoogleSettings {
                        scopes: Some(Vec::new()),
                        impersonate: None,
                    }),
                    ..source(&json!({}), &key_json(&pem))
                },
                "scopes",
            ),
        ];
        for (source, words) in &cases {
            let error = check_source(source).unwrap_err();
            assert_eq!(error.status, LeaseStatus::InvalidSource, "{words}");
            assert!(error.message.contains(words), "{words}: {}", error.message);
            let acquired =
                acquire_at(source, &scope(), &endpoints, None, deadline(), NOW).unwrap_err();
            assert_eq!(&acquired, &error);
            for canary in key_canaries(&pem) {
                scan::assert_no_secret(format!("{error} {error:?} {source:?}"), &canary);
            }
        }
        assert!(listener.accept().is_err(), "no provider call");
    }
}
