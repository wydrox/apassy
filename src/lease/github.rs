//! GitHub App installation tokens: the kind `github_app` (contract private-sharing-v1
//! sections 3 and 4, plan s6 decision S6-6).
//!
//! The key holder signs an RS256 JWT with the app's private key (`iss` = the app id,
//! `iat` 60 seconds back, `exp` 9 minutes ahead; GitHub allows 10) and asks
//! `POST {api_url}/app/installations/{installation_id}/access_tokens` for a token of the
//! installation, narrowed to the item's `repositories` and `permissions` when it has
//! them. GitHub fixes the token at one hour, so the key holder revokes it when the run
//! ends (`DELETE {api_url}/installation/token` with the token itself as bearer). The JWT
//! and the private key never leave this module; the lease holds only the `ghs_` token.

use std::fmt;
use std::time::Instant;

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::json::Object;
use super::jwt::{self, RsaKey};
use super::{
    Lease, LeaseError, LeaseKind, LeaseSecret, LeaseSource, LeaseStatus, ProviderEndpoints,
};
use crate::broker::http::{self, Body, HttpRequest, Method, TlsClient};
use crate::vault::{GithubAppSettings, SecretValue};

/// The default `api_url` (contract section 3.2).
pub const DEFAULT_API_URL: &str = GithubAppSettings::DEFAULT_API_URL;
/// The path of the revocation after the `api_url`; the lease's `revoke.url` is
/// `<api_url>/installation/token` (contract section 4).
pub const REVOKE_PATH: &str = "/installation/token";
/// The media type of the GitHub REST API.
pub const ACCEPT: &str = "application/vnd.github+json";
/// The REST API version that this module was written for.
pub const API_VERSION: &str = "2022-11-28";
/// The prefix of an installation token.
pub const TOKEN_PREFIX: &str = "ghs_";
/// An installation token lives one hour.
pub const TOKEN_SECS: u64 = 3600;

const KIND: LeaseKind = LeaseKind::GithubApp;

/// What a source gives for the calls, after every check: the app, the installation, the
/// key, and the API. `Debug` redacts the key.
pub(super) struct Prepared {
    app_id: String,
    installation_id: u64,
    key: RsaKey,
    api_url: String,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("key", &self.key)
            .field("api_url", &self.api_url)
            .finish()
    }
}

/// Read the fields of a `github_app` source (checked by the vault's rules already) and
/// parse its private key. No provider call.
pub(super) fn prepare(source: &LeaseSource) -> Result<Prepared, LeaseError> {
    let invalid = |why: &str| LeaseError::invalid_source(KIND, why);
    let super::LeaseSource {
        settings: crate::vault::ShortLivedSettings::GithubApp(settings),
        ..
    } = source
    else {
        return Err(invalid("its settings are of another kind."));
    };
    let text = |name: &str| {
        super::field(&source.fields, name)
            .map(|field| field.value.expose())
            .ok_or_else(|| invalid(&format!("the item has no field {name}.")))
    };
    let app_id = text("app_id")?.to_owned();
    let installation_id: u64 = text("installation_id")?
        .parse()
        .map_err(|_| invalid("the field installation_id is not a decimal number of at least 1."))?;
    let key = RsaKey::from_pem(text("private_key")?).map_err(invalid)?;
    Ok(Prepared {
        app_id,
        installation_id,
        key,
        api_url: settings.api_url().trim_end_matches('/').to_owned(),
    })
}

/// The JWT of the app at `now`: RS256, `iat` 60 seconds back, `exp` 9 minutes ahead.
fn app_jwt(prepared: &Prepared, now: u64) -> Result<Zeroizing<String>, LeaseError> {
    let claims = serde_json::json!({
        "iat": now.saturating_sub(jwt::BACKDATE_SECS),
        "exp": now + jwt::LIFETIME_SECS,
        "iss": prepared.app_id,
    });
    jwt::rs256(&prepared.key, None, &claims).map_err(|why| LeaseError::invalid_source(KIND, why))
}

/// The JSON body of the token request: the item's repositories and permissions, when it
/// has them (else `{}`: every repository and permission of the installation).
fn request_body(settings: &GithubAppSettings) -> Vec<u8> {
    let mut body = Map::new();
    if let Some(repositories) = &settings.repositories {
        body.insert("repositories".to_owned(), Value::from(repositories.clone()));
    }
    if let Some(permissions) = &settings.permissions {
        // `GithubPermissions` serializes as an object of strings.
        if let Ok(value) = serde_json::to_value(permissions) {
            body.insert("permissions".to_owned(), value);
        }
    }
    serde_json::to_vec(&Value::Object(body)).unwrap_or_else(|_| b"{}".to_vec())
}

/// Why GitHub refused, for the owner, without its body.
fn hint(status: u16) -> &'static str {
    match status {
        401 => {
            "GitHub refused the app's JWT: check the app id and the private key, and the clock of this computer."
        }
        403 | 422 => {
            "GitHub refused the repositories or the permissions: the installation may not have them."
        }
        404 => "GitHub has no such installation of the app: check the installation id.",
        _ => "",
    }
}

/// Make a `github_app` lease. `now` is the Unix time of the request (`made_at`).
pub(super) fn acquire(
    source: &LeaseSource,
    settings: &GithubAppSettings,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
    now: u64,
) -> Result<Lease, LeaseError> {
    let prepared = prepare(source)?;
    let (destination, prefix) = endpoints
        .github_api(&prepared.api_url)
        .map_err(|why| LeaseError::invalid_source(KIND, why))?;
    let token_jwt = app_jwt(&prepared, now)?;
    let path = format!(
        "{prefix}/app/installations/{}/access_tokens",
        prepared.installation_id
    );
    let body = request_body(settings);
    let headers = [("Accept", ACCEPT), ("X-GitHub-Api-Version", API_VERSION)];
    let request = HttpRequest {
        bearer: Some(token_jwt.as_str()),
        headers: &headers,
        body: Some(Body::Json(&body)),
        ..HttpRequest::new(Method::Post, &path)
    };
    let mut response = http::send(&destination, &request, deadline, tls)
        .map_err(|failure| LeaseError::from_http(KIND, failure))?;
    // The JWT and the key are not needed after the call.
    drop(token_jwt);
    let revoke_url = format!("{}{REVOKE_PATH}", prepared.api_url);
    drop(prepared);
    let answer = Zeroizing::new(std::mem::take(&mut response.body));
    if !matches!(response.status, 200 | 201) {
        return Err(LeaseError::http_status_because(
            KIND,
            response.status,
            hint(response.status),
        ));
    }
    let text = std::str::from_utf8(&answer).map_err(|_| LeaseError::invalid_answer(KIND))?;
    let object = Object::parse(text).ok_or_else(|| LeaseError::invalid_answer(KIND))?;
    let token = object
        .text("token")
        .filter(|token| is_installation_token(token))
        .ok_or_else(|| {
            LeaseError::invalid_answer_because(KIND, "the answer has no installation token.")
        })?;
    let expiry = object
        .text("expires_at")
        .and_then(|text| super::parse_rfc3339(&text))
        .ok_or_else(|| {
            LeaseError::invalid_answer_because(KIND, "the answer has no expiry time.")
        })?;
    let expires_at = super::capped_expiry(KIND, expiry, now, TOKEN_SECS)?;
    let lease = Lease {
        kind: KIND,
        secrets: vec![LeaseSecret {
            name: source.env_name.clone(),
            value: SecretValue::new(token.as_str().to_owned()),
        }],
        plain: Vec::new(),
        made_at: now,
        expires_at,
        revoke: Some(super::Revoke::Github { url: revoke_url }),
        update_field: None,
        lifetime_assumed: false,
    };
    drop(token);
    drop(object);
    drop(answer);
    lease
        .check()
        .map_err(|_| LeaseError::invalid_answer(KIND))?;
    Ok(lease)
}

/// `ghs_` and `[A-Za-z0-9_]`, a lease value.
fn is_installation_token(token: &str) -> bool {
    token.len() > TOKEN_PREFIX.len()
        && token.starts_with(TOKEN_PREFIX)
        && super::is_lease_value(token)
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Revoke the installation token `token` at `url` (`<api_url>/installation/token`): a
/// `DELETE` with the token as bearer; GitHub answers 204.
pub(super) fn revoke(
    url: &str,
    token: &SecretValue,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
) -> Result<(), LeaseError> {
    let refused = || LeaseError::revoke_failed(KIND, LeaseStatus::InvalidSource);
    let api_url = url.strip_suffix(REVOKE_PATH).ok_or_else(refused)?;
    let (destination, prefix) = endpoints.github_api(api_url).map_err(|_| refused())?;
    let path = format!("{prefix}{REVOKE_PATH}");
    let headers = [("Accept", ACCEPT), ("X-GitHub-Api-Version", API_VERSION)];
    let request = HttpRequest {
        bearer: Some(token.expose()),
        headers: &headers,
        ..HttpRequest::new(Method::Delete, &path)
    };
    let mut response = http::send(&destination, &request, deadline, tls)
        .map_err(|failure| LeaseError::revoke_failed_http(KIND, failure))?;
    drop(Zeroizing::new(std::mem::take(&mut response.body)));
    if response.status == 204 {
        Ok(())
    } else {
        Err(LeaseError::revoke_failed(
            KIND,
            LeaseStatus::Http(response.status),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;
    use crate::lease::jwt::tests::{pkcs1_pem, pkcs8_pem, verify};
    use crate::lease::testing::{Reply, Seen, deadline, endpoints, fake, untouched};
    use crate::lease::{LeaseCode, Revoke, acquire_at, check_source, revoke_at, scan};
    use crate::vault::{Field, ShortLivedSettings};

    const NOW: u64 = 1_793_700_000;
    const TOKEN: &str = "ghs_FakeInstallationToken000000000000001";
    const BODY_CANARY: &str = "FAKE-GITHUB-ERROR-BODY-CANARY-0001";

    fn fields(pem: &str) -> Vec<Field> {
        let field = |name: &str, value: &str, secret: bool| Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        };
        vec![
            field("app_id", "123456", false),
            field("installation_id", "7654321", false),
            field("private_key", pem, true),
        ]
    }

    fn source(settings: &Value, pem: &str) -> LeaseSource {
        LeaseSource {
            env_name: "GITHUB_TOKEN".to_owned(),
            fields: fields(pem),
            settings: ShortLivedSettings::parse_checked(KIND, &settings.to_string())
                .expect("GitHub settings"),
        }
    }

    fn token_answer(expires_at: &str) -> Reply {
        Reply::json(
            201,
            &json!({
                "token": TOKEN,
                "expires_at": expires_at,
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [{"id": 1, "name": "apassy-test", "full_name": "o/apassy-test"}]
            }),
        )
    }

    /// The private key's canaries: its base64 lines (each also in every encoded form
    /// that the scan knows).
    fn key_canaries(pem: &str) -> Vec<String> {
        pem.lines()
            .filter(|line| !line.starts_with("-----") && line.len() >= 16)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_github_app_jwt_is_rs256_with_a_short_expiry() {
        for pem in [pkcs1_pem(), pkcs8_pem()] {
            let (destination, fake) = fake(1, |_, seen: &Seen| {
                // The fake checks the JWT with the test key, as GitHub would.
                let (header, claims) = verify(seen.bearer().expect("bearer JWT"));
                assert_eq!(header["alg"], "RS256");
                assert_eq!(claims["iss"], "123456");
                let iat = claims["iat"].as_u64().expect("iat");
                let exp = claims["exp"].as_u64().expect("exp");
                assert_eq!(iat, NOW - 60, "iat 60 s back");
                assert!(exp - iat <= 600, "GitHub allows at most 10 minutes");
                assert!(exp <= NOW + 540, "exp at most 9 minutes ahead");
                token_answer("2026-11-03T11:00:00Z")
            });
            let result = acquire_at(
                &source(&json!({}), &pem),
                &crate::lease::RunScope {
                    run_label: "7".to_owned(),
                    ttl_wanted: 900,
                },
                &endpoints(destination),
                None,
                deadline(),
                NOW,
            );
            let seen = fake.join().expect("fake GitHub");
            let lease = result.expect("lease");
            assert_eq!(seen[0].method, "POST");
            assert_eq!(seen[0].path, "/app/installations/7654321/access_tokens");
            assert_eq!(seen[0].header("accept"), Some(ACCEPT));
            assert_eq!(seen[0].header("x-github-api-version"), Some(API_VERSION));
            assert_eq!(seen[0].json(), json!({}), "no narrowing asked");
            assert_eq!(lease.lifetime_secs(), 3600);
            // The private key never went over the wire.
            for canary in key_canaries(&pem) {
                scan::assert_no_secret(&seen[0].raw, &canary);
            }
        }
    }

    #[test]
    fn an_installation_token_is_delivered_and_revoked() {
        let settings = json!({
            "repositories": ["apassy-test"],
            "permissions": {"metadata": "read", "contents": "read"},
            "api_url": "https://api.github.com"
        });
        let (destination, server) = fake(2, |index, seen: &Seen| match index {
            0 => token_answer("2026-11-03T11:00:00Z"),
            _ => {
                assert_eq!(seen.bearer(), Some(TOKEN), "the token revokes itself");
                Reply::text(204, "")
            }
        });
        let both = endpoints(destination);
        let source = source(&settings, &pkcs1_pem());
        check_source(&source).expect("a valid source");
        let lease = acquire_at(
            &source,
            &crate::lease::RunScope {
                run_label: "7".to_owned(),
                ttl_wanted: 900,
            },
            &both,
            None,
            deadline(),
            NOW,
        )
        .expect("lease");
        assert_eq!(lease.kind, KIND);
        assert_eq!(lease.env_names(), ["GITHUB_TOKEN"]);
        assert_eq!(lease.secret("GITHUB_TOKEN").expect("token").expose(), TOKEN);
        assert_eq!(lease.made_at, NOW);
        assert_eq!(lease.expires_at, NOW + 3600);
        assert_eq!(
            lease.revoke,
            Some(Revoke::Github {
                url: "https://api.github.com/installation/token".to_owned()
            })
        );
        assert!(lease.update_field.is_none() && !lease.lifetime_assumed);
        revoke_at(&lease, None, &both, None, deadline()).expect("revoked");
        let seen = server.join().expect("fake GitHub");
        assert_eq!(
            seen[0].json(),
            json!({
                "repositories": ["apassy-test"],
                "permissions": {"contents": "read", "metadata": "read"}
            }),
            "the token is narrowed to the item's repositories and permissions"
        );
        assert_eq!(seen[1].method, "DELETE");
        assert_eq!(seen[1].path, "/installation/token");
        assert!(seen[1].body.is_empty());

        // A failed revocation is `lease_revoke_failed` with GitHub's status.
        let (destination, fake) = fake(1, |_, _: &Seen| Reply::text(401, BODY_CANARY));
        let error = revoke_at(
            &lease,
            None,
            &crate::lease::testing::endpoints(destination),
            None,
            deadline(),
        )
        .unwrap_err();
        fake.join().expect("fake GitHub");
        assert_eq!(error.code, LeaseCode::LeaseRevokeFailed);
        assert_eq!(error.status, LeaseStatus::Http(401));
        assert!(!error.message.contains(BODY_CANARY));
        scan::assert_no_secret(format!("{error} {error:?}"), TOKEN);
    }

    #[test]
    fn a_token_that_lives_longer_than_an_hour_or_is_not_an_installation_token_is_refused() {
        let cases: Vec<(Reply, &str)> = vec![
            (
                token_answer("2026-11-03T12:00:00Z"),
                "longer than 60 minutes",
            ),
            (token_answer("2026-11-03T10:00:30Z"), "less than a minute"),
            (
                Reply::json(
                    201,
                    &json!({"token": "gho_NotAnInstallationToken", "expires_at": "2026-11-03T11:00:00Z"}),
                ),
                "no installation token",
            ),
            (Reply::json(201, &json!({"token": TOKEN})), "no expiry time"),
            (
                Reply::text(
                    201,
                    &format!(r#"{{"token": "{TOKEN}", "token": "{TOKEN}"}}"#),
                ),
                "invalid answer",
            ),
        ];
        for (reply, words) in cases {
            let reply = Arc::new(Mutex::new(Some(reply)));
            let (destination, fake) = fake(1, move |_, _: &Seen| {
                reply.lock().expect("lock").take().expect("one reply")
            });
            let error = acquire_at(
                &source(&json!({}), &pkcs8_pem()),
                &crate::lease::RunScope {
                    run_label: "7".to_owned(),
                    ttl_wanted: 900,
                },
                &endpoints(destination),
                None,
                deadline(),
                NOW,
            )
            .unwrap_err();
            fake.join().expect("fake GitHub");
            assert_eq!(error.status, LeaseStatus::InvalidAnswer, "{words}");
            assert!(error.message.contains(words), "{words}: {}", error.message);
            scan::assert_no_secret(format!("{error} {error:?}"), TOKEN);
        }
        // Within the clock window, the lease is accepted and claims one hour at most.
        let (destination, fake) = fake(1, |_, _: &Seen| token_answer("2026-11-03T11:04:00Z"));
        let lease = acquire_at(
            &source(&json!({}), &pkcs8_pem()),
            &crate::lease::RunScope {
                run_label: "7".to_owned(),
                ttl_wanted: 900,
            },
            &endpoints(destination),
            None,
            deadline(),
            NOW,
        )
        .expect("lease");
        fake.join().expect("fake GitHub");
        assert_eq!(lease.expires_at, NOW + 3600);
    }

    #[test]
    fn github_errors_name_the_status_and_a_hint_but_never_the_body() {
        for status in [401, 404, 422, 500] {
            let (destination, fake) = fake(1, move |_, _: &Seen| {
                Reply::text(status, &format!(r#"{{"message": "{BODY_CANARY}"}}"#))
            });
            let error = acquire_at(
                &source(&json!({}), &pkcs1_pem()),
                &crate::lease::RunScope {
                    run_label: "7".to_owned(),
                    ttl_wanted: 900,
                },
                &endpoints(destination),
                None,
                deadline(),
                NOW,
            )
            .unwrap_err();
            fake.join().expect("fake GitHub");
            assert_eq!(error.code, LeaseCode::LeaseFailed);
            assert_eq!(error.status, LeaseStatus::Http(status));
            assert!(
                error
                    .message
                    .starts_with(&format!("GitHub answered {status}."))
            );
            assert!(error.message.ends_with(crate::lease::NOT_RUN));
            assert!(!format!("{error} {error:?}").contains(BODY_CANARY));
        }
    }

    #[test]
    fn a_bad_github_source_makes_no_call() {
        let (endpoints, listener) = untouched();
        let mut cases = Vec::new();
        let mut not_rsa = source(
            &json!({}),
            "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElD\n-----END RSA PRIVATE KEY-----\n",
        );
        cases.push(("not an RSA key", std::mem::take(&mut not_rsa.fields)));
        let mut flipped = fields(&pkcs1_pem());
        flipped[2].secret = false;
        cases.push(("must be secret", flipped));
        let mut zero = fields(&pkcs1_pem());
        zero[1].value = SecretValue::new("0".to_owned());
        cases.push(("installation_id", zero));
        let mut missing = fields(&pkcs1_pem());
        missing.remove(0);
        cases.push(("no field app_id", missing));
        let pem = pkcs1_pem();
        for (words, fields) in cases {
            let source = LeaseSource {
                fields,
                ..source(&json!({}), &pem)
            };
            let error = check_source(&source).unwrap_err();
            assert_eq!(error.status, LeaseStatus::InvalidSource, "{words}");
            assert!(error.message.contains(words), "{words}: {}", error.message);
            let acquired = acquire_at(
                &source,
                &crate::lease::RunScope {
                    run_label: "7".to_owned(),
                    ttl_wanted: 900,
                },
                &endpoints,
                None,
                deadline(),
                NOW,
            )
            .unwrap_err();
            assert_eq!(acquired, error);
            for canary in key_canaries(&pem) {
                scan::assert_no_secret(format!("{error} {error:?} {source:?}"), &canary);
            }
        }
        // Settings that break the rules (built without the parser) are refused too.
        let unparsed = LeaseSource {
            settings: ShortLivedSettings::GithubApp(GithubAppSettings {
                api_url: Some("http://api.github.com".to_owned()),
                ..GithubAppSettings::default()
            }),
            ..source(&json!({}), &pem)
        };
        assert_eq!(
            check_source(&unparsed).unwrap_err().status,
            LeaseStatus::InvalidSource
        );
        assert!(listener.accept().is_err(), "no provider call");
    }

    #[test]
    fn an_enterprise_api_url_keeps_its_path() {
        let production = ProviderEndpoints::production();
        let (destination, prefix) = production
            .github_api("https://ghe.example.com/api/v3/")
            .expect("GHES");
        assert_eq!(destination.host_header(), "ghe.example.com");
        assert_eq!(prefix, "/api/v3");
        let (destination, prefix) = production.github_api(DEFAULT_API_URL).expect("default");
        assert_eq!(destination, production.github);
        assert_eq!(prefix, "");
        assert!(production.github_api("http://ghe.example.com").is_err());
        assert!(
            production
                .github_api("https://user@ghe.example.com")
                .is_err()
        );
    }
}
