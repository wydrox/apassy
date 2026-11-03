//! OAuth access tokens from a refresh token: the kind `oauth_refresh` (contract
//! private-sharing-v1 sections 3 and 4, plan s6 decision S6-7).
//!
//! The key holder keeps the refresh token (and the client secret, for a confidential
//! client) and asks the item's `token_url` for an access token:
//! `POST token_url` with `grant_type=refresh_token`, the refresh token, the item's
//! `scope`, and the client authentication of `client_auth` (RFC 6749 sections 2.3.1 and
//! 6): `basic` sends `Authorization: Basic` of the form-encoded client id and secret;
//! `body` sends `client_id` and `client_secret` in the form. A public client (no
//! `client_secret`) sends its `client_id` in the form with either setting.
//!
//! The lease lives as long as the answer's `expires_in` says (its real expiry). Without
//! a `revoke_url`, an `expires_in` over one hour, or none, is `lease_failed`: the token
//! would outlive the run for longer than a lease may, or for an unknown time. With a
//! `revoke_url`, the access token is revoked at run end (RFC 7009), so a longer
//! `expires_in` is reported as it is, and a missing one gives a lease of one hour with
//! [`Lease::expiry_unknown`] (contract section 3.3).
//!
//! A `refresh_token` in the answer that differs from the stored one is a rotation: it is
//! returned in [`Lease::update_field`], or in [`LeaseError::update_field`] when the rest
//! of the answer is unusable, and the caller ([`super::holder::KeyHolder`]) MUST store it
//! before it delivers the lease or fails the run; a failed write still delivers the
//! lease (the old token is dead) and writes a loud activity row with "authorize again"
//! (contract section 4.2).

use std::fmt;
use std::time::Instant;

use zeroize::Zeroizing;

use super::json::Object;
use super::{
    Lease, LeaseError, LeaseKind, LeaseSecret, LeaseSource, LeaseStatus, ProviderEndpoints,
    UpdateField,
};
use crate::broker::http::{self, Body, HttpRequest, Method, TlsClient};
use crate::native::base64;
use crate::vault::{OauthClientAuth, OauthSettings, SecretValue};

/// The field that a rotation updates.
pub const REFRESH_TOKEN_FIELD: &str = "refresh_token";
/// The longest refresh token that the item stores (contract section 3.1).
pub const MAX_REFRESH_TOKEN_BYTES: usize = 4096;
/// The longest life of an access token that is not revoked at run end (contract section
/// 3.3): one hour. Without a `revoke_url`, an answer with a longer `expires_in`, or with
/// none, is `lease_failed`. With one, a lease without `expires_in` shows this lifetime
/// and [`Lease::expiry_unknown`].
pub const MAX_UNREVOKED_SECS: u64 = 3600;

const KIND: LeaseKind = LeaseKind::OauthRefresh;
const REFUSED_HINT: &str =
    "The token endpoint refused the refresh token or the client: authorize the item again.";
/// The end of the reason of a failed answer that rotated the refresh token, before the
/// caller stored it. [`super::holder::KeyHolder`] replaces it with [`ROTATED_STORED`]
/// when the new token is stored.
pub const ROTATED_NOT_STORED: &str = "It also gave a new refresh token, so the stored one may no longer work: authorize the item again.";
/// [`ROTATED_NOT_STORED`] after the new refresh token was stored.
pub const ROTATED_STORED: &str = "It also gave a new refresh token, which Apassy stored.";

/// The client of a source: its id and, for a confidential client, its secret. `Debug`
/// redacts the secret.
pub(super) struct Client<'a> {
    id: &'a str,
    secret: Option<&'a SecretValue>,
}

impl fmt::Debug for Client<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("secret", &self.secret.is_some())
            .finish()
    }
}

/// What a source gives for the token request. No provider call.
pub(super) struct Prepared<'a> {
    client: Client<'a>,
    refresh_token: &'a SecretValue,
}

impl fmt::Debug for Prepared<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("client", &self.client)
            .field("refresh_token", &"[redacted]")
            .finish()
    }
}

fn client(source: &LeaseSource) -> Result<Client<'_>, LeaseError> {
    let id = super::field(&source.fields, "client_id")
        .ok_or_else(|| LeaseError::invalid_source(KIND, "the item has no field client_id."))?;
    Ok(Client {
        id: id.value.expose(),
        secret: super::field(&source.fields, "client_secret").map(|field| &field.value),
    })
}

/// Read the fields of an `oauth_refresh` source (checked by the vault's rules already).
pub(super) fn prepare(source: &LeaseSource) -> Result<Prepared<'_>, LeaseError> {
    let refresh_token = super::field(&source.fields, REFRESH_TOKEN_FIELD)
        .ok_or_else(|| LeaseError::invalid_source(KIND, "the item has no field refresh_token."))?;
    Ok(Prepared {
        client: client(source)?,
        refresh_token: &refresh_token.value,
    })
}

/// The client authentication of a request: the form pairs to add and the value of an
/// `Authorization: Basic` header, if any (RFC 6749 section 2.3.1).
fn authenticate<'a>(
    client: &Client<'a>,
    auth: OauthClientAuth,
    pairs: &mut Vec<(&'a str, &'a str)>,
) -> Option<Zeroizing<String>> {
    match (auth, client.secret) {
        (OauthClientAuth::Basic, Some(secret)) => Some(basic(client.id, secret.expose())),
        (OauthClientAuth::Body, Some(secret)) => {
            pairs.push(("client_id", client.id));
            pairs.push(("client_secret", secret.expose()));
            None
        }
        // A public client identifies itself in the form (RFC 6749 section 3.2.1).
        (_, None) => {
            pairs.push(("client_id", client.id));
            None
        }
    }
}

/// `Basic <base64(urlencode(id) ":" urlencode(secret))>` in an erased buffer of the
/// exact size. The encoding is the one of [`http::form_body`] (RFC 3986 unreserved
/// characters as they are, every other byte `%XX`): its one pair `id=secret` has the
/// `=` of the pair as its only literal `=`, which becomes the `:`.
fn basic(id: &str, secret: &str) -> Zeroizing<String> {
    let mut pair = http::form_body(&[(id, secret)]);
    if let Some(separator) = pair.iter().position(|byte| *byte == b'=') {
        pair[separator] = b':';
    }
    let encoded = Zeroizing::new(base64::encode(&pair));
    drop(pair);
    let mut header = Zeroizing::new(String::with_capacity("Basic ".len() + encoded.len()));
    header.push_str("Basic ");
    header.push_str(&encoded);
    header
}

/// Make an `oauth_refresh` lease. `now` is the Unix time of the request (`made_at`).
pub(super) fn acquire(
    source: &LeaseSource,
    settings: &OauthSettings,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
    now: u64,
) -> Result<Lease, LeaseError> {
    let prepared = prepare(source)?;
    let (destination, path) = endpoints
        .oauth_for(&settings.token_url)
        .map_err(|why| LeaseError::invalid_source(KIND, why))?;
    let mut pairs: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        (REFRESH_TOKEN_FIELD, prepared.refresh_token.expose()),
    ];
    if let Some(scope) = settings.scope.as_deref() {
        pairs.push(("scope", scope));
    }
    let authorization = authenticate(&prepared.client, settings.client_auth, &mut pairs);
    let form = http::form_body(&pairs);
    drop(pairs);
    let headers: Vec<(&str, &str)> = authorization
        .as_ref()
        .map(|value| ("Authorization", value.as_str()))
        .into_iter()
        .collect();
    let request = HttpRequest {
        headers: &headers,
        body: Some(Body::Form(&form)),
        ..HttpRequest::new(Method::Post, &path)
    };
    let sent = http::send(&destination, &request, deadline, tls);
    drop(headers);
    drop(authorization);
    drop(form);
    let mut response = sent.map_err(|failure| LeaseError::from_http(KIND, failure))?;
    let answer = Zeroizing::new(std::mem::take(&mut response.body));
    if response.status != 200 {
        let hint = if matches!(response.status, 400 | 401) {
            REFUSED_HINT
        } else {
            ""
        };
        return Err(LeaseError::http_status_because(KIND, response.status, hint));
    }
    let text = std::str::from_utf8(&answer).map_err(|_| LeaseError::invalid_answer(KIND))?;
    let object = Object::parse(text).ok_or_else(|| LeaseError::invalid_answer(KIND))?;
    // The rotation is read first: a failure after it carries the new refresh token, which
    // the caller stores before it fails the run (the old one may be dead already).
    let rotated = match object.text(REFRESH_TOKEN_FIELD) {
        Some(token) if token.as_str() == prepared.refresh_token.expose() => None,
        Some(token) => Some(token),
        None if object.has(REFRESH_TOKEN_FIELD) => {
            return Err(LeaseError::invalid_answer_because(
                KIND,
                "the refresh token of the answer is not text.",
            ));
        }
        None => None,
    };
    if rotated
        .as_ref()
        .is_some_and(|token| !(1..=MAX_REFRESH_TOKEN_BYTES).contains(&token.len()))
    {
        return Err(LeaseError::invalid_answer_because(
            KIND,
            &format!("the new refresh token is not 1 to 4096 bytes. {ROTATED_NOT_STORED}"),
        ));
    }
    let rotation = rotated.map(|token| UpdateField {
        field: REFRESH_TOKEN_FIELD.to_owned(),
        value: SecretValue::new(token.as_str().to_owned()),
    });
    let failed = |why: &str| match &rotation {
        Some(update) => {
            LeaseError::invalid_answer_because(KIND, &format!("{why} {ROTATED_NOT_STORED}"))
                .with_update_field(Some(update.clone()))
        }
        None => LeaseError::invalid_answer_because(KIND, why),
    };
    let token = object
        .text("access_token")
        .filter(|token| super::is_token(token))
        .ok_or_else(|| {
            failed("the answer has no usable access token (1 to 4096 printable characters).")
        })?;
    if object
        .text("token_type")
        .is_some_and(|kind| !super::is_bearer_type(&kind))
        || (object.has("token_type") && object.text("token_type").is_none())
    {
        return Err(failed("the access token is not a bearer token."));
    }
    // A token that lives longer than an hour, or for an unknown time, is used only when
    // it is revoked at run end (contract section 3.3).
    let revoked = settings.revoke_url.is_some();
    let (lifetime, unknown) = if object.has("expires_in") {
        let seconds = object
            .uint("expires_in")
            .ok_or_else(|| failed("its expires_in is not a whole number of seconds."))?;
        if seconds > MAX_UNREVOKED_SECS && !revoked {
            return Err(failed(
                "the access token lives longer than one hour, and the item has no revoke_url to end it when the run ends.",
            ));
        }
        (seconds, false)
    } else if revoked {
        (MAX_UNREVOKED_SECS, true)
    } else {
        return Err(failed(
            "the answer does not say when the access token expires (no expires_in), and the item has no revoke_url to end it when the run ends.",
        ));
    };
    if lifetime < super::MIN_LEASE_SECS {
        return Err(failed("the credentials expire in less than a minute."));
    }
    let expires_at = now
        .checked_add(lifetime)
        .ok_or_else(|| failed("its expires_in is too large."))?;
    let lease = Lease {
        kind: KIND,
        secrets: vec![LeaseSecret {
            name: source.env_name.clone(),
            value: SecretValue::new(token.as_str().to_owned()),
        }],
        plain: Vec::new(),
        made_at: now,
        expires_at,
        revoke: settings
            .revoke_url
            .clone()
            .map(|url| super::Revoke::Oauth { url }),
        update_field: rotation,
        expiry_unknown: unknown,
    };
    drop(token);
    drop(object);
    drop(answer);
    if lease.check().is_err() {
        let mut lease = lease;
        return Err(match lease.update_field.take() {
            Some(update) => LeaseError::invalid_answer_because(
                KIND,
                &format!("the lease breaks the contract. {ROTATED_NOT_STORED}"),
            )
            .with_update_field(Some(update)),
            None => LeaseError::invalid_answer(KIND),
        });
    }
    Ok(lease)
}

/// Revoke the access token `token` at `url` (RFC 7009): `POST url` with `token` and
/// `token_type_hint=access_token`, and the client authentication of `source` when it is
/// given. The server answers 200 (also for a token that is no longer valid).
pub(super) fn revoke(
    url: &str,
    token: &SecretValue,
    source: Option<(&LeaseSource, &OauthSettings)>,
    endpoints: &ProviderEndpoints,
    tls: Option<&TlsClient>,
    deadline: Instant,
) -> Result<(), LeaseError> {
    let refused = || LeaseError::revoke_failed(KIND, LeaseStatus::InvalidSource);
    let (destination, path) = endpoints.oauth_for(url).map_err(|_| refused())?;
    let mut pairs: Vec<(&str, &str)> = vec![
        ("token", token.expose()),
        ("token_type_hint", "access_token"),
    ];
    let client = match source {
        Some((source, settings)) => Some((client(source).map_err(|_| refused())?, settings)),
        None => None,
    };
    let authorization = client
        .as_ref()
        .and_then(|(client, settings)| authenticate(client, settings.client_auth, &mut pairs));
    let form = http::form_body(&pairs);
    drop(pairs);
    let headers: Vec<(&str, &str)> = authorization
        .as_ref()
        .map(|value| ("Authorization", value.as_str()))
        .into_iter()
        .collect();
    let request = HttpRequest {
        headers: &headers,
        body: Some(Body::Form(&form)),
        ..HttpRequest::new(Method::Post, &path)
    };
    let sent = http::send(&destination, &request, deadline, tls);
    drop(headers);
    drop(authorization);
    drop(form);
    let mut response = sent.map_err(|failure| LeaseError::revoke_failed_http(KIND, failure))?;
    drop(Zeroizing::new(std::mem::take(&mut response.body)));
    if matches!(response.status, 200 | 204) {
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

    use serde_json::{Value, json};

    use super::*;
    use crate::lease::testing::{Reply, Seen, deadline, endpoints, fake, untouched};
    use crate::lease::{
        LeaseCode, Revoke, RunScope, UNKNOWN_EXPIRY_NOTE, acquire_at, check_source, revoke_at, scan,
    };
    use crate::vault::{Field, ShortLivedSettings};

    const NOW: u64 = 1_793_700_000;
    const CLIENT_ID: &str = "synthetic-client-id";
    const CLIENT_SECRET: &str = "synthetic-oauth-client-secret-0001";
    const REFRESH: &str = "synthetic-refresh-token-long-lived-0001";
    const ROTATED: &str = "synthetic-refresh-token-rotated-0002";
    const ACCESS: &str = "synthetic-access-token-0001";
    const BODY_CANARY: &str = "FAKE-OAUTH-ERROR-BODY-CANARY-0001";
    const TOKEN_URL: &str = "https://auth.example.test/oauth/token";
    const REVOKE_URL: &str = "https://auth.example.test/oauth/revoke";

    fn fields(secret: Option<&str>) -> Vec<Field> {
        let field = |name: &str, value: &str, secret: bool| Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        };
        let mut fields = vec![field("client_id", CLIENT_ID, false)];
        if let Some(secret) = secret {
            fields.push(field("client_secret", secret, true));
        }
        fields.push(field(REFRESH_TOKEN_FIELD, REFRESH, true));
        fields
    }

    fn source(settings: &Value, secret: Option<&str>) -> LeaseSource {
        LeaseSource {
            env_name: "EXAMPLE_ACCESS_TOKEN".to_owned(),
            fields: fields(secret),
            settings: ShortLivedSettings::parse_checked(KIND, &settings.to_string())
                .expect("OAuth settings"),
        }
    }

    fn settings(client_auth: &str) -> Value {
        json!({
            "token_url": TOKEN_URL,
            "client_auth": client_auth,
            "revoke_url": REVOKE_URL,
            "scope": "read write"
        })
    }

    fn scope() -> RunScope {
        RunScope {
            run_label: "7".to_owned(),
            ttl_wanted: 900,
        }
    }

    fn once(reply: Reply) -> (ProviderEndpoints, std::thread::JoinHandle<Vec<Seen>>) {
        let reply = Arc::new(Mutex::new(Some(reply)));
        let (destination, fake) = fake(1, move |_, _: &Seen| {
            reply.lock().expect("lock").take().expect("one reply")
        });
        (endpoints(destination), fake)
    }

    fn acquire_with(source: &LeaseSource, reply: Reply) -> (Result<Lease, LeaseError>, Seen) {
        let (endpoints, fake) = once(reply);
        let result = acquire_at(source, &scope(), &endpoints, None, deadline(), NOW);
        let mut seen = fake.join().expect("fake token endpoint");
        (result, seen.remove(0))
    }

    /// Every long-lived value of the source and the rotated token.
    const LONG_LIVED: [&str; 3] = [CLIENT_SECRET, REFRESH, ROTATED];

    #[test]
    fn an_oauth_refresh_returns_the_rotated_token_for_storage() {
        let source = source(&settings("basic"), Some(CLIENT_SECRET));
        check_source(&source).expect("a valid source");
        let (result, seen) = acquire_with(
            &source,
            Reply::json(
                200,
                &json!({
                    "access_token": ACCESS,
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "refresh_token": ROTATED,
                    "scope": "read write"
                }),
            ),
        );
        let lease = result.expect("lease");
        // The request: the refresh grant, the scope, and HTTP Basic client auth.
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.path, "/oauth/token");
        assert_eq!(
            seen.form(),
            [
                ("grant_type".to_owned(), "refresh_token".to_owned()),
                ("refresh_token".to_owned(), REFRESH.to_owned()),
                ("scope".to_owned(), "read write".to_owned()),
            ]
        );
        assert_eq!(
            seen.basic(),
            Some((CLIENT_ID.to_owned(), CLIENT_SECRET.to_owned()))
        );
        // The lease: the access token, the provider's lifetime, the revocation, and the
        // rotated refresh token for the caller to store before delivery.
        assert_eq!(lease.env_names(), ["EXAMPLE_ACCESS_TOKEN"]);
        assert_eq!(
            lease
                .secret("EXAMPLE_ACCESS_TOKEN")
                .expect("token")
                .expose(),
            ACCESS
        );
        assert_eq!(lease.expires_at, NOW + 3600);
        assert!(!lease.expiry_unknown);
        assert_eq!(
            lease.revoke,
            Some(Revoke::Oauth {
                url: REVOKE_URL.to_owned()
            })
        );
        let update = lease.update_field.as_ref().expect("rotation");
        assert_eq!(update.field, "refresh_token");
        assert_eq!(update.value.expose(), ROTATED);
        // The agent's side (the variable and the Debug form) holds no long-lived value.
        let agent_side = format!(
            "{}={}\n{lease:?}",
            lease.secrets[0].name,
            lease.secrets[0].value.expose()
        );
        scan::assert_no_secrets(&agent_side, &LONG_LIVED);
    }

    #[test]
    fn body_auth_a_public_client_and_an_unrotated_token() {
        // `body`: the client id and secret in the form; the same refresh token back is
        // no rotation; no `expires_in` with a `revoke_url`: one hour shown, the expiry
        // unknown, and the token revoked at run end.
        let (result, seen) = acquire_with(
            &source(&settings("body"), Some(CLIENT_SECRET)),
            Reply::json(
                200,
                &json!({"access_token": ACCESS, "token_type": "Bearer", "refresh_token": REFRESH}),
            ),
        );
        let lease = result.expect("lease");
        assert_eq!(seen.form_value("client_id").as_deref(), Some(CLIENT_ID));
        assert_eq!(
            seen.form_value("client_secret").as_deref(),
            Some(CLIENT_SECRET)
        );
        assert!(seen.header("authorization").is_none());
        assert!(
            lease.update_field.is_none(),
            "the same token is no rotation"
        );
        assert!(lease.expiry_unknown);
        assert_eq!(lease.lifetime_secs(), 3600);
        assert!(lease.revoke.is_some());
        assert!(UNKNOWN_EXPIRY_NOTE.contains("revokes it when the run ends"));
        // A public client: its id in the form, with either setting, and no secret.
        for client_auth in ["basic", "body"] {
            let (result, seen) = acquire_with(
                &source(
                    &json!({"token_url": TOKEN_URL, "client_auth": client_auth}),
                    None,
                ),
                Reply::json(200, &json!({"access_token": ACCESS, "expires_in": "600"})),
            );
            let lease = result.expect("lease");
            assert_eq!(seen.form_value("client_id").as_deref(), Some(CLIENT_ID));
            assert!(seen.form_value("client_secret").is_none());
            assert!(seen.header("authorization").is_none());
            assert_eq!(lease.expires_at, NOW + 600, "expires_in as a string");
            assert!(lease.revoke.is_none(), "no revoke_url, no revocation");
        }
    }

    #[test]
    fn an_oauth_token_is_revoked_with_the_client_auth() {
        let source = source(&settings("basic"), Some(CLIENT_SECRET));
        let (result, _) = acquire_with(
            &source,
            Reply::json(200, &json!({"access_token": ACCESS, "expires_in": 900})),
        );
        let lease = result.expect("lease");
        let (destination, fake) = fake(2, |_, _: &Seen| Reply::text(200, ""));
        let endpoints = endpoints(destination);
        revoke_at(&lease, Some(&source), &endpoints, None, deadline()).expect("revoked");
        revoke_at(&lease, None, &endpoints, None, deadline()).expect("revoked without auth");
        let seen = fake.join().expect("fake revoke endpoint");
        for request in &seen {
            assert_eq!(request.path, "/oauth/revoke");
            assert_eq!(request.form_value("token").as_deref(), Some(ACCESS));
            assert_eq!(
                request.form_value("token_type_hint").as_deref(),
                Some("access_token")
            );
            scan::assert_no_secret(&request.raw, REFRESH);
        }
        assert_eq!(
            seen[0].basic(),
            Some((CLIENT_ID.to_owned(), CLIENT_SECRET.to_owned()))
        );
        assert!(seen[1].header("authorization").is_none());
        // A refusal is `lease_revoke_failed` with the status, never the body.
        let (endpoints, fake) = once(Reply::text(503, BODY_CANARY));
        let error = revoke_at(&lease, Some(&source), &endpoints, None, deadline()).unwrap_err();
        fake.join().expect("fake revoke endpoint");
        assert_eq!(error.code, LeaseCode::LeaseRevokeFailed);
        assert_eq!(error.status, LeaseStatus::Http(503));
        let text = format!("{error} {error:?}");
        assert!(!text.contains(BODY_CANARY));
        scan::assert_no_secrets(&text, &LONG_LIVED);
        scan::assert_no_secret(&text, ACCESS);
    }

    #[test]
    fn a_bad_oauth_answer_is_lease_failed_and_a_rotation_says_authorize_again() {
        let cases: Vec<(Value, &str)> = vec![
            (json!({"token_type": "Bearer"}), "no usable access token"),
            (json!({"access_token": "a b"}), "no usable access token"),
            (
                json!({"access_token": "x".repeat(4097)}),
                "no usable access token",
            ),
            (
                json!({"access_token": ACCESS, "token_type": "DPoP"}),
                "not a bearer token",
            ),
            (
                json!({"access_token": ACCESS, "expires_in": 30}),
                "less than a minute",
            ),
            (
                json!({"access_token": ACCESS, "expires_in": -5}),
                "whole number",
            ),
            (
                json!({"access_token": ACCESS, "expires_in": 1.5}),
                "whole number",
            ),
            (
                json!({"access_token": ACCESS, "refresh_token": 7}),
                "not text",
            ),
            (
                json!({"access_token": "a b", "refresh_token": ROTATED}),
                "authorize the item again",
            ),
            (
                json!({"access_token": ACCESS, "refresh_token": ROTATED, "expires_in": 5}),
                "authorize the item again",
            ),
        ];
        for (answer, words) in cases {
            let (result, _) = acquire_with(
                &source(&settings("body"), Some(CLIENT_SECRET)),
                Reply::json(200, &answer),
            );
            let error = result.unwrap_err();
            assert_eq!(error.code, LeaseCode::LeaseFailed, "{words}");
            assert_eq!(error.status, LeaseStatus::InvalidAnswer, "{words}");
            assert!(error.message.contains(words), "{words}: {}", error.message);
            // A rotated refresh token goes with the error, for the caller to store
            // before it fails the run; never in the message or the Debug form.
            let rotated = answer.get("refresh_token").is_some_and(Value::is_string);
            assert_eq!(
                error
                    .update_field
                    .as_ref()
                    .map(|update| (update.field.as_str(), update.value.expose())),
                rotated.then_some(("refresh_token", ROTATED)),
                "{words}"
            );
            scan::assert_no_secrets(format!("{error} {error:?}"), &LONG_LIVED);
        }
    }

    #[test]
    fn a_long_or_unknown_lifetime_needs_a_revocation_at_run_end() {
        let without = json!({"token_url": TOKEN_URL, "client_auth": "body"});
        let cases = [
            (json!({"access_token": ACCESS}), "no expires_in"),
            (
                json!({"access_token": ACCESS, "expires_in": 3601}),
                "longer than one hour",
            ),
        ];
        for (answer, words) in &cases {
            let (result, _) = acquire_with(
                &source(&without, Some(CLIENT_SECRET)),
                Reply::json(200, answer),
            );
            let error = result.unwrap_err();
            assert_eq!(error.code, LeaseCode::LeaseFailed, "{words}");
            assert_eq!(error.status, LeaseStatus::InvalidAnswer, "{words}");
            assert!(error.message.contains(words), "{words}: {}", error.message);
            assert!(error.message.contains("revoke_url"), "{}", error.message);
        }
        // One hour without a revocation is fine.
        let (result, _) = acquire_with(
            &source(&without, Some(CLIENT_SECRET)),
            Reply::json(200, &json!({"access_token": ACCESS, "expires_in": 3600})),
        );
        assert_eq!(result.expect("lease").expires_at, NOW + 3600);
        // With a revocation, the real expiry of a longer token is reported as it is.
        let (result, _) = acquire_with(
            &source(&settings("body"), Some(CLIENT_SECRET)),
            Reply::json(200, &json!({"access_token": ACCESS, "expires_in": 86_400})),
        );
        let lease = result.expect("lease");
        assert_eq!(lease.expires_at, NOW + 86_400);
        assert!(!lease.expiry_unknown);
        assert!(lease.revoke.is_some());
    }

    #[test]
    fn a_provider_error_body_never_reaches_the_message() {
        for status in [400, 401, 500] {
            let body = format!(
                r#"{{"error": "invalid_grant", "error_description": "{BODY_CANARY} {REFRESH} {CLIENT_SECRET}"}}"#
            );
            let (result, _) = acquire_with(
                &source(&settings("basic"), Some(CLIENT_SECRET)),
                Reply::text(status, &body),
            );
            let error = result.unwrap_err();
            assert_eq!(error.status, LeaseStatus::Http(status));
            assert!(
                error
                    .message
                    .starts_with(&format!("The OAuth token endpoint answered {status}."))
            );
            let text = format!("{error} {error:?}");
            assert!(!text.contains(BODY_CANARY) && !text.contains("invalid_grant"));
            scan::assert_no_secrets(&text, &LONG_LIVED);
        }
        // An unreachable endpoint and a bad source make no message with a value either.
        let (idle, listener) = untouched();
        let mut flipped = source(&settings("basic"), Some(CLIENT_SECRET));
        flipped.fields[2].secret = false;
        let error = acquire_at(&flipped, &scope(), &idle, None, deadline(), NOW).unwrap_err();
        assert_eq!(error.status, LeaseStatus::InvalidSource);
        assert!(error.message.contains("refresh_token must be secret"));
        scan::assert_no_secrets(format!("{error} {error:?} {flipped:?}"), &LONG_LIVED);
        assert!(listener.accept().is_err(), "no provider call");
    }

    #[test]
    fn the_basic_credentials_are_form_encoded() {
        let header = basic("id with space", "s:e/c+r=et");
        let encoded = header.strip_prefix("Basic ").expect("Basic");
        let decoded = String::from_utf8(base64::decode(encoded).expect("base64")).expect("text");
        assert_eq!(decoded, "id%20with%20space:s%3Ae%2Fc%2Br%3Det");
        assert_eq!(header.capacity(), header.len(), "the buffer never grew");
    }
}
