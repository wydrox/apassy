//! Push handles through the push gateway (contract push-gateway-v1, sections 6, 10, 11,
//! and 12): the device side.
//!
//! On the hosted relay the iPhone gives the relay its APNs token, as before
//! (relay-questions-v1 section 14). On any other relay (a node: the relay inside the Mac
//! app or `apassy serve`) it exchanges the token at the gateway for a **handle** and a
//! **secret**, one per questions team, and gives the node only those
//! (`PUT /v1/push/handle`). The handle, the secret, and `expires_at` are kept per vault
//! in `questions-push.json` with a digest of the token and its environment, never the
//! token: the token comes from APNs at each launch, and a new handle is made when the
//! digest differs or the handle expires within 30 days.
//!
//! The Apple Watch registers its own handle with the kind `watch` (section 11). It never
//! sends a token to a relay: the hosted relay's Worker pushes to the iPhone topic only.
//!
//! The summary key of section 12 is derived here from the question key, for the
//! Notification Service Extensions.

use std::time::Duration;

use ring::hkdf;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use apassy::sync::{DEFAULT_RELAY_URL, RelayUrl, decode_b64u, encode_b64u, post_json, sha256_hex};

use super::super::errors::{CoreError, CoreResult};
use super::super::wire::Secret;

/// The Apassy project's gateway (push-gateway-v1 section 2), the nodes' default.
pub(super) const DEFAULT_GATEWAY: &str = "https://push.apassy.wyderka.cc";
/// The bundle ID of the watch app: the topic of the kind `watch`.
pub(super) const WATCH_BUNDLE_ID: &str = "com.wydrox.apassy.companion.watchkitapp";
/// A handle that expires within this time is renewed (section 6).
pub(super) const RENEW_SECONDS: u64 = 30 * 86_400;
/// The lifetime of a handle at the gateway (section 5).
const HANDLE_LIFETIME: u64 = 15_552_000;
/// The gateway call, from the connection to the last byte of the answer.
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(10);
/// The bytes of a handle as the node accepts it (section 10).
const MIN_HANDLE_BYTES: usize = 16;
const MAX_HANDLE_BYTES: usize = 1024;
/// The domain of the token digest.
const TOKEN_DIGEST_DOMAIN: &str = "apassy-push-token-v1";
/// The HKDF info of the summary key (section 12).
const SUMMARY_INFO: &[u8] = b"apassy-push-summary-v1";
/// The most handles kept: one per vault on this device.
pub(super) const MAX_HANDLES: usize = 64;

/// The device kind of a handle (section 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Iphone,
    Watch,
}

impl Kind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Iphone => "iphone",
            Self::Watch => "watch",
        }
    }
}

/// How the push of one questions team goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    /// `PUT /v1/push/token` (the hosted relay, and a loopback test relay without a gateway).
    Token,
    /// A handle of the gateway, `PUT /v1/push/handle`.
    Handle,
    /// No push for this device on this relay (the watch on the hosted relay).
    Unavailable,
}

/// The route of a team on `relay_url`. `stored`: a handle of this vault is kept;
/// `explicit_gateway`: the app named a gateway (a test or a self-hosted build).
pub(super) fn route(relay_url: &str, kind: Kind, stored: bool, explicit_gateway: bool) -> Route {
    let hosted = relay_url == DEFAULT_RELAY_URL;
    match kind {
        Kind::Watch if hosted => Route::Unavailable,
        Kind::Watch => Route::Handle,
        Kind::Iphone if hosted => Route::Token,
        Kind::Iphone if stored => Route::Handle,
        // A relay on this computer is a development or test relay: it keeps the token
        // route unless a gateway was named.
        Kind::Iphone if relay_url.starts_with("http://") && !explicit_gateway => Route::Token,
        Kind::Iphone => Route::Handle,
    }
}

/// The normalized origin of a gateway the app names, else an error.
pub(super) fn gateway_origin(text: &str) -> CoreResult<String> {
    let parsed = RelayUrl::parse(text)
        .map_err(|_| CoreError::invalid("The push service address is not valid."))?;
    Ok(parsed.as_str().to_owned())
}

/// The digest of the token and its environment: tells whether the token changed without
/// keeping it.
pub(super) fn token_digest(environment: &str, token: &str) -> String {
    sha256_hex(format!("{TOKEN_DIGEST_DOMAIN}\0{environment}\0{token}").as_bytes())
}

/// The handle of one vault's questions team, in `questions-push.json`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredHandle {
    pub(super) team_id: String,
    pub(super) relay_url: String,
    pub(super) gateway: String,
    /// b64u, as the gateway gave it.
    pub(super) handle: String,
    /// b64u of 32 bytes.
    pub(super) secret: String,
    pub(super) expires_at: u64,
    /// [`token_digest`] of the token that the handle seals.
    pub(super) token_digest: String,
}

impl std::fmt::Debug for StoredHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredHandle")
            .field("team_id", &self.team_id)
            .field("relay_url", &self.relay_url)
            .field("gateway", &self.gateway)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl StoredHandle {
    /// Whether the entry read from the file has the forms of the contract.
    pub(super) fn is_valid(&self) -> bool {
        valid_handle(&self.handle)
            && valid_secret(&self.secret)
            && RelayUrl::parse(&self.gateway).is_ok_and(|url| url.as_str() == self.gateway)
            && !self.team_id.is_empty()
            && self.token_digest.len() == 64
    }

    /// Whether this handle still serves the team `team_id` on `relay_url` for the token
    /// of `digest` through `gateway`: the same team, gateway, and token, and more than
    /// 30 days left.
    pub(super) fn serves(
        &self,
        team_id: &str,
        relay_url: &str,
        gateway: &str,
        digest: &str,
        now: u64,
    ) -> bool {
        self.team_id == team_id
            && self.relay_url == relay_url
            && self.gateway == gateway
            && self.token_digest == digest
            && self.expires_at > now.saturating_add(RENEW_SECONDS)
    }
}

fn valid_handle(text: &str) -> bool {
    decode_b64u(text)
        .is_some_and(|bytes| (MIN_HANDLE_BYTES..=MAX_HANDLE_BYTES).contains(&bytes.len()))
}

fn valid_secret(text: &str) -> bool {
    text.len() == 43 && decode_b64u(text).is_some_and(|bytes| bytes.len() == 32)
}

#[derive(Serialize)]
struct HandleRequest<'a> {
    v: u8,
    kind: &'static str,
    token: &'a str,
    environment: &'a str,
    bundle_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleAnswer {
    v: u64,
    handle: String,
    secret: Secret,
    expires_at: u64,
}

/// A new handle from the gateway.
pub(super) struct Made {
    pub(super) handle: String,
    pub(super) secret: Zeroizing<String>,
    pub(super) expires_at: u64,
}

fn gateway_unreachable() -> CoreError {
    CoreError::new(
        "push_gateway_unreachable",
        "The push service cannot be reached. Apassy tries again at the next refresh.",
    )
}

/// `POST /v1/handles` at `gateway`: the token goes there and nowhere else.
pub(super) fn make_handle(
    gateway: &str,
    kind: Kind,
    token: &str,
    environment: &str,
    bundle_id: &str,
    now: u64,
) -> CoreResult<Made> {
    let origin = RelayUrl::parse(gateway)
        .map_err(|_| CoreError::invalid("The push service address is not valid."))?;
    let body = Zeroizing::new(
        serde_json::to_vec(&HandleRequest {
            v: 1,
            kind: kind.as_str(),
            token,
            environment,
            bundle_id,
        })
        .map_err(|_| CoreError::internal("The push request cannot be written."))?,
    );
    let (status, answer) = post_json(&origin, "/v1/handles", &body, GATEWAY_TIMEOUT)
        .map_err(|_| gateway_unreachable())?;
    match status {
        200 => parse_made(&answer, now).ok_or_else(gateway_unreachable),
        // `wrong_bundle`, `kind_unavailable`, or a body this gateway does not take.
        400 | 409 => Err(CoreError::new(
            "push_unavailable",
            "The push service does not send notifications to this app.",
        )),
        _ => Err(gateway_unreachable()),
    }
}

/// The answer of `POST /v1/handles`, checked: `v` 1, a handle of 16 to 1024 bytes, a
/// secret of 32 bytes, and an `expires_at` in the future and within the lifetime.
pub(super) fn parse_made(answer: &[u8], now: u64) -> Option<Made> {
    let wire: HandleAnswer = serde_json::from_slice(answer).ok()?;
    let secret = wire.secret.into_inner();
    let fits = wire.v == 1
        && valid_handle(&wire.handle)
        && valid_secret(&secret)
        && wire.expires_at > now
        // The gateway's clock may run ahead of this device's by a few minutes.
        && wire.expires_at <= now.saturating_add(HANDLE_LIFETIME + 3600);
    fits.then_some(Made {
        handle: wire.handle,
        secret,
        expires_at: wire.expires_at,
    })
}

/// The summary key of a question key (section 12): HKDF-SHA256 with an empty salt and
/// the info `apassy-push-summary-v1`, 32 bytes, as b64u.
pub(super) fn summary_key(question_key: &[u8]) -> Option<Zeroizing<String>> {
    struct Len32;
    impl hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    if question_key.len() != 32 {
        return None;
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(question_key);
    let info = [SUMMARY_INFO];
    let okm = prk.expand(&info, Len32).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    okm.fill(&mut out[..]).ok()?;
    Some(Zeroizing::new(encode_b64u(&out[..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_key_is_the_contract_vector() {
        let question_key: Vec<u8> = (0xc0..=0xdf).collect();
        assert_eq!(
            summary_key(&question_key).as_deref().map(String::as_str),
            Some("K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc")
        );
        assert!(summary_key(&question_key[..31]).is_none());
    }

    #[test]
    fn the_route_follows_the_relay_and_the_kind() {
        let node = "https://mac.tailnet-1234.ts.net:8444";
        assert_eq!(
            route(DEFAULT_RELAY_URL, Kind::Iphone, false, false),
            Route::Token
        );
        assert_eq!(
            route(DEFAULT_RELAY_URL, Kind::Iphone, true, true),
            Route::Token
        );
        assert_eq!(route(node, Kind::Iphone, false, false), Route::Handle);
        assert_eq!(
            route("http://127.0.0.1:4000", Kind::Iphone, false, false),
            Route::Token
        );
        assert_eq!(
            route("http://127.0.0.1:4000", Kind::Iphone, false, true),
            Route::Handle
        );
        assert_eq!(
            route("http://127.0.0.1:4000", Kind::Iphone, true, false),
            Route::Handle
        );
        assert_eq!(
            route(DEFAULT_RELAY_URL, Kind::Watch, false, false),
            Route::Unavailable
        );
        assert_eq!(route(node, Kind::Watch, false, false), Route::Handle);
    }

    #[test]
    fn the_token_digest_hides_the_token_and_follows_it() {
        let token = "a1".repeat(32);
        let digest = token_digest("production", &token);
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains(&token));
        assert_ne!(digest, token_digest("development", &token));
        assert_ne!(digest, token_digest("production", &"a2".repeat(32)));
    }

    #[test]
    fn a_gateway_answer_is_checked() {
        let now = 1_790_000_000;
        let handle = "AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGa";
        let secret = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";
        let good = format!(
            r#"{{"v":1,"handle":"{handle}","secret":"{secret}","expires_at":{}}}"#,
            now + HANDLE_LIFETIME
        );
        let made = parse_made(good.as_bytes(), now).unwrap();
        assert_eq!(made.handle, handle);
        assert_eq!(made.secret.as_str(), secret);
        for bad in [
            good.replace(r#""v":1"#, r#""v":2"#),
            good.replace(secret, &secret[..42]),
            good.replace(handle, "AQE"),
            good.replace('}', r#","token":"x"}"#),
            format!(r#"{{"v":1,"handle":"{handle}","secret":"{secret}","expires_at":{now}}}"#),
        ] {
            assert!(parse_made(bad.as_bytes(), now).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_stored_handle_serves_until_thirty_days_before_it_expires() {
        let now = 1_790_000_000;
        let stored = StoredHandle {
            team_id: "t_7k2m5q4x3c".into(),
            relay_url: "https://mac.example:8444".into(),
            gateway: DEFAULT_GATEWAY.into(),
            handle: "AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGa".into(),
            secret: "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8".into(),
            expires_at: now + RENEW_SECONDS + 1,
            token_digest: token_digest("production", &"a1".repeat(32)),
        };
        assert!(stored.is_valid());
        let digest = stored.token_digest.clone();
        let serves = |at| {
            stored.serves(
                "t_7k2m5q4x3c",
                "https://mac.example:8444",
                DEFAULT_GATEWAY,
                &digest,
                at,
            )
        };
        assert!(serves(now));
        assert!(!serves(now + 1));
        assert!(!stored.serves(
            "t_other",
            "https://mac.example:8444",
            DEFAULT_GATEWAY,
            &digest,
            now
        ));
        assert!(!stored.serves(
            "t_7k2m5q4x3c",
            "https://mac.example:8444",
            DEFAULT_GATEWAY,
            &"0".repeat(64),
            now
        ));
        // The debug form names no handle or secret.
        let shown = format!("{stored:?}");
        assert!(!shown.contains("YGFi") && !shown.contains("AQEA"));
    }
}
