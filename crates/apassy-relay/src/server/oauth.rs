//! The MCP authorization flow of an embedded node (docs/SPEC.md section 31): OAuth 2.1
//! with PKCE, dynamic client registration, and a connect request that the owner allows
//! on the Mac.
//!
//! A remote agent gets only the MCP address. Its first `POST /mcp` is 401 with
//! `WWW-Authenticate: Bearer resource_metadata=…`; it reads the metadata (RFC 9728, RFC
//! 8414), registers (RFC 7591), and opens `/oauth/authorize` in a browser. That makes a
//! connect request with a match code and sends the browser to `/oauth/wait/<id>`, a page
//! with no script, form, cookie, or button: nothing on it can authorize. A second
//! authorize of the same client with other parameters ends its waiting request and opens a
//! new one with its own code: a client id is public, so a request that someone else keeps
//! open never stands in for this browser's. The owner allows the request in the app
//! (`RunningNode::decide_connect`), which names the agent of the personal team (always a
//! new one, made for this request); the next refresh of the page sends the browser back
//! to the client with a one-time code. `POST /oauth/token` trades the code (with its PKCE verifier) for an
//! access token, which is the relay agent token of that agent (so `/mcp` auth does not
//! change), and a refresh token.
//!
//! Every state is in the directory `relay.db` (version 1004): `oauth_client`,
//! `connect_request`, `oauth_refresh`. Codes and refresh tokens are stored as SHA-256
//! hashes only; the access token is the agent token, whose hash is in the team file. One
//! agent has one live access token and one live refresh family at a time. A second use of
//! a code or of a rotated refresh token revokes the family and drops the access token.
//!
//! The limits are per node: Funnel forwards no client identity. A client that the owner
//! never allowed costs a stranger nothing to make, so it never fills a limit that a real
//! client needs: only clients allowed at least once count toward `MAX_CLIENTS` and the
//! registration window, a full table drops the oldest client that was never allowed, and
//! such a client is pruned an hour after its registration. Bad codes and refresh tokens
//! count for their client only (`ClientFailures`), never for the whole listener.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{OAuthConfig, RelayConfig};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, TeamId};
use crate::secret::{SecretString, TokenKind, new_token, parse_token, same_bytes, token_hash};
use crate::server::Core;
use crate::server::hub::Hub;
use crate::server::store::{db, to_i, to_u};

/// The lifetime of an access token: 24 hours. The physical test may lower it in a
/// development build to see the refresh work.
pub const ACCESS_TOKEN_SECS: u64 = 86_400;
/// The lifetime of a refresh token: 90 days. Each use rotates it, with a new lifetime.
pub const REFRESH_TOKEN_SECS: u64 = 90 * 86_400;
/// How long a connect request waits for the owner.
pub const CONNECT_SECS: u64 = 300;
/// How long a code can be redeemed after the page sent it.
pub const CODE_SECS: u64 = 300;
/// The one scope.
pub const SCOPE: &str = "apassy";
/// The largest body of `/oauth/register`, `/oauth/token`, and `/oauth/revoke`.
pub const MAX_BODY: usize = 16 * 1024;
/// The longest redirect URI.
pub const MAX_REDIRECT_URI: usize = 512;
/// Redirect URIs of one client, at most.
pub const MAX_REDIRECT_URIS: usize = 8;
/// The longest client name after cleaning, in bytes.
pub const MAX_CLIENT_NAME: usize = 64;
/// The longest `state`.
pub const MAX_STATE: usize = 512;
/// Registrations in `REGISTRATION_WINDOW_SECS` of clients that the owner then allowed, at
/// most. A client that was never allowed does not count.
pub const REGISTRATIONS_PER_WINDOW: u64 = 10;
/// The window of `REGISTRATIONS_PER_WINDOW`: 10 minutes.
pub const REGISTRATION_WINDOW_SECS: u64 = 600;
/// Stored clients, at most. Only clients that the owner allowed at least once can fill it:
/// at the limit, a registration drops the oldest client that was never allowed (one with
/// no waiting request first), with its requests.
pub const MAX_CLIENTS: u64 = 100;
/// A client with no live connection and no use in 7 days is pruned.
pub const UNUSED_CLIENT_SECS: u64 = 7 * 86_400;
/// A client that the owner never allowed is pruned this long after its registration, with
/// its requests: 1 hour. An authorize does not renew it.
pub const NEVER_ALLOWED_CLIENT_SECS: u64 = 3_600;
/// Bad codes and refresh tokens of one client in `CLIENT_FAILURE_WINDOW_SECS`, at most.
pub const CLIENT_FAILURES_MAX: u32 = 20;
/// The window of `CLIENT_FAILURES_MAX`, in seconds, and the `Retry-After` of its 429.
pub const CLIENT_FAILURE_WINDOW_SECS: u64 = 60;
/// Clients whose failures are kept in memory, at most.
const MAX_FAILING_CLIENTS: usize = 1_024;
/// Connect requests that wait for the owner at once, on the whole node.
pub const OPEN_CONNECTS: u64 = 3;
/// The `Refresh` of the waiting page, in seconds.
pub const PAGE_REFRESH_SECS: u64 = 3;
/// The `NodeError` code of `decide_connect` for a request that does not wait any more.
pub const CONNECT_NOT_PENDING: &str = "connect_not_pending";
/// The actor of the audit rows of this module.
pub const OAUTH_ACTOR: &str = "oauth";
/// The headers of every page and redirect of this module.
pub const PAGE_HEADERS: [(&str, &str); 5] = [
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'",
    ),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
];

/// The paths of the flow.
pub mod paths {
    pub const PROTECTED_RESOURCE: &str = "/.well-known/oauth-protected-resource";
    pub const PROTECTED_RESOURCE_MCP: &str = "/.well-known/oauth-protected-resource/mcp";
    pub const AUTHORIZATION_SERVER: &str = "/.well-known/oauth-authorization-server";
    pub const OPENID_CONFIGURATION: &str = "/.well-known/openid-configuration";
    pub const REGISTER: &str = "/oauth/register";
    pub const AUTHORIZE: &str = "/oauth/authorize";
    pub const WAIT_PREFIX: &str = "/oauth/wait/";
    pub const TOKEN: &str = "/oauth/token";
    pub const REVOKE: &str = "/oauth/revoke";
}

/// One endpoint of the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    ProtectedResource,
    AuthorizationServer,
    Register,
    Authorize,
    Wait,
    Token,
    Revoke,
}

/// The endpoint of `method` and `path`, or `None`. Only a relay with
/// `RelayConfig::oauth` asks.
pub fn route(method: &str, path: &str) -> Option<Route> {
    match (method, path) {
        ("GET", paths::PROTECTED_RESOURCE | paths::PROTECTED_RESOURCE_MCP) => {
            Some(Route::ProtectedResource)
        }
        ("GET", paths::AUTHORIZATION_SERVER | paths::OPENID_CONFIGURATION) => {
            Some(Route::AuthorizationServer)
        }
        ("POST", paths::REGISTER) => Some(Route::Register),
        ("GET", paths::AUTHORIZE) => Some(Route::Authorize),
        ("POST", paths::TOKEN) => Some(Route::Token),
        ("POST", paths::REVOKE) => Some(Route::Revoke),
        ("GET", _) => path
            .strip_prefix(paths::WAIT_PREFIX)
            .filter(|id| !id.is_empty() && !id.contains('/'))
            .map(|_| Route::Wait),
        _ => None,
    }
}

/// True for an endpoint with a body (`MAX_BODY`).
pub fn has_body(route: Route) -> bool {
    matches!(route, Route::Register | Route::Token | Route::Revoke)
}

/// What an endpoint answers. `http.rs` writes it.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// A JSON object (not the relay envelope), with `Cache-Control: no-store`.
    Json {
        status: u16,
        body: Value,
        /// A bad code or refresh token: it counts for its client (`ClientFailures`), not
        /// in the failed-auth limiter of the listener.
        auth_failed: bool,
        retry_after: Option<u64>,
    },
    /// An HTML page with `PAGE_HEADERS`; `refresh` adds `Refresh: 3`.
    Page {
        status: u16,
        html: String,
        refresh: bool,
    },
    /// 303 to `location`, with `PAGE_HEADERS`.
    Redirect { location: String },
}

impl Reply {
    fn json(status: u16, body: Value) -> Self {
        Self::Json {
            status,
            body,
            auth_failed: false,
            retry_after: None,
        }
    }

    /// An error of RFC 6749 section 5.2 (or RFC 7591 section 3.2.2).
    fn error(status: u16, code: &str, description: &str) -> Self {
        Self::json(
            status,
            json!({"error": code, "error_description": description}),
        )
    }

    /// `invalid_grant` that counts for its client (`ClientFailures`).
    fn bad_grant(description: &str) -> Self {
        Self::Json {
            status: 400,
            body: json!({"error": "invalid_grant", "error_description": description}),
            auth_failed: true,
            retry_after: None,
        }
    }

    fn limited(description: &str, retry_after: u64) -> Self {
        Self::Json {
            status: 429,
            body: json!({"error": "rate_limited", "error_description": description}),
            auth_failed: false,
            retry_after: Some(retry_after),
        }
    }

    fn page(status: u16, page: Page) -> Self {
        Self::Page {
            status,
            refresh: false,
            html: page.html(),
        }
    }
}

/// The value of `WWW-Authenticate` on a 401 of `POST /mcp` when the relay has OAuth.
/// `token_sent`: the request had a bearer token, which the node refused.
pub fn www_authenticate(config: &RelayConfig, token_sent: bool) -> Option<String> {
    config.oauth.as_ref()?;
    let mut value = format!(
        "Bearer resource_metadata=\"{}{}\", scope=\"{SCOPE}\"",
        config.public_url,
        paths::PROTECTED_RESOURCE_MCP
    );
    if token_sent {
        value.push_str(", error=\"invalid_token\"");
    }
    Some(value)
}

/// Answers one request of the flow. `path` and `query` are the request's, `body` is read
/// (at most `MAX_BODY`), and `content_type` is its header.
pub fn handle(
    hub: &Hub,
    route: Route,
    path: &str,
    query: &str,
    body: &[u8],
    content_type: Option<&str>,
    now: u64,
) -> Reply {
    let Some(oauth) = hub.config.oauth.clone() else {
        return Reply::error(404, "not_found", "No such path.");
    };
    let flow = Flow {
        hub,
        oauth: &oauth,
        origin: &hub.config.public_url,
        now,
    };
    let answer = match route {
        Route::ProtectedResource => Ok(Reply::json(200, flow.resource_metadata())),
        Route::AuthorizationServer => Ok(Reply::json(200, flow.server_metadata())),
        Route::Register => flow.register(body),
        Route::Authorize => flow.authorize(query),
        Route::Wait => flow.wait(path.strip_prefix(paths::WAIT_PREFIX).unwrap_or("")),
        Route::Token => match params_of(body, content_type) {
            Some(form) => flow.token(&form),
            None => Ok(Reply::error(
                400,
                "invalid_request",
                "The body is not a form with each parameter once.",
            )),
        },
        Route::Revoke => match params_of(body, content_type) {
            Some(form) => flow.revoke(&form).map(|()| Reply::json(200, json!({}))),
            None => Ok(Reply::json(200, json!({}))),
        },
    };
    answer.unwrap_or_else(|error| {
        if matches!(route, Route::Authorize | Route::Wait) {
            Reply::page(500, Page::broken())
        } else if error.code == codes::BUSY {
            Reply::error(503, "temporarily_unavailable", "Try again in a moment.")
        } else {
            Reply::error(500, "server_error", "The node could not answer.")
        }
    })
}

/// The parameters of a token or revocation request: a form (RFC 6749 appendix B), or a
/// JSON object of strings, which some clients send. `None` when it does not parse or a
/// parameter is there twice.
fn params_of(body: &[u8], content_type: Option<&str>) -> Option<HashMap<String, String>> {
    let json = content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
    });
    if json {
        let object: serde_json::Map<String, Value> = serde_json::from_slice(body).ok()?;
        return object
            .into_iter()
            .map(|(key, value)| value.as_str().map(|text| (key, text.to_string())))
            .collect();
    }
    decode_form(std::str::from_utf8(body).ok()?)
}

// ---- Bad codes and refresh tokens ----

/// The bad codes and refresh tokens of each registered client (`invalid_grant` of `POST
/// /oauth/token`), in a fixed window of `CLIENT_FAILURE_WINDOW_SECS` that starts at its
/// first failure. With `CLIENT_FAILURES_MAX` of them, every token request of that client
/// is 429 `rate_limited` until the window ends; no other client and no other endpoint is
/// refused. Codes and refresh tokens are 256 random bits: this only slows a client that
/// sends bad ones in a loop. In memory only, in the hub.
#[derive(Debug, Default)]
pub struct ClientFailures {
    /// For each client: the start of its window and the failures in it.
    windows: Mutex<HashMap<String, (u64, u32)>>,
}

impl ClientFailures {
    /// True while `client_id` is at its limit.
    pub fn limited(&self, client_id: &str, now: u64) -> bool {
        let windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        windows.get(client_id).is_some_and(|&(start, count)| {
            now < start.saturating_add(CLIENT_FAILURE_WINDOW_SECS) && count >= CLIENT_FAILURES_MAX
        })
    }

    /// Counts one bad code or refresh token of `client_id`.
    pub fn record(&self, client_id: &str, now: u64) {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= MAX_FAILING_CLIENTS && !windows.contains_key(client_id) {
            windows.retain(|_, &mut (start, _)| {
                now < start.saturating_add(CLIENT_FAILURE_WINDOW_SECS)
            });
            if windows.len() >= MAX_FAILING_CLIENTS {
                let oldest = windows
                    .iter()
                    .min_by_key(|(_, window)| window.0)
                    .map(|(id, _)| id.clone());
                if let Some(oldest) = oldest {
                    windows.remove(&oldest);
                }
            }
        }
        let window = windows.entry(client_id.to_string()).or_insert((now, 0));
        if window.1 == 0 || now >= window.0.saturating_add(CLIENT_FAILURE_WINDOW_SECS) {
            *window = (now, 0);
        }
        window.1 = window.1.saturating_add(1);
    }
}

// ---- The form decoder ----

/// Decodes `application/x-www-form-urlencoded` text (also a query): `+` is a space, `%XX`
/// a byte, the result must be UTF-8. `None` for a bad escape, bad UTF-8, or a name that
/// is there twice (RFC 6749 section 3.1).
pub fn decode_form(text: &str) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name)?;
        let value = percent_decode(value)?;
        if out.insert(name, value).is_some() {
            return None;
        }
    }
    Some(out)
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes.get(index + 1..index + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).ok()
}

/// Encodes a query value: every byte but the unreserved ones (RFC 3986) as `%XX`.
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

// ---- Checks ----

/// The host, the port, and the rest (path and query) of an `http://` loopback URI:
/// `localhost`, `127.0.0.1`, or `[::1]` (RFC 8252 section 7.3).
fn loopback_parts(uri: &str) -> Option<(&str, Option<&str>, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = if let Some(after) = authority.strip_prefix("[::1]") {
        if after.is_empty() {
            ("[::1]", None)
        } else {
            ("[::1]", Some(after.strip_prefix(':')?))
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        return None;
    }
    if port.is_some_and(|port| {
        port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit())
    }) {
        return None;
    }
    Some((host, port, tail))
}

/// A redirect URI that a client may register: `https://<host>…`, or `http://` to the
/// loopback with any port; ASCII, at most `MAX_REDIRECT_URI` bytes, no fragment, no space,
/// no control character, no user part.
pub fn check_redirect_uri(uri: &str) -> bool {
    if uri.is_empty()
        || !uri.is_ascii()
        || uri.len() > MAX_REDIRECT_URI
        || uri.contains('#')
        || uri.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..end];
        return !authority.is_empty()
            && !authority.starts_with(':')
            && authority
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ".-:[]".contains(ch));
    }
    loopback_parts(uri).is_some()
}

/// True when `given` is the registered URI: the same text, or for a loopback URI the
/// same host and rest with any port (RFC 8252 section 7.3).
pub fn redirect_matches(registered: &str, given: &str) -> bool {
    if registered == given {
        return true;
    }
    match (loopback_parts(registered), loopback_parts(given)) {
        (Some((host_a, _, rest_a)), Some((host_b, _, rest_b))) => {
            host_a == host_b && rest_a == rest_b
        }
        _ => false,
    }
}

/// A client name for the page and the app: no control, format, or tag character (the one
/// rule of the core, `apassy::text::is_hidden_char`, that the node and the connect card
/// use too), runs of spaces as one, trimmed, at most `MAX_CLIENT_NAME` bytes (cut at a
/// character). `None` when nothing is left.
pub fn clean_name(name: &str) -> Option<String> {
    let mut out = String::new();
    let mut space = false;
    for ch in name.chars() {
        if apassy::text::is_hidden_char(ch) {
            continue;
        }
        if ch.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if space {
            if out.len() + 1 + ch.len_utf8() > MAX_CLIENT_NAME {
                break;
            }
            out.push(' ');
            space = false;
        }
        if out.len() + ch.len_utf8() > MAX_CLIENT_NAME {
            break;
        }
        out.push(ch);
    }
    (!out.is_empty()).then_some(out)
}

/// Escapes text for HTML.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// A PKCE verifier (RFC 7636 section 4.1): 43 to 128 unreserved characters.
fn verifier_ok(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// An S256 challenge: 43 characters of base64url.
fn challenge_ok(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The S256 challenge of a verifier.
pub fn s256(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random<const N: usize>() -> RelayResult<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| RelayError::internal("The system has no random source."))?;
    Ok(bytes)
}

fn random_hex<const N: usize>() -> RelayResult<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(N * 2);
    for byte in random::<N>()? {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(out)
}

/// A code or a refresh token: 256 random bits as base64url. Only its hash is stored.
fn new_secret() -> RelayResult<SecretString> {
    Ok(SecretString::new(
        BASE64_URL_SAFE_NO_PAD.encode(random::<32>()?),
    ))
}

fn hash_of(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// The 24 letters of a match code: no 0/O, 1/I/L, 2/Z, 5/S, 6, 8/B.
const MATCH_LETTERS: &[u8; 24] = b"ACDEFGHJKMNPQRTUVWXY3479";

/// A match code such as `K7Q-4MD`: the same on the page and in the app.
fn new_match_code() -> RelayResult<String> {
    let mut out = String::with_capacity(7);
    while out.len() < 7 {
        for byte in random::<16>()? {
            // 240 = 10 × 24: no bias.
            if byte >= 240 || out.len() >= 7 {
                continue;
            }
            if out.len() == 3 {
                out.push('-');
            }
            out.push(char::from(MATCH_LETTERS[usize::from(byte) % 24]));
        }
    }
    Ok(out)
}

/// The id of a connect request: 32 hex characters.
fn request_id_ok(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---- The page ----

/// The line of the waiting and the busy page: requests that someone else started can wait
/// on the Mac, and only the owner can end them.
pub const DENY_OTHERS: &str =
    "Deny requests on your Mac that you did not start, then connect again.";

/// The text of the connect page. Every field is plain text, escaped when written.
struct Page {
    title: String,
    code: Option<String>,
    lines: Vec<String>,
}

impl Page {
    fn waiting(client: &str, mac: &str, code: &str, seconds_left: u64) -> Self {
        let minutes = seconds_left.div_ceil(60).max(1);
        let unit = if minutes == 1 { "minute" } else { "minutes" };
        Self {
            title: format!("{client} wants to connect to {mac}"),
            code: Some(code.to_string()),
            lines: vec![
                "Approve on your Mac or iPhone.".to_string(),
                format!(
                    "Check that the app shows the same code. Apassy must be open and unlocked on the Mac. The request ends in {minutes} {unit}."
                ),
                DENY_OTHERS.to_string(),
            ],
        }
    }

    fn denied() -> Self {
        Self {
            title: "You denied the connection.".to_string(),
            code: None,
            lines: vec!["You can close this page.".to_string()],
        }
    }

    fn ended() -> Self {
        Self {
            title: "The request ended.".to_string(),
            code: None,
            lines: vec!["Connect again from the app that sent you here.".to_string()],
        }
    }

    fn connected() -> Self {
        Self {
            title: "Connected".to_string(),
            code: None,
            lines: vec!["You can close this page.".to_string()],
        }
    }

    fn invalid() -> Self {
        Self {
            title: "This connection link is not valid.".to_string(),
            code: None,
            lines: vec!["Connect again from the app that sent you here.".to_string()],
        }
    }

    fn busy() -> Self {
        Self {
            title: "Too many connection requests wait.".to_string(),
            code: None,
            lines: vec![DENY_OTHERS.to_string()],
        }
    }

    fn broken() -> Self {
        Self {
            title: "The Mac could not answer.".to_string(),
            code: None,
            lines: vec!["Try again in a moment.".to_string()],
        }
    }

    /// The HTML: no script, form, button, link, image, or cookie.
    fn html(&self) -> String {
        let code = self
            .code
            .as_deref()
            .map(|code| format!("<p class=\"code\">{}</p>", escape_html(code)))
            .unwrap_or_default();
        let mut lines = String::new();
        for line in &self.lines {
            lines.push_str("<p>");
            lines.push_str(&escape_html(line));
            lines.push_str("</p>");
        }
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\"><title>Apassy</title><style>\
body{{margin:0;font:16px/1.45 -apple-system,BlinkMacSystemFont,\"Helvetica Neue\",sans-serif;\
background:#f5f5f7;color:#1d1d1f;display:flex;min-height:100vh;align-items:center;justify-content:center}}\
main{{background:#fff;border-radius:14px;padding:32px 36px;max-width:420px;text-align:center;\
box-shadow:0 1px 3px rgba(0,0,0,.12)}}h1{{font-size:20px;margin:0 0 16px}}\
.code{{font:600 30px/1.2 ui-monospace,Menlo,monospace;letter-spacing:.12em;margin:8px 0 16px}}\
p{{margin:8px 0;color:#424245}}@media (prefers-color-scheme:dark){{body{{background:#1c1c1e;color:#f5f5f7}}\
main{{background:#2c2c2e}}p{{color:#d1d1d6}}}}</style></head>\
<body><main><h1>{}</h1>{code}{lines}</main></body></html>\n",
            escape_html(&self.title)
        )
    }
}

// ---- Rows ----

struct Client {
    name: Option<String>,
    redirect_uris: Vec<String>,
}

fn load_client(conn: &Connection, client_id: &str) -> RelayResult<Option<Client>> {
    let row: Option<(Option<String>, String)> = conn
        .query_row(
            "SELECT client_name, redirect_uris FROM oauth_client WHERE client_id = ?1",
            params![client_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    Ok(row.map(|(name, uris)| Client {
        name,
        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
    }))
}

/// The name of a client on the page: its name, cleaned again (a client stored by an older
/// version kept characters that `clean_name` now removes), or "An MCP client".
fn shown_name(name: Option<&str>) -> String {
    name.and_then(clean_name)
        .unwrap_or_else(|| "An MCP client".to_string())
}

/// The SQL test that the `oauth_client` row of the outer query was allowed at least once:
/// a request of it was allowed (only an allow sets `team_id`), or it has a refresh token.
const ALLOWED_ONCE: &str = "(EXISTS (SELECT 1 FROM connect_request a \
     WHERE a.client_id = oauth_client.client_id AND a.team_id IS NOT NULL) \
     OR EXISTS (SELECT 1 FROM oauth_refresh f WHERE f.client_id = oauth_client.client_id))";

/// Deletes the client `client_id` and every connect request of it. Only for a client that
/// was never allowed: it has no team, no agent, and no refresh token.
fn delete_client(conn: &Connection, client_id: &str) -> RelayResult<()> {
    conn.execute(
        "DELETE FROM connect_request WHERE client_id = ?1",
        params![client_id],
    )
    .map_err(db)?;
    conn.execute(
        "DELETE FROM oauth_client WHERE client_id = ?1",
        params![client_id],
    )
    .map_err(db)?;
    Ok(())
}

/// Removes what no flow needs any more: connect requests older than 7 days, refresh
/// tokens past their end, clients that the owner never allowed `NEVER_ALLOWED_CLIENT_SECS`
/// after their registration (with their requests), and clients that have no live
/// connection, no open request, and no use in `UNUSED_CLIENT_SECS`.
fn prune(conn: &Connection, now: u64) -> RelayResult<()> {
    let old = to_i(now.saturating_sub(UNUSED_CLIENT_SECS));
    conn.execute(
        "DELETE FROM connect_request WHERE created_at < ?1",
        params![old],
    )
    .map_err(db)?;
    conn.execute(
        "DELETE FROM oauth_refresh WHERE expires_at <= ?1",
        params![to_i(now)],
    )
    .map_err(db)?;
    let never_allowed = to_i(now.saturating_sub(NEVER_ALLOWED_CLIENT_SECS));
    conn.execute(
        &format!(
            "DELETE FROM connect_request WHERE client_id IN (SELECT client_id FROM oauth_client \
             WHERE created_at < ?1 AND NOT {ALLOWED_ONCE})"
        ),
        params![never_allowed],
    )
    .map_err(db)?;
    conn.execute(
        &format!("DELETE FROM oauth_client WHERE created_at < ?1 AND NOT {ALLOWED_ONCE}"),
        params![never_allowed],
    )
    .map_err(db)?;
    conn.execute(
        "DELETE FROM oauth_client WHERE coalesce(used_at, created_at) < ?1 \
         AND client_id NOT IN (SELECT client_id FROM oauth_refresh \
           WHERE used_at IS NULL AND revoked_at IS NULL) \
         AND client_id NOT IN (SELECT client_id FROM connect_request \
           WHERE status IN ('pending', 'allowed'))",
        params![old],
    )
    .map_err(db)?;
    Ok(())
}

/// Marks the due connect requests `expired`.
fn expire_requests(conn: &Connection, now: u64) -> RelayResult<()> {
    conn.execute(
        "UPDATE connect_request SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?1",
        params![to_i(now)],
    )
    .map_err(db)?;
    Ok(())
}

/// Revokes the live refresh tokens of a family. Returns the agent of the family when a
/// live token was revoked: its access token came from it, so the caller drops it.
fn revoke_family(conn: &Connection, family: &str, now: u64) -> RelayResult<Option<(String, u64)>> {
    let agent: Option<(String, i64)> = conn
        .query_row(
            "SELECT team_id, agent_id FROM oauth_refresh WHERE family = ?1 LIMIT 1",
            params![family],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    let changed = conn
        .execute(
            "UPDATE oauth_refresh SET revoked_at = ?2 WHERE family = ?1 AND revoked_at IS NULL \
             AND used_at IS NULL",
            params![family, to_i(now)],
        )
        .map_err(db)?;
    conn.execute(
        "UPDATE oauth_refresh SET revoked_at = ?2 WHERE family = ?1 AND revoked_at IS NULL",
        params![family, to_i(now)],
    )
    .map_err(db)?;
    Ok(agent
        .filter(|_| changed > 0)
        .map(|(team, agent)| (team, to_u(agent))))
}

// ---- Team-file changes ----

/// Gives a live agent a new access token: a fresh relay agent token for `secs`, which
/// replaces its old one (one live access token per agent). An `agent_token_issued` row.
pub fn issue_access(core: &Core, agent: AgentId, secs: u64, now: u64) -> RelayResult<SecretString> {
    let token = new_token(TokenKind::Agent, &core.team)?;
    let hash = token_hash(token.expose());
    let expires_at = now.saturating_add(secs);
    core.store.tx(|tx| {
        let changed = tx
            .execute(
                "UPDATE agent SET token_hash = ?2, expires_at = ?3 WHERE id = ?1 \
                 AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM member m \
                 WHERE m.id = agent.member_id AND m.revoked_at IS NULL)",
                params![to_i(agent.0), hash.0.as_slice(), to_i(expires_at)],
            )
            .map_err(db)?;
        if changed == 0 {
            return Err(RelayError::not_found("agent"));
        }
        core.audit.write_on(
            tx,
            now,
            OAUTH_ACTOR,
            "agent_token_issued",
            None,
            &json!({"agent_id": agent.0, "expires_at": expires_at, "via": "oauth"}),
        )?;
        Ok(())
    })?;
    Ok(token)
}

/// Takes the access token of an agent away: its hash becomes that of a token nobody
/// holds, and it ends now. The agent stays; a new token comes from the flow. An
/// `agent_token_dropped` row with `reason`.
pub fn drop_access(core: &Core, agent: AgentId, reason: &str, now: u64) -> RelayResult<()> {
    let nobody = new_token(TokenKind::Agent, &core.team)?;
    let hash = token_hash(nobody.expose());
    drop(nobody);
    core.store.tx(|tx| {
        let changed = tx
            .execute(
                "UPDATE agent SET token_hash = ?2, expires_at = min(expires_at, ?3) WHERE id = ?1",
                params![to_i(agent.0), hash.0.as_slice(), to_i(now)],
            )
            .map_err(db)?;
        if changed == 0 {
            return Err(RelayError::not_found("agent"));
        }
        core.audit.write_on(
            tx,
            now,
            OAUTH_ACTOR,
            "agent_token_dropped",
            None,
            &json!({"agent_id": agent.0, "reason": reason}),
        )?;
        Ok(())
    })
}

/// Drops the access token of `(team, agent)` when the team is open. A team that is gone
/// has no token to drop.
fn drop_access_of(hub: &Hub, team: &str, agent: u64, reason: &str, now: u64) {
    if let Some(core) = TeamId::parse(team).and_then(|id| hub.team(&id)) {
        let _ = drop_access(&core, AgentId(agent), reason, now);
    }
}

fn agent_is_live(core: &Core, agent: AgentId) -> RelayResult<bool> {
    core.store.with(|conn| {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent WHERE id = ?1 AND revoked_at IS NULL)",
            params![to_i(agent.0)],
            |row| row.get(0),
        )
        .map_err(db)
    })
}

/// Wakes the host loops: `wait_pending` of every team returns to look at the connects.
fn wake_hosts(hub: &Hub) {
    for core in hub.all() {
        core.notify.notify();
    }
}

// ---- The endpoints ----

struct Flow<'a> {
    hub: &'a Hub,
    oauth: &'a OAuthConfig,
    origin: &'a str,
    now: u64,
}

/// What a redemption found, inside its transaction: the transaction commits either way,
/// so a revocation stays.
enum Redeemed {
    Granted {
        team: String,
        agent: u64,
        refresh: SecretString,
    },
    Refused {
        reply: Reply,
        drop: Option<(String, u64)>,
    },
}

impl Flow<'_> {
    fn resource(&self) -> String {
        format!("{}/mcp", self.origin)
    }

    fn resource_metadata(&self) -> Value {
        json!({
            "resource": self.resource(),
            "authorization_servers": [self.origin],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE],
            "resource_name": "Apassy",
        })
    }

    fn server_metadata(&self) -> Value {
        let origin = self.origin;
        json!({
            "issuer": origin,
            "authorization_endpoint": format!("{origin}{}", paths::AUTHORIZE),
            "token_endpoint": format!("{origin}{}", paths::TOKEN),
            "registration_endpoint": format!("{origin}{}", paths::REGISTER),
            "revocation_endpoint": format!("{origin}{}", paths::REVOKE),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
            "authorization_response_iss_parameter_supported": true,
        })
    }

    /// `POST /oauth/register` (RFC 7591).
    fn register(&self, body: &[u8]) -> RelayResult<Reply> {
        let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(body) else {
            return Ok(Reply::error(
                400,
                "invalid_client_metadata",
                "The body is a JSON object.",
            ));
        };
        let uris: Vec<String> = match request.get("redirect_uris") {
            Some(Value::Array(list)) if !list.is_empty() && list.len() <= MAX_REDIRECT_URIS => {
                match list
                    .iter()
                    .map(|uri| uri.as_str().filter(|uri| check_redirect_uri(uri)))
                    .collect::<Option<Vec<_>>>()
                {
                    Some(uris) => uris.into_iter().map(str::to_string).collect(),
                    None => {
                        return Ok(Reply::error(
                            400,
                            "invalid_redirect_uri",
                            "A redirect URI is https://, or http:// to localhost, 127.0.0.1, or [::1], with at most 512 bytes and no fragment.",
                        ));
                    }
                }
            }
            _ => {
                return Ok(Reply::error(
                    400,
                    "invalid_redirect_uri",
                    "redirect_uris is a list of 1 to 8 URIs.",
                ));
            }
        };
        let name = match request.get("client_name") {
            None | Some(Value::Null) => None,
            Some(Value::String(name)) => clean_name(name),
            Some(_) => {
                return Ok(Reply::error(
                    400,
                    "invalid_client_metadata",
                    "client_name is text.",
                ));
            }
        };
        let client_id = format!("c_{}", random_hex::<16>()?);
        let now = self.now;
        // `None`: at a limit. `Some(woke)`: registered; `woke` when a dropped client had
        // a waiting request, so the host loops look again.
        let registered = self.hub.directory.store.tx(|tx| {
            prune(tx, now)?;
            // Only clients that the owner allowed count: a stranger's registrations fill
            // nothing that a real client needs.
            let recent: i64 = tx
                .query_row(
                    &format!(
                        "SELECT count(*) FROM oauth_client WHERE created_at > ?1 AND {ALLOWED_ONCE}"
                    ),
                    params![to_i(now.saturating_sub(REGISTRATION_WINDOW_SECS))],
                    |row| row.get(0),
                )
                .map_err(db)?;
            let allowed: i64 = tx
                .query_row(
                    &format!("SELECT count(*) FROM oauth_client WHERE {ALLOWED_ONCE}"),
                    [],
                    |row| row.get(0),
                )
                .map_err(db)?;
            if to_u(recent) >= REGISTRATIONS_PER_WINDOW || to_u(allowed) >= MAX_CLIENTS {
                return Ok(None);
            }
            // A full table: the oldest clients that were never allowed go, those with no
            // waiting request first, with their requests.
            let all: i64 = tx
                .query_row("SELECT count(*) FROM oauth_client", [], |row| row.get(0))
                .map_err(db)?;
            let over = to_u(all).saturating_add(1).saturating_sub(MAX_CLIENTS);
            let mut woke = false;
            if over > 0 {
                let mut statement = tx
                    .prepare(&format!(
                        "SELECT client_id, EXISTS(SELECT 1 FROM connect_request p \
                         WHERE p.client_id = oauth_client.client_id AND p.status = 'pending') AS waits \
                         FROM oauth_client WHERE NOT {ALLOWED_ONCE} \
                         ORDER BY waits, created_at, rowid LIMIT ?1"
                    ))
                    .map_err(db)?;
                let evicted = statement
                    .query_map(params![to_i(over)], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
                    })
                    .map_err(db)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(db)?;
                drop(statement);
                for (old_client, waits) in evicted {
                    delete_client(tx, &old_client)?;
                    woke |= waits;
                    self.hub.directory.audit.write_on(
                        tx,
                        now,
                        OAUTH_ACTOR,
                        "oauth_client_evicted",
                        None,
                        &json!({"client_id": old_client}),
                    )?;
                }
            }
            tx.execute(
                "INSERT INTO oauth_client (client_id, client_name, redirect_uris, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    client_id,
                    name,
                    serde_json::to_string(&uris).unwrap_or_default(),
                    to_i(now)
                ],
            )
            .map_err(db)?;
            self.hub.directory.audit.write_on(
                tx,
                now,
                OAUTH_ACTOR,
                "oauth_client_registered",
                None,
                &json!({"client_id": client_id}),
            )?;
            Ok(Some(woke))
        })?;
        match registered {
            None => {
                return Ok(Reply::limited(
                    "Too many clients registered on this Mac. Try again later.",
                    REGISTRATION_WINDOW_SECS,
                ));
            }
            Some(true) => wake_hosts(self.hub),
            Some(false) => {}
        }
        let mut answer = json!({
            "client_id": client_id,
            "client_id_issued_at": now,
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPE,
        });
        if let Some(name) = name {
            answer["client_name"] = json!(name);
        }
        Ok(Reply::json(201, answer))
    }

    /// `GET /oauth/authorize`: a connect request, then 303 to its page. A bad client or
    /// redirect URI is a page; any other error goes back to the client (RFC 6749 section
    /// 4.1.2.1).
    fn authorize(&self, query: &str) -> RelayResult<Reply> {
        let Some(params) = decode_form(query) else {
            return Ok(Reply::page(400, Page::invalid()));
        };
        let get = |name: &str| params.get(name).map(String::as_str);
        let Some(client_id) = get("client_id") else {
            return Ok(Reply::page(400, Page::invalid()));
        };
        let Some(client) = self
            .hub
            .directory
            .store
            .with(|conn| load_client(conn, client_id))?
        else {
            return Ok(Reply::page(400, Page::invalid()));
        };
        let redirect_uri = match get("redirect_uri") {
            Some(uri)
                if client
                    .redirect_uris
                    .iter()
                    .any(|registered| redirect_matches(registered, uri)) =>
            {
                uri.to_string()
            }
            None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
            _ => return Ok(Reply::page(400, Page::invalid())),
        };
        let state = get("state");
        let back = |error: &str, description: &str| {
            let mut location = format!(
                "{redirect_uri}{}error={}&error_description={}",
                if redirect_uri.contains('?') { '&' } else { '?' },
                percent_encode(error),
                percent_encode(description)
            );
            if let Some(state) = state {
                location.push_str(&format!("&state={}", percent_encode(state)));
            }
            location.push_str(&format!("&iss={}", percent_encode(self.origin)));
            Reply::Redirect { location }
        };
        if get("response_type") != Some("code") {
            return Ok(back(
                "unsupported_response_type",
                "The response type is code.",
            ));
        }
        let Some(challenge) = get("code_challenge").filter(|c| challenge_ok(c)) else {
            return Ok(back("invalid_request", "PKCE with S256 is required."));
        };
        if get("code_challenge_method") != Some("S256") {
            return Ok(back("invalid_request", "PKCE with S256 is required."));
        }
        if get("resource").is_some_and(|resource| resource != self.resource()) {
            return Ok(back(
                "invalid_target",
                "The resource is the MCP address of this Mac.",
            ));
        }
        if state.is_some_and(|state| state.len() > MAX_STATE) {
            return Ok(back("invalid_request", "The state is at most 512 bytes."));
        }
        let id = random_hex::<16>()?;
        let match_code = new_match_code()?;
        let now = self.now;
        let expires_at = now.saturating_add(self.oauth.connect_secs);
        enum Opened {
            New,
            Same(String),
            Busy,
        }
        let opened = self.hub.directory.store.tx(|tx| {
            prune(tx, now)?;
            expire_requests(tx, now)?;
            let waiting: Option<(String, String, String, Option<String>)> = tx
                .query_row(
                    "SELECT id, redirect_uri, code_challenge, state FROM connect_request \
                     WHERE client_id = ?1 AND status = 'pending'",
                    params![client_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(db)?;
            if let Some((open, uri, open_challenge, open_state)) = waiting {
                // The same request again (a reload of the link): its page.
                if uri == redirect_uri
                    && open_challenge == challenge
                    && open_state.as_deref() == state
                {
                    return Ok(Opened::Same(open));
                }
                // Another request of the same client: the waiting one ends, and this one
                // gets its own page and code. A client id is public, so a waiting request
                // that someone else started must never stand in for this browser's: the
                // owner compares the code that this page shows.
                tx.execute(
                    "UPDATE connect_request SET status = 'expired' \
                     WHERE client_id = ?1 AND status = 'pending'",
                    params![client_id],
                )
                .map_err(db)?;
                self.hub.directory.audit.write_on(
                    tx,
                    now,
                    OAUTH_ACTOR,
                    "connect_replaced",
                    None,
                    &json!({"client_id": client_id}),
                )?;
            }
            let open: i64 = tx
                .query_row(
                    "SELECT count(*) FROM connect_request WHERE status = 'pending'",
                    [],
                    |row| row.get(0),
                )
                .map_err(db)?;
            if to_u(open) >= OPEN_CONNECTS {
                return Ok(Opened::Busy);
            }
            tx.execute(
                "INSERT INTO connect_request (id, client_id, redirect_uri, state, code_challenge, \
                 match_code, status, created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8)",
                params![
                    id,
                    client_id,
                    redirect_uri,
                    state,
                    challenge,
                    match_code,
                    to_i(now),
                    to_i(expires_at)
                ],
            )
            .map_err(db)?;
            // No `used_at`: an authorize renews no client. A client that is never allowed
            // goes `NEVER_ALLOWED_CLIENT_SECS` after its registration.
            self.hub.directory.audit.write_on(
                tx,
                now,
                OAUTH_ACTOR,
                "connect_requested",
                None,
                &json!({"client_id": client_id, "expires_at": expires_at}),
            )?;
            Ok(Opened::New)
        })?;
        Ok(match opened {
            Opened::New => {
                wake_hosts(self.hub);
                Reply::Redirect {
                    location: format!("{}{id}", paths::WAIT_PREFIX),
                }
            }
            Opened::Same(open) => Reply::Redirect {
                location: format!("{}{open}", paths::WAIT_PREFIX),
            },
            Opened::Busy => Reply::page(429, Page::busy()),
        })
    }

    /// `GET /oauth/wait/<id>`: the page of a connect request. Allowed: 303 back to the
    /// client with the code, once.
    fn wait(&self, id: &str) -> RelayResult<Reply> {
        if !request_id_ok(id) {
            return Ok(Reply::page(404, Page::ended()));
        }
        let now = self.now;
        let code_secs = self.oauth.code_secs;
        let mac = self.oauth.mac_name.clone();
        let origin = self.origin;
        self.hub.directory.store.tx(|tx| {
            expire_requests(tx, now)?;
            let row: Option<(String, String, Option<String>, String, String, i64, Option<i64>, bool)> = tx
                .query_row(
                    "SELECT r.status, r.redirect_uri, r.state, r.match_code, r.client_id, \
                     r.expires_at, r.decided_at, r.code_hash IS NOT NULL \
                     FROM connect_request r WHERE r.id = ?1",
                    params![id],
                    |row| {
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
                    },
                )
                .optional()
                .map_err(db)?;
            let Some((status, redirect_uri, state, match_code, client_id, expires_at, decided_at, sent)) =
                row
            else {
                return Ok(Reply::page(404, Page::ended()));
            };
            Ok(match status.as_str() {
                "pending" => {
                    let name = load_client(tx, &client_id)?.and_then(|client| client.name);
                    Reply::Page {
                        status: 200,
                        refresh: true,
                        html: Page::waiting(
                            &shown_name(name.as_deref()),
                            &mac,
                            &match_code,
                            to_u(expires_at).saturating_sub(now),
                        )
                        .html(),
                    }
                }
                "denied" => Reply::page(200, Page::denied()),
                "allowed" if !sent => {
                    // A browser that comes back long after the answer gets no code.
                    let decided = decided_at.map_or(now, to_u);
                    if now >= decided.saturating_add(code_secs) {
                        tx.execute(
                            "UPDATE connect_request SET status = 'expired' WHERE id = ?1",
                            params![id],
                        )
                        .map_err(db)?;
                        return Ok(Reply::page(200, Page::ended()));
                    }
                    let code = new_secret()?;
                    tx.execute(
                        "UPDATE connect_request SET code_hash = ?2, code_expires_at = ?3 WHERE id = ?1",
                        params![id, hash_of(code.expose()), to_i(now.saturating_add(code_secs))],
                    )
                    .map_err(db)?;
                    let mut location = format!(
                        "{redirect_uri}{}code={}",
                        if redirect_uri.contains('?') { '&' } else { '?' },
                        percent_encode(code.expose())
                    );
                    if let Some(state) = state {
                        location.push_str(&format!("&state={}", percent_encode(&state)));
                    }
                    location.push_str(&format!("&iss={}", percent_encode(origin)));
                    Reply::Redirect { location }
                }
                "allowed" | "redeemed" => Reply::page(200, Page::connected()),
                _ => Reply::page(200, Page::ended()),
            })
        })
    }

    /// `POST /oauth/token` (RFC 6749 sections 4.1.3 and 6, RFC 7636 section 4.6).
    fn token(&self, form: &HashMap<String, String>) -> RelayResult<Reply> {
        let get = |name: &str| form.get(name).map(String::as_str);
        if get("resource").is_some_and(|resource| resource != self.resource()) {
            return Ok(Reply::error(
                400,
                "invalid_target",
                "The resource is the MCP address of this Mac.",
            ));
        }
        let Some(client_id) = get("client_id").filter(|id| !id.is_empty()) else {
            return Ok(Reply::error(
                400,
                "invalid_request",
                "client_id is required.",
            ));
        };
        let failures = &self.hub.oauth_failures;
        if failures.limited(client_id, self.now) {
            return Ok(Reply::limited(
                "Too many bad codes or refresh tokens from this client. Try again later.",
                CLIENT_FAILURE_WINDOW_SECS,
            ));
        }
        let reply = self.grant_of(form, client_id)?;
        if let Reply::Json {
            auth_failed: true, ..
        } = reply
        {
            // Only a registered client is counted, so the map holds no made-up ids.
            let known = self
                .hub
                .directory
                .store
                .with(|conn| load_client(conn, client_id))?
                .is_some();
            if known {
                failures.record(client_id, self.now);
            }
        }
        Ok(reply)
    }

    /// The grant of a token request of `client_id`.
    fn grant_of(&self, form: &HashMap<String, String>, client_id: &str) -> RelayResult<Reply> {
        let get = |name: &str| form.get(name).map(String::as_str);
        match get("grant_type") {
            Some("authorization_code") => {
                let (Some(code), Some(verifier)) = (get("code"), get("code_verifier")) else {
                    return Ok(Reply::error(
                        400,
                        "invalid_request",
                        "code and code_verifier are required.",
                    ));
                };
                self.redeem_code(client_id, code, verifier, get("redirect_uri"))
            }
            Some("refresh_token") => {
                let Some(refresh) = get("refresh_token") else {
                    return Ok(Reply::error(
                        400,
                        "invalid_request",
                        "refresh_token is required.",
                    ));
                };
                self.redeem_refresh(client_id, refresh)
            }
            _ => Ok(Reply::error(
                400,
                "unsupported_grant_type",
                "The grant type is authorization_code or refresh_token.",
            )),
        }
    }

    fn redeem_code(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
        redirect_uri: Option<&str>,
    ) -> RelayResult<Reply> {
        let now = self.now;
        let refresh_secs = self.oauth.refresh_token_secs;
        let redeemed = self.hub.directory.store.tx(|tx| {
            let row: Option<(
                String,
                String,
                String,
                String,
                String,
                Option<i64>,
                Option<String>,
                Option<i64>,
            )> = tx
                .query_row(
                    "SELECT id, client_id, redirect_uri, code_challenge, status, code_expires_at, \
                     team_id, agent_id FROM connect_request WHERE code_hash = ?1",
                    params![hash_of(code)],
                    |row| {
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
                    },
                )
                .optional()
                .map_err(db)?;
            let refused = |drop| Redeemed::Refused {
                reply: Reply::bad_grant("The code is not valid."),
                drop,
            };
            let Some((family, bound_client, bound_uri, challenge, status, code_end, team, agent)) =
                row
            else {
                return Ok(refused(None));
            };
            if status == "redeemed" {
                // A second use: whatever the first one got is revoked.
                let drop = revoke_family(tx, &family, now)?;
                self.hub.directory.audit.write_on(
                    tx,
                    now,
                    OAUTH_ACTOR,
                    "oauth_family_revoked",
                    None,
                    &json!({"client_id": bound_client, "reason": "code_reused"}),
                )?;
                return Ok(refused(drop));
            }
            if status != "allowed" {
                return Ok(refused(None));
            }
            // One use: a failed redemption uses the code up too.
            tx.execute(
                "UPDATE connect_request SET status = 'redeemed' WHERE id = ?1",
                params![family],
            )
            .map_err(db)?;
            let bound = same_bytes(bound_client.as_bytes(), client_id.as_bytes())
                && redirect_uri.is_none_or(|uri| uri == bound_uri)
                && code_end.is_some_and(|end| now < to_u(end))
                && verifier_ok(verifier)
                && same_bytes(s256(verifier).as_bytes(), challenge.as_bytes());
            let (Some(team), Some(agent), true) = (team, agent, bound) else {
                let drop = revoke_family(tx, &family, now)?;
                self.hub.directory.audit.write_on(
                    tx,
                    now,
                    OAUTH_ACTOR,
                    "oauth_family_revoked",
                    None,
                    &json!({"client_id": bound_client, "reason": "code_mismatch"}),
                )?;
                return Ok(refused(drop));
            };
            // One live family for each agent: an older connection ends.
            tx.execute(
                "UPDATE oauth_refresh SET revoked_at = ?3 WHERE team_id = ?1 AND agent_id = ?2 \
                 AND revoked_at IS NULL",
                params![team, agent, to_i(now)],
            )
            .map_err(db)?;
            let refresh = new_secret()?;
            tx.execute(
                "INSERT INTO oauth_refresh (token_hash, family, client_id, team_id, agent_id, \
                 created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    hash_of(refresh.expose()),
                    family,
                    bound_client,
                    team,
                    agent,
                    to_i(now),
                    to_i(now.saturating_add(refresh_secs))
                ],
            )
            .map_err(db)?;
            tx.execute(
                "UPDATE oauth_client SET used_at = ?2 WHERE client_id = ?1",
                params![bound_client, to_i(now)],
            )
            .map_err(db)?;
            self.hub.directory.audit.write_on(
                tx,
                now,
                OAUTH_ACTOR,
                "oauth_code_redeemed",
                None,
                &json!({"client_id": bound_client, "team_id": team, "agent_id": agent}),
            )?;
            Ok(Redeemed::Granted {
                team,
                agent: to_u(agent),
                refresh,
            })
        })?;
        self.grant(redeemed)
    }

    fn redeem_refresh(&self, client_id: &str, refresh: &str) -> RelayResult<Reply> {
        let now = self.now;
        let refresh_secs = self.oauth.refresh_token_secs;
        let hash = hash_of(refresh);
        let redeemed = self.hub.directory.store.tx(|tx| {
            let row: Option<(String, String, String, i64, i64, Option<i64>, Option<i64>)> = tx
                .query_row(
                    "SELECT family, client_id, team_id, agent_id, expires_at, used_at, revoked_at \
                     FROM oauth_refresh WHERE token_hash = ?1",
                    params![hash],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(db)?;
            let refused = |drop| Redeemed::Refused {
                reply: Reply::bad_grant("The refresh token is not valid."),
                drop,
            };
            let Some((family, bound_client, team, agent, expires_at, used_at, revoked_at)) = row
            else {
                return Ok(refused(None));
            };
            if revoked_at.is_some() || now >= to_u(expires_at) {
                return Ok(refused(None));
            }
            let reused = used_at.is_some();
            if reused || !same_bytes(bound_client.as_bytes(), client_id.as_bytes()) {
                let drop = revoke_family(tx, &family, now)?;
                self.hub.directory.audit.write_on(
                    tx,
                    now,
                    OAUTH_ACTOR,
                    "oauth_family_revoked",
                    None,
                    &json!({
                        "client_id": bound_client,
                        "reason": if reused { "refresh_reused" } else { "refresh_mismatch" },
                    }),
                )?;
                return Ok(refused(drop));
            }
            tx.execute(
                "UPDATE oauth_refresh SET used_at = ?2 WHERE token_hash = ?1",
                params![hash, to_i(now)],
            )
            .map_err(db)?;
            let next = new_secret()?;
            tx.execute(
                "INSERT INTO oauth_refresh (token_hash, family, client_id, team_id, agent_id, \
                 created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    hash_of(next.expose()),
                    family,
                    bound_client,
                    team,
                    agent,
                    to_i(now),
                    to_i(now.saturating_add(refresh_secs))
                ],
            )
            .map_err(db)?;
            tx.execute(
                "UPDATE oauth_client SET used_at = ?2 WHERE client_id = ?1",
                params![bound_client, to_i(now)],
            )
            .map_err(db)?;
            Ok(Redeemed::Granted {
                team,
                agent: to_u(agent),
                refresh: next,
            })
        })?;
        self.grant(redeemed)
    }

    /// The token answer, with a new access token from the team file. A team or agent
    /// that is gone revokes the new refresh token.
    fn grant(&self, redeemed: Redeemed) -> RelayResult<Reply> {
        let now = self.now;
        let (team, agent, refresh) = match redeemed {
            Redeemed::Refused { reply, drop } => {
                if let Some((team, agent)) = drop {
                    drop_access_of(self.hub, &team, agent, "family_revoked", now);
                }
                return Ok(reply);
            }
            Redeemed::Granted {
                team,
                agent,
                refresh,
            } => (team, agent, refresh),
        };
        let access = TeamId::parse(&team)
            .and_then(|id| self.hub.team(&id))
            .ok_or_else(|| RelayError::not_found("team"))
            .and_then(|core| {
                issue_access(&core, AgentId(agent), self.oauth.access_token_secs, now)
            });
        let access = match access {
            Ok(access) => access,
            Err(error) if error.code == codes::NOT_FOUND => {
                let hash = hash_of(refresh.expose());
                self.hub.directory.store.tx(|tx| {
                    let family: Option<String> = tx
                        .query_row(
                            "SELECT family FROM oauth_refresh WHERE token_hash = ?1",
                            params![hash],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(db)?;
                    if let Some(family) = family {
                        revoke_family(tx, &family, now)?;
                    }
                    Ok(())
                })?;
                return Ok(Reply::bad_grant("The agent of this connection is gone."));
            }
            Err(error) => return Err(error),
        };
        Ok(Reply::json(
            200,
            json!({
                "access_token": access.expose(),
                "token_type": "Bearer",
                "expires_in": self.oauth.access_token_secs,
                "refresh_token": refresh.expose(),
                "scope": SCOPE,
            }),
        ))
    }

    /// `POST /oauth/revoke` (RFC 7009): a refresh token revokes its family and the access
    /// token; an access token of an OAuth agent does the same. Always 200.
    fn revoke(&self, form: &HashMap<String, String>) -> RelayResult<()> {
        let Some(token) = form.get("token").filter(|token| !token.is_empty()) else {
            return Ok(());
        };
        let now = self.now;
        let directory = &self.hub.directory;
        let drop = directory.store.tx(|tx| {
            let family: Option<String> = tx
                .query_row(
                    "SELECT family FROM oauth_refresh WHERE token_hash = ?1",
                    params![hash_of(token)],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db)?;
            match family {
                Some(family) => {
                    let drop = revoke_family(tx, &family, now)?;
                    directory.audit.write_on(
                        tx,
                        now,
                        OAUTH_ACTOR,
                        "oauth_family_revoked",
                        None,
                        &json!({"reason": "revoked_by_client"}),
                    )?;
                    Ok(drop)
                }
                None => Ok(None),
            }
        })?;
        if let Some((team, agent)) = drop {
            drop_access_of(self.hub, &team, agent, "revoked_by_client", now);
            return Ok(());
        }
        // An access token: the agent token of an agent that has an OAuth connection.
        let Some(core) = parse_token(token)
            .filter(|parsed| parsed.kind == TokenKind::Agent)
            .and_then(|parsed| parsed.team)
            .and_then(|team| self.hub.team(&team))
        else {
            return Ok(());
        };
        let agent: Option<i64> = core.store.with(|conn| {
            conn.query_row(
                "SELECT id FROM agent WHERE token_hash = ?1 AND revoked_at IS NULL",
                params![token_hash(token).0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)
        })?;
        let Some(agent) = agent.map(to_u) else {
            return Ok(());
        };
        let team = core.team.as_str().to_string();
        let had = directory.store.tx(|tx| {
            let changed = tx
                .execute(
                    "UPDATE oauth_refresh SET revoked_at = ?3 WHERE team_id = ?1 AND agent_id = ?2 \
                     AND revoked_at IS NULL",
                    params![team, to_i(agent), to_i(now)],
                )
                .map_err(db)?;
            Ok(changed > 0)
        })?;
        if had {
            drop_access(&core, AgentId(agent), "revoked_by_client", now)?;
        }
        Ok(())
    }
}

// ---- The node side (`RunningNode`) ----

/// A connect request that waits for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectView {
    pub id: String,
    pub client_id: String,
    /// The cleaned name the client registered, if any.
    pub client_name: Option<String>,
    /// The match code on the page, such as `K7Q-4MD`.
    pub match_code: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// The requests that wait for the owner, oldest first. Due ones become `expired` first.
pub fn pending(hub: &Hub, now: u64) -> RelayResult<Vec<ConnectView>> {
    hub.directory.store.tx(|tx| {
        expire_requests(tx, now)?;
        let mut statement = tx
            .prepare(
                "SELECT r.id, r.client_id, c.client_name, r.match_code, r.created_at, r.expires_at \
                 FROM connect_request r LEFT JOIN oauth_client c ON c.client_id = r.client_id \
                 WHERE r.status = 'pending' ORDER BY r.created_at, r.rowid",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok(ConnectView {
                    id: row.get(0)?,
                    client_id: row.get(1)?,
                    client_name: row.get(2)?,
                    match_code: row.get(3)?,
                    created_at: to_u(row.get(4)?),
                    expires_at: to_u(row.get(5)?),
                })
            })
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })
}

/// A mark of the waiting requests: it changes when one comes, or one is answered or
/// ends. `wait_pending` returns early when it changes.
pub fn pending_mark(hub: &Hub, now: u64) -> RelayResult<(i64, i64)> {
    hub.directory.store.with(|conn| {
        conn.query_row(
            "SELECT count(*), coalesce(max(rowid), 0) FROM connect_request \
             WHERE status = 'pending' AND expires_at > ?1",
            params![to_i(now)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db)
    })
}

/// Answers a waiting request: `Some((team, agent))` allows it for that live agent of an
/// open team, `None` denies it. A request that does not wait any more is
/// `CONNECT_NOT_PENDING`.
pub fn decide(hub: &Hub, id: &str, allow: Option<(TeamId, AgentId)>, now: u64) -> RelayResult<()> {
    if let Some((team, agent)) = &allow {
        let core = hub
            .team(team)
            .ok_or_else(|| RelayError::not_found("team"))?;
        if !agent_is_live(&core, *agent)? {
            return Err(RelayError::not_found("agent"));
        }
    }
    hub.directory.store.tx(|tx| {
        let client: Option<String> = tx
            .query_row(
                "SELECT client_id FROM connect_request WHERE id = ?1 AND status = 'pending' \
                 AND expires_at > ?2",
                params![id, to_i(now)],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let Some(client) = client else {
            return Err(RelayError::new(
                CONNECT_NOT_PENDING,
                "This connect request does not wait any more.",
            ));
        };
        let (status, team, agent) = match &allow {
            Some((team, agent)) => ("allowed", Some(team.as_str()), Some(to_i(agent.0))),
            None => ("denied", None, None),
        };
        tx.execute(
            "UPDATE connect_request SET status = ?2, decided_at = ?3, team_id = ?4, agent_id = ?5 \
             WHERE id = ?1",
            params![id, status, to_i(now), team, agent],
        )
        .map_err(db)?;
        let mut detail = json!({"client_id": client});
        if let (Some(team), Some(agent)) = (team, agent) {
            detail["team_id"] = json!(team);
            detail["agent_id"] = json!(agent);
        }
        hub.directory.audit.write_on(
            tx,
            now,
            OAUTH_ACTOR,
            if allow.is_some() {
                "connect_allowed"
            } else {
                "connect_denied"
            },
            None,
            &detail,
        )?;
        Ok(())
    })?;
    wake_hosts(hub);
    Ok(())
}

/// The OAuth connection of an agent, if it has a live one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentConnection {
    pub client_id: Option<String>,
    pub connected_at: Option<u64>,
    pub refresh_expires_at: Option<u64>,
}

/// The live refresh family of `(team, agent)`: its client, its first token, and the end
/// of its live refresh token.
pub fn connection_of(
    hub: &Hub,
    team: &TeamId,
    agent: AgentId,
    now: u64,
) -> RelayResult<AgentConnection> {
    hub.directory.store.with(|conn| {
        let live: Option<(String, String, i64)> = conn
            .query_row(
                "SELECT family, client_id, expires_at FROM oauth_refresh WHERE team_id = ?1 \
                 AND agent_id = ?2 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?3 \
                 ORDER BY created_at DESC LIMIT 1",
                params![team.as_str(), to_i(agent.0), to_i(now)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((family, client_id, expires_at)) = live else {
            return Ok(AgentConnection::default());
        };
        let first: i64 = conn
            .query_row(
                "SELECT min(created_at) FROM oauth_refresh WHERE family = ?1",
                params![family],
                |row| row.get(0),
            )
            .map_err(db)?;
        Ok(AgentConnection {
            client_id: Some(client_id),
            connected_at: Some(to_u(first)),
            refresh_expires_at: Some(to_u(expires_at)),
        })
    })
}

/// After an agent is revoked: its refresh families are revoked, and the open requests of
/// its clients (waiting, or allowed for it and not redeemed) are denied.
pub fn forget_agent(hub: &Hub, team: &TeamId, agent: AgentId, now: u64) -> RelayResult<()> {
    let (team, agent_i) = (team.as_str(), to_i(agent.0));
    hub.directory.store.tx(|tx| {
        tx.execute(
            "UPDATE connect_request SET status = 'denied', decided_at = ?3 \
             WHERE status = 'pending' AND client_id IN ( \
               SELECT client_id FROM oauth_refresh WHERE team_id = ?1 AND agent_id = ?2 \
               UNION SELECT client_id FROM connect_request WHERE team_id = ?1 AND agent_id = ?2)",
            params![team, agent_i, to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE connect_request SET status = 'denied' WHERE status = 'allowed' \
             AND team_id = ?1 AND agent_id = ?2",
            params![team, agent_i],
        )
        .map_err(db)?;
        let revoked = tx
            .execute(
                "UPDATE oauth_refresh SET revoked_at = ?3 WHERE team_id = ?1 AND agent_id = ?2 \
                 AND revoked_at IS NULL",
                params![team, agent_i, to_i(now)],
            )
            .map_err(db)?;
        if revoked > 0 {
            hub.directory.audit.write_on(
                tx,
                now,
                OAUTH_ACTOR,
                "oauth_family_revoked",
                None,
                &json!({"team_id": team, "agent_id": agent.0, "reason": "agent_revoked"}),
            )?;
        }
        Ok(())
    })?;
    wake_hosts(hub);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_decoder_takes_escapes_and_refuses_repeats() {
        let form = decode_form("grant_type=authorization_code&code=a%2Bb+c&empty=&flag").unwrap();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "a+b c");
        assert_eq!(form["empty"], "");
        assert_eq!(form["flag"], "");
        assert!(decode_form("a=1&a=2").is_none());
        assert!(decode_form("a=%zz").is_none());
        assert!(decode_form("a=%f").is_none());
        assert!(decode_form("a=%+f").is_none());
        assert!(decode_form("a=%ff").is_none(), "not UTF-8");
        assert_eq!(decode_form("").unwrap().len(), 0);
        assert_eq!(decode_form("x=%C3%A9").unwrap()["x"], "é");
        let text = "https://a.example/cb?x=1&y=é ~";
        assert_eq!(
            decode_form(&format!("v={}", percent_encode(text))).unwrap()["v"],
            text
        );
    }

    #[test]
    fn redirect_uris_are_https_or_the_loopback() {
        for good in [
            "https://grok.example/oauth/callback",
            "https://grok.example:8443/cb?x=1",
            "http://localhost/cb",
            "http://127.0.0.1:53682/callback",
            "http://[::1]:8080/cb",
            "http://localhost",
        ] {
            assert!(check_redirect_uri(good), "{good}");
        }
        for bad in [
            "",
            "http://grok.example/cb",
            "http://127.0.0.2/cb",
            "http://localhost.evil.example/cb",
            "http://[::1]x/cb",
            "http://localhost:abc/cb",
            "https://user@grok.example/cb",
            "https://grok.example/cb#frag",
            "https://grok.example/a b",
            "javascript:alert(1)",
            "custom-scheme://cb",
            "https:///cb",
            "HTTPS://grok.example/cb",
            "https://grok.example/caf\u{e9}",
        ] {
            assert!(!check_redirect_uri(bad), "{bad}");
        }
        assert!(!check_redirect_uri(&format!(
            "https://grok.example/{}",
            "a".repeat(MAX_REDIRECT_URI)
        )));
        // Exact, or any port on the loopback.
        assert!(redirect_matches(
            "https://a.example/cb",
            "https://a.example/cb"
        ));
        assert!(!redirect_matches(
            "https://a.example/cb",
            "https://a.example/cb2"
        ));
        assert!(!redirect_matches(
            "https://a.example/cb",
            "https://a.example:444/cb"
        ));
        assert!(redirect_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1:61000/cb"
        ));
        assert!(redirect_matches("http://[::1]:1/cb", "http://[::1]:2/cb"));
        assert!(!redirect_matches(
            "http://127.0.0.1/cb",
            "http://localhost:61000/cb"
        ));
        assert!(!redirect_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1:61000/other"
        ));
    }

    #[test]
    fn client_names_are_cleaned_and_short() {
        assert_eq!(clean_name("  Grok \t Bot \n").as_deref(), Some("Grok Bot"));
        assert_eq!(
            clean_name("Gr\u{202E}ok\u{200B} Bot\u{0007}").as_deref(),
            Some("Grok Bot")
        );
        assert_eq!(clean_name(" \u{200B}\n"), None);
        // The characters that the old list missed: U+061C, U+180E, U+206A–206F,
        // U+FFF9–FFFB, and the tag block U+E0000–E007F.
        assert_eq!(
            clean_name("Gr\u{061C}ok\u{180E} \u{206A}\u{206F}Bot\u{FFF9}\u{FFFB}\u{E0001}\u{E0041}\u{E007F}")
                .as_deref(),
            Some("Grok Bot")
        );
        assert_eq!(clean_name("\u{E0000}\u{E0020}\u{2066}"), None);
        // A name stored before the rule is cleaned again on the page.
        assert_eq!(shown_name(Some("Grok\u{061C} Bot\u{E0041}")), "Grok Bot");
        assert_eq!(shown_name(Some("\u{E0041}")), "An MCP client");
        assert_eq!(shown_name(None), "An MCP client");
        let long = clean_name(&"é".repeat(100)).unwrap();
        assert!(long.len() <= MAX_CLIENT_NAME);
        assert_eq!(long.len(), 64);
        assert_eq!(
            escape_html("<script>\"x\"&'y'</script>"),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;&lt;/script&gt;"
        );
    }

    #[test]
    fn pkce_and_codes() {
        // RFC 7636 appendix B.
        assert_eq!(
            s256("dBjftJeZ4CVP-mJ92K9N0lE5n0aahg8JtEsQ1fx8ptg"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(challenge_ok("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!challenge_ok("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c"));
        assert!(!verifier_ok("short"));
        assert!(!verifier_ok(&"a".repeat(129)));
        assert!(verifier_ok(&"a".repeat(43)));
        let code = new_match_code().unwrap();
        assert_eq!(code.len(), 7);
        assert_eq!(code.as_bytes()[3], b'-');
        assert!(
            code.bytes()
                .filter(|b| *b != b'-')
                .all(|b| MATCH_LETTERS.contains(&b))
        );
        let distinct: std::collections::HashSet<u8> = MATCH_LETTERS.iter().copied().collect();
        assert_eq!(distinct.len(), 24);
        assert!(request_id_ok(&random_hex::<16>().unwrap()));
        assert!(!request_id_ok("../../etc"));
    }

    #[test]
    fn bad_grants_limit_their_client_only_and_the_window_ends() {
        let failures = ClientFailures::default();
        let start = 1_000;
        for n in 0..CLIENT_FAILURES_MAX {
            assert!(!failures.limited("c_a", start + u64::from(n)), "{n}");
            failures.record("c_a", start + u64::from(n));
        }
        assert!(failures.limited("c_a", start + 20));
        assert!(!failures.limited("c_b", start + 20), "another client");
        assert!(failures.limited("c_a", start + CLIENT_FAILURE_WINDOW_SECS - 1));
        assert!(!failures.limited("c_a", start + CLIENT_FAILURE_WINDOW_SECS));
        failures.record("c_a", start + CLIENT_FAILURE_WINDOW_SECS);
        assert!(!failures.limited("c_a", start + CLIENT_FAILURE_WINDOW_SECS + 1));
        // The map stays bounded: old windows go first, then the oldest one.
        let many = ClientFailures::default();
        for n in 0..MAX_FAILING_CLIENTS + 10 {
            many.record(&format!("c_{n}"), start);
        }
        let held = many.windows.lock().unwrap().len();
        assert!(held <= MAX_FAILING_CLIENTS, "{held}");
    }

    #[test]
    fn routes() {
        assert_eq!(
            route("GET", "/.well-known/oauth-protected-resource/mcp"),
            Some(Route::ProtectedResource)
        );
        assert_eq!(
            route("GET", "/.well-known/openid-configuration"),
            Some(Route::AuthorizationServer)
        );
        assert_eq!(route("GET", "/oauth/wait/abc"), Some(Route::Wait));
        assert_eq!(route("GET", "/oauth/wait/"), None);
        assert_eq!(route("GET", "/oauth/wait/a/b"), None);
        assert_eq!(route("GET", "/oauth/token"), None);
        assert_eq!(route("POST", "/oauth/authorize"), None);
        assert_eq!(route("POST", "/oauth/token"), Some(Route::Token));
    }

    #[test]
    fn the_page_has_no_active_part() {
        for page in [
            Page::waiting("<b>Grok</b>", "Mac \"mini\"", "K7Q-4MD", 299),
            Page::denied(),
            Page::ended(),
            Page::connected(),
            Page::invalid(),
            Page::busy(),
            Page::broken(),
        ] {
            let html = page.html().to_ascii_lowercase();
            for word in [
                "<script", "<form", "<button", "<a ", "<img", "<iframe", "<input", "cookie",
                "<link",
            ] {
                assert!(!html.contains(word), "{word} in {html}");
            }
        }
        let html = Page::waiting("<b>Grok</b>", "Mac", "K7Q-4MD", 299).html();
        assert!(html.contains("&lt;b&gt;Grok&lt;/b&gt; wants to connect to Mac"));
        assert!(html.contains("K7Q-4MD"));
        assert!(html.contains("ends in 5 minutes"));
        // The waiting and the busy page tell the owner to deny what they did not start.
        let line = "Deny requests on your Mac that you did not start, then connect again.";
        assert_eq!(DENY_OTHERS, line);
        assert!(html.contains(line), "{html}");
        let busy = Page::busy().html();
        assert!(busy.contains("Too many connection requests wait."));
        assert!(busy.contains(line), "{busy}");
    }
}
