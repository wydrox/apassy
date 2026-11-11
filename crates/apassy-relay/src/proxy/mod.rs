//! Track proxy: the reverse proxy of a session (docs/SPEC.md, "Reverse proxy").
//!
//! `ANY /p/<session key>/<host[:port]>/<path>?<query>` goes to
//! `https://<host[:port]>/<path>?<query>`. The proxy puts the real value in place of
//! a placeholder only in an auth position, only for a host of that item, and puts
//! the placeholder back in the response. Everything else with a placeholder is
//! refused with 403 and `X-Apassy-Relay: refused`.
//!
//! The public interface below is fixed by the skeleton: the server calls
//! `Proxy::new` once and `Proxy::handle` for each request on the proxy path, after
//! it has checked the edge secret. `base_url` and `mint` are what the server uses
//! to build the environment of a session.

mod stream;
mod swap;
mod upstream;

use std::sync::Arc;

use apassy::broker::proxy::HostRule;
use zeroize::Zeroizing;

use self::stream::{BodyLen, BodyReader, Pair, Pattern, Replacer, Scanner};
use self::swap::{Refusal, SwapSecret, swap_request};
use self::upstream::{ServiceStream, Upstream, UpstreamRequest, read_response_head, send_request};
use crate::api::{RELAY_HEADER, paths};
use crate::config::UpstreamOptions;
use crate::error::{RelayError, RelayResult, codes};
use crate::secret::{SecretString, TokenKind};
use crate::session::{LiveSession, ProxyEvent, ProxyOutcome, SessionSource};

/// The largest request body the proxy reads. It must read the whole body to look
/// for placeholders before it sends anything upstream. Larger: 413.
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// The base URL of one host in one session: `<public_url>/p/<session key>/<host>`.
/// `host` is shown as `host` for port 443 and `host:port` otherwise.
pub fn base_url(public_url: &str, session_key: &SecretString, host: &HostRule) -> String {
    format!(
        "{}{}{}/{}",
        public_url.trim_end_matches('/'),
        paths::PROXY_PREFIX,
        session_key.expose(),
        host
    )
}

/// A fresh placeholder for a value (ADR 0011 of the core: same length, known
/// prefix kept, at least 64 random bits). `None` when the value is too short or
/// has too little room for random characters; the server then refuses the item.
pub fn mint(value: &SecretString) -> Option<SecretString> {
    apassy::broker::proxy::mint_placeholder(value.expose()).map(SecretString::new)
}

/// The reverse proxy. One per relay; `handle` is called from many threads.
pub struct Proxy {
    sessions: Arc<dyn SessionSource>,
    upstream: Upstream,
}

/// Response headers that the relay does not pass on: hop-by-hop headers, and
/// `Content-Length`, which tiny_http sets again from the length it is given.
const DROPPED_RESPONSE_HEADERS: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "trailer",
    "upgrade",
    "content-length",
];

/// What the audit needs to know about a request, before the response is known.
struct Context {
    at: u64,
    method: String,
    /// `host` or `host:port`; empty when the host of the path did not parse.
    host: String,
    session: Option<Arc<LiveSession>>,
}

impl Context {
    fn event(
        &self,
        status: u16,
        outcome: ProxyOutcome,
        code: Option<&str>,
        path: Option<String>,
        swapped: Vec<String>,
    ) -> ProxyEvent {
        ProxyEvent {
            team: self.session.as_ref().map(|s| s.team.clone()),
            session_id: self.session.as_ref().map(|s| s.id),
            run_id: self.session.as_ref().map(|s| s.run_id),
            agent_id: self.session.as_ref().map(|s| s.agent_id),
            at: self.at,
            method: self.method.clone(),
            host: self.host.clone(),
            path,
            status,
            outcome,
            code: code.map(str::to_owned),
            swapped,
        }
    }
}

/// The parts of `/p/<key>/<host>/<rest>?<query>`.
struct Route<'a> {
    key: &'a str,
    host: &'a str,
    /// The path after the host, at least `/`.
    path: &'a str,
    query: Option<&'a str>,
}

fn parse_route(url: &str) -> Option<Route<'_>> {
    let after = url.strip_prefix(paths::PROXY_PREFIX)?;
    let (key, rest) = after.split_once('/').unwrap_or((after, ""));
    let host_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host, tail) = rest.split_at(host_end);
    let (path, query) = match tail.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (tail, None),
    };
    Some(Route {
        key,
        host,
        path: if path.is_empty() { "/" } else { path },
        query,
    })
}

/// Bytes that cannot be in a request target on the wire.
fn clean_target(text: &str) -> bool {
    text.bytes().all(|b| b > b' ' && b != 0x7f && b.is_ascii())
}

impl Proxy {
    /// Builds the TLS client configuration for upstream hosts: the system roots
    /// (rustls-platform-verifier) plus `options.extra_roots_der`.
    pub fn new(options: &UpstreamOptions, sessions: Arc<dyn SessionSource>) -> RelayResult<Self> {
        Ok(Self {
            sessions,
            upstream: Upstream::new(options)?,
        })
    }

    /// Serves one request whose path starts with `/p/`, and responds to it.
    /// It never panics on input and never returns an error: every failure is a
    /// response (403, 404, 413, 501, 502) with `X-Apassy-Relay`, and one
    /// `SessionSource::record` call.
    pub fn handle(&self, mut request: tiny_http::Request, now: u64) {
        let mut context = Context {
            at: now,
            method: request.method().as_str().to_owned(),
            host: String::new(),
            session: None,
        };
        match self.serve(&mut request, &mut context) {
            Ok(Forward {
                response,
                status,
                path,
                swapped,
            }) => {
                let _ = request.respond(response);
                self.sessions.record(context.event(
                    status,
                    ProxyOutcome::Forwarded,
                    None,
                    Some(path),
                    swapped,
                ));
            }
            Err(failure) => {
                let status = failure.error.status();
                let outcome = if status == 502 {
                    ProxyOutcome::UpstreamFailed
                } else {
                    ProxyOutcome::Refused
                };
                respond_error(request, &failure.error);
                self.sessions.record(context.event(
                    status,
                    outcome,
                    Some(failure.error.code),
                    None,
                    failure.swapped,
                ));
            }
        }
    }

    /// Answers `request` as a request whose session key names no live session (the answer
    /// and the audit of `handle`), without looking the key up: the HTTP layer found the
    /// session, but on another public origin of the node than the one it was made for.
    pub fn refuse_unknown_session(&self, request: tiny_http::Request, now: u64) {
        let context = Context {
            at: now,
            method: request.method().as_str().to_owned(),
            host: String::new(),
            session: None,
        };
        let error = session_invalid();
        respond_error(request, &error);
        self.sessions.record(context.event(
            error.status(),
            ProxyOutcome::Refused,
            Some(error.code),
            None,
            Vec::new(),
        ));
    }

    /// Every check, then the upstream exchange. `Ok` is a response to send.
    fn serve(
        &self,
        request: &mut tiny_http::Request,
        context: &mut Context,
    ) -> Result<Forward, Failure> {
        let url = request.url().to_owned();
        let route = parse_route(&url)
            .ok_or_else(|| RelayError::not_found("proxy route"))
            .map_err(Failure::new)?;

        // The key, the session, and the host.
        if TokenKind::of(route.key) != Some(TokenKind::Session) {
            return Err(Failure::new(session_invalid()));
        }
        let session = self
            .sessions
            .find(route.key, context.at)
            .ok_or_else(|| Failure::new(session_invalid()))?;
        context.session = Some(Arc::clone(&session));
        let rule = HostRule::parse(route.host).map_err(|_| Failure::new(host_not_in_session()))?;
        context.host = rule.to_string();
        let (host, port) = (rule.host(), rule.port());
        if !session.covers_host(host, port) {
            return Err(Failure::new(host_not_in_session()));
        }

        // Methods that the relay cannot carry.
        if *request.method() == tiny_http::Method::Connect || wants_upgrade(request) {
            return Err(Failure::new(RelayError::new(
                codes::NOT_SUPPORTED,
                "The relay does not carry CONNECT, Upgrade, or WebSocket.",
            )));
        }
        let method = request.method().as_str().to_owned();

        // The swap. It runs before anything goes upstream.
        if session
            .secrets
            .iter()
            .any(|s| s.value.is_empty() || s.value.len() != s.placeholder.len())
        {
            return Err(Failure::new(RelayError::internal(
                "A value and its placeholder differ in length.",
            )));
        }
        let secrets: Vec<SwapSecret<'_>> = session
            .secrets
            .iter()
            .map(|s| SwapSecret {
                placeholder: s.placeholder.expose(),
                value: s.value.expose(),
                hosts: &s.hosts,
            })
            .collect();
        let mut target = String::from(route.path);
        if let Some(query) = route.query {
            target.push('?');
            target.push_str(query);
        }
        if !clean_target(&target) {
            return Err(Failure::new(RelayError::invalid(
                "The request target is not valid.",
            )));
        }
        let mut headers = Vec::with_capacity(request.headers().len());
        for header in request.headers() {
            let value = header.value.as_str();
            if value.bytes().any(|b| b == 0) {
                return Err(Failure::new(RelayError::invalid(
                    "A header value is not valid.",
                )));
            }
            headers.push((header.field.as_str().as_str().to_owned(), value.to_owned()));
        }
        let swapped = swap_request(&target, &headers, host, port, &secrets)
            .map_err(|refusal| Failure::new(refusal_error(&refusal, &session)))?;
        let names: Vec<String> = swapped
            .used
            .iter()
            .map(|&index| session.secrets[index].env_name.clone())
            .collect();

        // The body, in full, before anything goes upstream.
        let needles: Vec<&[u8]> = secrets
            .iter()
            .map(|secret| secret.placeholder.as_bytes())
            .collect();
        let body = read_body(request, &needles).map_err(Failure::new)?;

        // Upstream.
        let authority = rule.to_string();
        let mut conn = self
            .upstream
            .connect(host, port)
            .map_err(|error| Failure::new(upstream_failed(error.0)))?;
        let sent = UpstreamRequest {
            method: &method,
            target: &swapped.target,
            authority: &authority,
            headers: &swapped.headers,
            body: &body,
        };
        // From here on a value may have gone upstream, so the audit names the variables.
        let failed = |error: RelayError| Failure {
            error,
            swapped: names.clone(),
        };
        send_request(&mut conn, &sent)
            .map_err(|_| failed(upstream_failed("The request could not be sent upstream.")))?;
        let head = read_response_head(&mut conn, &method)
            .map_err(|error| failed(upstream_failed(error.0)))?;
        if head.status == 101 {
            return Err(failed(RelayError::new(
                codes::NOT_SUPPORTED,
                "The upstream host tried to switch protocols.",
            )));
        }
        if head.encoded {
            return Err(failed(RelayError::new(
                codes::ENCODED_RESPONSE,
                "The upstream response is compressed, so the relay cannot search it.",
            )));
        }

        // The response: values back to placeholders in the headers and the body. The
        // encoded forms that this request sent (Basic, query) go first, so an echo of
        // the request shows the placeholder and not an encoded value.
        let pairs = || -> Vec<Pair> {
            swapped
                .echoes
                .iter()
                .map(|echo| Pair {
                    from: Zeroizing::new(echo.sent.as_bytes().to_vec()),
                    to: echo.shown.as_bytes().to_vec(),
                })
                .chain(session.secrets.iter().map(|s| Pair {
                    from: Zeroizing::new(s.value.expose().as_bytes().to_vec()),
                    to: s.placeholder.expose().as_bytes().to_vec(),
                }))
                .collect()
        };
        // The JSON, HTML, and percent escapes of each value (`\/`, `\"`, `\u003c`,
        // `\u00e9`, `&amp;`, `&#x2F;`, `%2F`), so an upstream host that echoes the value
        // escaped gives back no value either. A pattern also replaces the raw pair of
        // its value, and it shows the placeholder with the extra bytes after it.
        let patterns = || -> Vec<Pattern> {
            session
                .secrets
                .iter()
                .filter_map(|s| {
                    Pattern::escaped(
                        s.value.expose().as_bytes(),
                        s.placeholder.expose().as_bytes(),
                    )
                })
                .collect()
        };
        let header_replacer = Replacer::new(pairs()).with_patterns(patterns());
        let mut out_headers = Vec::with_capacity(head.headers.len());
        for (name, value) in &head.headers {
            if DROPPED_RESPONSE_HEADERS
                .iter()
                .any(|dropped| name.eq_ignore_ascii_case(dropped))
            {
                continue;
            }
            let mut value = Zeroizing::new(value.to_vec());
            header_replacer.replace_all(&mut value);
            if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_slice()) {
                out_headers.push(header);
            }
        }
        let data_length = match head.body {
            BodyLen::Length(length) => usize::try_from(length).ok(),
            BodyLen::None => Some(
                head.content_length
                    .and_then(|length| usize::try_from(length).ok())
                    .filter(|_| method.eq_ignore_ascii_case("HEAD") || head.status == 304)
                    .unwrap_or(0),
            ),
            BodyLen::Chunked | BodyLen::UntilClose => None,
        };
        let reader = BodyReader::new(
            conn,
            head.body,
            Replacer::new(pairs()).with_patterns(patterns()),
        );
        let mut response = tiny_http::Response::new(
            tiny_http::StatusCode(head.status),
            out_headers,
            reader,
            data_length,
            None,
        );
        if data_length.is_some() {
            // Keep the `Content-Length` of the upstream, however large.
            response = response.with_chunked_threshold(usize::MAX);
        }
        Ok(Forward {
            response,
            status: head.status,
            path: route.path.to_owned(),
            swapped: names,
        })
    }
}

/// A response to send, and what to record.
struct Forward {
    response: tiny_http::Response<BodyReader<ServiceStream>>,
    status: u16,
    path: String,
    swapped: Vec<String>,
}

/// A refusal or a failure, with the variables whose value may have gone upstream.
struct Failure {
    error: RelayError,
    swapped: Vec<String>,
}

impl Failure {
    fn new(error: RelayError) -> Self {
        Self {
            error,
            swapped: Vec::new(),
        }
    }
}

fn session_invalid() -> RelayError {
    RelayError::new(
        codes::SESSION_INVALID,
        "The session is unknown, expired, or ended.",
    )
}

fn host_not_in_session() -> RelayError {
    RelayError::new(
        codes::HOST_NOT_IN_SESSION,
        "The host is not a host of this session.",
    )
}

fn upstream_failed(message: &str) -> RelayError {
    RelayError::new(codes::UPSTREAM_FAILED, message)
}

/// The error for a swap refusal. The text has the name of the variable, which is
/// not secret, and never the placeholder or the value.
fn refusal_error(refusal: &Refusal, session: &LiveSession) -> RelayError {
    match refusal {
        Refusal::WrongHost { index } => RelayError::new(
            codes::WRONG_HOST,
            format!(
                "The placeholder of {} is not for this host.",
                session.secrets[*index].env_name
            ),
        ),
        Refusal::NoEcho { index } => RelayError::new(
            codes::NOT_SUPPORTED,
            format!(
                "The relay cannot hide the encoded value of {} in the response.",
                session.secrets[*index].env_name
            ),
        ),
        Refusal::Misplaced { index, place } => RelayError::new(
            codes::MISPLACED_PLACEHOLDER,
            format!(
                "The placeholder of {} is in {place}. It works only in an auth position.",
                session.secrets[*index].env_name
            ),
        ),
    }
}

/// True for an `Upgrade` header or `Connection: upgrade`.
fn wants_upgrade(request: &tiny_http::Request) -> bool {
    request.headers().iter().any(|header| {
        header.field.equiv("upgrade")
            || (header.field.equiv("connection")
                && header
                    .value
                    .as_str()
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade")))
    })
}

/// Reads the request body, at most `MAX_REQUEST_BODY` bytes. A placeholder in it
/// stops the request; a longer body is 413.
fn read_body(request: &mut tiny_http::Request, needles: &[&[u8]]) -> Result<Vec<u8>, RelayError> {
    let too_large = || {
        RelayError::new(
            codes::PAYLOAD_TOO_LARGE,
            "The request body is larger than 8 MiB.",
        )
    };
    if request
        .body_length()
        .is_some_and(|len| len > MAX_REQUEST_BODY)
    {
        return Err(too_large());
    }
    let mut scanner = Scanner::new(needles);
    let mut body = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let reader = request.as_reader();
    loop {
        let count = reader
            .read(&mut chunk)
            .map_err(|_| RelayError::invalid("The request body could not be read."))?;
        if count == 0 {
            return Ok(body);
        }
        if body.len() + count > MAX_REQUEST_BODY {
            return Err(too_large());
        }
        if scanner.feed(&chunk[..count]).is_some() {
            return Err(RelayError::new(
                codes::PLACEHOLDER_IN_BODY,
                "A placeholder is in the request body. It works only in an auth position.",
            ));
        }
        body.extend_from_slice(&chunk[..count]);
    }
}

/// A JSON error response. `X-Apassy-Relay` is `upstream-error` for 502 and `refused`
/// for everything else.
fn respond_error(request: tiny_http::Request, error: &RelayError) {
    let body = serde_json::to_vec(&error.to_envelope()).unwrap_or_default();
    let mut response = tiny_http::Response::from_data(body).with_status_code(error.status());
    let kind = if error.status() == 502 {
        "upstream-error"
    } else {
        "refused"
    };
    for (name, value) in [(RELAY_HEADER, kind), ("Content-Type", "application/json")] {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_shape() {
        let key = SecretString::new(format!("apassy_ses_{}", "a".repeat(64)));
        let host = HostRule::parse("api.stripe.com").unwrap();
        assert_eq!(
            base_url("https://relay.example.test/", &key, &host),
            format!(
                "https://relay.example.test/p/apassy_ses_{}/api.stripe.com",
                "a".repeat(64)
            )
        );
        let port = HostRule::parse("api.example.com:8443").unwrap();
        assert!(base_url("https://r.test", &key, &port).ends_with("/api.example.com:8443"));
    }

    #[test]
    fn routes_split_into_key_host_path_and_query() {
        let route = parse_route("/p/KEY/api.example.com/v1/x?a=1&b=2").unwrap();
        assert_eq!(
            (route.key, route.host, route.path, route.query),
            ("KEY", "api.example.com", "/v1/x", Some("a=1&b=2"))
        );
        let route = parse_route("/p/KEY/api.example.com:8443").unwrap();
        assert_eq!(
            (route.host, route.path, route.query),
            ("api.example.com:8443", "/", None)
        );
        let route = parse_route("/p/KEY/host?q=1").unwrap();
        assert_eq!(
            (route.host, route.path, route.query),
            ("host", "/", Some("q=1"))
        );
        let route = parse_route("/p/KEY").unwrap();
        assert_eq!((route.key, route.host), ("KEY", ""));
        let route = parse_route("/p/").unwrap();
        assert_eq!((route.key, route.host), ("", ""));
        // A second `?` belongs to the query. A `//` in the rest stays.
        let route = parse_route("/p/K/h//a//b?x=?y").unwrap();
        assert_eq!((route.path, route.query), ("//a//b", Some("x=?y")));
        assert!(parse_route("/q/KEY/host").is_none());
    }

    #[test]
    fn targets_are_clean_or_refused() {
        assert!(clean_target("/a/b?c=d%20e"));
        assert!(!clean_target("/a b"));
        assert!(!clean_target("/a\u{7f}"));
        assert!(!clean_target("/\u{e9}"));
        assert!(!clean_target("/a\r\nX: y"));
    }

    #[test]
    fn mint_keeps_length_and_prefix() {
        let value = SecretString::new("sk_test_51SyntheticCanaryValue0123456789abcdef".into());
        let placeholder = mint(&value).expect("a placeholder");
        assert_eq!(placeholder.len(), value.len());
        assert!(placeholder.expose().starts_with("sk_test_"));
        assert_ne!(placeholder, value);
        assert!(mint(&SecretString::new("short".into())).is_none());
    }
}
