//! The reverse proxy end to end: a `Proxy` in a tiny_http server on 127.0.0.1, a test
//! `SessionSource`, and a mock HTTPS upstream. Synthetic values only.

#[path = "common/upstream.rs"]
mod upstream;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use apassy::broker::proxy::HostRule;
use apassy_relay::config::UpstreamOptions;
use apassy_relay::ids::{AgentId, ItemId, MemberId, RunId, SessionId};
use apassy_relay::proxy::{MAX_REQUEST_BODY, Proxy, mint};
use apassy_relay::secret::{SecretString, TokenKind, new_token};
use apassy_relay::session::{LiveSession, ProxyEvent, ProxyOutcome, SessionSecret, SessionSource};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use upstream::MockUpstream;

const VALUE_A: &str = "sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF";
const VALUE_B: &str = "ghp_SyntheticCanaryValueForGithub0123456789abcdefgh";
const VALUE_Q: &str = "sk_test_51Synthetic/Canary+Value=0123456789abcdefABCDEF";
const RELAY_HEADER: &str = "X-Apassy-Relay";

// ---------------------------------------------------------------------------
// A test session source: a map of sessions and a list of recorded events.

#[derive(Default)]
struct TestSessions {
    sessions: Mutex<HashMap<String, Arc<LiveSession>>>,
    events: Mutex<Vec<ProxyEvent>>,
}

impl SessionSource for TestSessions {
    fn find(&self, session_key: &str, now: u64) -> Option<Arc<LiveSession>> {
        self.sessions
            .lock()
            .unwrap()
            .get(session_key)
            .filter(|session| session.is_live(now))
            .cloned()
    }

    fn record(&self, event: ProxyEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn secret(id: u64, env: &str, value: &str, hosts: &[&str]) -> SessionSecret {
    let value = SecretString::new(value.to_owned());
    SessionSecret {
        item_id: ItemId(id),
        env_name: env.to_owned(),
        placeholder: mint(&value).expect("placeholder"),
        value,
        hosts: hosts.iter().map(|h| HostRule::parse(h).unwrap()).collect(),
    }
}

// ---------------------------------------------------------------------------
// The harness: proxy + server + upstream.

struct Harness {
    addr: SocketAddr,
    key: String,
    expired_key: String,
    sessions: Arc<TestSessions>,
    upstream: MockUpstream,
    server: Arc<tiny_http::Server>,
    placeholder_a: String,
    placeholder_b: String,
    placeholder_q: String,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

fn now() -> u64 {
    apassy_relay::now_unix()
}

impl Harness {
    fn new() -> Self {
        let mock = upstream::start(&["api.stripe.com", "api.github.com", "other.example.test"]);
        let options = mock.options();
        Self::with(mock, options)
    }

    fn with(mock: MockUpstream, options: UpstreamOptions) -> Self {
        let sessions = Arc::new(TestSessions::default());
        let secrets = vec![
            secret(1, "STRIPE_API_KEY", VALUE_A, &["api.stripe.com"]),
            secret(2, "GITHUB_TOKEN", VALUE_B, &["api.github.com"]),
            secret(3, "QUERY_KEY", VALUE_Q, &["api.stripe.com"]),
        ];
        let placeholder_a = secrets[0].placeholder.expose().to_owned();
        let placeholder_b = secrets[1].placeholder.expose().to_owned();
        let placeholder_q = secrets[2].placeholder.expose().to_owned();
        let key = new_token(TokenKind::Session).unwrap().expose().to_owned();
        let expired_key = new_token(TokenKind::Session).unwrap().expose().to_owned();
        for (session_key, id, expires_at) in [
            (&key, 1u64, now() + 3600),
            (&expired_key, 2, now().saturating_sub(1)),
        ] {
            sessions.sessions.lock().unwrap().insert(
                session_key.clone(),
                Arc::new(LiveSession {
                    id: SessionId(id),
                    run_id: RunId(10 + id),
                    agent_id: AgentId(20 + id),
                    member_id: MemberId(30 + id),
                    expires_at,
                    secrets: secrets.clone(),
                }),
            );
        }
        let source: Arc<dyn SessionSource> = sessions.clone();
        let proxy = Arc::new(Proxy::new(&options, source).expect("proxy"));
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("server"));
        let addr = server.server_addr().to_ip().expect("ip address");
        let serving = Arc::clone(&server);
        thread::spawn(move || {
            for request in serving.incoming_requests() {
                let proxy = Arc::clone(&proxy);
                thread::spawn(move || proxy.handle(request, now()));
            }
        });
        Self {
            addr,
            key,
            expired_key,
            sessions,
            upstream: mock,
            server,
            placeholder_a,
            placeholder_b,
            placeholder_q,
        }
    }

    /// The path of `host` and `rest` in the session of this harness.
    fn path(&self, host: &str, rest: &str) -> String {
        format!("/p/{}/{host}{rest}", self.key)
    }

    fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut head =
            format!("{method} {path} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() || method == "POST" {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        raw(self.addr, head.into_bytes(), body)
    }

    fn get(&self, path: &str, headers: &[(&str, &str)]) -> Reply {
        self.send("GET", path, headers, b"")
    }

    fn events(&self) -> Vec<ProxyEvent> {
        self.sessions.events.lock().unwrap().clone()
    }

    fn last_event(&self) -> ProxyEvent {
        self.events().pop().expect("an event")
    }

    /// Every real value, placeholder, and key of the harness.
    fn secret_texts(&self) -> Vec<String> {
        let mut texts: Vec<String> = [VALUE_A, VALUE_B, VALUE_Q]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        texts.extend([
            self.placeholder_a.clone(),
            self.placeholder_b.clone(),
            self.placeholder_q.clone(),
            self.key.clone(),
            self.expired_key.clone(),
        ]);
        texts
    }

    fn assert_upstream_untouched(&self) {
        assert!(self.upstream.requests().is_empty());
        assert_eq!(self.upstream.connections(), 0, "no connection was opened");
    }

    /// A refusal by the relay: status, the header, and the code, with no secret text.
    fn assert_refused(&self, reply: &Reply, status: u16, code: &str) {
        assert_eq!(reply.status, status, "{}", reply.text());
        assert_eq!(reply.header(RELAY_HEADER), Some("refused"));
        let json = reply.json();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["code"], code, "{json}");
        for text in self.secret_texts() {
            assert!(!reply.text().contains(&text), "the refusal holds a secret");
        }
    }
}

// ---------------------------------------------------------------------------
// A small raw HTTP client, for full control of the request bytes.

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {}", self.text()))
    }
}

fn decode_chunked(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&data[..end])
                .unwrap()
                .split(';')
                .next()
                .unwrap(),
            16,
        )
        .expect("chunk size");
        data = &data[end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// Sends `head` and `body`, reads the whole answer. The body is written from another
/// thread, so an early answer (413) is read even when the server stops reading.
fn raw(addr: SocketAddr, head: Vec<u8>, body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let body = body.to_vec();
    let sender = thread::spawn(move || {
        let _ = writer.write_all(&head);
        let _ = writer.write_all(&body);
    });
    let mut data = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => data.extend_from_slice(&chunk[..count]),
            Err(error) if !data.is_empty() => {
                let _ = error;
                break;
            }
            Err(error) => panic!("no answer: {error}"),
        }
    }
    let _ = sender.join();
    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut slots);
    let httparse::Status::Complete(head_len) = response.parse(&data).expect("response head") else {
        panic!("incomplete head");
    };
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_owned(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let mut body = data[head_len..].to_vec();
    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    });
    if chunked {
        body = decode_chunked(&body);
    }
    Reply {
        status: response.code.expect("status"),
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------
// Swaps in auth positions.

#[test]
fn bearer_is_swapped_and_the_echo_comes_back_as_the_placeholder() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/v1/balance?limit=3"),
        &[("Authorization", &bearer), ("X-Custom", "kept")],
    );
    assert_eq!(reply.status, 200);
    // The upstream saw the value, and only the value.
    let seen = h.upstream.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/v1/balance?limit=3");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {VALUE_A}").as_str())
    );
    assert_eq!(seen[0].header("host"), Some("api.stripe.com"));
    assert_eq!(seen[0].header("connection"), Some("close"));
    assert_eq!(seen[0].header("x-custom"), Some("kept"));
    // The client sees the placeholder in the body and in the header, never the value.
    let json = reply.json();
    assert_eq!(json["authorization"], bearer);
    assert_eq!(json["target"], "/v1/balance?limit=3");
    assert_eq!(reply.header("X-Echo-Authorization"), Some(bearer.as_str()));
    assert!(!reply.text().contains(VALUE_A));
    assert!(reply.headers.iter().all(|(_, v)| !v.contains(VALUE_A)));
    // The relay added no header of its own to a forwarded response.
    assert!(reply.header(RELAY_HEADER).is_none());
    assert_eq!(reply.header("Content-Type"), Some("application/json"));
    assert_eq!(
        reply
            .header("Content-Length")
            .map(|v| v.parse::<usize>().unwrap()),
        Some(reply.body.len())
    );
    // The event.
    let events = h.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.method, "GET");
    assert_eq!(event.host, "api.stripe.com");
    assert_eq!(event.path.as_deref(), Some("/v1/balance"));
    assert_eq!(event.status, 200);
    assert_eq!(event.outcome, ProxyOutcome::Forwarded);
    assert_eq!(event.code, None);
    assert_eq!(event.swapped, vec!["STRIPE_API_KEY".to_owned()]);
    assert_eq!(event.session_id, Some(SessionId(1)));
    assert_eq!(event.agent_id, Some(AgentId(21)));
}

#[test]
fn a_bare_placeholder_in_authorization_is_swapped() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("Authorization", &h.placeholder_a)],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(
        h.upstream.requests()[0].header("authorization"),
        Some(VALUE_A)
    );
    assert_eq!(reply.json()["authorization"], h.placeholder_a);
}

#[test]
fn basic_user_and_password_are_swapped() {
    let h = Harness::new();
    let password = BASE64_STANDARD.encode(format!("robot:{}", h.placeholder_a));
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("Authorization", &format!("Basic {password}"))],
    );
    assert_eq!(reply.status, 200);
    let expected = BASE64_STANDARD.encode(format!("robot:{VALUE_A}"));
    assert_eq!(
        h.upstream.requests()[0].header("authorization"),
        Some(format!("Basic {expected}").as_str())
    );
    // The value is not in the answer in clear. (Its Base64 form is not searched.)
    assert!(!reply.text().contains(VALUE_A));

    let user = BASE64_STANDARD.encode(format!("{}:", h.placeholder_a));
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("Authorization", &format!("Basic {user}"))],
    );
    assert_eq!(reply.status, 200);
    let expected = BASE64_STANDARD.encode(format!("{VALUE_A}:"));
    assert_eq!(
        h.upstream.requests()[1].header("authorization"),
        Some(format!("Basic {expected}").as_str())
    );
}

#[test]
fn a_key_header_is_swapped_and_echoed_back_as_the_placeholder() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("x-api-key", &h.placeholder_a)],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(h.upstream.requests()[0].header("x-api-key"), Some(VALUE_A));
    let json = reply.json();
    assert_eq!(json["headers"]["x-api-key"], h.placeholder_a);
    assert!(!reply.text().contains(VALUE_A));
    assert_eq!(h.last_event().swapped, vec!["STRIPE_API_KEY".to_owned()]);
}

#[test]
fn a_key_query_parameter_is_swapped_with_percent_encoding() {
    let h = Harness::new();
    let path = h.path(
        "api.stripe.com",
        &format!("/v1/x?a=1&api_key={}&b=2", h.placeholder_q),
    );
    let reply = h.get(&path, &[]);
    assert_eq!(reply.status, 200);
    let target = &h.upstream.requests()[0].target;
    assert_eq!(
        target,
        "/v1/x?a=1&api_key=sk_test_51Synthetic%2FCanary%2BValue%3D0123456789abcdefABCDEF&b=2"
    );
    // The raw value is not in the answer. (Its encoded form is the value of a
    // different string, which the relay does not search.)
    assert!(!reply.text().contains(VALUE_Q));
    assert_eq!(h.last_event().swapped, vec!["QUERY_KEY".to_owned()]);
    // A percent-encoded name and value of a placeholder is swapped too.
    let encoded = h.placeholder_q.replacen("sk_", "%73k%5F", 1);
    let path = h.path("api.stripe.com", &format!("/v1/x?API%5FKEY={encoded}"));
    let reply = h.get(&path, &[]);
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert!(
        h.upstream.requests()[1]
            .target
            .starts_with("/v1/x?API%5FKEY=sk_test_")
    );
}

#[test]
fn a_request_without_placeholders_is_forwarded_as_it_is() {
    let h = Harness::new();
    let reply = h.send(
        "POST",
        &h.path("api.stripe.com", "/public?x=1"),
        &[("Content-Type", "text/plain")],
        b"hello body",
    );
    assert_eq!(reply.status, 200);
    let seen = &h.upstream.requests()[0];
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.target, "/public?x=1");
    assert_eq!(seen.body, b"hello body");
    assert_eq!(seen.header("content-length"), Some("10"));
    assert!(seen.header("authorization").is_none());
    assert_eq!(reply.json()["body"], "hello body");
    assert!(h.last_event().swapped.is_empty());
}

#[test]
fn an_empty_rest_means_the_root_and_a_query_can_follow_the_host() {
    let h = Harness::new();
    assert_eq!(h.get(&h.path("api.stripe.com", ""), &[]).status, 200);
    assert_eq!(h.get(&h.path("api.stripe.com", "?x=1"), &[]).status, 200);
    let seen = h.upstream.requests();
    assert_eq!(seen[0].target, "/");
    assert_eq!(seen[1].target, "/?x=1");
    assert_eq!(h.events()[0].path.as_deref(), Some("/"));
}

#[test]
fn a_large_post_body_goes_upstream_whole() {
    let h = Harness::new();
    let body: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let reply = h.send("POST", &h.path("api.stripe.com", "/upload"), &[], &body);
    assert_eq!(reply.status, 200);
    assert_eq!(h.upstream.requests()[0].body, body);
}

// ---------------------------------------------------------------------------
// Refusals: 403 with `X-Apassy-Relay: refused`, and the upstream got nothing.

#[test]
fn a_placeholder_in_the_path_is_refused() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", &format!("/v1/{}", h.placeholder_a)),
        &[],
    );
    h.assert_refused(&reply, 403, "misplaced_placeholder");
    h.assert_upstream_untouched();
    let event = h.last_event();
    assert_eq!(event.outcome, ProxyOutcome::Refused);
    assert_eq!(event.status, 403);
    assert_eq!(event.code.as_deref(), Some("misplaced_placeholder"));
    assert_eq!(event.path, None);
    assert!(event.swapped.is_empty());
}

#[test]
fn a_percent_decoded_placeholder_in_the_path_is_refused() {
    let h = Harness::new();
    let encoded = h.placeholder_a.replacen("sk_", "%73k%5F", 1);
    let reply = h.get(&h.path("api.stripe.com", &format!("/v1/{encoded}")), &[]);
    h.assert_refused(&reply, 403, "misplaced_placeholder");
    h.assert_upstream_untouched();
}

#[test]
fn a_placeholder_in_another_header_is_refused() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("X-Note", &format!("see {}", h.placeholder_a))],
    );
    h.assert_refused(&reply, 403, "misplaced_placeholder");
    h.assert_upstream_untouched();
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("Cookie", &format!("s={}", h.placeholder_a))],
    );
    h.assert_refused(&reply, 403, "misplaced_placeholder");
    h.assert_upstream_untouched();
}

#[test]
fn a_placeholder_in_another_query_parameter_is_refused() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", &format!("/echo?note={}", h.placeholder_a)),
        &[],
    );
    h.assert_refused(&reply, 403, "misplaced_placeholder");
    h.assert_upstream_untouched();
}

#[test]
fn a_placeholder_in_the_body_is_refused_even_across_pieces() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let body = format!("{{\"token\":\"{}\"}}", h.placeholder_a);
    let reply = h.send(
        "POST",
        &h.path("api.stripe.com", "/echo"),
        &[("Authorization", &bearer)],
        body.as_bytes(),
    );
    h.assert_refused(&reply, 403, "placeholder_in_body");
    h.assert_upstream_untouched();
    // Deep in a body that is longer than one read.
    let mut long = vec![b'x'; 200_000];
    long.extend_from_slice(h.placeholder_a.as_bytes());
    let reply = h.send("POST", &h.path("api.stripe.com", "/echo"), &[], &long);
    h.assert_refused(&reply, 403, "placeholder_in_body");
    h.assert_upstream_untouched();
    assert_eq!(h.last_event().code.as_deref(), Some("placeholder_in_body"));
}

#[test]
fn a_placeholder_inside_a_basic_part_with_more_text_is_refused() {
    let h = Harness::new();
    let text = BASE64_STANDARD.encode(format!("user:pw-{}", h.placeholder_a));
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("Authorization", &format!("Basic {text}"))],
    );
    h.assert_refused(&reply, 403, "misplaced_placeholder");
    h.assert_upstream_untouched();
}

#[test]
fn a_placeholder_of_one_item_sent_to_a_host_of_another_is_wrong_host() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.github.com", "/user"),
        &[("Authorization", &bearer)],
    );
    h.assert_refused(&reply, 403, "wrong_host");
    h.assert_upstream_untouched();
    let event = h.last_event();
    assert_eq!(event.host, "api.github.com");
    assert_eq!(event.code.as_deref(), Some("wrong_host"));
    // The item of the host works there.
    let bearer = format!("Bearer {}", h.placeholder_b);
    let reply = h.get(
        &h.path("api.github.com", "/user"),
        &[("Authorization", &bearer)],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(
        h.upstream.requests()[0].header("authorization"),
        Some(format!("Bearer {VALUE_B}").as_str())
    );
}

#[test]
fn a_host_that_is_not_in_the_session_is_refused() {
    let h = Harness::new();
    // The mock has a certificate for it, and the relay must still not go there.
    for host in [
        "other.example.test",
        "evil.example",
        "API.STRIPE.COM",
        "api.stripe.com:8443",
    ] {
        let reply = h.get(&h.path(host, "/echo"), &[]);
        h.assert_refused(&reply, 403, "host_not_in_session");
    }
    let reply = h.get(&format!("/p/{}", h.key), &[]);
    h.assert_refused(&reply, 403, "host_not_in_session");
    let reply = h.get(&format!("/p/{}/", h.key), &[]);
    h.assert_refused(&reply, 403, "host_not_in_session");
    h.assert_upstream_untouched();
}

#[test]
fn an_unknown_expired_or_malformed_key_is_session_invalid() {
    let h = Harness::new();
    let unknown = new_token(TokenKind::Session).unwrap();
    let wrong_kind = new_token(TokenKind::Agent).unwrap();
    for key in [
        unknown.expose().to_owned(),
        h.expired_key.clone(),
        wrong_kind.expose().to_owned(),
        "apassy_ses_tooshort".to_owned(),
        String::new(),
        "x".to_owned(),
    ] {
        let reply = h.get(&format!("/p/{key}/api.stripe.com/echo"), &[]);
        h.assert_refused(&reply, 403, "session_invalid");
    }
    let reply = h.get("/p/", &[]);
    h.assert_refused(&reply, 403, "session_invalid");
    h.assert_upstream_untouched();
    let events = h.events();
    assert_eq!(events.len(), 7);
    // An unknown key has no session ids; an expired one is not found either.
    assert!(
        events
            .iter()
            .all(|e| e.session_id.is_none() && e.outcome == ProxyOutcome::Refused)
    );
}

#[test]
fn a_bad_target_or_header_is_refused() {
    let h = Harness::new();
    let reply = h.get(&h.path("api.stripe.com", "/a\u{7f}b"), &[]);
    assert_eq!(reply.status, 400, "{}", reply.text());
    assert_eq!(reply.header(RELAY_HEADER), Some("refused"));
    h.assert_upstream_untouched();
}

// ---------------------------------------------------------------------------
// Request headers, and what the relay does not carry.

#[test]
fn listed_request_headers_are_not_forwarded() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[
            ("Accept-Encoding", "gzip, br"),
            ("Proxy-Authorization", "Basic eDp5"),
            ("Proxy-Connection", "keep-alive"),
            ("Keep-Alive", "timeout=5"),
            ("TE", "trailers"),
            ("X-Apassy-Edge", "edge-secret-synthetic"),
            ("CDN-Loop", "cloudflare"),
            ("X-Forwarded-For", "203.0.113.9"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "relay.example.test"),
            ("X-Real-IP", "203.0.113.9"),
            ("CF-Connecting-IP", "203.0.113.9"),
            ("CF-Ray", "abc"),
            ("User-Agent", "synthetic-agent/1"),
        ],
    );
    assert_eq!(reply.status, 200);
    let seen = &h.upstream.requests()[0];
    for name in [
        "accept-encoding",
        "proxy-authorization",
        "proxy-connection",
        "keep-alive",
        "te",
        "x-apassy-edge",
        "cdn-loop",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-real-ip",
        "cf-connecting-ip",
        "cf-ray",
    ] {
        assert!(seen.header(name).is_none(), "{name} was forwarded");
    }
    assert_eq!(seen.header("user-agent"), Some("synthetic-agent/1"));
    assert_eq!(seen.header("host"), Some("api.stripe.com"));
    assert_eq!(seen.header("connection"), Some("close"));
}

#[test]
fn upgrade_and_connect_are_not_supported() {
    let h = Harness::new();
    let reply = h.get(
        &h.path("api.stripe.com", "/socket"),
        &[("Connection", "Upgrade"), ("Upgrade", "websocket")],
    );
    h.assert_refused(&reply, 501, "not_supported");
    let reply = h.get(&h.path("api.stripe.com", "/socket"), &[("Upgrade", "h2c")]);
    h.assert_refused(&reply, 501, "not_supported");
    let reply = h.get(
        &h.path("api.stripe.com", "/socket"),
        &[("Connection", "keep-alive, upgrade")],
    );
    h.assert_refused(&reply, 501, "not_supported");
    let reply = h.send("CONNECT", &h.path("api.stripe.com", ""), &[], b"");
    h.assert_refused(&reply, 501, "not_supported");
    h.assert_upstream_untouched();
    assert_eq!(h.events().len(), 4);
}

// ---------------------------------------------------------------------------
// Responses.

#[test]
fn a_gzip_response_is_502_encoded_response() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/gzip"),
        &[("Authorization", &bearer), ("Accept-Encoding", "gzip")],
    );
    assert_eq!(reply.status, 502);
    assert_eq!(reply.header(RELAY_HEADER), Some("upstream-error"));
    assert_eq!(reply.json()["error"]["code"], "encoded_response");
    // Accept-Encoding was not forwarded.
    assert!(h.upstream.requests()[0].header("accept-encoding").is_none());
    let event = h.last_event();
    assert_eq!(event.outcome, ProxyOutcome::UpstreamFailed);
    assert_eq!(event.status, 502);
    assert_eq!(event.code.as_deref(), Some("encoded_response"));
    assert_eq!(event.swapped, vec!["STRIPE_API_KEY".to_owned()]);
    assert_eq!(event.path, None);
}

#[test]
fn a_chunked_response_comes_back_whole_with_the_value_replaced() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/chunked"),
        &[("Authorization", &bearer), ("x-api-key", &h.placeholder_a)],
    );
    assert_eq!(reply.status, 200);
    // The 7-byte pieces of the upstream cut the value in many places.
    let json = reply.json();
    assert_eq!(json["authorization"], bearer);
    assert_eq!(json["headers"]["x-api-key"], h.placeholder_a);
    assert_eq!(json["target"], "/chunked");
    assert!(!reply.text().contains(VALUE_A));
    assert_eq!(reply.header("X-Echo-Authorization"), Some(bearer.as_str()));
    assert!(reply.header("Content-Length").is_none());
    assert_eq!(reply.header("Transfer-Encoding"), Some("chunked"));
}

#[test]
fn a_big_response_comes_back_whole_with_every_value_replaced() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/big?n=5000"),
        &[("Authorization", &bearer)],
    );
    assert_eq!(reply.status, 200);
    let expected = vec![bearer.as_str(); 5000].join(",");
    assert_eq!(reply.body.len(), expected.len());
    assert!(reply.body == expected.as_bytes(), "the body differs");
    assert!(!reply.text().contains(VALUE_A));
}

#[test]
fn a_read_to_close_response_is_replaced() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/close"),
        &[("Authorization", &bearer)],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["authorization"], bearer);
    assert!(!reply.text().contains(VALUE_A));
}

#[test]
fn a_redirect_is_passed_through_and_not_followed() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/redirect"),
        &[("Authorization", &bearer)],
    );
    assert_eq!(reply.status, 302);
    assert_eq!(
        reply.header("Location"),
        Some("https://api.stripe.com/echo")
    );
    assert_eq!(h.upstream.requests().len(), 1);
    let event = h.last_event();
    assert_eq!(event.status, 302);
    assert_eq!(event.outcome, ProxyOutcome::Forwarded);
}

#[test]
fn head_has_the_upstream_length_and_no_body() {
    let h = Harness::new();
    let reply = h.send("HEAD", &h.path("api.stripe.com", "/echo"), &[], b"");
    assert_eq!(reply.status, 200);
    assert!(reply.body.is_empty());
    let length: usize = reply.header("Content-Length").unwrap().parse().unwrap();
    assert!(length > 10);
    assert_eq!(h.upstream.requests()[0].method, "HEAD");
}

// ---------------------------------------------------------------------------
// Size, TLS, and the audit.

#[test]
fn a_9_mib_body_is_413_and_nothing_goes_upstream() {
    let h = Harness::new();
    let body = vec![b'x'; 9 * 1024 * 1024];
    assert!(body.len() > MAX_REQUEST_BODY);
    let reply = h.send("POST", &h.path("api.stripe.com", "/upload"), &[], &body);
    h.assert_refused(&reply, 413, "payload_too_large");
    h.assert_upstream_untouched();
    assert_eq!(h.last_event().status, 413);
}

#[test]
fn a_chunked_request_body_over_the_limit_is_413() {
    let h = Harness::new();
    // No Content-Length: the body is chunked and the relay counts what it reads.
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n",
        h.path("api.stripe.com", "/upload")
    )
    .into_bytes();
    let piece = vec![b'y'; 1024 * 1024];
    let mut body = Vec::new();
    for _ in 0..9 {
        body.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        body.extend_from_slice(&piece);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    request.extend_from_slice(&[]);
    let reply = raw(h.addr, request, &body);
    h.assert_refused(&reply, 413, "payload_too_large");
    h.assert_upstream_untouched();
}

#[test]
fn a_chunked_request_body_within_the_limit_goes_upstream_with_a_length() {
    let h = Harness::new();
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n",
        h.path("api.stripe.com", "/upload")
    )
    .into_bytes();
    let reply = raw(h.addr, request, b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    assert_eq!(reply.status, 200);
    let seen = &h.upstream.requests()[0];
    assert_eq!(seen.body, b"hello world");
    assert_eq!(seen.header("content-length"), Some("11"));
    assert!(seen.header("transfer-encoding").is_none());
}

#[test]
fn an_upstream_certificate_from_an_unknown_authority_is_502() {
    let trusted = upstream::start(&["api.stripe.com"]);
    let other = upstream::start(&["api.stripe.com"]);
    // The relay resolves to `other` and trusts only the root of `trusted`.
    let mut options = other.options();
    options.extra_roots_der = vec![trusted.ca_der.clone()];
    let h = Harness::with(other, options);
    let bearer = format!("Bearer {}", h.placeholder_a);
    let reply = h.get(
        &h.path("api.stripe.com", "/echo"),
        &[("Authorization", &bearer)],
    );
    assert_eq!(reply.status, 502);
    assert_eq!(reply.header(RELAY_HEADER), Some("upstream-error"));
    assert_eq!(reply.json()["error"]["code"], "upstream_failed");
    // The handshake failed, so no request byte, and so no value, went out.
    assert!(h.upstream.requests().is_empty());
    assert_eq!(
        h.upstream.connections(),
        1,
        "it connected, then refused the certificate"
    );
    let event = h.last_event();
    assert_eq!(event.outcome, ProxyOutcome::UpstreamFailed);
    assert_eq!(event.code.as_deref(), Some("upstream_failed"));
    assert!(event.swapped.is_empty());
    for text in h.secret_texts() {
        assert!(!reply.text().contains(&text));
    }
}

#[test]
fn an_unreachable_upstream_is_502() {
    let mock = upstream::start(&["api.stripe.com"]);
    let mut options = mock.options();
    // A port with no listener: bind, take the address, and drop the listener.
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    options.resolve = vec![("api.stripe.com".to_owned(), 443, dead)];
    let h = Harness::with(mock, options);
    let reply = h.get(&h.path("api.stripe.com", "/echo"), &[]);
    assert_eq!(reply.status, 502);
    assert_eq!(reply.header(RELAY_HEADER), Some("upstream-error"));
    assert_eq!(reply.json()["error"]["code"], "upstream_failed");
}

#[test]
fn there_is_one_clean_event_per_request() {
    let h = Harness::new();
    let bearer_a = format!("Bearer {}", h.placeholder_a);
    let bearer_b = format!("Bearer {}", h.placeholder_b);
    let mut sent = 0;
    let mut go = |reply: Reply| {
        sent += 1;
        reply
    };
    go(h.get(
        &h.path("api.stripe.com", "/v1/x"),
        &[("Authorization", &bearer_a)],
    ));
    go(h.get(
        &h.path("api.github.com", "/user"),
        &[("Authorization", &bearer_b)],
    ));
    go(h.get(&h.path("api.stripe.com", "/gzip"), &[]));
    go(h.get(
        &h.path("api.stripe.com", &format!("/x/{}", h.placeholder_a)),
        &[],
    ));
    go(h.get(
        &h.path("api.github.com", "/user"),
        &[("Authorization", &bearer_a)],
    ));
    go(h.get(&h.path("evil.example", "/x"), &[]));
    go(h.get(
        &h.path(
            "api.stripe.com",
            &format!("/echo?api_key={}", h.placeholder_q),
        ),
        &[],
    ));
    go(h.get(&format!("/p/{}/api.stripe.com/x", h.expired_key), &[]));
    go(h.send(
        "POST",
        &h.path("api.stripe.com", "/e"),
        &[],
        h.placeholder_a.as_bytes(),
    ));
    let events = h.events();
    assert_eq!(events.len(), sent);
    let text = serde_json::to_string(&events).unwrap();
    for secret in h.secret_texts() {
        assert!(!text.contains(&secret), "an event holds a secret");
    }
    assert!(
        !text.contains("limit") && !text.contains("api_key"),
        "an event holds a query"
    );
    // Forwarded events have a path. Refused ones do not.
    for event in &events {
        assert_eq!(
            event.path.is_some(),
            event.outcome == ProxyOutcome::Forwarded,
            "{event:?}"
        );
    }
    let outcomes: Vec<_> = events.iter().map(|e| (e.status, e.outcome)).collect();
    assert_eq!(
        outcomes,
        vec![
            (200, ProxyOutcome::Forwarded),
            (200, ProxyOutcome::Forwarded),
            (502, ProxyOutcome::UpstreamFailed),
            (403, ProxyOutcome::Refused),
            (403, ProxyOutcome::Refused),
            (403, ProxyOutcome::Refused),
            (200, ProxyOutcome::Forwarded),
            (403, ProxyOutcome::Refused),
            (403, ProxyOutcome::Refused),
        ]
    );
}

#[test]
fn many_requests_at_once_each_get_their_own_answer() {
    let h = Harness::new();
    let bearer = format!("Bearer {}", h.placeholder_a);
    thread::scope(|scope| {
        for index in 0..12 {
            let (h, bearer) = (&h, &bearer);
            scope.spawn(move || {
                let reply = h.get(
                    &h.path("api.stripe.com", &format!("/big?n={}", 50 + index)),
                    &[("Authorization", bearer)],
                );
                assert_eq!(reply.status, 200);
                let expected = vec![bearer.as_str(); 50 + index].join(",");
                assert!(reply.body == expected.as_bytes());
            });
        }
    });
    assert_eq!(h.events().len(), 12);
}
