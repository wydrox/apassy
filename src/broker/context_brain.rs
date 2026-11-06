//! Local-only, pinned context candidate. No execution path consumes this verdict.
use super::bouncer::{BouncerClient, is_heads_hash};
use super::http::{self, DestinationUrl, HttpFailure};
use super::secret_facts::{CONTRACT_NAME, ContextInput, contract_sha256};
use serde_json::{Value, json};
use std::time::Duration;
use zeroize::Zeroizing;

pub const CONTEXT_PATH: &str = "/v1/context-evaluate";
pub const QUESTION: &str = "owner_accepts_use";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPin {
    pub heads: String,
    pub model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextUnavailable {
    RemoteNotInScope,
    BadPin,
    NotOffered,
    UnsupportedContract,
    UnknownHeads,
    NotContextHeads,
    InputTooLong,
    Refused401,
    Status(u16),
    Timeout,
    Transport,
    BadAnswer,
    PinMismatch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContextVerdict {
    Scored {
        owner_accepts_use: f64,
        model: String,
    },
    Unavailable(ContextUnavailable),
}

fn valid_pin(pin: &ContextPin) -> bool {
    is_heads_hash(&pin.heads) && pin.model == format!("apassy-context-v1+{}", &pin.heads[..8])
}

pub fn request_body(input: &ContextInput, pin: &ContextPin) -> Value {
    wire_body(input.model_text(), input.contract_sha256(), pin)
}

// Shared by the public builder and transport tests. This does not construct a
// ContextInput or bypass its production budget check.
fn wire_body(model_text: &str, hash: &str, pin: &ContextPin) -> Value {
    json!({"contract": CONTRACT_NAME, "contract_sha256": hash,
        "heads": pin.heads, "model_text": model_text})
}

pub fn parse_answer(status: u16, body: &[u8], pin: &ContextPin) -> ContextVerdict {
    use ContextUnavailable::*;
    let unavailable = ContextVerdict::Unavailable;
    if !valid_pin(pin) {
        return unavailable(BadPin);
    }
    // Status-only refusals work even when an older server sends HTML or a huge
    // error body. Structured errors and successful answers are size bounded.
    if status == 404 {
        return unavailable(NotOffered);
    }
    if status == 401 {
        return unavailable(Refused401);
    }
    if body.len() > http::MAX_RESPONSE_BYTES {
        return unavailable(if status == 200 {
            BadAnswer
        } else {
            Status(status)
        });
    }
    let parsed = serde_json::from_slice::<Value>(body);
    if status != 200 {
        let code = parsed
            .as_ref()
            .ok()
            .and_then(|v| v.get("detail"))
            .and_then(|v| v.get("code"))
            .and_then(Value::as_str);
        return unavailable(match (status, code) {
            (409, Some("unsupported_contract")) => UnsupportedContract,
            (409, Some("unknown_heads")) => UnknownHeads,
            (409, Some("not_context_heads")) => NotContextHeads,
            (422, Some("input_too_long")) => InputTooLong,
            _ => Status(status),
        });
    }
    let Ok(value) = parsed else {
        return unavailable(BadAnswer);
    };
    if value.get("contract_sha256").and_then(Value::as_str) != Some(contract_sha256())
        || value.get("heads").and_then(Value::as_str) != Some(pin.heads.as_str())
        || value.get("model").and_then(Value::as_str) != Some(pin.model.as_str())
    {
        return unavailable(PinMismatch);
    }
    let Some(p) = value
        .get("answers")
        .and_then(|v| v.get(QUESTION))
        .and_then(|v| v.get("noul"))
        .and_then(Value::as_f64)
        .filter(|p| p.is_finite() && (0.0..=1.0).contains(p))
    else {
        return unavailable(BadAnswer);
    };
    ContextVerdict::Scored {
        owner_accepts_use: p,
        model: pin.model.clone(),
    }
}

/// Advisory only. No network call; the POST answer is authoritative.
pub fn offers_contract(health_body: &[u8], hash: &str) -> bool {
    if !is_heads_hash(hash) || health_body.len() > http::MAX_RESPONSE_BYTES {
        return false;
    }
    let Ok(v) = serde_json::from_slice::<Value>(health_body) else {
        return false;
    };
    v.get("context_contracts")
        .and_then(Value::as_array)
        .is_some_and(|contracts| {
            contracts
                .iter()
                .all(|v| v.as_str().is_some_and(is_heads_hash))
                && contracts.iter().any(|v| v.as_str() == Some(hash))
        })
}

// Intentionally no Debug: credentials and destination are not diagnostics.
pub struct ContextClient {
    destination: DestinationUrl,
    api_key: Option<Zeroizing<String>>,
    timeout: Duration,
    pin: ContextPin,
}

impl ContextClient {
    pub fn local(bouncer: &BouncerClient, pin: ContextPin) -> Result<Self, ContextUnavailable> {
        if bouncer.is_remote() {
            return Err(ContextUnavailable::RemoteNotInScope);
        }
        let destination = http::parse_destination(bouncer.url())
            .map_err(|_| ContextUnavailable::RemoteNotInScope)?;
        if !matches!(destination, DestinationUrl::Loopback { .. }) {
            return Err(ContextUnavailable::RemoteNotInScope);
        }
        if !valid_pin(&pin) {
            return Err(ContextUnavailable::BadPin);
        }
        Ok(Self {
            destination,
            api_key: bouncer.api_key().map(|key| Zeroizing::new(key.to_owned())),
            timeout: bouncer.timeout(),
            pin,
        })
    }

    pub fn evaluate(&self, input: &ContextInput) -> ContextVerdict {
        self.evaluate_body(&request_body(input, &self.pin))
    }

    fn evaluate_body(&self, body: &Value) -> ContextVerdict {
        let Ok(bytes) = serde_json::to_vec(body) else {
            return ContextVerdict::Unavailable(ContextUnavailable::BadAnswer);
        };
        let send = || {
            http::post_json_loopback(
                &self.destination,
                CONTEXT_PATH,
                &bytes,
                self.api_key.as_ref().map(|key| key.as_str()),
                self.timeout,
            )
        };
        let response = match send() {
            Err(HttpFailure::Timeout) => send(),
            other => other,
        };
        match response {
            Ok(response) => parse_answer(response.status, &response.body, &self.pin),
            Err(HttpFailure::Timeout) => ContextVerdict::Unavailable(ContextUnavailable::Timeout),
            Err(_) => ContextVerdict::Unavailable(ContextUnavailable::Transport),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::bouncer::StaticBearer;
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;
    use zeroize::Zeroizing;

    const ANSWER: &[u8] =
        include_bytes!("../../tests/fixtures/secret-decision-context-v1/wire/answer.json");
    fn fixture() -> Value {
        serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/secret-decision-context-v1/wire/request.json"
        ))
        .unwrap()
    }
    fn input() -> ContextInput {
        use super::super::action_kind::ActionKind;
        use super::super::bouncer::BouncerRequest;
        use super::super::secret_facts::{
            ContextV1, HostFit, ItemRunMatch, ProjectFit, build_input, facts_from_evidence,
        };
        use crate::contracts::CredentialKind;
        use crate::vault::{EventAge, ItemDecisionEvidence, UseCount};

        let golden: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/secret-decision-context-v1/serializer/one-unknown.json"
        ))
        .unwrap();
        let request = &golden["request"];
        let text = |name: &str| request[name].as_str().unwrap().to_owned();
        let request = BouncerRequest {
            user_request: text("user_request"),
            command: text("command"),
            purpose: text("purpose"),
            instruction: text("instruction"),
            relative_dir: text("relative_dir"),
            env_names: Vec::new(),
            task_provenance: text("task_provenance"),
        };
        let evidence = ItemDecisionEvidence {
            kind: CredentialKind::ApiKey,
            provider: None,
            declaration: None,
            declaration_sources: None,
            agent_created_here: false,
            agent_allowed_before: false,
            owner_allowed_same_scope: UseCount::Known(0),
            owner_denied_same_scope: UseCount::Known(0),
            owner_denied_other_scope: UseCount::Known(0),
            last_secret_change: EventAge::None,
            last_access_change: EventAge::None,
        };
        let context = ContextV1 {
            action: ActionKind::Read,
            secrets: vec![facts_from_evidence(
                &evidence,
                ItemRunMatch {
                    project: ProjectFit::Undeclared,
                    hosts: HostFit::None,
                },
                0,
            )],
        };
        build_input(&request, &context).expect("measured golden context fits")
    }
    fn pin() -> ContextPin {
        ContextPin {
            heads: fixture()["heads"].as_str().unwrap().into(),
            model: "apassy-context-v1+a1b2c3d4".into(),
        }
    }
    fn unavailable(code: ContextUnavailable) -> ContextVerdict {
        ContextVerdict::Unavailable(code)
    }

    #[test]
    fn status_table_and_closed_errors() {
        use ContextUnavailable::*;
        let cases: &[(u16, &[u8], ContextUnavailable)] = &[
            (404, b"not JSON", NotOffered),
            (401, b"", Refused401),
            (
                409,
                include_bytes!(
                    "../../tests/fixtures/secret-decision-context-v1/wire/error-unsupported-contract.json"
                ),
                UnsupportedContract,
            ),
            (
                409,
                include_bytes!(
                    "../../tests/fixtures/secret-decision-context-v1/wire/error-unknown-heads.json"
                ),
                UnknownHeads,
            ),
            (
                409,
                include_bytes!(
                    "../../tests/fixtures/secret-decision-context-v1/wire/error-not-context-heads.json"
                ),
                NotContextHeads,
            ),
            (
                422,
                include_bytes!(
                    "../../tests/fixtures/secret-decision-context-v1/wire/error-input-too-long.json"
                ),
                InputTooLong,
            ),
            (500, b"untrusted server text", Status(500)),
            (409, br#"{"detail":{"code":"untrusted text"}}"#, Status(409)),
            (422, br#"{"detail":{"code":"unknown_heads"}}"#, Status(422)),
            (200, b"not JSON", BadAnswer),
        ];
        for (status, bytes, reason) in cases {
            assert_eq!(parse_answer(*status, bytes, &pin()), unavailable(*reason));
        }
        assert_eq!(
            parse_answer(200, ANSWER, &pin()),
            ContextVerdict::Scored {
                owner_accepts_use: 0.91,
                model: pin().model,
            }
        );
    }

    #[test]
    fn answer_pins_probability_and_bounds() {
        for field in ["heads", "model", "contract_sha256"] {
            let mut answer: Value = serde_json::from_slice(ANSWER).unwrap();
            answer[field] = json!("different");
            assert_eq!(
                parse_answer(200, &serde_json::to_vec(&answer).unwrap(), &pin()),
                unavailable(ContextUnavailable::PinMismatch)
            );
        }
        for p in [
            json!(-0.1),
            json!(1.1),
            Value::Null,
            json!("0.9"),
            json!(true),
        ] {
            let mut answer: Value = serde_json::from_slice(ANSWER).unwrap();
            answer["answers"][QUESTION]["noul"] = p;
            assert_eq!(
                parse_answer(200, &serde_json::to_vec(&answer).unwrap(), &pin()),
                unavailable(ContextUnavailable::BadAnswer)
            );
        }
        let mut answer: Value = serde_json::from_slice(ANSWER).unwrap();
        answer["answers"] = json!({});
        assert_eq!(
            parse_answer(200, &serde_json::to_vec(&answer).unwrap(), &pin()),
            unavailable(ContextUnavailable::BadAnswer)
        );
        for p in [0.0, 1.0] {
            answer["answers"] = json!({"owner_accepts_use": {"noul": p}});
            answer["future"] = json!({"ignored": true});
            assert!(matches!(
                parse_answer(200, &serde_json::to_vec(&answer).unwrap(), &pin()),
                ContextVerdict::Scored { .. }
            ));
        }
        assert_eq!(
            parse_answer(200, &vec![b' '; http::MAX_RESPONSE_BYTES + 1], &pin()),
            unavailable(ContextUnavailable::BadAnswer)
        );
    }

    #[test]
    fn health_is_pure_advisory_and_bounded() {
        assert!(offers_contract(
            include_bytes!("../../tests/fixtures/secret-decision-context-v1/wire/health.json"),
            contract_sha256()
        ));
        for bytes in [
            include_bytes!(
                "../../tests/fixtures/secret-decision-context-v1/wire/health-without.json"
            )
            .as_slice(),
            b"bad JSON",
            br#"{"context_contracts":[null]}"#,
        ] {
            assert!(!offers_contract(bytes, contract_sha256()));
        }
        assert!(!offers_contract(
            include_bytes!("../../tests/fixtures/secret-decision-context-v1/wire/health.json"),
            &"b".repeat(64)
        ));
        assert!(!offers_contract(
            &vec![b' '; http::MAX_RESPONSE_BYTES + 1],
            contract_sha256()
        ));
    }

    #[test]
    fn bad_pin_and_remote_are_rejected_without_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let local =
            BouncerClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        for heads in ["bad".into(), "A".repeat(64), "a".repeat(63)] {
            let bad = ContextPin {
                heads,
                model: pin().model,
            };
            assert!(matches!(
                ContextClient::local(&local, bad),
                Err(ContextUnavailable::BadPin)
            ));
        }
        let mut bad = pin();
        bad.model = "wrong".into();
        assert!(matches!(
            ContextClient::local(&local, bad),
            Err(ContextUnavailable::BadPin)
        ));
        let remote = BouncerClient::remote(
            &format!(
                "https://127.0.0.1:{}",
                listener.local_addr().unwrap().port()
            ),
            Arc::new(StaticBearer::new(Zeroizing::new("synthetic-bearer".into())).unwrap()),
            Arc::new(http::TlsClient::platform().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            ContextClient::local(&remote, pin()),
            Err(ContextUnavailable::RemoteNotInScope)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = std::str::from_utf8(&bytes[..end])
                    .unwrap()
                    .to_ascii_lowercase();
                let len: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + len {
                    return bytes;
                }
            }
            assert!(bytes.len() < 64 * 1024);
        }
    }

    // None = hold the accepted connection open until the client timeout. All
    // threads are joined; each listener has an ephemeral port and finite deadline.
    fn mocked(replies: Vec<Option<(u16, Vec<u8>)>>) -> (ContextVerdict, Vec<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let bouncer = BouncerClient::new(&format!("http://{}", listener.local_addr().unwrap()))
            .unwrap()
            .with_timeout(Duration::from_millis(150));
        let client = ContextClient::local(&bouncer, pin()).unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            let mut held = Vec::new();
            let deadline = Instant::now() + Duration::from_millis(700);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets can inherit the listener's mode on
                        // macOS; request reads use the finite read timeout.
                        stream.set_nonblocking(false).unwrap();
                        requests.push(read_request(&mut stream));
                        match replies.get(requests.len() - 1).and_then(Option::as_ref) {
                            Some((status, body)) => {
                                let header = format!(
                                    "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(header.as_bytes());
                                let _ = stream.write_all(body);
                            }
                            None => held.push(stream),
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
            requests
        });
        // Use the public builder and client; no unchecked ContextInput constructor.
        let verdict = client.evaluate(&input());
        (verdict, worker.join().unwrap())
    }

    #[test]
    fn real_transport_fixture_and_timeout_only_retry() {
        let (verdict, requests) = mocked(vec![Some((200, ANSWER.to_vec()))]);
        assert!(matches!(verdict, ContextVerdict::Scored { .. }));
        assert_eq!(requests.len(), 1);
        let bytes = &requests[0];
        assert!(bytes.starts_with(b"POST /v1/context-evaluate HTTP/1.1\r\n"));
        let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes[end..]).unwrap(),
            fixture()
        );
        for forbidden in ["item_id", "revision", "CANARY", "instructions"] {
            assert!(!std::str::from_utf8(bytes).unwrap().contains(forbidden));
        }
        let (verdict, requests) = mocked(vec![None, Some((200, ANSWER.to_vec()))]);
        assert!(matches!(verdict, ContextVerdict::Scored { .. }));
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        let (verdict, requests) = mocked(vec![None, None]);
        assert_eq!(verdict, unavailable(ContextUnavailable::Timeout));
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn no_status_retries_and_oversized_transport_refuses() {
        for status in [401, 404, 409, 422, 500] {
            let (verdict, requests) = mocked(vec![Some((status, b"{}".to_vec()))]);
            assert!(matches!(verdict, ContextVerdict::Unavailable(_)));
            assert_eq!(requests.len(), 1);
        }
        let (verdict, requests) =
            mocked(vec![Some((200, vec![b'x'; http::MAX_RESPONSE_BYTES + 1]))]);
        assert_eq!(verdict, unavailable(ContextUnavailable::Transport));
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn golden_wire_body_has_exactly_four_fields() {
        let fixture = fixture();
        assert_eq!(request_body(&input(), &pin()), fixture);
        assert_eq!(fixture.as_object().unwrap().len(), 4);
        let golden: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/secret-decision-context-v1/serializer/one-unknown.json"
        ))
        .unwrap();
        assert_eq!(fixture["model_text"], golden["model_text"]);
        assert!(golden["refusal"].is_null());
    }
}
