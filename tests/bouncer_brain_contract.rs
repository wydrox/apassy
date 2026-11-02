//! The fixtures of the bouncer brain wire contract (`docs/contracts/bouncer-brain-v1.md`).
//!
//! The structs here are local to the test, not product code: they read the fixtures as
//! a client and a server of the contract would. Only the client's own request is
//! strict (section 9: the client sends no field that the contract does not define);
//! every answer accepts unknown fields, as the client does.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

const REQUEST: &str = include_str!("fixtures/bouncer-brain-v1/request.json");
const REQUEST_WITH_SHADOW: &str =
    include_str!("fixtures/bouncer-brain-v1/request-with-shadow.json");
const ANSWER: &str = include_str!("fixtures/bouncer-brain-v1/answer.json");
const ANSWER_WITH_SHADOW: &str = include_str!("fixtures/bouncer-brain-v1/answer-with-shadow.json");
const ANSWER_SHADOW_UNKNOWN: &str =
    include_str!("fixtures/bouncer-brain-v1/answer-shadow-unknown.json");
const ERROR_UNKNOWN_HEADS: &str =
    include_str!("fixtures/bouncer-brain-v1/error-unknown-heads.json");
const ERROR_BAD_HEADS: &str = include_str!("fixtures/bouncer-brain-v1/error-bad-heads.json");
const HEADS_INFO: &str = include_str!("fixtures/bouncer-brain-v1/heads-info.json");
const MANIFEST: &str = include_str!("fixtures/bouncer-brain-v1/manifest.json");

const FIXTURES: [(&str, &str); 9] = [
    ("request.json", REQUEST),
    ("request-with-shadow.json", REQUEST_WITH_SHADOW),
    ("answer.json", ANSWER),
    ("answer-with-shadow.json", ANSWER_WITH_SHADOW),
    ("answer-shadow-unknown.json", ANSWER_SHADOW_UNKNOWN),
    ("error-unknown-heads.json", ERROR_UNKNOWN_HEADS),
    ("error-bad-heads.json", ERROR_BAD_HEADS),
    ("heads-info.json", HEADS_INFO),
    ("manifest.json", MANIFEST),
];

/// Section 8: a response body of `POST /v1/systemone` is at most 64 KiB.
const MAX_ANSWER_BYTES: usize = 64 * 1024;
/// `vault::MAX_MODEL_VERSION`.
const MAX_MODEL_VERSION: usize = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    state: Value,
    questions: BTreeMap<String, Question>,
    heads: Option<String>,
    shadow_heads: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Question {
    #[serde(rename = "type")]
    kind: String,
    instructions: String,
}

#[derive(Debug, Deserialize)]
struct Answer {
    model: String,
    heads: String,
    answers: BTreeMap<String, Noul>,
    shadow: Option<Shadow>,
}

#[derive(Debug, Deserialize)]
struct Noul {
    noul: f64,
}

#[derive(Debug, Deserialize)]
struct Shadow {
    heads: String,
    model: Option<String>,
    answers: Option<BTreeMap<String, Noul>>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    detail: Detail,
}

#[derive(Debug, Deserialize)]
struct Detail {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct HeadsInfo {
    heads: String,
    model: String,
    size_bytes: u64,
    default: bool,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema: u32,
    name: String,
    version: String,
    checkpoint: Checkpoint,
    base: Base,
}

#[derive(Debug, Deserialize)]
struct Checkpoint {
    file: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct Base {
    repo: String,
    revision: String,
    weights_file: String,
    weights_sha256: String,
}

fn parse<T: DeserializeOwned>(name: &str, text: &str) -> T {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha256(text: &str) -> bool {
    is_lower_hex(text, 64)
}

/// `<name>+<first 8 hex of heads>`, with the characters of `bouncer::valid_model_version`.
fn assert_model_names_heads(model: &str, heads: &str) {
    assert!(is_sha256(heads), "heads {heads:?} is not 64 lowercase hex");
    assert!(
        model.len() <= MAX_MODEL_VERSION,
        "model {model:?} is too long"
    );
    let (name, short) = model
        .rsplit_once('+')
        .unwrap_or_else(|| panic!("model {model:?} has no `+<8 hex>`"));
    assert!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "model name {name:?} has other characters"
    );
    assert!(
        is_lower_hex(short, 8),
        "model {model:?} does not end in 8 hex"
    );
    assert_eq!(
        short,
        &heads[..8],
        "model {model:?} does not name heads {heads}"
    );
}

fn assert_answers_cover(name: &str, answers: &BTreeMap<String, Noul>, request: &Request) {
    let asked: Vec<&String> = request.questions.keys().collect();
    let answered: Vec<&String> = answers.keys().collect();
    assert_eq!(answered, asked, "{name}: the answers are not the questions");
    for (id, answer) in answers {
        assert!(
            (0.0..=1.0).contains(&answer.noul),
            "{name}: {id} has noul {}",
            answer.noul
        );
    }
}

fn assert_request(name: &str, request: &Request) {
    assert!(
        request.state.is_string() || request.state.is_object(),
        "{name}: state is a string or an object"
    );
    assert!(!request.questions.is_empty(), "{name}: no questions");
    for (id, question) in &request.questions {
        assert_eq!(question.kind, "noul", "{name}: {id} is not a noul question");
        assert!(
            !question.instructions.is_empty(),
            "{name}: {id} has no text"
        );
    }
    for heads in [&request.heads, &request.shadow_heads]
        .into_iter()
        .flatten()
    {
        assert!(
            is_sha256(heads),
            "{name}: {heads:?} is not 64 lowercase hex"
        );
    }
}

/// `sk_` only at the start of a word: `task_match` is a question, not a key.
fn has_word_prefix(text: &str, prefix: &str) -> bool {
    text.match_indices(prefix).any(|(at, _)| {
        text[..at]
            .bytes()
            .next_back()
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
    })
}

#[test]
fn every_bouncer_brain_fixture_matches_the_contract() {
    for (name, text) in FIXTURES {
        serde_json::from_str::<Value>(text).unwrap_or_else(|error| panic!("{name}: {error}"));
    }

    let request: Request = parse("request.json", REQUEST);
    let with_shadow: Request = parse("request-with-shadow.json", REQUEST_WITH_SHADOW);
    assert_request("request.json", &request);
    assert_request("request-with-shadow.json", &with_shadow);
    assert!(request.heads.is_some() && request.shadow_heads.is_none());
    assert!(with_shadow.heads.is_some() && with_shadow.shadow_heads.is_some());
    assert_ne!(with_shadow.heads, with_shadow.shadow_heads);

    for (name, text, asked) in [
        ("answer.json", ANSWER, &request),
        ("answer-with-shadow.json", ANSWER_WITH_SHADOW, &with_shadow),
        (
            "answer-shadow-unknown.json",
            ANSWER_SHADOW_UNKNOWN,
            &with_shadow,
        ),
    ] {
        assert!(text.len() <= MAX_ANSWER_BYTES, "{name} is over 64 KiB");
        let answer: Answer = parse(name, text);
        assert_eq!(Some(&answer.heads), asked.heads.as_ref(), "{name}: heads");
        assert_model_names_heads(&answer.model, &answer.heads);
        assert_answers_cover(name, &answer.answers, asked);
        match (&answer.shadow, &asked.shadow_heads) {
            (None, None) => {}
            (Some(shadow), Some(sent)) => {
                assert_eq!(&shadow.heads, sent, "{name}: shadow heads");
                match (&shadow.model, &shadow.answers, &shadow.error) {
                    (Some(model), Some(answers), None) => {
                        assert_model_names_heads(model, &shadow.heads);
                        assert_answers_cover(name, answers, asked);
                    }
                    (None, None, Some(error)) => assert_eq!(error, "unknown_heads", "{name}"),
                    other => panic!("{name}: shadow is neither answers nor an error: {other:?}"),
                }
            }
            (got, sent) => panic!("{name}: shadow {got:?} for shadow_heads {sent:?}"),
        }
    }

    let info: HeadsInfo = parse("heads-info.json", HEADS_INFO);
    assert_model_names_heads(&info.model, &info.heads);
    assert!(info.size_bytes > 0);
}

#[test]
fn the_client_request_rejects_a_field_outside_the_contract() {
    let mut value: Value = parse("request.json", REQUEST);
    value["owner"] = Value::String("synthetic".to_owned());
    assert!(serde_json::from_value::<Request>(value).is_err());

    let mut value: Value = parse("request.json", REQUEST);
    value["questions"]["task_match"]["criteria"] = Value::Bool(true);
    assert!(serde_json::from_value::<Request>(value).is_err());
}

#[test]
fn an_unknown_or_malformed_head_set_has_its_error_code() {
    let unknown: ErrorBody = parse("error-unknown-heads.json", ERROR_UNKNOWN_HEADS);
    assert_eq!(unknown.detail.code, "unknown_heads");
    assert!(!unknown.detail.message.is_empty());
    let bad: ErrorBody = parse("error-bad-heads.json", ERROR_BAD_HEADS);
    assert_eq!(bad.detail.code, "bad_heads");
    assert!(!bad.detail.message.is_empty());
}

#[test]
fn an_unknown_shadow_head_set_keeps_the_active_answers() {
    let request: Request = parse("request-with-shadow.json", REQUEST_WITH_SHADOW);
    let answer: Answer = parse("answer-shadow-unknown.json", ANSWER_SHADOW_UNKNOWN);
    assert_answers_cover("answer-shadow-unknown.json", &answer.answers, &request);
    let shadow = answer.shadow.expect("a shadow part");
    assert_eq!(shadow.error.as_deref(), Some("unknown_heads"));
    assert!(shadow.model.is_none() && shadow.answers.is_none());
}

#[test]
fn the_manifest_names_the_head_set_that_it_describes() {
    let manifest: Manifest = parse("manifest.json", MANIFEST);
    let info: HeadsInfo = parse("heads-info.json", HEADS_INFO);
    assert_eq!(manifest.schema, 1);
    assert_eq!(manifest.checkpoint.file, "candidate.safetensors");
    assert_eq!(manifest.checkpoint.sha256, info.heads);
    assert_eq!(manifest.checkpoint.size_bytes, info.size_bytes);
    assert_eq!(manifest.version, info.model);
    assert_eq!(
        manifest.version,
        format!("{}+{}", manifest.name, &manifest.checkpoint.sha256[..8])
    );
    assert_model_names_heads(&manifest.version, &manifest.checkpoint.sha256);
    assert!(!manifest.base.repo.is_empty() && !manifest.base.weights_file.is_empty());
    assert!(is_lower_hex(&manifest.base.revision, 40));
    assert!(is_sha256(&manifest.base.weights_sha256));
    assert!(
        !info.default,
        "an uploaded candidate is not the default head set"
    );
}

#[test]
fn no_bouncer_brain_fixture_looks_like_a_secret_or_a_path() {
    assert!(has_word_prefix("key sk_x", "sk_") && !has_word_prefix("task_match", "sk_"));
    for (name, text) in FIXTURES {
        assert!(!has_word_prefix(text, "sk_"), "{name} has `sk_`");
        for needle in ["BEGIN ", "password=", "/Users/"] {
            assert!(!text.contains(needle), "{name} has {needle:?}");
        }
    }
}
