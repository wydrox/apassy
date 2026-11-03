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
const ERROR_NO_TOKEN: &str = include_str!("fixtures/bouncer-brain-v1/error-no-token.json");
const HEADS_INFO: &str = include_str!("fixtures/bouncer-brain-v1/heads-info.json");
const MANIFEST: &str = include_str!("fixtures/bouncer-brain-v1/manifest.json");

const CONTRACT: &str = include_str!("../docs/contracts/bouncer-brain-v1.md");

const FIXTURES: [(&str, &str); 10] = [
    ("request.json", REQUEST),
    ("request-with-shadow.json", REQUEST_WITH_SHADOW),
    ("answer.json", ANSWER),
    ("answer-with-shadow.json", ANSWER_WITH_SHADOW),
    ("answer-shadow-unknown.json", ANSWER_SHADOW_UNKNOWN),
    ("error-unknown-heads.json", ERROR_UNKNOWN_HEADS),
    ("error-bad-heads.json", ERROR_BAD_HEADS),
    ("error-no-token.json", ERROR_NO_TOKEN),
    ("heads-info.json", HEADS_INFO),
    ("manifest.json", MANIFEST),
];

const ERRORS: [(&str, &str, &str); 3] = [
    (
        "error-unknown-heads.json",
        ERROR_UNKNOWN_HEADS,
        "unknown_heads",
    ),
    ("error-bad-heads.json", ERROR_BAD_HEADS, "bad_heads"),
    ("error-no-token.json", ERROR_NO_TOKEN, "no_token"),
];

/// The code table of section 1.
const CODES: [&str; 8] = [
    "unknown_heads",
    "bad_heads",
    "default_heads",
    "input_too_long",
    "too_large",
    "no_token",
    "heads_full",
    "shadow_failed",
];
/// Section 3.2: the codes of `shadow.error`.
const SHADOW_ERRORS: [&str; 2] = ["unknown_heads", "shadow_failed"];

/// Section 8: the whole response of `POST /v1/systemone`, headers included, is at most
/// 64 KiB, so its body is too.
const MAX_ANSWER_BYTES: usize = 64 * 1024;
/// `vault::MAX_MODEL_VERSION`.
const MAX_MODEL_VERSION: usize = 64;
/// Section 3.2: `<name>+<8 hex>` fits `MAX_MODEL_VERSION`.
const MAX_MODEL_NAME: usize = 55;

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

/// Section 3.2: a letter or digit first, then letters, digits, `.`, `_` and `-`, at most
/// `MAX_MODEL_NAME` characters.
fn is_model_name(name: &str) -> bool {
    name.len() <= MAX_MODEL_NAME
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A run of 64 hex characters: a hash that a `message` must not repeat.
fn has_sha256_run(text: &str) -> bool {
    let mut run = 0;
    text.bytes().any(|b| {
        run = if b.is_ascii_hexdigit() { run + 1 } else { 0 };
        run >= 64
    })
}

/// `<name>+<first 8 hex of heads>`, with the name rule of section 3.2.
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
        is_model_name(name),
        "model name {name:?} breaks the name rule"
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
                    (None, None, Some(error)) => {
                        assert!(SHADOW_ERRORS.contains(&error.as_str()), "{name}: {error}")
                    }
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
fn a_null_head_hash_counts_as_absent() {
    let mut value: Value = parse("request-with-shadow.json", REQUEST_WITH_SHADOW);
    value["heads"] = Value::Null;
    value["shadow_heads"] = Value::Null;
    let request: Request = serde_json::from_value(value).expect("null hashes parse");
    assert!(request.heads.is_none() && request.shadow_heads.is_none());
    assert_request("request-with-shadow.json with null hashes", &request);
}

#[test]
fn every_error_fixture_has_a_code_of_the_table() {
    for code in CODES {
        assert!(
            CONTRACT.contains(&format!("| `{code}` |")),
            "the code table has no row for {code}"
        );
    }
    for (name, text, code) in ERRORS {
        let body: ErrorBody = parse(name, text);
        assert_eq!(body.detail.code, code, "{name}");
        assert!(CODES.contains(&body.detail.code.as_str()), "{name}");
        assert!(!body.detail.message.is_empty(), "{name}: no message");
    }
    for error in SHADOW_ERRORS {
        assert!(CODES.contains(&error), "{error} is not in the code table");
    }
}

#[test]
fn no_error_message_repeats_a_hash() {
    let hash = "a1b2c3d4e5f60718e5f60718e5f60718e5f60718e5f60718e5f60718e5f60718";
    assert!(has_sha256_run(&format!("no head set {hash}")));
    assert!(!has_sha256_run(&hash[..63]));
    for (name, text, _) in ERRORS {
        let body: ErrorBody = parse(name, text);
        assert!(
            !has_sha256_run(&body.detail.message),
            "{name}: the message repeats a hash"
        );
    }
}

#[test]
fn a_model_name_follows_the_name_rule() {
    assert_eq!(MAX_MODEL_NAME + 1 + 8, MAX_MODEL_VERSION);
    let longest = "n".repeat(MAX_MODEL_NAME);
    let too_long = "n".repeat(MAX_MODEL_NAME + 1);
    for name in ["a", "9", "apassy-local-v1", "v1.2_rc-3", longest.as_str()] {
        assert!(is_model_name(name), "{name:?} is a valid name");
    }
    for name in [
        "",
        "-a",
        ".a",
        "_a",
        "a b",
        "a+b",
        "a/b",
        "\u{e9}t\u{e9}",
        too_long.as_str(),
    ] {
        assert!(!is_model_name(name), "{name:?} is not a valid name");
    }
}

#[test]
fn a_non_finite_number_is_not_an_answer() {
    for word in ["NaN", "Infinity", "-Infinity"] {
        let text = ANSWER.replacen("\"noul\": 0.91", &format!("\"noul\": {word}"), 1);
        assert_ne!(text, ANSWER);
        assert!(
            serde_json::from_str::<Answer>(&text).is_err(),
            "noul {word} parses"
        );
    }
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

/// Contract v2 (`docs/contracts/bouncer-brain-v2.md`): training jobs, the Connect sign-in
/// and owner namespaces. The v1 checks above still hold: v2 changes no v1 route.
mod v2 {
    use std::collections::BTreeMap;

    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::{
        ErrorBody, MANIFEST, MAX_ANSWER_BYTES, Manifest, assert_model_names_heads, has_sha256_run,
        has_word_prefix, is_lower_hex, is_model_name, is_sha256, parse,
    };

    const HEALTH: &str = include_str!("fixtures/bouncer-brain-v2/health.json");
    const JOB_MANIFEST: &str = include_str!("fixtures/bouncer-brain-v2/job-manifest.json");
    const JOB_QUEUED: &str = include_str!("fixtures/bouncer-brain-v2/job-queued.json");
    const JOB_RUNNING: &str = include_str!("fixtures/bouncer-brain-v2/job-running.json");
    const JOB_DONE: &str = include_str!("fixtures/bouncer-brain-v2/job-done.json");
    const JOB_FAILED: &str = include_str!("fixtures/bouncer-brain-v2/job-failed.json");
    const JOB_DELETED: &str = include_str!("fixtures/bouncer-brain-v2/job-deleted.json");
    const OWNER_DELETED: &str = include_str!("fixtures/bouncer-brain-v2/owner-deleted.json");
    const CHALLENGE_REQUEST: &str =
        include_str!("fixtures/bouncer-brain-v2/sign-in-challenge-request.json");
    const CHALLENGE: &str = include_str!("fixtures/bouncer-brain-v2/sign-in-challenge.json");
    const SIGN_IN_REQUEST: &str = include_str!("fixtures/bouncer-brain-v2/sign-in-request.json");
    const SIGN_IN: &str = include_str!("fixtures/bouncer-brain-v2/sign-in.json");
    const DIRECTORY_REQUEST: &str =
        include_str!("fixtures/bouncer-brain-v2/directory-request.json");
    const DIRECTORY_ANSWER: &str = include_str!("fixtures/bouncer-brain-v2/directory-answer.json");
    const REVOKE_REQUEST: &str = include_str!("fixtures/bouncer-brain-v2/revoke-request.json");
    const REVOKE: &str = include_str!("fixtures/bouncer-brain-v2/revoke.json");
    const FORGET_REQUEST: &str = include_str!("fixtures/bouncer-brain-v2/forget-request.json");
    const FORGET: &str = include_str!("fixtures/bouncer-brain-v2/forget.json");
    const ERROR_JOB_BUSY: &str = include_str!("fixtures/bouncer-brain-v2/error-job-busy.json");
    const ERROR_UNKNOWN_JOB: &str =
        include_str!("fixtures/bouncer-brain-v2/error-unknown-job.json");
    const ERROR_NOT_ENTITLED: &str =
        include_str!("fixtures/bouncer-brain-v2/error-not-entitled.json");
    const ERROR_SIGN_IN_FAILED: &str =
        include_str!("fixtures/bouncer-brain-v2/error-sign-in-failed.json");
    const ERROR_UNAUTHENTICATED: &str =
        include_str!("fixtures/bouncer-brain-v2/error-unauthenticated.json");

    const CONTRACT_V1: &str = include_str!("../docs/contracts/bouncer-brain-v1.md");
    const CONTRACT: &str = include_str!("../docs/contracts/bouncer-brain-v2.md");

    const FIXTURES: &[(&str, &str)] = &[
        ("health.json", HEALTH),
        ("job-manifest.json", JOB_MANIFEST),
        ("job-queued.json", JOB_QUEUED),
        ("job-running.json", JOB_RUNNING),
        ("job-done.json", JOB_DONE),
        ("job-failed.json", JOB_FAILED),
        ("job-deleted.json", JOB_DELETED),
        ("owner-deleted.json", OWNER_DELETED),
        ("sign-in-challenge-request.json", CHALLENGE_REQUEST),
        ("sign-in-challenge.json", CHALLENGE),
        ("sign-in-request.json", SIGN_IN_REQUEST),
        ("sign-in.json", SIGN_IN),
        ("directory-request.json", DIRECTORY_REQUEST),
        ("directory-answer.json", DIRECTORY_ANSWER),
        ("revoke-request.json", REVOKE_REQUEST),
        ("revoke.json", REVOKE),
        ("forget-request.json", FORGET_REQUEST),
        ("forget.json", FORGET),
        ("error-job-busy.json", ERROR_JOB_BUSY),
        ("error-unknown-job.json", ERROR_UNKNOWN_JOB),
        ("error-not-entitled.json", ERROR_NOT_ENTITLED),
        ("error-sign-in-failed.json", ERROR_SIGN_IN_FAILED),
        ("error-unauthenticated.json", ERROR_UNAUTHENTICATED),
    ];

    /// The JSON request bodies of sections 5 and 7: at most 8 KiB each.
    const REQUESTS: &[(&str, &str)] = &[
        ("sign-in-challenge-request.json", CHALLENGE_REQUEST),
        ("sign-in-request.json", SIGN_IN_REQUEST),
        ("directory-request.json", DIRECTORY_REQUEST),
        ("revoke-request.json", REVOKE_REQUEST),
        ("forget-request.json", FORGET_REQUEST),
    ];

    const ERRORS: [(&str, &str, &str); 5] = [
        ("error-job-busy.json", ERROR_JOB_BUSY, "job_busy"),
        ("error-unknown-job.json", ERROR_UNKNOWN_JOB, "unknown_job"),
        (
            "error-not-entitled.json",
            ERROR_NOT_ENTITLED,
            "not_entitled",
        ),
        (
            "error-sign-in-failed.json",
            ERROR_SIGN_IN_FAILED,
            "sign_in_failed",
        ),
        (
            "error-unauthenticated.json",
            ERROR_UNAUTHENTICATED,
            "unauthenticated",
        ),
    ];

    /// The new codes of section 1.3.
    const CODES: [&str; 10] = [
        "unauthenticated",
        "sign_in_failed",
        "not_entitled",
        "bad_request",
        "rate_limited",
        "busy",
        "bad_job",
        "unknown_job",
        "job_busy",
        "job_not_done",
    ];
    /// Section 4.3.
    const STATES: [&str; 5] = ["queued", "running", "done", "failed", "deleted"];
    const JOB_ERRORS: [&str; 5] = [
        "training_failed",
        "deadline",
        "expired",
        "interrupted",
        "bad_result",
    ];

    const JOB_KIND: &str = "apassy-train-job-v1";
    /// Section 4.7: the examples live at most 24 hours after the upload.
    const EXAMPLES_HOLD: u64 = 24 * 60 * 60;
    /// Section 4.5: an undeleted result lives 7 days after the job end.
    const RESULT_HOLD: u64 = 7 * 24 * 60 * 60;
    /// Section 4.1.
    const MAX_JOB_BYTES: u64 = 64 * 1024 * 1024;
    /// v1 section 5: the encoded `Apassy-Manifest` header.
    const MAX_MANIFEST_HEADER: usize = 16 * 1024;
    /// Section 4.4: the compact JSON of a result manifest, so that it fits the header.
    const MAX_RESULT_MANIFEST: usize = 12 * 1024;
    /// Section 1.1.
    const MAX_JSON_REQUEST: usize = 8 * 1024;
    /// The training gate (`src/broker/finetune.rs:43-45`).
    const MIN_OWNER_DECISIONS: u64 = 300;
    const MIN_OWNER_DENIALS: u64 = 30;
    /// Section 5.1 and 5.4.
    const NONCE_LIFE: u64 = 60;
    const TOKEN_LIFE: u64 = 15 * 60;
    /// relay-sync-v1 section 2: a DER signature has at most 72 bytes.
    const MAX_SIGNATURE_BYTES: usize = 72;

    const SIGN_IN_TAG: &str = "apassy-bouncer sign-in v1";
    const RELAY_SIGN_IN_TAG: &str = "apassy-relay sign-in v1";
    const ACCOUNT_SIGN_IN_TAG: &str = "apassy-connect sign-in v1";
    /// The brain origin of the fixtures (I-5 is a build constant of the app).
    const ORIGIN: &str = "https://brain.connect.example.test";

    #[derive(Debug, Deserialize)]
    struct Health {
        status: String,
        loaded: Vec<String>,
        device: String,
        contract: String,
        jobs: bool,
        sign_in: bool,
    }

    /// What the client sends: strict (v1 section 9).
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JobManifest {
        schema: u32,
        kind: String,
        name: String,
        base: JobBase,
        files: JobFiles,
        stats: BTreeMap<String, u64>,
        keep_heads: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JobBase {
        revision: String,
        weights_sha256: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JobFiles {
        train: JobFile,
        val: JobFile,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JobFile {
        size_bytes: u64,
        sha256: String,
    }

    #[derive(Debug, Deserialize)]
    struct Job {
        job: String,
        state: String,
        created_at: u64,
        started_at: Option<u64>,
        ended_at: Option<u64>,
        examples_held: bool,
        examples_deleted_at: Option<u64>,
        examples_deadline: u64,
        result_deadline: Option<u64>,
        error: Option<String>,
        result: Option<JobResult>,
    }

    #[derive(Debug, Deserialize)]
    struct JobResult {
        heads: String,
        model: String,
        size_bytes: u64,
        stored: bool,
        manifest: Manifest,
        metrics: BTreeMap<String, Value>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ChallengeRequest {
        account: String,
        key_id: String,
        public_key: String,
    }

    #[derive(Debug, Deserialize)]
    struct Challenge {
        nonce: String,
        expires_at: u64,
        origin: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignInRequest {
        account: String,
        key_id: String,
        public_key: String,
        nonce: String,
        signature: String,
    }

    #[derive(Debug, Deserialize)]
    struct SignIn {
        token: String,
        expires_at: u64,
        account: String,
        hosting: bool,
        training: bool,
    }

    /// What the brain sends to Connect: strict.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DirectoryRequest {
        key_id: String,
        public_key_sha256: String,
    }

    #[derive(Debug, Deserialize)]
    struct DirectoryAnswer {
        account: String,
        entitled_hosting: bool,
        entitled_training: bool,
        revoked: bool,
    }

    #[derive(Debug, Deserialize)]
    struct RevokeRequest {
        key_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct ForgetRequest {
        account: String,
    }

    #[derive(Debug, Deserialize)]
    struct Tokens {
        tokens: u64,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Deleted {
        heads: u64,
        jobs: u64,
        examples: u64,
    }

    #[derive(Debug, Deserialize)]
    struct OwnerDeleted {
        deleted: Deleted,
    }

    #[derive(Debug, Deserialize)]
    struct Forget {
        deleted: Deleted,
        tokens: u64,
    }

    /// The base of the server in the fixtures: the base of v1's `manifest.json`.
    fn server_base() -> Manifest {
        parse("v1 manifest.json", MANIFEST)
    }

    /// The length of base64url without padding for `bytes` bytes.
    fn b64u_len(bytes: usize) -> usize {
        (bytes * 4).div_ceil(3)
    }

    /// A character of base64url (RFC 4648 section 5).
    fn is_b64u_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
    }

    fn is_b64u(text: &str) -> bool {
        !text.is_empty() && text.len() % 4 != 1 && text.bytes().all(is_b64u_byte)
    }

    /// `a-z2-7`, the alphabet of a Connect account id.
    fn is_base32(b: u8) -> bool {
        b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)
    }

    /// Section 5: a Connect account id, `acc_` and 10 characters of `a-z2-7`.
    fn is_account(text: &str) -> bool {
        let Some(rest) = text.strip_prefix("acc_") else {
            return false;
        };
        rest.len() == 10 && rest.bytes().all(is_base32)
    }

    /// Section 5: an opaque key id of I-1, 1 to 64 characters of base64url.
    fn is_key_id(text: &str) -> bool {
        (1..=64).contains(&text.len()) && text.bytes().all(is_b64u_byte)
    }

    /// Section 5.2: `apassy_brn_` and 64 lowercase hex characters.
    fn is_token(text: &str) -> bool {
        let hex = text.strip_prefix("apassy_brn_");
        hex.is_some_and(|rest| is_lower_hex(rest, 64))
    }

    /// An X9.63 P-256 public key of 65 bytes from `0x04`, as b64u: its first character
    /// is `B` (the six bits `000001`).
    fn is_public_key(text: &str) -> bool {
        is_b64u(text) && text.len() == b64u_len(65) && text.starts_with('B')
    }

    /// Section 5.2: the parts joined with `\0`, no trailing `\0`.
    fn sign_in_message(tag: &str, origin: &str, account: &str, key: &str, nonce: &str) -> Vec<u8> {
        [tag, origin, account, key, nonce].join("\0").into_bytes()
    }

    fn strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
        match value {
            Value::String(text) => out.push(text),
            Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
            Value::Object(map) => map.values().for_each(|item| strings(item, out)),
            _ => {}
        }
    }

    /// Section 4.4: a metric is a number, or an object of numbers.
    fn is_metric(value: &Value, depth: usize) -> bool {
        match value {
            Value::Number(_) => true,
            Value::Object(map) if depth > 0 => map.values().all(|item| is_metric(item, depth - 1)),
            _ => false,
        }
    }

    /// The checks of section 4.1 that the manifest alone decides, in the order of the
    /// contract after the body hash. `None` when the server starts the job.
    fn job_manifest_problem(
        manifest: &JobManifest,
        body_bytes: u64,
        server: &Manifest,
    ) -> Option<&'static str> {
        if manifest.schema != 1 || manifest.kind != JOB_KIND {
            return Some("kind");
        }
        let files = [&manifest.files.train, &manifest.files.val];
        if files.iter().any(|file| !is_sha256(&file.sha256)) {
            return Some("hash");
        }
        let total = manifest
            .files
            .train
            .size_bytes
            .checked_add(manifest.files.val.size_bytes);
        if total != Some(body_bytes) || body_bytes > MAX_JOB_BYTES {
            return Some("size");
        }
        if manifest.base.revision != server.base.revision
            || manifest.base.weights_sha256 != server.base.weights_sha256
        {
            return Some("base");
        }
        if !is_model_name(&manifest.name) {
            return Some("name");
        }
        let count = |key: &str| manifest.stats.get(key).copied();
        match (
            count("owner_decisions"),
            count("owner_denials"),
            count("train"),
            count("val"),
        ) {
            (Some(decisions), Some(denials), Some(train), Some(val))
                if decisions >= MIN_OWNER_DECISIONS
                    && denials >= MIN_OWNER_DENIALS
                    && train > 0
                    && val > 0 =>
            {
                None
            }
            _ => Some("gate"),
        }
    }

    fn job_body_bytes(manifest: &JobManifest) -> u64 {
        manifest.files.train.size_bytes + manifest.files.val.size_bytes
    }

    #[test]
    fn every_v2_fixture_parses_and_fits_its_cap() {
        for (name, text) in FIXTURES {
            serde_json::from_str::<Value>(text).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(text.len() <= MAX_ANSWER_BYTES, "{name} is over 64 KiB");
        }
        for (name, text) in REQUESTS {
            assert!(text.len() <= MAX_JSON_REQUEST, "{name} is over 8 KiB");
        }
        assert!(
            b64u_len(JOB_MANIFEST.len()) <= MAX_MANIFEST_HEADER,
            "the job manifest does not fit the Apassy-Manifest header"
        );

        // A v1 client reads the v2 health answer as before; the new fields are extra.
        let health: Health = parse("health.json", HEALTH);
        assert_eq!(health.status, "ok");
        assert!(!health.loaded.is_empty() && !health.device.is_empty());
        assert_eq!(health.contract, "bouncer-brain-v2");
        assert!(health.jobs && !health.sign_in, "an own server with jobs");
    }

    #[test]
    fn the_job_manifest_passes_the_upload_checks() {
        let manifest: JobManifest = parse("job-manifest.json", JOB_MANIFEST);
        let server = server_base();
        assert_eq!(
            job_manifest_problem(&manifest, job_body_bytes(&manifest), &server),
            None
        );
        assert_ne!(manifest.files.train.sha256, manifest.files.val.sha256);
        assert!(manifest.files.train.size_bytes > 0 && manifest.files.val.size_bytes > 0);
        assert!(is_lower_hex(&manifest.base.revision, 40));
        assert!(is_sha256(&manifest.base.weights_sha256));
        assert!(!manifest.keep_heads);
        assert_eq!(manifest.stats.get("train"), Some(&540));
    }

    #[test]
    fn a_job_under_the_gate_off_the_base_or_of_the_wrong_size_is_refused() {
        let server = server_base();
        let body = job_body_bytes(&parse::<JobManifest>("job-manifest.json", JOB_MANIFEST));
        let cases = [
            ("/kind", json!("apassy-heads-v1"), "kind"),
            ("/schema", json!(2), "kind"),
            ("/files/val/sha256", json!("A".repeat(64)), "hash"),
            ("/files/val/size_bytes", json!(1), "size"),
            ("/base/revision", json!("0".repeat(40)), "base"),
            ("/base/weights_sha256", json!("0".repeat(64)), "base"),
            ("/name", json!("-remote"), "name"),
            (
                "/stats/owner_decisions",
                json!(MIN_OWNER_DECISIONS - 1),
                "gate",
            ),
            ("/stats/owner_denials", json!(MIN_OWNER_DENIALS - 1), "gate"),
            ("/stats/val", json!(0), "gate"),
        ];
        for (pointer, replacement, problem) in cases {
            let mut value: Value = parse("job-manifest.json", JOB_MANIFEST);
            *value.pointer_mut(pointer).expect(pointer) = replacement;
            let manifest: JobManifest = serde_json::from_value(value).expect(pointer);
            assert_eq!(
                job_manifest_problem(&manifest, body, &server),
                Some(problem),
                "{pointer}"
            );
        }

        let manifest: JobManifest = parse("job-manifest.json", JOB_MANIFEST);
        assert_eq!(
            job_manifest_problem(&manifest, body + 1, &server),
            Some("size")
        );

        let mut value: Value = parse("job-manifest.json", JOB_MANIFEST);
        value["stats"]
            .as_object_mut()
            .expect("stats is an object")
            .remove("owner_denials");
        let manifest: JobManifest = serde_json::from_value(value).expect("no denials count");
        let problem = job_manifest_problem(&manifest, body, &server);
        assert_eq!(problem, Some("gate"));
    }

    #[test]
    fn a_job_manifest_holds_counts_only_and_no_other_field() {
        let file = json!({"size_bytes": 1, "sha256": "0".repeat(64)});
        for (pointer, field, extra) in [
            ("", "owner", json!("synthetic")),
            ("/files", "stats", file),
            ("/base", "repo", json!("convaiinnovations/laya")),
        ] {
            let mut value: Value = parse("job-manifest.json", JOB_MANIFEST);
            value
                .pointer_mut(pointer)
                .and_then(Value::as_object_mut)
                .expect(pointer)
                .insert(field.to_owned(), extra);
            assert!(
                serde_json::from_value::<JobManifest>(value).is_err(),
                "{pointer}/{field} is outside the contract"
            );
        }
        for count in [
            json!("Run the migrations"),
            json!(-1),
            json!(1.5),
            json!(null),
        ] {
            let mut value: Value = parse("job-manifest.json", JOB_MANIFEST);
            value["stats"]["train"] = count.clone();
            assert!(
                serde_json::from_value::<JobManifest>(value).is_err(),
                "stats.train {count} is not a count"
            );
        }
    }

    #[test]
    fn every_job_state_follows_the_state_table() {
        let mut seen = Vec::new();
        for (name, text) in [
            ("job-queued.json", JOB_QUEUED),
            ("job-running.json", JOB_RUNNING),
            ("job-done.json", JOB_DONE),
            ("job-failed.json", JOB_FAILED),
            ("job-deleted.json", JOB_DELETED),
        ] {
            let job: Job = parse(name, text);
            assert!(is_sha256(&job.job), "{name}: the job id is a SHA-256");
            assert!(STATES.contains(&job.state.as_str()), "{name}");
            assert_eq!(
                job.examples_deadline,
                job.created_at + EXAMPLES_HOLD,
                "{name}: the examples live 24 hours at most"
            );
            if let Some(started) = job.started_at {
                assert!(started >= job.created_at, "{name}: started before created");
            }
            if let Some(ended) = job.ended_at {
                assert!(
                    job.started_at.is_some_and(|started| ended >= started),
                    "{name}: ended before started"
                );
            }
            if let Some(deleted) = job.examples_deleted_at {
                assert!(
                    deleted <= job.examples_deadline,
                    "{name}: examples after 24 h"
                );
                assert!(!job.examples_held, "{name}: deleted examples are held");
            }
            let running = matches!(job.state.as_str(), "queued" | "running");
            assert_eq!(job.examples_held, running, "{name}: examples_held");
            assert_eq!(job.ended_at.is_none(), running, "{name}: ended_at");
            assert_eq!(
                job.examples_deleted_at.is_none(),
                running,
                "{name}: examples_deleted_at"
            );
            assert_eq!(
                job.started_at.is_some(),
                job.state != "queued",
                "{name}: started_at"
            );
            match job.state.as_str() {
                "done" => {
                    assert!(job.result.is_some() && job.error.is_none(), "{name}");
                    assert_eq!(
                        job.result_deadline,
                        job.ended_at.map(|ended| ended + RESULT_HOLD),
                        "{name}: the result lives 7 days at most"
                    );
                }
                "failed" => {
                    let error = job.error.as_deref().expect("a failed job names its error");
                    assert!(JOB_ERRORS.contains(&error), "{name}: {error}");
                    assert!(job.result.is_none(), "{name}");
                    assert!(job.result_deadline.is_none(), "{name}");
                }
                _ => {
                    assert!(job.error.is_none() && job.result.is_none(), "{name}");
                    assert!(job.result_deadline.is_none(), "{name}");
                }
            }
            seen.push(job.state);
        }
        assert_eq!(seen, STATES, "one fixture for each state");

        let jobs: Vec<Job> = [JOB_QUEUED, JOB_RUNNING, JOB_DONE, JOB_FAILED, JOB_DELETED]
            .into_iter()
            .map(|text| parse("a job fixture", text))
            .collect();
        assert!(
            jobs.windows(2).all(|pair| pair[0].job == pair[1].job),
            "the fixtures are one job"
        );
    }

    #[test]
    fn a_job_result_names_its_head_set_and_holds_no_server_path() {
        let job: Job = parse("job-done.json", JOB_DONE);
        let upload: JobManifest = parse("job-manifest.json", JOB_MANIFEST);
        let result = job.result.expect("a done job has a result");
        assert_model_names_heads(&result.model, &result.heads);
        assert!(result.model.starts_with(&format!("{}+", upload.name)));
        assert_ne!(result.heads, job.job, "the head file is not the upload");
        assert!(result.size_bytes > 0);
        assert!(!result.stored, "keep_heads is false in the upload");

        let manifest = &result.manifest;
        assert_eq!(manifest.schema, 1);
        assert_eq!(manifest.name, upload.name);
        assert_eq!(manifest.version, result.model);
        assert_eq!(manifest.checkpoint.file, "candidate.safetensors");
        assert_eq!(manifest.checkpoint.sha256, result.heads);
        assert_eq!(manifest.checkpoint.size_bytes, result.size_bytes);
        assert_eq!(manifest.base.revision, upload.base.revision);
        assert_eq!(manifest.base.weights_sha256, upload.base.weights_sha256);
        assert!(!manifest.base.repo.is_empty() && !manifest.base.weights_file.is_empty());

        let value: Value = parse("job-done.json", JOB_DONE);
        let compact = serde_json::to_string(&value["result"]["manifest"]).expect("manifest");
        assert!(
            compact.len() <= MAX_RESULT_MANIFEST,
            "the result manifest does not fit an Apassy-Manifest header"
        );
        assert!(b64u_len(compact.len()) <= MAX_MANIFEST_HEADER);

        assert!(!result.metrics.is_empty());
        for (key, metric) in &result.metrics {
            assert!(is_metric(metric, 1), "metrics.{key} is not a number");
        }

        let mut texts = Vec::new();
        strings(&value, &mut texts);
        for text in texts {
            assert!(!text.starts_with('/'), "a path: {text:?}");
        }
        for field in ["checkpoint", "manifest_path", "init_sha256"] {
            assert!(
                value["result"].get(field).is_none(),
                "the trainer's own result.json field {field} leaked"
            );
        }
    }

    #[test]
    fn the_owner_deletion_gives_counts() {
        let owner: OwnerDeleted = parse("owner-deleted.json", OWNER_DELETED);
        let forget: Forget = parse("forget.json", FORGET);
        assert_eq!(forget.deleted, owner.deleted, "forget is DELETE /v1/owner");
        assert!(owner.deleted.examples <= owner.deleted.jobs);
        assert!(owner.deleted.heads + owner.deleted.jobs > 0);
        assert!(forget.tokens > 0);
        let revoke: Tokens = parse("revoke.json", REVOKE);
        assert_eq!(revoke.tokens, 1);
    }

    #[test]
    fn the_sign_in_fixtures_follow_the_encodings() {
        let request: ChallengeRequest = parse("sign-in-challenge-request.json", CHALLENGE_REQUEST);
        let challenge: Challenge = parse("sign-in-challenge.json", CHALLENGE);
        let sign_in: SignInRequest = parse("sign-in-request.json", SIGN_IN_REQUEST);
        let answer: SignIn = parse("sign-in.json", SIGN_IN);
        let directory: DirectoryAnswer = parse("directory-answer.json", DIRECTORY_ANSWER);

        assert!(is_account(&request.account), "{}", request.account);
        assert!(is_key_id(&request.key_id), "{}", request.key_id);
        assert!(is_public_key(&request.public_key));

        assert!(is_b64u(&challenge.nonce) && challenge.nonce.len() == b64u_len(32));
        assert_eq!(challenge.origin, ORIGIN);
        assert!(challenge.origin.starts_with("https://") && !challenge.origin.ends_with('/'));

        assert_eq!(sign_in.account, request.account);
        assert_eq!(sign_in.key_id, request.key_id);
        assert_eq!(sign_in.public_key, request.public_key);
        assert_eq!(sign_in.nonce, challenge.nonce);
        assert!(is_b64u(&sign_in.signature));
        assert!(sign_in.signature.len() <= b64u_len(MAX_SIGNATURE_BYTES));

        assert!(is_token(&answer.token));
        assert_eq!(answer.account, request.account);
        assert_eq!(answer.account, directory.account);
        assert_eq!(answer.hosting, directory.entitled_hosting);
        assert_eq!(answer.training, directory.entitled_training);
        assert!(!directory.revoked, "a revoked key signs in no more");
        // The token starts inside the life of the nonce and lasts 15 minutes.
        let issued = answer.expires_at - TOKEN_LIFE;
        assert!(issued <= challenge.expires_at && issued + NONCE_LIFE >= challenge.expires_at);
    }

    #[test]
    fn a_sign_in_request_carries_no_account_token() {
        for field in ["token", "account_token", "entitlement", "origin"] {
            let mut value: Value = parse("sign-in-request.json", SIGN_IN_REQUEST);
            value[field] = json!("synthetic");
            assert!(
                serde_json::from_value::<SignInRequest>(value).is_err(),
                "{field} is outside the sign-in request"
            );
            let mut value: Value = parse("sign-in-challenge-request.json", CHALLENGE_REQUEST);
            value[field] = json!("synthetic");
            assert!(
                serde_json::from_value::<ChallengeRequest>(value).is_err(),
                "{field} is outside the challenge request"
            );
        }
    }

    #[test]
    fn the_sign_in_message_has_its_own_tag() {
        let request: SignInRequest = parse("sign-in-request.json", SIGN_IN_REQUEST);
        let message = sign_in_message(
            SIGN_IN_TAG,
            ORIGIN,
            &request.account,
            &request.public_key,
            &request.nonce,
        );
        let expected = format!(
            "apassy-bouncer sign-in v1\0https://brain.connect.example.test\0acc_7k2m5q4x3c\0{}\0{}",
            request.public_key, request.nonce
        );
        assert_eq!(message, expected.into_bytes());
        assert_eq!(message.iter().filter(|&&b| b == 0).count(), 4);
        assert_ne!(message.last(), Some(&0), "no trailing zero byte");
        assert!(!message.contains(&b'\n'));

        for other in [RELAY_SIGN_IN_TAG, ACCOUNT_SIGN_IN_TAG] {
            let theirs = sign_in_message(
                other,
                ORIGIN,
                &request.account,
                &request.public_key,
                &request.nonce,
            );
            assert_ne!(message, theirs, "{other} gives the same bytes");
            // Same form, other tag: only the first part differs.
            assert_eq!(
                message[SIGN_IN_TAG.len()..],
                theirs[other.len()..],
                "{other} has another form"
            );
        }
        let elsewhere = sign_in_message(
            SIGN_IN_TAG,
            "https://brain.other.example.test",
            &request.account,
            &request.public_key,
            &request.nonce,
        );
        assert_ne!(message, elsewhere, "the origin is in the message");
        assert!(CONTRACT.contains(&format!("\"{SIGN_IN_TAG}\" 0x00 <origin> 0x00 <account>")));
        let reserved = format!("`{SIGN_IN_TAG}`");
        assert!(CONTRACT_V1.contains(&reserved), "v1 reserved the tag");
    }

    /// The relay keeps its own message form (`sign_in_message`, relay-sync-v1 section 5);
    /// the brain message is the same form with its own tag and the account id.
    #[cfg(feature = "vault")]
    #[test]
    fn a_brain_sign_in_signature_verifies_only_for_its_tag_and_origin() {
        use apassy::sync::{DeviceKey, decode_b64u, verify_signature};

        // The test vectors of relay-sync-v1 section 15.
        const PRIVATE: &str = "4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f";
        const RELAY_ORIGIN: &str = "https://relay.example.test";
        const RELAY_TEAM: &str = "t_7k2m5q4x3c";
        let unhex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
                .collect()
        };

        let request: SignInRequest = parse("sign-in-request.json", SIGN_IN_REQUEST);
        let public = decode_b64u(&request.public_key).expect("b64u public key");
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);
        let nonce = decode_b64u(&request.nonce).expect("b64u nonce");
        assert_eq!(nonce, (0u8..32).collect::<Vec<_>>());
        let key = DeviceKey::from_raw(&unhex(PRIVATE), &public).expect("the relay-sync-v1 key");
        assert_eq!(key.public_key_b64u(), request.public_key);

        let relay = apassy::sync::sign_in_message(
            ORIGIN,
            &request.account,
            &request.public_key,
            &request.nonce,
        );
        let brain = sign_in_message(
            SIGN_IN_TAG,
            ORIGIN,
            &request.account,
            &request.public_key,
            &request.nonce,
        );
        assert!(relay.starts_with(RELAY_SIGN_IN_TAG.as_bytes()));
        let (ours, theirs) = (
            &brain[SIGN_IN_TAG.len()..],
            &relay[RELAY_SIGN_IN_TAG.len()..],
        );
        assert_eq!(ours, theirs, "the same form");

        let signature = key.sign(&brain).expect("a signature");
        assert!(signature.len() <= MAX_SIGNATURE_BYTES);
        assert!(verify_signature(&public, &brain, &signature));
        assert!(!verify_signature(&public, &relay, &signature));
        let elsewhere = sign_in_message(
            SIGN_IN_TAG,
            RELAY_ORIGIN,
            &request.account,
            &request.public_key,
            &request.nonce,
        );
        assert!(!verify_signature(&public, &elsewhere, &signature));

        // The fixture's signature is the relay-sync-v1 vector: a relay sign-in. It
        // verifies as one, and never as a brain sign-in with the same parts.
        let fixture = decode_b64u(&request.signature).expect("b64u signature");
        let relay_vector = apassy::sync::sign_in_message(
            RELAY_ORIGIN,
            RELAY_TEAM,
            &request.public_key,
            &request.nonce,
        );
        assert!(verify_signature(&public, &relay_vector, &fixture));
        let brain_vector = sign_in_message(
            SIGN_IN_TAG,
            RELAY_ORIGIN,
            RELAY_TEAM,
            &request.public_key,
            &request.nonce,
        );
        assert!(!verify_signature(&public, &brain_vector, &fixture));
        assert!(!verify_signature(&public, &brain, &fixture));
    }

    #[test]
    fn the_internal_bodies_carry_no_request_data() {
        let directory: DirectoryRequest = parse("directory-request.json", DIRECTORY_REQUEST);
        assert!(is_key_id(&directory.key_id));
        assert!(is_sha256(&directory.public_key_sha256));
        let answer: DirectoryAnswer = parse("directory-answer.json", DIRECTORY_ANSWER);
        assert!(is_account(&answer.account));
        let revoke: RevokeRequest = parse("revoke-request.json", REVOKE_REQUEST);
        assert_eq!(revoke.key_id, directory.key_id);
        let forget: ForgetRequest = parse("forget-request.json", FORGET_REQUEST);
        assert_eq!(forget.account, answer.account);

        let mut value: Value = parse("directory-request.json", DIRECTORY_REQUEST);
        value["heads"] = json!("0".repeat(64));
        assert!(
            serde_json::from_value::<DirectoryRequest>(value).is_err(),
            "the brain sends Connect nothing but the key"
        );
    }

    #[test]
    fn every_v2_error_fixture_has_a_code_of_the_table_and_no_request_data() {
        for code in CODES {
            assert!(
                CONTRACT.contains(&format!("| `{code}` |")),
                "the code table has no row for {code}"
            );
            assert!(!super::CODES.contains(&code), "{code} is a v1 code");
        }
        for (name, text, code) in ERRORS {
            let body: ErrorBody = parse(name, text);
            assert_eq!(body.detail.code, code, "{name}");
            let message = &body.detail.message;
            assert!(!message.is_empty(), "{name}: no message");
            assert!(!has_sha256_run(message), "{name}: a hash");
            for needle in ["acc_", "key_", "apassy_brn_"] {
                assert!(!message.contains(needle), "{name}: {needle}");
            }
        }
        for error in JOB_ERRORS {
            let quoted = format!("`{error}`");
            assert!(CONTRACT.contains(&quoted), "{error} is not stated");
        }
    }

    #[test]
    fn the_contract_states_the_origin_24_hour_and_download_rules() {
        for rule in [
            "**For existing clients, v1 is unchanged.**",
            "**The client MUST compare it with its own brain origin, the build constant of I-5",
            "verifies the signature with its own `APASSY_BRAIN_ORIGIN`, never with a value",
            "at the latest at `examples_deadline` (24 hours after the upload)",
            "**The result is deleted after the download.**",
            "is never sent to the bouncer brain (I-2)",
        ] {
            assert!(CONTRACT.contains(rule), "not stated: {rule}");
        }
        assert!(CONTRACT_V1.contains("bouncer-brain-v2.md"), "v1 links v2");
    }

    #[test]
    fn no_v2_fixture_looks_like_a_secret_or_a_path() {
        for (name, text) in FIXTURES {
            assert!(!has_word_prefix(text, "sk_"), "{name} has `sk_`");
            for needle in ["BEGIN ", "password=", "/Users/", "/home/", "/tmp/", "/var/"] {
                assert!(!text.contains(needle), "{name} has {needle:?}");
            }
            let value: Value = parse(name, text);
            let mut texts = Vec::new();
            strings(&value, &mut texts);
            for text in texts {
                assert!(!text.starts_with('/'), "{name} has the path {text:?}");
            }
        }
    }
}
