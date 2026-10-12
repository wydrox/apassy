//! The sealed parts of contract relay-questions-v1 as the answering iPhone reads and
//! writes them: the AAD and the ChaCha20-Poly1305 seal (section 6), the question card
//! and its checks (section 7), the question digest v2 (section 8), the answer, its
//! string, and the settle (section 9). Pure functions only; the calls are in the parent
//! module.

use std::collections::BTreeSet;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{Context, SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use apassy::sync::decode_b64u;

/// The tag at the start of every AAD.
const AAD_TAG: &str = "apassy-question-v1";
/// The tag of the answer string.
const ANSWER_TAG: &str = "apassy-question-answer-v1";
/// The tag of the question digest v2.
const DIGEST_TAG: &str = "apassy-question-v2";

/// The largest plaintexts (section 6.3).
pub const MAX_CARD_BYTES: usize = 32_768;
pub const MAX_ANSWER_BYTES: usize = 8_192;
pub const MAX_SETTLE_BYTES: usize = 1_024;
const TAG_BYTES: usize = 16;

/// The count limits of a card (section 7.2).
const MAX_COMMAND: usize = 256;
const MAX_ENV_NAMES: usize = 64;
const MAX_ITEMS: usize = 64;
const MAX_VALID_ANSWERS: usize = 16;
const MAX_ASKER_NAME_BYTES: usize = 64;

// ---- Encodings (section 4). ----

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `key_id` of a question key: the first 8 bytes of its SHA-256, in hex.
pub fn key_id(key: &[u8]) -> String {
    hex(&digest(&SHA256, key).as_ref()[..8])
}

/// A `qid`: 22 characters of b64u that decode to 16 bytes.
pub fn valid_qid(qid: &str) -> bool {
    qid.len() == 22 && decode_b64u(qid).is_some_and(|bytes| bytes.len() == 16)
}

/// A `key_id`: 16 lowercase hex characters.
pub fn valid_key_id(key_id: &str) -> bool {
    key_id.len() == 16
        && key_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A digest: 64 lowercase hex characters.
fn valid_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A device UUID: 36 lowercase characters `8-4-4-4-12`.
pub fn valid_device_uuid(uuid: &str) -> bool {
    let bytes = uuid.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, b)| match at {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// A decimal string of the wire: digits only, no leading zero, a u64.
fn decimal(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

// ---- AAD and the seal (section 6). ----

fn aad(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, part) in parts.iter().enumerate() {
        if at > 0 {
            out.push(0);
        }
        out.extend_from_slice(part.as_bytes());
    }
    out
}

/// The AAD of a card.
pub fn card_aad(team: &str, qid: &str, key_id: &str, to: &str, expires_at: u64) -> Vec<u8> {
    aad(&[
        AAD_TAG,
        "card",
        team,
        qid,
        key_id,
        to,
        &expires_at.to_string(),
    ])
}

/// The AAD of an answer: the relay device id that the relay stamps on it.
pub fn answer_aad(team: &str, qid: &str, key_id: &str, device_id: u64) -> Vec<u8> {
    aad(&[AAD_TAG, "answer", team, qid, key_id, &device_id.to_string()])
}

/// The AAD of a settle.
pub fn settle_aad(team: &str, qid: &str, key_id: &str) -> Vec<u8> {
    aad(&[AAD_TAG, "settle", team, qid, key_id])
}

fn sealing_key(key: &[u8]) -> Option<LessSafeKey> {
    UnboundKey::new(&CHACHA20_POLY1305, key)
        .ok()
        .map(LessSafeKey::new)
}

/// Seal `plaintext`: the ciphertext followed by the 16-byte tag.
pub fn seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let key = sealing_key(key)?;
    let mut sealed = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        &mut sealed,
    )
    .ok()?;
    Some(sealed)
}

/// Open a sealed envelope. Every cause of a failure is the same `None` (section 6.2).
pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    if ciphertext.len() < TAG_BYTES {
        return None;
    }
    let key = sealing_key(key)?;
    let mut buffer = ciphertext.to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buffer,
        )
        .ok()?;
    Some(plain.to_vec())
}

// ---- The card (section 7). ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asker {
    pub device: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remember {
    pub pattern: String,
    pub approvals: u32,
    pub needed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: u64,
    pub agent: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub env_names: Vec<String>,
    pub purpose: String,
    pub risk: String,
    pub user_request: String,
    pub request_source: String,
    pub agent_request: String,
    pub remember: Option<Remember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub item_id: u64,
    pub name: String,
    pub production: bool,
    pub unconfirmed: bool,
    pub always_ask: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u64,
    pub item_ids: Vec<u64>,
    pub items: Vec<Item>,
    pub project: Option<Project>,
    pub action: String,
    pub production: bool,
    pub why: String,
    pub valid_answers: Vec<String>,
}

/// A card that passed the checks 2 to 4 of section 7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub qid: String,
    pub asker: Asker,
    pub created_at: u64,
    pub run: Run,
    pub question: Question,
    pub digest: String,
}

/// Why a card cannot be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardRefusal {
    /// An unknown or missing field, or another `v`: "Update Apassy to read this
    /// question".
    Update,
    /// Anything else: "This question could not be read".
    Unreadable,
}

type Fields<'a> = &'a Map<String, Value>;

/// The object `value` when it has exactly the fields `names`.
fn exact<'a>(value: &'a Value, names: &[&str]) -> Result<Fields<'a>, CardRefusal> {
    let map = value.as_object().ok_or(CardRefusal::Unreadable)?;
    if map.len() != names.len() || names.iter().any(|name| !map.contains_key(*name)) {
        return Err(CardRefusal::Update);
    }
    Ok(map)
}

fn text(map: Fields<'_>, name: &str) -> Result<String, CardRefusal> {
    map[name]
        .as_str()
        .map(str::to_owned)
        .ok_or(CardRefusal::Unreadable)
}

fn texts(map: Fields<'_>, name: &str, max: usize) -> Result<Vec<String>, CardRefusal> {
    let list = map[name].as_array().ok_or(CardRefusal::Unreadable)?;
    if list.len() > max {
        return Err(CardRefusal::Unreadable);
    }
    list.iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or(CardRefusal::Unreadable)
        })
        .collect()
}

fn flag(map: Fields<'_>, name: &str) -> Result<bool, CardRefusal> {
    map[name].as_bool().ok_or(CardRefusal::Unreadable)
}

fn number(map: Fields<'_>, name: &str) -> Result<u64, CardRefusal> {
    map[name].as_u64().ok_or(CardRefusal::Unreadable)
}

fn id(map: Fields<'_>, name: &str) -> Result<u64, CardRefusal> {
    map[name]
        .as_str()
        .and_then(decimal)
        .ok_or(CardRefusal::Unreadable)
}

/// The kinds of action of a card.
pub fn valid_action(action: &str) -> bool {
    matches!(action, "read" | "change" | "deploy" | "delete")
}

/// An answer text of `valid_answers` (section 7.1).
fn valid_answer_text(answer: &str) -> bool {
    match answer.split_once(':') {
        Some(("in_project" | "production", action)) => valid_action(action),
        Some(_) => false,
        None => matches!(
            answer,
            "once"
                | "never_for_agent"
                | "always_ask_for_agent"
                | "disconnect"
                | "correct_environment"
        ),
    }
}

/// Parse a card plaintext and check it: the fields, the limits, `v`, the `qid` of the
/// relay record, and the digest (section 7.3, checks 2 to 4).
pub fn parse_card(plaintext: &[u8], relay_qid: &str) -> Result<Card, CardRefusal> {
    if plaintext.len() > MAX_CARD_BYTES {
        return Err(CardRefusal::Unreadable);
    }
    let value: Value = serde_json::from_slice(plaintext).map_err(|_| CardRefusal::Unreadable)?;
    // The version first: a later card may have other fields.
    if value.get("v").is_some_and(|v| v.as_u64() != Some(1)) {
        return Err(CardRefusal::Update);
    }
    let card = exact(
        &value,
        &[
            "v",
            "qid",
            "asker",
            "created_at",
            "run",
            "question",
            "digest",
        ],
    )?;
    let asker = exact(&card["asker"], &["device", "name"])?;
    let run = exact(
        &card["run"],
        &[
            "id",
            "agent",
            "command",
            "cwd",
            "env_names",
            "purpose",
            "risk",
            "user_request",
            "request_source",
            "agent_request",
            "remember",
        ],
    )?;
    let question = exact(
        &card["question"],
        &[
            "id",
            "item_ids",
            "items",
            "project",
            "action",
            "production",
            "why",
            "valid_answers",
        ],
    )?;
    let remember = match &run["remember"] {
        Value::Null => None,
        value => {
            let offer = exact(value, &["pattern", "approvals", "needed"])?;
            let count = |name| {
                number(offer, name)
                    .and_then(|n| u32::try_from(n).map_err(|_| CardRefusal::Unreadable))
            };
            Some(Remember {
                pattern: text(offer, "pattern")?,
                approvals: count("approvals")?,
                needed: count("needed")?,
            })
        }
    };
    let project = match &question["project"] {
        Value::Null => None,
        value => {
            let project = exact(value, &["key", "label"])?;
            Some(Project {
                key: text(project, "key")?,
                label: text(project, "label")?,
            })
        }
    };
    let item_ids = question["item_ids"]
        .as_array()
        .filter(|ids| ids.len() <= MAX_ITEMS)
        .ok_or(CardRefusal::Unreadable)?
        .iter()
        .map(|id| id.as_str().and_then(decimal).ok_or(CardRefusal::Unreadable))
        .collect::<Result<Vec<u64>, _>>()?;
    let items = question["items"]
        .as_array()
        .ok_or(CardRefusal::Unreadable)?
        .iter()
        .map(|item| {
            let item = exact(
                item,
                &["item_id", "name", "production", "unconfirmed", "always_ask"],
            )?;
            Ok(Item {
                item_id: id(item, "item_id")?,
                name: text(item, "name")?,
                production: flag(item, "production")?,
                unconfirmed: flag(item, "unconfirmed")?,
                always_ask: flag(item, "always_ask")?,
            })
        })
        .collect::<Result<Vec<Item>, CardRefusal>>()?;
    let valid_answers = texts(question, "valid_answers", MAX_VALID_ANSWERS)?;
    let parsed = Card {
        qid: text(card, "qid")?,
        asker: Asker {
            device: text(asker, "device")?,
            name: text(asker, "name")?,
        },
        created_at: number(card, "created_at")?,
        run: Run {
            id: id(run, "id")?,
            agent: text(run, "agent")?,
            command: texts(run, "command", MAX_COMMAND)?,
            cwd: text(run, "cwd")?,
            env_names: texts(run, "env_names", MAX_ENV_NAMES)?,
            purpose: text(run, "purpose")?,
            risk: text(run, "risk")?,
            user_request: text(run, "user_request")?,
            request_source: text(run, "request_source")?,
            agent_request: text(run, "agent_request")?,
            remember,
        },
        question: Question {
            id: id(question, "id")?,
            item_ids,
            items,
            project,
            action: text(question, "action")?,
            production: flag(question, "production")?,
            why: text(question, "why")?,
            valid_answers,
        },
        digest: text(card, "digest")?,
    };
    let unique: BTreeSet<&String> = parsed.question.valid_answers.iter().collect();
    let checks = parsed.qid == relay_qid
        && valid_qid(&parsed.qid)
        && valid_device_uuid(&parsed.asker.device)
        && !parsed.asker.name.is_empty()
        && parsed.asker.name.len() <= MAX_ASKER_NAME_BYTES
        && parsed.question.id == parsed.run.id
        && parsed.question.items.len() == parsed.question.item_ids.len()
        && parsed
            .question
            .items
            .iter()
            .zip(&parsed.question.item_ids)
            .all(|(item, id)| item.item_id == *id)
        && valid_action(&parsed.question.action)
        && unique.len() == parsed.question.valid_answers.len()
        && valid_digest(&parsed.digest);
    if !checks {
        return Err(CardRefusal::Unreadable);
    }
    if parsed
        .question
        .valid_answers
        .iter()
        .any(|answer| !valid_answer_text(answer))
    {
        return Err(CardRefusal::Update);
    }
    if question_digest_v2(&parsed.run, &parsed.question) != parsed.digest {
        return Err(CardRefusal::Unreadable);
    }
    Ok(parsed)
}

// ---- The question digest v2 (section 8). ----

fn put_len(hash: &mut Context, len: usize) {
    hash.update(&(len as u64).to_be_bytes());
}

fn put_text(hash: &mut Context, value: &str) {
    put_len(hash, value.len());
    hash.update(value.as_bytes());
}

fn put_list(hash: &mut Context, values: &[String]) {
    put_len(hash, values.len());
    for value in values {
        put_text(hash, value);
    }
}

fn put_flag(hash: &mut Context, value: bool) {
    hash.update(&[u8::from(value)]);
}

/// The question digest v2 of a run and its question, as 64 lowercase hex characters.
pub fn question_digest_v2(run: &Run, question: &Question) -> String {
    let mut hash = Context::new(&SHA256);
    put_text(&mut hash, DIGEST_TAG);
    hash.update(&run.id.to_be_bytes());
    put_text(&mut hash, &run.agent);
    put_list(&mut hash, &run.command);
    put_text(&mut hash, &run.cwd);
    put_list(&mut hash, &run.env_names);
    put_text(&mut hash, &run.purpose);
    put_text(&mut hash, &run.risk);
    put_text(&mut hash, &run.user_request);
    put_text(&mut hash, &run.request_source);
    put_text(&mut hash, &run.agent_request);
    match &run.remember {
        None => hash.update(&[0]),
        Some(offer) => {
            hash.update(&[1]);
            put_text(&mut hash, &offer.pattern);
            hash.update(&offer.approvals.to_be_bytes());
            hash.update(&offer.needed.to_be_bytes());
        }
    }
    hash.update(&question.id.to_be_bytes());
    put_len(&mut hash, question.item_ids.len());
    for id in &question.item_ids {
        hash.update(&id.to_be_bytes());
    }
    match &question.project {
        None => hash.update(&[0]),
        Some(project) => {
            hash.update(&[1]);
            put_text(&mut hash, &project.key);
            put_text(&mut hash, &project.label);
        }
    }
    put_text(&mut hash, &question.action);
    put_flag(&mut hash, question.production);
    put_text(&mut hash, &question.why);
    put_len(&mut hash, question.items.len());
    for item in &question.items {
        hash.update(&item.item_id.to_be_bytes());
        put_text(&mut hash, &item.name);
        put_flag(&mut hash, item.production);
        put_flag(&mut hash, item.unconfirmed);
        put_flag(&mut hash, item.always_ask);
    }
    put_list(&mut hash, &question.valid_answers);
    hex(hash.finish().as_ref())
}

// ---- The answer (section 9). ----

/// An answer of section 9.1, with its extra fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    ApproveOnce,
    ApproveInProject { action: String, project_key: String },
    AllowProduction { action: String, project_key: String },
    CorrectEnvironment { item_id: u64, environment: String },
    Deny,
    NeverForAgent,
    AlwaysAskForAgent,
    Disconnect,
}

impl Choice {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ApproveOnce => "approve_once",
            Self::ApproveInProject { .. } => "approve_in_project",
            Self::AllowProduction { .. } => "allow_production",
            Self::CorrectEnvironment { .. } => "correct_environment",
            Self::Deny => "deny",
            Self::NeverForAgent => "never_for_agent",
            Self::AlwaysAskForAgent => "always_ask_for_agent",
            Self::Disconnect => "disconnect",
        }
    }

    /// Whether the iPhone signs this answer with its answer key after Face ID (section
    /// 5.3): the answers that give authority. The others take it away and are signed with
    /// the relay key of the device.
    pub fn needs_face_id(&self) -> bool {
        match self {
            Self::ApproveOnce | Self::ApproveInProject { .. } | Self::AllowProduction { .. } => {
                true
            }
            Self::CorrectEnvironment { environment, .. } => environment == "development",
            Self::Deny | Self::NeverForAgent | Self::AlwaysAskForAgent | Self::Disconnect => false,
        }
    }

    /// The `<choice>` line of the answer string. `None` when a field holds a control
    /// character (section 9.3).
    pub fn line(&self) -> Option<String> {
        let line = match self {
            Self::ApproveInProject {
                action,
                project_key,
            } => format!("approve_in_project:{action}:{project_key}"),
            Self::AllowProduction {
                action,
                project_key,
            } => format!("allow_production:{action}:{project_key}"),
            Self::CorrectEnvironment {
                item_id,
                environment,
            } => format!("correct_environment:{environment}:{item_id}"),
            other => other.kind().to_owned(),
        };
        (!line.chars().any(char::is_control)).then_some(line)
    }

    /// The answer of the request fields, checked against the card (section 9.1). The
    /// text of the refusal is for the owner.
    pub fn for_card(
        kind: &str,
        action: Option<&str>,
        project_key: Option<&str>,
        item_id: Option<&str>,
        environment: Option<&str>,
        card: &Card,
    ) -> Result<Self, &'static str> {
        let question = &card.question;
        let offered = |text: &str| question.valid_answers.iter().any(|answer| answer == text);
        let project = |offer: &str| -> Result<(String, String), &'static str> {
            let project = question
                .project
                .as_ref()
                .ok_or("This question has no project.")?;
            if action.is_some_and(|action| action != question.action)
                || project_key.is_some_and(|key| key != project.key)
            {
                return Err("The answer does not match the question.");
            }
            if !offered(&format!("{offer}:{}", question.action)) {
                return Err("This question does not offer this answer.");
            }
            Ok((question.action.clone(), project.key.clone()))
        };
        let plain = |text: &str, choice: Self| {
            if offered(text) {
                Ok(choice)
            } else {
                Err("This question does not offer this answer.")
            }
        };
        let choice = match kind {
            "approve_once" => plain("once", Self::ApproveOnce)?,
            "approve_in_project" => {
                let (action, project_key) = project("in_project")?;
                Self::ApproveInProject {
                    action,
                    project_key,
                }
            }
            "allow_production" => {
                let (action, project_key) = project("production")?;
                Self::AllowProduction {
                    action,
                    project_key,
                }
            }
            "correct_environment" => {
                if !offered("correct_environment") {
                    return Err("This question does not offer this answer.");
                }
                let item_id = item_id
                    .and_then(decimal)
                    .ok_or("Name the item to correct.")?;
                if !question
                    .items
                    .iter()
                    .any(|item| item.item_id == item_id && item.unconfirmed)
                {
                    return Err("This item cannot be corrected here.");
                }
                let environment = match environment {
                    Some(env @ ("development" | "production")) => env.to_owned(),
                    _ => return Err("Choose Development or Production."),
                };
                Self::CorrectEnvironment {
                    item_id,
                    environment,
                }
            }
            // Deny is always valid.
            "deny" => Self::Deny,
            "never_for_agent" => plain("never_for_agent", Self::NeverForAgent)?,
            "always_ask_for_agent" => plain("always_ask_for_agent", Self::AlwaysAskForAgent)?,
            "disconnect" => plain("disconnect", Self::Disconnect)?,
            _ => return Err("This answer is not known."),
        };
        if !matches!(
            choice,
            Self::ApproveInProject { .. }
                | Self::AllowProduction { .. }
                | Self::CorrectEnvironment { .. }
        ) && (action.is_some()
            || project_key.is_some()
            || item_id.is_some()
            || environment.is_some())
        {
            return Err("This answer takes no other fields.");
        }
        Ok(choice)
    }
}

/// The answer string (section 9.3). `None` when the choice cannot be signed.
pub fn answer_string(
    by: &str,
    team: &str,
    qid: &str,
    choice: &Choice,
    digest: &str,
    time: u64,
) -> Option<String> {
    let line = choice.line()?;
    Some(format!(
        "{ANSWER_TAG}\n{by}\n{team}\n{qid}\n{line}\n{digest}\n{time}"
    ))
}

#[derive(Serialize)]
struct AnswerWire<'a> {
    v: u8,
    qid: &'a str,
    by: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    digest: &'a str,
    time: u64,
    signature: &'a str,
}

/// The answer plaintext (section 9.2): the fields of its kind in the order of the
/// contract. `signature` is b64u DER.
pub fn answer_plaintext(
    qid: &str,
    by: &str,
    choice: &Choice,
    digest: &str,
    time: u64,
    signature: &str,
) -> Vec<u8> {
    let (action, project_key, item_id, environment) = match choice {
        Choice::ApproveInProject {
            action,
            project_key,
        }
        | Choice::AllowProduction {
            action,
            project_key,
        } => (
            Some(action.as_str()),
            Some(project_key.as_str()),
            None,
            None,
        ),
        Choice::CorrectEnvironment {
            item_id,
            environment,
        } => (
            None,
            None,
            Some(item_id.to_string()),
            Some(environment.as_str()),
        ),
        _ => (None, None, None, None),
    };
    serde_json::to_vec(&AnswerWire {
        v: 1,
        qid,
        by,
        kind: choice.kind(),
        action,
        project_key,
        item_id,
        environment,
        digest,
        time,
        signature,
    })
    .unwrap_or_default()
}

// ---- The settle (section 9.4). ----

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settle {
    pub v: u8,
    pub qid: String,
    pub outcome: String,
    pub answered_by: Option<String>,
    pub device_name: Option<String>,
    pub device_kind: Option<String>,
    pub kind: Option<String>,
    pub at: u64,
    #[serde(default)]
    pub replaced_by: Option<String>,
}

/// Parse a settle plaintext of the question `qid`.
pub fn parse_settle(plaintext: &[u8], qid: &str) -> Option<Settle> {
    if plaintext.len() > MAX_SETTLE_BYTES {
        return None;
    }
    let settle: Settle = serde_json::from_slice(plaintext).ok()?;
    let known = matches!(
        settle.outcome.as_str(),
        "approved" | "denied" | "timed_out" | "invalidated" | "replaced"
    );
    (settle.v == 1 && settle.qid == qid && known).then_some(settle)
}

// ---- Display (section 7.3). ----

/// `text` with control and format characters replaced by `?`, shortened in the middle
/// to `max` characters: the rules of `shown_path` of the Mac app.
pub fn shown(text: &str, max: usize) -> String {
    let clean: Vec<char> = text
        .chars()
        .map(|c| {
            // Unicode 17, category Cf, as `shown_path` (src/broker/approvals.rs).
            let hidden = c.is_control()
                || matches!(
                    c,
                    '\u{00AD}'
                        | '\u{0600}'..='\u{0605}'
                        | '\u{061C}'
                        | '\u{06DD}'
                        | '\u{070F}'
                        | '\u{0890}'..='\u{0891}'
                        | '\u{08E2}'
                        | '\u{180E}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'..='\u{206F}'
                        | '\u{FEFF}'
                        | '\u{FFF9}'..='\u{FFFB}'
                        | '\u{110BD}'
                        | '\u{110CD}'
                        | '\u{13430}'..='\u{1343F}'
                        | '\u{1BCA0}'..='\u{1BCA3}'
                        | '\u{1D173}'..='\u{1D17A}'
                        | '\u{E0001}'
                        | '\u{E0020}'..='\u{E007F}'
                );
            if hidden { '?' } else { c }
        })
        .collect();
    if clean.len() <= max {
        return clean.into_iter().collect();
    }
    let keep = max.saturating_sub(1);
    let (head, tail) = (keep / 2, keep - keep / 2);
    let mut out: String = clean[..head].iter().collect();
    out.push('…');
    out.extend(&clean[clean.len() - tail..]);
    out
}

#[cfg(test)]
mod tests {
    //! The test vectors of contract relay-questions-v1, section 20.

    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const TEAM: &str = "t_7k2m5q4x3c";
    const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
    const ANSWERING: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
    const DIGEST: &str = "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d";
    pub(crate) const CARD: &str = r#"{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","asker":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"created_at":1790000000,"run":{"id":"123456789012345","agent":"claude-code","command":["npm","run","migrate"],"cwd":"/tmp/synthetic-shop","env_names":["DATABASE_URL","API_TOKEN"],"purpose":"Apply the new migration.","risk":"production credential: always asks the owner","user_request":"Deploy the new schema to staging.","request_source":"from the host hook","agent_request":"Run the migration.","remember":null},"question":{"id":"123456789012345","item_ids":["7","9"],"items":[{"item_id":"7","name":"Shop database","production":true,"unconfirmed":false,"always_ask":false},{"item_id":"9","name":"API token","production":false,"unconfirmed":true,"always_ask":false}],"project":{"key":"/tmp/synthetic-shop/.git","label":"synthetic-shop"},"action":"deploy","production":true,"why":"A production credential goes to a deploy.","valid_answers":["once","production:deploy","correct_environment","never_for_agent","always_ask_for_agent","disconnect"]},"digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"}"#;
    const CARD_CIPHERTEXT: &str = "f2d97e2213268962c6ea5bd1a23f61288e19ddd10218ddc883f85ea404b2d477def55e84c43293f9445913aa47aef4011ae1df1d9e4d9aa13088bb30f57afde5185585a9d47201dda5242f91201fea95f7ea2202095b910c6c64933abc5f2e9d23bf0196d5e305b9d038b1d8cdfa97d09b007445a57f238a2a0c40ba1d60de32835cf28a9003ef5c79234f4a001e194fda53bd092906a87c08c39603972f950f0881b8d88c76a7d2bb5c4a3206d68a6eaa769c6874371b60bc7ac3f20852f132f5653ce00e906e71496a1f55ef281d6040f4e74e13618d7b344445c2897b08984e1e2692edc761c2e0d82732c668bbff8931df900e0fc3fd93f303b495df2d00e6ff74d60725dbf1e8f8a51c48b59fbab440e585539629fb5744514e5432f0097360125db91fad7922072ba7e46729661b4d8997ddb612f737c872a6020d0bde2233e7626b3de5f7808253ac3be6e0d31dc7aa6282180fbb043a20f46eb42b180b1a695f1c13360fb03ddfbb58c46063d173951a4982f4a0913f3339535b78f7854537a69637511d5e2c226e30d37f159a0ec897fc28d4a6ea749989f37b590cf7f6a30caf27de4e2802d14b1db0dc0de3db79e82ccd1e76f2572f82af25e365317e42bffd3e97a056e727352a699d6350e12f9ceb2b7ddb169decdad203236ff12350de3bab743232a4dd3f5685f47cc72981327ed03cc4323d575371249f8418739fe2eee8a3fc7ceda1da72d0a62d8a741b920ad04be913f15fae7d572703194d4cba17f66443a28362038e58c0dff69e4307fbb11072f42b14735d691cf1ff6c91e24f9f65d451fabe07796ea5299e93c7586b6e3280d03d436c14146585f0b9e3218f4a52c29ed0798582b55c22aa91d40bd1ec73bfc38c2bd3407fd7c8ccc8e0e4575223d1eccdb3c4f760df7b7122667449f39c38c89422c0dc468bf2a0665307af7d388d734d4656b83983446820fedce1131846d821fe09ca81baaa8a80aae9c92d925bf07de3974e62c60d4ad08adc9b7d4a1f700915d1ea0b967ea64c84bc4780add5347e5153825db90afa9c02f3cbaaa126dbc3fb97c2ba8ed92c4cc0d241e23d6fc59b78b4d59e36d0882f110acdbdb75e026c9df55fc80577c8726e7e012d391ede22c42ce32ba5878926adf56d7cab49b150a201d9fa07f545dd5152181821c7e17100ff04cb5f46b3d3e7a7b675e9c4c6d63198562b627b8392a4ec03ca59e2f19396cd8817eb18109903c1fb0afd39b6c4462405490fcf931f1053ecf73483e7b28c3ac615f63f4fab000a6259259a98d219dde6c4e8715c1e14eebd130f6e1f22ee269ef7f6c1acac47d244597baeb538b9e97c83438bb4f1eca9a36ebef614c3b6cd86f4b4868b9a6c81d78d3dce172a591b5bba86b4245b79040a3cb37079e995f5e8b83b1113c1bca6576f113d645d1136accc2bff64bada12aad3eb950834f63caa3fff01c55952edd9ac6f374f86eded6cc93825c114418705f39324695c99b3d7e9914484015fd789ccc85359d662fdddf55cc373592d345335c277af91b1f2bb758f652496ca22d87b75118bb17eafb0885e9759633a2cb69ccaa58a3890a212cabd334cb8a64023ed808b856f3e612507ce64a66b";
    const CARD_AAD_HEX: &str = "6170617373792d7175657374696f6e2d7631006361726400745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636006d656d6265720031373930303030333030";
    const ANSWER_STRING: &str = "apassy-question-answer-v1\n6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b\nt_7k2m5q4x3c\noKGio6SlpqeoqaqrrK2urw\nallow_production:deploy:/tmp/synthetic-shop/.git\nf3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d\n1790000030";
    const SIGNATURE: &str = "MEQCIGMC9y1cqvAp-20KSFEKld0OxGzAAChwzuk1koc-mdXRAiAU9SNPzZkCVoP16J25cR9fHwzNI7JcENt9p-SIAsvETA";
    const ANSWER_PUBLIC: &str =
        "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
    const ANSWER_PLAINTEXT: &str = r#"{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","kind":"allow_production","action":"deploy","project_key":"/tmp/synthetic-shop/.git","digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d","time":1790000030,"signature":"MEQCIGMC9y1cqvAp-20KSFEKld0OxGzAAChwzuk1koc-mdXRAiAU9SNPzZkCVoP16J25cR9fHwzNI7JcENt9p-SIAsvETA"}"#;
    const ANSWER_AAD_HEX: &str = "6170617373792d7175657374696f6e2d763100616e7377657200745f376b326d357134783363006f4b47696f36536c7071656f71617172724b3275727700363330646364323936366334333336360033";
    const ANSWER_CIPHERTEXT: &str = "25e833253c28ea4b6aaf5741e389da3e3d0f9a1fd7aea605e7fcc66c9dced1adcefff20efba899be0cb7c1ceb3cb32bf206d626c9953465defbab3b89e8d1ff8327cf7ec21c7ec2787484140c0b291f117db2557de3967a5f61be0d5bcf26128d2d20e2eda7de6910266abba48c80fb399588f148fb234ca61707674c2ca04549304e6b80a7a418b40b0a3e798143e954cf74dafda3441b8e0a99ded218ce4f533dcfdffac93b4114b8dd6b5a4bffeb094da742ad1e5e6a8821c796b3c594c23683028ef1c55d1b464cce313780013a5fecc377db92cc3bfcd5469686e75b04a01e226f674b06b3e519ad72f975b5aee88e3e4a8c5e8d3edca1a4b57c3d1627e17b8a7630579bf1b458e7660749530e2b713d036f4b7b363d0935a5b115481975d54a9351cda0cba86e3d202a94a984f4dd2bedf7d690c38ed4a3c058e95c8456e92c408d061d0062ede9e7299e4a0e157b9fc13d09fd25e76bfa0b456b99d17885a8f5d6583b02cbe06327ca1eb93ab08de920c3f69fd1aa8d635952bfa3b561c30";
    const SETTLE_PLAINTEXT: &str = r#"{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","outcome":"approved","answered_by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","device_name":"Test iPhone","device_kind":"iphone","kind":"allow_production","at":1790000031}"#;
    const SETTLE_AAD_HEX: &str = "6170617373792d7175657374696f6e2d763100736574746c6500745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636";
    const SETTLE_CIPHERTEXT: &str = "08c5fe5e2bded018eaacc9ea731de0f33c0711044305ef3ce38e4cc5cdc9a95931c2f021ee37f50891bb8e780d94417ae76d1515fc3c76f7ca24e0c3472df717faea79cbe8b60ad589fe1467835b1e42cf7dad045cca0dc97bf303a57429ee4bc00a4175fd49e86be86a99b517e0fba583d6af00b7fc7d6a983f524c793c91a2f1a27695d2a61fb5a3dfb82ba1b0cc87f5cb65f8b240c5048e9db9946699d9cf33b2e300c919917c85e02c39b7da8a4cbd1d46065030eb6a8df582bea0f277bfec618de93fe7d74fd233a2f8646fb5f066a9390178f5251b3cc003cfec";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn nonce(first: u8) -> [u8; 12] {
        std::array::from_fn(|at| first + at as u8)
    }

    fn key() -> Vec<u8> {
        unhex(KEY)
    }

    fn sha(bytes: &[u8]) -> String {
        hex(digest(&SHA256, bytes).as_ref())
    }

    fn base_run(remember: Option<Remember>) -> Run {
        Run {
            id: 123_456_789_012_345,
            agent: "claude-code".to_owned(),
            command: vec!["npm".into(), "run".into(), "migrate".into()],
            cwd: "/tmp/synthetic-shop".to_owned(),
            env_names: vec!["DATABASE_URL".into(), "API_TOKEN".into()],
            purpose: "Apply the new migration.".to_owned(),
            risk: "production credential: always asks the owner".to_owned(),
            user_request: "Deploy the new schema to staging.".to_owned(),
            request_source: "from the host hook".to_owned(),
            agent_request: "Run the migration.".to_owned(),
            remember,
        }
    }

    fn vector_question() -> Question {
        Question {
            id: 123_456_789_012_345,
            item_ids: vec![7, 9],
            items: vec![
                Item {
                    item_id: 7,
                    name: "Shop database".into(),
                    production: true,
                    unconfirmed: false,
                    always_ask: false,
                },
                Item {
                    item_id: 9,
                    name: "API token".into(),
                    production: false,
                    unconfirmed: true,
                    always_ask: false,
                },
            ],
            project: Some(Project {
                key: "/tmp/synthetic-shop/.git".into(),
                label: "synthetic-shop".into(),
            }),
            action: "deploy".into(),
            production: true,
            why: "A production credential goes to a deploy.".into(),
            valid_answers: [
                "once",
                "production:deploy",
                "correct_environment",
                "never_for_agent",
                "always_ask_for_agent",
                "disconnect",
            ]
            .map(str::to_owned)
            .to_vec(),
        }
    }

    #[test]
    fn the_key_gives_its_key_id() {
        assert_eq!(key_id(&key()), "630dcd2966c43366");
        assert!(valid_key_id("630dcd2966c43366"));
        assert!(valid_qid(QID));
        assert!(!valid_qid("oKGio6SlpqeoqaqrrK2ur"));
    }

    #[test]
    fn the_digests_match_the_vectors() {
        assert_eq!(
            question_digest_v2(&base_run(None), &vector_question()),
            DIGEST
        );
        let default_question = Question {
            id: 0,
            item_ids: vec![],
            items: vec![],
            project: None,
            action: "change".into(),
            production: false,
            why: String::new(),
            valid_answers: vec!["once".into()],
        };
        let offer = Remember {
            pattern: "npm run migrate".into(),
            approvals: 1,
            needed: 3,
        };
        assert_eq!(
            question_digest_v2(&base_run(Some(offer)), &default_question),
            "0807a3e555dbde9f82b73ab8a6660911c1a28149eb1fe6382460166a798bf274"
        );
    }

    #[test]
    fn every_field_of_the_question_changes_the_digest() {
        let run = base_run(None);
        let base = vector_question();
        let original = question_digest_v2(&run, &base);
        let mut variants: Vec<Question> = Vec::new();
        let mut push = |change: fn(&mut Question)| {
            let mut question = vector_question();
            change(&mut question);
            variants.push(question);
        };
        push(|q| q.id = 1);
        push(|q| q.item_ids = vec![7]);
        push(|q| q.items[0].name = "Shop db".into());
        push(|q| q.items[0].production = false);
        push(|q| q.items[1].unconfirmed = false);
        push(|q| q.items[1].always_ask = true);
        push(|q| q.items[0].item_id = 8);
        push(|q| q.project = None);
        push(|q| q.project.as_mut().unwrap().key = "/tmp/other/.git".into());
        push(|q| q.project.as_mut().unwrap().label = "other".into());
        push(|q| q.action = "read".into());
        push(|q| q.production = false);
        push(|q| q.why = String::new());
        push(|q| q.valid_answers.pop().map(drop).unwrap_or(()));
        // Text that moves between `why` and an item name, or between two items.
        push(|q| {
            q.why = "A production credential goes to a deploy.Shop".into();
            q.items[0].name = " database".into();
        });
        push(|q| {
            q.items[0].name = "Shop databaseAPI".into();
            q.items[1].name = " token".into();
        });
        for variant in variants {
            assert_ne!(question_digest_v2(&run, &variant), original, "{variant:?}");
        }
    }

    #[test]
    fn the_card_seals_and_opens_with_the_vectors() {
        assert_eq!(CARD.len(), 1138);
        assert_eq!(
            sha(CARD.as_bytes()),
            "6b25b67d3570fe460fd30999abdd692269f46fd092f015846baafc2ba57c03dc"
        );
        let card_aad_bytes = card_aad(TEAM, QID, "630dcd2966c43366", "member", 1_790_000_300);
        assert_eq!(hex(&card_aad_bytes), CARD_AAD_HEX);
        let sealed = seal(&key(), &nonce(0), &card_aad_bytes, CARD.as_bytes()).unwrap();
        assert_eq!(hex(&sealed), CARD_CIPHERTEXT);
        assert_eq!(
            sha(&sealed),
            "23bff23dc75b1d95e9e20a69e3b2fd622377422a0f781c749f0abec68c843d4f"
        );
        let opened = open(&key(), &nonce(0), &card_aad_bytes, &unhex(CARD_CIPHERTEXT)).unwrap();
        assert_eq!(opened, CARD.as_bytes());
        let card = parse_card(&opened, QID).unwrap();
        assert_eq!(card.digest, DIGEST);
        assert_eq!(card.run, base_run(None));
        assert_eq!(card.question, vector_question());
        // The card binds every field of its AAD.
        let wrong = [
            card_aad(TEAM, QID, "630dcd2966c43366", "approvers", 1_790_000_300),
            card_aad(TEAM, QID, "630dcd2966c43366", "member", 1_790_000_301),
            card_aad(
                TEAM,
                "oKGio6SlpqeoqaqrrK2urA",
                "630dcd2966c43366",
                "member",
                1_790_000_300,
            ),
            card_aad(
                "t_0000000000",
                QID,
                "630dcd2966c43366",
                "member",
                1_790_000_300,
            ),
            card_aad(TEAM, QID, "630dcd2966c43367", "member", 1_790_000_300),
            aad(&[
                AAD_TAG,
                "answer",
                TEAM,
                QID,
                "630dcd2966c43366",
                "member",
                "1790000300",
            ]),
        ];
        for wrong_aad in wrong {
            assert!(open(&key(), &nonce(0), &wrong_aad, &unhex(CARD_CIPHERTEXT)).is_none());
        }
    }

    #[test]
    fn the_answer_string_signature_and_envelope_match_the_vectors() {
        let card = parse_card(CARD.as_bytes(), QID).unwrap();
        let choice = Choice::for_card("allow_production", None, None, None, None, &card).unwrap();
        assert!(choice.needs_face_id());
        let text = answer_string(ANSWERING, TEAM, QID, &choice, DIGEST, 1_790_000_030).unwrap();
        assert_eq!(text, ANSWER_STRING);
        assert_eq!(
            sha(text.as_bytes()),
            "92988898270a1b99cbe4550c67ba69f8a5d3c872bc9f9b41341cb19d2eaab270"
        );
        let public = decode_b64u(ANSWER_PUBLIC).unwrap();
        let signature = decode_b64u(SIGNATURE).unwrap();
        assert!(apassy::sync::verify_signature(
            &public,
            text.as_bytes(),
            &signature
        ));
        let changed = text.replace("deploy", "deplox");
        assert!(!apassy::sync::verify_signature(
            &public,
            changed.as_bytes(),
            &signature
        ));
        let plaintext = answer_plaintext(QID, ANSWERING, &choice, DIGEST, 1_790_000_030, SIGNATURE);
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), ANSWER_PLAINTEXT);
        assert_eq!(plaintext.len(), 370);
        let aad = answer_aad(TEAM, QID, "630dcd2966c43366", 3);
        assert_eq!(hex(&aad), ANSWER_AAD_HEX);
        let sealed = seal(&key(), &nonce(0x10), &aad, &plaintext).unwrap();
        assert_eq!(hex(&sealed), ANSWER_CIPHERTEXT);
        // The answer does not open with another device id.
        let moved = answer_aad(TEAM, QID, "630dcd2966c43366", 2);
        assert!(open(&key(), &nonce(0x10), &moved, &sealed).is_none());
    }

    #[test]
    fn the_settle_opens_with_the_vectors_and_not_as_a_card() {
        let aad = settle_aad(TEAM, QID, "630dcd2966c43366");
        assert_eq!(hex(&aad), SETTLE_AAD_HEX);
        let sealed = seal(&key(), &nonce(0x20), &aad, SETTLE_PLAINTEXT.as_bytes()).unwrap();
        assert_eq!(hex(&sealed), SETTLE_CIPHERTEXT);
        let opened = open(&key(), &nonce(0x20), &aad, &sealed).unwrap();
        let settle = parse_settle(&opened, QID).unwrap();
        assert_eq!(settle.outcome, "approved");
        assert_eq!(settle.device_name.as_deref(), Some("Test iPhone"));
        let as_card = card_aad(TEAM, QID, "630dcd2966c43366", "member", 1_790_000_300);
        assert!(open(&key(), &nonce(0x20), &as_card, &sealed).is_none());
        assert!(parse_settle(&opened, "oKGio6SlpqeoqaqrrK2urA").is_none());
    }

    #[test]
    fn a_card_with_a_wrong_digest_or_shape_is_refused() {
        let wrong_digest = CARD.replace(DIGEST, &"0".repeat(64));
        assert_eq!(
            parse_card(wrong_digest.as_bytes(), QID),
            Err(CardRefusal::Unreadable)
        );
        // A changed field with the old digest.
        let changed = CARD.replace("npm\",\"run\",\"migrate", "npm\",\"run\",\"drop");
        assert_eq!(
            parse_card(changed.as_bytes(), QID),
            Err(CardRefusal::Unreadable)
        );
        assert_eq!(
            parse_card(CARD.as_bytes(), "oKGio6SlpqeoqaqrrK2urA"),
            Err(CardRefusal::Unreadable)
        );
        let extra = CARD.replacen("{\"v\":1,", "{\"v\":1,\"extra\":true,", 1);
        assert_eq!(parse_card(extra.as_bytes(), QID), Err(CardRefusal::Update));
        let missing = CARD.replace(",\"remember\":null", "");
        assert_eq!(
            parse_card(missing.as_bytes(), QID),
            Err(CardRefusal::Update)
        );
        let later = CARD.replacen("{\"v\":1,", "{\"v\":2,", 1);
        assert_eq!(parse_card(later.as_bytes(), QID), Err(CardRefusal::Update));
        let unknown_answer = CARD.replace("\"disconnect\"]", "\"forget\"]");
        assert!(parse_card(unknown_answer.as_bytes(), QID).is_err());
    }

    #[test]
    fn answers_are_checked_against_the_card() {
        let card = parse_card(CARD.as_bytes(), QID).unwrap();
        let choice =
            |kind, action, key, item, env| Choice::for_card(kind, action, key, item, env, &card);
        // Not offered: the question has no `in_project:deploy`.
        assert!(choice("approve_in_project", None, None, None, None).is_err());
        assert!(choice("allow_production", Some("read"), None, None, None).is_err());
        assert!(
            choice(
                "allow_production",
                None,
                Some("/tmp/other/.git"),
                None,
                None
            )
            .is_err()
        );
        assert_eq!(choice("deny", None, None, None, None), Ok(Choice::Deny));
        assert!(choice("deny", Some("deploy"), None, None, None).is_err());
        assert_eq!(
            choice("approve_once", None, None, None, None),
            Ok(Choice::ApproveOnce)
        );
        // Item 7 is confirmed production; item 9 is unconfirmed.
        assert!(
            choice(
                "correct_environment",
                None,
                None,
                Some("7"),
                Some("development")
            )
            .is_err()
        );
        let development = choice(
            "correct_environment",
            None,
            None,
            Some("9"),
            Some("development"),
        )
        .unwrap();
        assert!(development.needs_face_id());
        assert_eq!(
            development.line().as_deref(),
            Some("correct_environment:development:9")
        );
        let production = choice(
            "correct_environment",
            None,
            None,
            Some("9"),
            Some("production"),
        )
        .unwrap();
        assert!(!production.needs_face_id());
        for stricter in [
            "deny",
            "never_for_agent",
            "always_ask_for_agent",
            "disconnect",
        ] {
            assert!(
                !choice(stricter, None, None, None, None)
                    .unwrap()
                    .needs_face_id()
            );
        }
        let control = Choice::AllowProduction {
            action: "deploy".into(),
            project_key: "/tmp/a\nb".into(),
        };
        assert_eq!(control.line(), None);
    }

    #[test]
    fn display_text_hides_format_characters_and_shortens() {
        assert_eq!(
            shown("/tmp/a\u{00AD}b\u{E0041}\u{206A}/x", usize::MAX),
            "/tmp/a?b??/x"
        );
        assert_eq!(shown("abcdefghij", 5), "ab…ij");
    }
}
