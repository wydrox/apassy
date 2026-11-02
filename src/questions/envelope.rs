//! The sealed parts of a question on the wire (contract relay-questions-v1, sections 6
//! to 9): the card, the answer, and the settle, each sealed with ChaCha20-Poly1305 under
//! the question key, with an AAD that binds the team, the `qid`, the key, and the clear
//! metadata that the relay keeps.
//!
//! Nothing here talks to the relay. The asker and the answering device both use it; the
//! asker never parses an answer string: it rebuilds it ([`answer_string`]) from what it
//! is about to do.

use std::path::PathBuf;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::{AnswerKind, PendingRun, QuestionInfo, QuestionItem, RememberOffer};
use crate::broker::project::Project;
use crate::companion::digest::{answer_kind_text, parse_answer_kind, question_digest_v2_hex};
use crate::sync::{decode_b64u, encode_b64u};
use crate::vault::QuestionKey;

/// The tag of every AAD.
pub const AAD_TAG: &str = "apassy-question-v1";
/// The first line of the answer string.
pub const ANSWER_TAG: &str = "apassy-question-answer-v1";
/// The version of every card, answer, settle, and request body.
pub const VERSION: u32 = 1;

/// The largest plaintext of a card, an answer, and a settle (section 6.3).
pub const MAX_CARD_BYTES: usize = 32_768;
pub const MAX_ANSWER_BYTES: usize = 8192;
pub const MAX_SETTLE_BYTES: usize = 1024;
/// The ChaCha20-Poly1305 tag.
pub const TAG_BYTES: usize = 16;

/// The count limits of a card (section 7.2).
pub const MAX_COMMAND_ENTRIES: usize = 256;
pub const MAX_ENV_NAMES: usize = 64;
pub const MAX_ITEMS: usize = 64;
pub const MAX_VALID_ANSWERS: usize = 16;

/// A `to` of a question: the asking member's devices, or also the approvers of a team.
pub const TO_MEMBER: &str = "member";
pub const TO_APPROVERS: &str = "approvers";

// ---- Forms. ----

/// A `qid`: 22 characters of `A-Za-z0-9-_` (16 bytes as b64u).
pub fn valid_qid(text: &str) -> bool {
    text.len() == 22
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && decode_b64u(text).is_some_and(|bytes| bytes.len() == 16)
}

/// A `key_id`: 16 lowercase hex characters.
pub fn valid_key_id(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A new `qid` from the system random source.
pub fn new_qid() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(encode_b64u(&bytes))
}

/// A new nonce from the system random source.
pub fn new_nonce() -> Option<[u8; 12]> {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes)
}

/// A decimal string of the wire: digits only, no leading zero, within `u64`.
pub fn parse_decimal(text: &str) -> Option<u64> {
    let valid = !text.is_empty()
        && text.len() <= 20
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if valid { text.parse().ok() } else { None }
}

// ---- AAD and sealing (section 6). ----

fn aad(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

/// The AAD of a card.
pub fn card_aad(team_id: &str, qid: &str, key_id: &str, to: &str, expires_at: u64) -> Vec<u8> {
    aad(&[
        AAD_TAG,
        "card",
        team_id,
        qid,
        key_id,
        to,
        &expires_at.to_string(),
    ])
}

/// The AAD of an answer, with the relay device number that the relay stamped on it.
pub fn answer_aad(team_id: &str, qid: &str, key_id: &str, device_id: u64) -> Vec<u8> {
    aad(&[
        AAD_TAG,
        "answer",
        team_id,
        qid,
        key_id,
        &device_id.to_string(),
    ])
}

/// The AAD of a settle.
pub fn settle_aad(team_id: &str, qid: &str, key_id: &str) -> Vec<u8> {
    aad(&[AAD_TAG, "settle", team_id, qid, key_id])
}

fn sealing_key(key: &QuestionKey) -> Option<LessSafeKey> {
    UnboundKey::new(&CHACHA20_POLY1305, key.bytes())
        .ok()
        .map(LessSafeKey::new)
}

/// Seal `plaintext` with `key`, `nonce`, and `aad`: the ciphertext and the 16-byte tag.
pub fn seal(key: &QuestionKey, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    if let Some(key) = sealing_key(key) {
        let sealed = key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut out,
        );
        if sealed.is_ok() {
            return out;
        }
    }
    // A key that ring refuses cannot happen for 32 bytes. Never send the plaintext.
    Vec::new()
}

/// Open `ciphertext` with `key`, `nonce`, and `aad`. `None` for any failure: one result
/// for every cause (section 6.2).
pub fn open(
    key: &QuestionKey,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < TAG_BYTES {
        return None;
    }
    let key = sealing_key(key)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let len = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            buffer.as_mut_slice(),
        )
        .ok()?
        .len();
    buffer.truncate(len);
    Some(buffer)
}

/// A sealed part as the wire carries it: the key name, the nonce, and the ciphertext, as
/// b64u.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl Sealed {
    /// Seal `plaintext` with a new random nonce.
    pub fn new(key: &QuestionKey, aad: &[u8], plaintext: &[u8]) -> Option<Self> {
        Some(Self::with_nonce(key, &new_nonce()?, aad, plaintext))
    }

    /// Seal `plaintext` with `nonce`, for a test vector.
    pub fn with_nonce(key: &QuestionKey, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Self {
        Self {
            key_id: key.key_id(),
            nonce: encode_b64u(nonce),
            ciphertext: encode_b64u(&seal(key, nonce, aad, plaintext)),
        }
    }

    /// Open with `key` and `aad`. `None` when the key is not the one named, the nonce or
    /// the ciphertext has a bad form, or the envelope does not open.
    pub fn open(&self, key: &QuestionKey, aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if key.key_id() != self.key_id {
            return None;
        }
        let nonce: [u8; 12] = decode_b64u(&self.nonce)?.try_into().ok()?;
        let ciphertext = decode_b64u(&self.ciphertext)?;
        open(key, &nonce, aad, &ciphertext)
    }

    /// The length of the ciphertext in bytes, without decoding it twice by the caller.
    pub fn ciphertext_len(&self) -> usize {
        decode_b64u(&self.ciphertext).map_or(0, |bytes| bytes.len())
    }
}

// ---- The card (section 7). ----

/// A nullable field that must be present: `null` or a value, never missing.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// The plaintext of a card, with exactly the fields of the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Card {
    pub v: u32,
    pub qid: String,
    pub asker: CardAsker,
    pub created_at: u64,
    pub run: CardRun,
    pub question: CardQuestion,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardAsker {
    /// The asker's `trusted_device.uuid`.
    pub device: String,
    /// The asker's `trusted_device.name`. Not in the digest.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardRun {
    pub id: String,
    pub agent: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub env_names: Vec<String>,
    pub purpose: String,
    pub risk: String,
    pub user_request: String,
    pub request_source: String,
    pub agent_request: String,
    #[serde(deserialize_with = "required")]
    pub remember: Option<CardRemember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardRemember {
    pub pattern: String,
    pub approvals: u32,
    pub needed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardQuestion {
    pub id: String,
    pub item_ids: Vec<String>,
    pub items: Vec<CardItem>,
    #[serde(deserialize_with = "required")]
    pub project: Option<CardProject>,
    pub action: String,
    pub production: bool,
    pub why: String,
    pub valid_answers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardItem {
    pub item_id: String,
    pub name: String,
    pub production: bool,
    pub unconfirmed: bool,
    pub always_ask: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardProject {
    pub key: String,
    pub label: String,
}

/// Why a card cannot be posted or shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardError {
    /// Over a count limit or the plaintext size: the question stays on the asking Mac.
    TooLong,
    /// The card does not have the form of the contract ("Update Apassy to read this
    /// question" or "This question could not be read").
    Unreadable,
}

impl Card {
    /// The card of `run` as it waits. `asker` is the trusted device of the asking Mac.
    pub fn from_run(
        qid: &str,
        asker_device: &str,
        asker_name: &str,
        created_at: u64,
        run: &PendingRun,
    ) -> Self {
        let question = &run.question;
        Self {
            v: VERSION,
            qid: qid.to_owned(),
            asker: CardAsker {
                device: asker_device.to_owned(),
                name: asker_name.to_owned(),
            },
            created_at,
            run: CardRun {
                id: run.id.to_string(),
                agent: run.agent.clone(),
                command: run.command.clone(),
                cwd: run.cwd.clone(),
                env_names: run.env_names.clone(),
                purpose: run.purpose.clone(),
                risk: run.risk.clone(),
                user_request: run.user_request.clone(),
                request_source: run.request_source.clone(),
                agent_request: run.agent_request.clone(),
                remember: run.remember.as_ref().map(|offer| CardRemember {
                    pattern: offer.pattern.clone(),
                    approvals: offer.approvals,
                    needed: offer.needed,
                }),
            },
            question: CardQuestion {
                id: question.id.to_string(),
                item_ids: question.item_ids.iter().map(u64::to_string).collect(),
                items: question
                    .items
                    .iter()
                    .map(|item| CardItem {
                        item_id: item.item_id.to_string(),
                        name: item.name.clone(),
                        production: item.production,
                        unconfirmed: item.unconfirmed,
                        always_ask: item.always_ask,
                    })
                    .collect(),
                project: question.project.as_ref().map(|project| CardProject {
                    key: project.key.clone(),
                    label: project.label.clone(),
                }),
                action: question.action.as_str().to_owned(),
                production: question.production,
                why: question.why.clone(),
                valid_answers: question
                    .valid_answers
                    .iter()
                    .map(|kind| answer_kind_text(*kind))
                    .collect(),
            },
            digest: question_digest_v2_hex(run),
        }
    }

    /// The counts of section 7.2.
    pub fn within_limits(&self) -> bool {
        self.run.command.len() <= MAX_COMMAND_ENTRIES
            && self.run.env_names.len() <= MAX_ENV_NAMES
            && self.question.item_ids.len() <= MAX_ITEMS
            && self.question.items.len() <= MAX_ITEMS
            && self.question.valid_answers.len() <= MAX_VALID_ANSWERS
    }

    /// The plaintext of the card: one JSON object. `TooLong` over a limit of sections
    /// 6.3 and 7.2: the asker never cuts a card.
    pub fn to_plaintext(&self) -> Result<Zeroizing<Vec<u8>>, CardError> {
        if !self.within_limits() {
            return Err(CardError::TooLong);
        }
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| CardError::Unreadable)?);
        if bytes.len() > MAX_CARD_BYTES {
            return Err(CardError::TooLong);
        }
        Ok(bytes)
    }

    /// Parse a card plaintext with exactly the fields of the contract, within the
    /// limits.
    pub fn parse(plaintext: &[u8]) -> Result<Self, CardError> {
        if plaintext.len() > MAX_CARD_BYTES {
            return Err(CardError::Unreadable);
        }
        let card: Self = serde_json::from_slice(plaintext).map_err(|_| CardError::Unreadable)?;
        if !card.within_limits() {
            return Err(CardError::Unreadable);
        }
        Ok(card)
    }

    /// The waiting run that the card names, with every field the digest covers. The root
    /// of the project is not on the wire: it is the working directory. `None` when a
    /// field has a bad form: an ID that is not a decimal string, items that do not match
    /// the item IDs, an unknown action or answer, a duplicate answer.
    pub fn to_run(&self) -> Option<PendingRun> {
        let run_id = parse_decimal(&self.run.id)?;
        let question_id = parse_decimal(&self.question.id)?;
        let item_ids: Vec<u64> = self
            .question
            .item_ids
            .iter()
            .map(|id| parse_decimal(id))
            .collect::<Option<_>>()?;
        let items: Vec<QuestionItem> = self
            .question
            .items
            .iter()
            .map(|item| {
                Some(QuestionItem {
                    item_id: parse_decimal(&item.item_id)?,
                    name: item.name.clone(),
                    production: item.production,
                    unconfirmed: item.unconfirmed,
                    always_ask: item.always_ask,
                })
            })
            .collect::<Option<_>>()?;
        if items
            .iter()
            .map(|item| item.item_id)
            .ne(item_ids.iter().copied())
        {
            return None;
        }
        let mut valid_answers: Vec<AnswerKind> = Vec::new();
        for text in &self.question.valid_answers {
            let kind = parse_answer_kind(text)?;
            if valid_answers.contains(&kind) {
                return None;
            }
            valid_answers.push(kind);
        }
        Some(PendingRun {
            id: run_id,
            agent: self.run.agent.clone(),
            command: self.run.command.clone(),
            cwd: self.run.cwd.clone(),
            env_names: self.run.env_names.clone(),
            purpose: self.run.purpose.clone(),
            risk: self.run.risk.clone(),
            user_request: self.run.user_request.clone(),
            request_source: self.run.request_source.clone(),
            agent_request: self.run.agent_request.clone(),
            remember: self.run.remember.as_ref().map(|offer| RememberOffer {
                pattern: offer.pattern.clone(),
                approvals: offer.approvals,
                needed: offer.needed,
            }),
            question: QuestionInfo {
                reason: Default::default(),
                id: question_id,
                item_ids,
                project: self.question.project.as_ref().map(|project| Project {
                    key: project.key.clone(),
                    label: project.label.clone(),
                    root: PathBuf::from(&self.run.cwd),
                }),
                action: ActionKind::parse(&self.question.action)?,
                production: self.question.production,
                why: self.question.why.clone(),
                items,
                valid_answers,
            },
        })
    }
}

// ---- The answer (section 9). ----

/// The environment of a correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteEnvironment {
    Development,
    Production,
}

impl RemoteEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "development" => Some(Self::Development),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

/// An answer to a question (section 9.1) with its extra fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    ApproveOnce,
    ApproveInProject {
        action: ActionKind,
        project_key: String,
    },
    AllowProduction {
        action: ActionKind,
        project_key: String,
    },
    CorrectEnvironment {
        item_id: u64,
        environment: RemoteEnvironment,
    },
    Deny,
    NeverForAgent,
    AlwaysAskForAgent,
    Disconnect,
}

impl Choice {
    /// The `kind` of the answer.
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

    /// An approving kind: it gives authority, so a device signs it with its biometric
    /// key (an iPhone) or after a local Touch ID (a Mac), and the asker runs the owner
    /// check (section 5.3). A correction to development is checked too.
    pub fn needs_owner_check(&self) -> bool {
        matches!(
            self,
            Self::ApproveOnce
                | Self::ApproveInProject { .. }
                | Self::AllowProduction { .. }
                | Self::CorrectEnvironment {
                    environment: RemoteEnvironment::Development,
                    ..
                }
        )
    }

    /// Whether the answer settles the question (a correction does not, section 12.5).
    pub fn settles(&self) -> bool {
        !matches!(self, Self::CorrectEnvironment { .. })
    }

    /// The `<choice>` line of the answer string. `None` when the project key has a
    /// control character: such a question offers no project answer remotely.
    pub fn line(&self) -> Option<String> {
        let line = match self {
            Self::ApproveInProject {
                action,
                project_key,
            } => format!("approve_in_project:{}:{project_key}", action.as_str()),
            Self::AllowProduction {
                action,
                project_key,
            } => format!("allow_production:{}:{project_key}", action.as_str()),
            Self::CorrectEnvironment {
                item_id,
                environment,
            } => format!("correct_environment:{}:{item_id}", environment.as_str()),
            other => other.kind().to_owned(),
        };
        (!line.chars().any(char::is_control)).then_some(line)
    }

    /// Whether `question` offers this answer, with extra fields that match it (sections
    /// 9.1 and 12.3 step 4). `deny` is always valid.
    pub fn valid_for(&self, question: &QuestionInfo) -> bool {
        let offered = |kind: AnswerKind| question.valid_answers.contains(&kind);
        let same_project = |action: &ActionKind, key: &str| {
            *action == question.action
                && question
                    .project
                    .as_ref()
                    .is_some_and(|project| project.key == key)
        };
        match self {
            Self::ApproveOnce => offered(AnswerKind::Once),
            Self::ApproveInProject {
                action,
                project_key,
            } => offered(AnswerKind::InProject(*action)) && same_project(action, project_key),
            Self::AllowProduction {
                action,
                project_key,
            } => offered(AnswerKind::Production(*action)) && same_project(action, project_key),
            Self::CorrectEnvironment { item_id, .. } => {
                offered(AnswerKind::CorrectEnvironment)
                    && question
                        .items
                        .iter()
                        .any(|item| item.item_id == *item_id && item.unconfirmed)
            }
            Self::Deny => true,
            Self::NeverForAgent => offered(AnswerKind::NeverForAgent),
            Self::AlwaysAskForAgent => offered(AnswerKind::AlwaysAskForAgent),
            Self::Disconnect => offered(AnswerKind::Disconnect),
        }
    }

    /// The choice of an answer body: the kind with exactly its extra fields. `None` for
    /// an unknown kind, a missing or an extra field, or a field of a bad form.
    pub fn from_body(body: &AnswerBody) -> Option<Self> {
        let none = |fields: &[&Option<String>]| fields.iter().all(|field| field.is_none());
        let project = || -> Option<(ActionKind, String)> {
            if !none(&[&body.item_id, &body.environment]) {
                return None;
            }
            Some((
                ActionKind::parse(body.action.as_deref()?)?,
                body.project_key.clone()?,
            ))
        };
        let plain = |choice: Self| {
            none(&[
                &body.action,
                &body.project_key,
                &body.item_id,
                &body.environment,
            ])
            .then_some(choice)
        };
        match body.kind.as_str() {
            "approve_once" => plain(Self::ApproveOnce),
            "deny" => plain(Self::Deny),
            "never_for_agent" => plain(Self::NeverForAgent),
            "always_ask_for_agent" => plain(Self::AlwaysAskForAgent),
            "disconnect" => plain(Self::Disconnect),
            "approve_in_project" => project().map(|(action, project_key)| Self::ApproveInProject {
                action,
                project_key,
            }),
            "allow_production" => project().map(|(action, project_key)| Self::AllowProduction {
                action,
                project_key,
            }),
            "correct_environment" => {
                if !none(&[&body.action, &body.project_key]) {
                    return None;
                }
                Some(Self::CorrectEnvironment {
                    item_id: parse_decimal(body.item_id.as_deref()?)?,
                    environment: RemoteEnvironment::parse(body.environment.as_deref()?)?,
                })
            }
            _ => None,
        }
    }
}

/// The plaintext of an answer: `v`, `qid`, `by`, `kind`, the extra fields of its kind,
/// `digest`, `time`, and `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBody {
    pub v: u32,
    pub qid: String,
    pub by: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub digest: String,
    pub time: u64,
    /// The DER ECDSA signature over the answer string, as b64u.
    pub signature: String,
}

impl AnswerBody {
    /// The body of `choice`, signed with `signature` (DER).
    pub fn new(
        qid: &str,
        by: &str,
        choice: &Choice,
        digest: &str,
        time: u64,
        signature: &[u8],
    ) -> Self {
        let mut body = Self {
            v: VERSION,
            qid: qid.to_owned(),
            by: by.to_owned(),
            kind: choice.kind().to_owned(),
            action: None,
            project_key: None,
            item_id: None,
            environment: None,
            digest: digest.to_owned(),
            time,
            signature: encode_b64u(signature),
        };
        match choice {
            Choice::ApproveInProject {
                action,
                project_key,
            }
            | Choice::AllowProduction {
                action,
                project_key,
            } => {
                body.action = Some(action.as_str().to_owned());
                body.project_key = Some(project_key.clone());
            }
            Choice::CorrectEnvironment {
                item_id,
                environment,
            } => {
                body.item_id = Some(item_id.to_string());
                body.environment = Some(environment.as_str().to_owned());
            }
            _ => {}
        }
        body
    }

    /// The plaintext: one JSON object, at most [`MAX_ANSWER_BYTES`].
    pub fn to_plaintext(&self) -> Option<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).ok()?);
        (bytes.len() <= MAX_ANSWER_BYTES).then_some(bytes)
    }

    /// Parse an answer plaintext: `v` 1 and the known fields only.
    pub fn parse(plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() > MAX_ANSWER_BYTES {
            return None;
        }
        let body: Self = serde_json::from_slice(plaintext).ok()?;
        (body.v == VERSION).then_some(body)
    }
}

/// The signed text of an answer (section 9.3): seven lines joined with `\n`, no trailing
/// newline. `None` when a field has a control character.
pub fn answer_string(
    by: &str,
    team_id: &str,
    qid: &str,
    choice: &Choice,
    digest: &str,
    time: u64,
) -> Option<String> {
    let line = choice.line()?;
    let fields = [by, team_id, qid, digest];
    if fields
        .iter()
        .any(|field| field.is_empty() || field.chars().any(char::is_control))
    {
        return None;
    }
    Some(format!(
        "{ANSWER_TAG}\n{by}\n{team_id}\n{qid}\n{line}\n{digest}\n{time}"
    ))
}

// ---- The settle (section 9.4). ----

/// How a question ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcome {
    Approved,
    Denied,
    TimedOut,
    Invalidated,
    Replaced,
}

impl SettleOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::TimedOut => "timed_out",
            Self::Invalidated => "invalidated",
            Self::Replaced => "replaced",
        }
    }
}

/// The plaintext of a settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleBody {
    pub v: u32,
    pub qid: String,
    pub outcome: String,
    #[serde(deserialize_with = "required")]
    pub answered_by: Option<String>,
    #[serde(deserialize_with = "required")]
    pub device_name: Option<String>,
    #[serde(deserialize_with = "required")]
    pub device_kind: Option<String>,
    #[serde(deserialize_with = "required")]
    pub kind: Option<String>,
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
}

impl SettleBody {
    /// The plaintext: one JSON object, at most [`MAX_SETTLE_BYTES`].
    pub fn to_plaintext(&self) -> Option<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).ok()?);
        (bytes.len() <= MAX_SETTLE_BYTES).then_some(bytes)
    }

    pub fn parse(plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() > MAX_SETTLE_BYTES {
            return None;
        }
        let body: Self = serde_json::from_slice(plaintext).ok()?;
        (body.v == VERSION).then_some(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> QuestionKey {
        let mut bytes = [0u8; 32];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = at as u8;
        }
        QuestionKey::from_bytes(bytes)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn forms_of_the_wire() {
        assert!(valid_qid("oKGio6SlpqeoqaqrrK2urw"));
        assert!(!valid_qid("oKGio6SlpqeoqaqrrK2ur"));
        assert!(!valid_qid("oKGio6SlpqeoqaqrrK2ur="));
        assert!(valid_key_id("630dcd2966c43366"));
        assert!(!valid_key_id("630DCD2966C43366"));
        let qid = new_qid().unwrap();
        assert!(valid_qid(&qid), "{qid}");
        assert_ne!(new_qid().unwrap(), qid);
        assert_eq!(parse_decimal("123456789012345"), Some(123_456_789_012_345));
        for bad in ["", "01", "-1", "1a", "123456789012345678901"] {
            assert_eq!(parse_decimal(bad), None, "{bad}");
        }
        assert_eq!(parse_decimal("0"), Some(0));
    }

    #[test]
    fn the_aads_have_the_contract_bytes() {
        let qid = "oKGio6SlpqeoqaqrrK2urw";
        assert_eq!(
            hex(&card_aad(
                "t_7k2m5q4x3c",
                qid,
                "630dcd2966c43366",
                "member",
                1_790_000_300
            )),
            "6170617373792d7175657374696f6e2d7631006361726400745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636006d656d6265720031373930303030333030"
        );
        assert_eq!(
            hex(&answer_aad("t_7k2m5q4x3c", qid, "630dcd2966c43366", 3)),
            "6170617373792d7175657374696f6e2d763100616e7377657200745f376b326d357134783363006f4b47696f36536c7071656f71617172724b3275727700363330646364323936366334333336360033"
        );
        assert_eq!(
            hex(&settle_aad("t_7k2m5q4x3c", qid, "630dcd2966c43366")),
            "6170617373792d7175657374696f6e2d763100736574746c6500745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636"
        );
    }

    #[test]
    fn a_sealed_part_opens_only_with_its_aad_and_key() {
        let key = key();
        let aad = settle_aad("t_7k2m5q4x3c", "oKGio6SlpqeoqaqrrK2urw", &key.key_id());
        let sealed = Sealed::new(&key, &aad, b"synthetic settle").unwrap();
        assert_eq!(sealed.ciphertext_len(), 16 + 16);
        assert_eq!(
            sealed.open(&key, &aad).unwrap().as_slice(),
            b"synthetic settle"
        );
        let other = settle_aad("t_7k2m5q4x3c", "oKGio6SlpqeoqaqrrK2urw", "0000000000000000");
        assert!(sealed.open(&key, &other).is_none());
        let mut bytes = *key.bytes();
        bytes[0] ^= 1;
        assert!(sealed.open(&QuestionKey::from_bytes(bytes), &aad).is_none());
        // Two seals of the same text differ (a new nonce each).
        assert_ne!(
            Sealed::new(&key, &aad, b"x").unwrap(),
            Sealed::new(&key, &aad, b"x").unwrap()
        );
    }

    #[test]
    fn an_answer_body_needs_exactly_the_fields_of_its_kind() {
        let base = AnswerBody::new(
            "oKGio6SlpqeoqaqrrK2urw",
            "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            &Choice::ApproveOnce,
            "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d",
            1_790_000_030,
            b"sig",
        );
        assert_eq!(Choice::from_body(&base), Some(Choice::ApproveOnce));
        let mut extra = base.clone();
        extra.action = Some("deploy".to_owned());
        assert_eq!(Choice::from_body(&extra), None);
        let mut project = base.clone();
        project.kind = "allow_production".to_owned();
        project.action = Some("deploy".to_owned());
        assert_eq!(Choice::from_body(&project), None, "no project key");
        project.project_key = Some("/tmp/synthetic-shop/.git".to_owned());
        assert_eq!(
            Choice::from_body(&project),
            Some(Choice::AllowProduction {
                action: ActionKind::Deploy,
                project_key: "/tmp/synthetic-shop/.git".to_owned()
            })
        );
        let mut correct = base.clone();
        correct.kind = "correct_environment".to_owned();
        correct.item_id = Some("09".to_owned());
        correct.environment = Some("development".to_owned());
        assert_eq!(Choice::from_body(&correct), None, "a leading zero");
        correct.item_id = Some("9".to_owned());
        assert_eq!(
            Choice::from_body(&correct),
            Some(Choice::CorrectEnvironment {
                item_id: 9,
                environment: RemoteEnvironment::Development
            })
        );
        let mut unknown = base;
        unknown.kind = "approve_and_remember".to_owned();
        assert_eq!(Choice::from_body(&unknown), None);
        assert!(
            AnswerBody::parse(br#"{"v":1,"qid":"q","by":"b","kind":"deny","digest":"d","time":1,"signature":"s","extra":1}"#)
                .is_none()
        );
        assert!(
            AnswerBody::parse(br#"{"v":2,"qid":"q","by":"b","kind":"deny","digest":"d","time":1,"signature":"s"}"#)
                .is_none()
        );
    }

    #[test]
    fn a_control_character_in_a_project_key_makes_no_answer_string() {
        let choice = Choice::ApproveInProject {
            action: ActionKind::Change,
            project_key: "/tmp/x\n/.git".to_owned(),
        };
        assert_eq!(choice.line(), None);
        assert_eq!(
            answer_string("by", "t_7k2m5q4x3c", "qid", &choice, "d", 1),
            None
        );
        assert_eq!(
            answer_string("by", "t_7k2m5q4x3c", "qid", &Choice::Deny, "d", 1).as_deref(),
            Some("apassy-question-answer-v1\nby\nt_7k2m5q4x3c\nqid\ndeny\nd\n1")
        );
    }

    #[test]
    fn a_card_needs_every_field_and_no_other() {
        let card = r#"{"v":1,"qid":"q","asker":{"device":"d","name":"n"},"created_at":1,"run":{"id":"1","agent":"a","command":[],"cwd":"/","env_names":[],"purpose":"","risk":"","user_request":"","request_source":"","agent_request":"","remember":null},"question":{"id":"1","item_ids":[],"items":[],"project":null,"action":"read","production":false,"why":"","valid_answers":["once"]},"digest":"x"}"#;
        let parsed = Card::parse(card.as_bytes()).unwrap();
        assert!(parsed.to_run().is_some());
        let missing = card.replace(r#","remember":null"#, "");
        assert_eq!(Card::parse(missing.as_bytes()), Err(CardError::Unreadable));
        let missing = card.replace(r#""project":null,"#, "");
        assert_eq!(Card::parse(missing.as_bytes()), Err(CardError::Unreadable));
        let extra = card.replace(r#""digest":"x""#, r#""digest":"x","extra":1"#);
        assert_eq!(Card::parse(extra.as_bytes()), Err(CardError::Unreadable));
        let duplicate = card.replace(r#"["once"]"#, r#"["once","once"]"#);
        assert!(
            Card::parse(duplicate.as_bytes())
                .unwrap()
                .to_run()
                .is_none()
        );
        let mismatch = card.replace(r#""item_ids":[]"#, r#""item_ids":["7"]"#);
        assert!(Card::parse(mismatch.as_bytes()).unwrap().to_run().is_none());
    }
}
