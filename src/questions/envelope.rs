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
/// Published card version. Keep 1 until every recipient can decode card v2:
/// the relay sends one ciphertext to all devices, without capability negotiation.
pub const QUESTION_CARD_VERSION: u32 = 1;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_prompt: Option<OwnerPrompt>,
}

/// Display context and the current answer contract. Card v2 only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPrompt {
    pub agent_stated_task: String,
    pub purpose: String,
    pub task_provenance: String,
    pub reason_headline: String,
    pub environment_known: bool,
    pub allowed_answer_kinds: Vec<String>,
}

/// The answers of the card. "Allow as dev" and "Allow as prod" name no item: they label
/// the first unconfirmed item ([`QuestionInfo::classifiable_item`]). A run without one
/// offers "approve". A run with two or more also keeps "approve", which labels nothing:
/// an iPhone from before 0.5.19 answers such a run only with it.
pub fn allowed_answer_kinds(question: &QuestionInfo) -> Vec<String> {
    let mut kinds = vec!["deny".to_owned(), "deny_with_comment".to_owned()];
    if question.classifiable_item().is_some() {
        kinds.extend([
            "approve_as_development".into(),
            "approve_as_production".into(),
        ]);
    }
    if question.classifiable_item().is_none() || question.unconfirmed_after_classification() > 0 {
        kinds.push("approve".into());
    }
    kinds
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
        Self::from_run_with_version(
            qid,
            asker_device,
            asker_name,
            created_at,
            run,
            QUESTION_CARD_VERSION,
        )
    }

    fn from_run_with_version(
        qid: &str,
        asker_device: &str,
        asker_name: &str,
        created_at: u64,
        run: &PendingRun,
        version: u32,
    ) -> Self {
        assert!(matches!(version, 1 | 2));
        let question = &run.question;
        Self {
            v: version,
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
            owner_prompt: (version == 2).then(|| OwnerPrompt {
                agent_stated_task: if run.agent_request.is_empty() {
                    run.user_request.clone()
                } else {
                    run.agent_request.clone()
                },
                purpose: run.purpose.clone(),
                task_provenance: if run.request_source.starts_with("from the agent")
                    || run.request_source.is_empty()
                {
                    "agent-stated"
                } else {
                    "hook"
                }
                .into(),
                reason_headline: question.reason.headline().into(),
                environment_known: !question.items.iter().any(|item| item.unconfirmed),
                allowed_answer_kinds: allowed_answer_kinds(question),
            }),
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
                flags: Vec::new(),
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

// ---- The connect card, card v2 (section 7.4). ----

/// The version of a connect card. Run cards stay [`QUESTION_CARD_VERSION`] (1): an old
/// reader shows "Update Apassy to read this question" for a connect card only.
pub const CONNECT_CARD_VERSION: u32 = 2;
/// The `kind` of a connect card.
pub const CONNECT_KIND: &str = "connect";
/// The tag of the connect digest (section 8.1).
pub const CONNECT_DIGEST_TAG: &str = "apassy-connect-question-v1";
/// The `<choice>` line and the answer `kind` of "Allow" on a connect card.
pub const ALLOW_CONNECT: &str = "allow_connect";
/// The limits of the fields of a connect card (section 7.4).
pub const MAX_CONNECT_ID_BYTES: usize = 64;
pub const MAX_CLIENT_NAME_BYTES: usize = 64;
pub const MAX_MAC_NAME_BYTES: usize = 64;
pub const MAX_CODE_BYTES: usize = 16;
/// The longest `redirect_host` of a connect card: a DNS name has at most 253 bytes.
pub const MAX_REDIRECT_HOST_BYTES: usize = 255;
/// The line of the Mac's owner check for a connect request whose code goes back to a
/// program on a computer (review 0.5.16).
pub const LOCAL_CONNECT_WARNING: &str = concat!(
    "A program on this ",
    crate::computer!(),
    " can start this request."
);

/// True for the host of a redirect URI that names a computer itself, not a site:
/// `localhost` and names under it, an address of `127.0.0.0/8`, `[::1]`, or the
/// unspecified address. The code then goes to a program on the computer of the browser,
/// and on the Mac any program can make such a request: the node's listener is on the
/// loopback (review 0.5.16).
pub fn is_local_redirect_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback() || v4.is_unspecified();
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&host);
    bare.parse::<std::net::Ipv6Addr>().is_ok_and(|v6| {
        v6.is_loopback()
            || v6.is_unspecified()
            || v6
                .to_ipv4_mapped()
                .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
    })
}

/// The line of the owner's prompts and cards about where the code of a connect request
/// goes back: "Returns to <host>", "Returns to a program on a computer (localhost)" for
/// a local host ([`is_local_redirect_host`]), or "Returns to an address that was not
/// given" for an empty one.
pub fn connect_returns_to(host: &str) -> String {
    if host.is_empty() {
        "Returns to an address that was not given".to_owned()
    } else if is_local_redirect_host(host) {
        "Returns to a program on a computer (localhost)".to_owned()
    } else {
        format!("Returns to {host}")
    }
}

/// The connect request of a connect card: a remote agent asks to connect to a Mac (the
/// MCP authorization flow of ADR 0037). No token, no item, and no agent list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardConnect {
    /// The connect request of the node (`PendingConnect.id`).
    pub id: String,
    /// The client name that the agent registered, cleaned by the relay.
    pub client_name: String,
    /// The Mac that the agent connects to.
    pub mac_name: String,
    /// The match code that the agent's browser page shows.
    pub code: String,
    /// When the connect request ends on the node (Unix seconds).
    pub expires_at: u64,
    /// The host of the redirect URI of the request (`PendingConnect.redirect_host`):
    /// where the code goes back. Since 0.5.16 (review 0.5.16) a Mac always sends it; a
    /// card of an older Mac has none. The digest covers it when it is there. A reader
    /// before 0.5.16 refuses a card with it ("Update Apassy"): its answer would not say
    /// where the code goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_host: Option<String>,
}

impl CardConnect {
    /// The forms of section 7.4: an ID of `A-Za-z0-9-_`, names and a code without a
    /// control, format, or tag character (`crate::text::is_hidden_char`), within their
    /// limits, and a `redirect_host`, when there is one, of printable ASCII without a
    /// space, at most [`MAX_REDIRECT_HOST_BYTES`].
    pub fn valid(&self) -> bool {
        let text = |value: &str, max: usize| {
            !value.is_empty()
                && value.len() <= max
                && !value.chars().any(crate::text::is_hidden_char)
        };
        !self.id.is_empty()
            && self.id.len() <= MAX_CONNECT_ID_BYTES
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && text(&self.client_name, MAX_CLIENT_NAME_BYTES)
            && text(&self.mac_name, MAX_MAC_NAME_BYTES)
            && text(&self.code, MAX_CODE_BYTES)
            && self
                .redirect_host
                .as_deref()
                .is_none_or(valid_redirect_host)
    }

    /// The line "Returns to …" of the card ([`connect_returns_to`]). `None` for a card of
    /// a Mac before 0.5.16, which has no host.
    pub fn returns_to(&self) -> Option<String> {
        self.redirect_host.as_deref().map(connect_returns_to)
    }
}

/// A `redirect_host` of a connect card: not empty, at most [`MAX_REDIRECT_HOST_BYTES`],
/// printable ASCII without a space.
pub fn valid_redirect_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_REDIRECT_HOST_BYTES
        && host.bytes().all(|b| b.is_ascii_graphic())
}

/// The plaintext of a connect card (card v2, `kind = connect`), with exactly the fields of
/// the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectCard {
    pub v: u32,
    pub kind: String,
    pub qid: String,
    pub asker: CardAsker,
    pub created_at: u64,
    pub connect: CardConnect,
    pub digest: String,
}

/// The connect digest (section 8.1) as 64 lowercase hex characters: it covers the asker
/// and every field of the connect request, so the device signs what it showed. A card
/// with a `redirect_host` adds the text `redirect_host` and the host after `expires_at`;
/// a card without one has the digest of 0.5.15.
pub fn connect_digest_hex(asker_device: &str, connect: &CardConnect) -> String {
    use ring::digest::{Context, SHA256};
    let mut hash = Context::new(&SHA256);
    let text = |hash: &mut Context, value: &str| {
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    };
    text(&mut hash, CONNECT_DIGEST_TAG);
    text(&mut hash, asker_device);
    text(&mut hash, &connect.id);
    text(&mut hash, &connect.client_name);
    text(&mut hash, &connect.mac_name);
    text(&mut hash, &connect.code);
    hash.update(&connect.expires_at.to_be_bytes());
    if let Some(host) = &connect.redirect_host {
        text(&mut hash, "redirect_host");
        text(&mut hash, host);
    }
    hash.finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl ConnectCard {
    /// The card of `connect`, asked by this Mac (`asker`).
    pub fn new(
        qid: &str,
        asker_device: &str,
        asker_name: &str,
        created_at: u64,
        connect: &CardConnect,
    ) -> Self {
        Self {
            v: CONNECT_CARD_VERSION,
            kind: CONNECT_KIND.to_owned(),
            qid: qid.to_owned(),
            asker: CardAsker {
                device: asker_device.to_owned(),
                name: asker_name.to_owned(),
            },
            created_at,
            connect: connect.clone(),
            digest: connect_digest_hex(asker_device, connect),
        }
    }

    /// The plaintext: one JSON object. `TooLong` for a field over its limit or of a bad
    /// form: the connect request stays on this Mac.
    pub fn to_plaintext(&self) -> Result<Zeroizing<Vec<u8>>, CardError> {
        if !self.connect.valid() || self.asker.name.is_empty() || self.asker.name.len() > 64 {
            return Err(CardError::TooLong);
        }
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| CardError::Unreadable)?);
        if bytes.len() > MAX_CARD_BYTES {
            return Err(CardError::TooLong);
        }
        Ok(bytes)
    }

    /// Parse a connect card with exactly the fields of the contract: `v` 2, `kind`
    /// `connect`, the forms of section 7.4, and the digest of its own fields.
    pub fn parse(plaintext: &[u8]) -> Result<Self, CardError> {
        if plaintext.len() > MAX_CARD_BYTES {
            return Err(CardError::Unreadable);
        }
        let card: Self = serde_json::from_slice(plaintext).map_err(|_| CardError::Unreadable)?;
        let good = card.v == CONNECT_CARD_VERSION
            && card.kind == CONNECT_KIND
            && valid_qid(&card.qid)
            && card.connect.valid()
            && !card.asker.name.is_empty()
            && card.asker.name.len() <= 64
            && card.digest == connect_digest_hex(&card.asker.device, &card.connect);
        if good {
            Ok(card)
        } else {
            Err(CardError::Unreadable)
        }
    }
}

/// Whether `plaintext` is a card v2 of the kind `connect` (any form): a Mac that lists
/// the questions of the other devices leaves it out (the asking Mac and the iPhones
/// answer a connect request).
pub fn is_connect_card(plaintext: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(plaintext).is_ok_and(|value| {
        value.get("v").and_then(serde_json::Value::as_u64) == Some(u64::from(CONNECT_CARD_VERSION))
            && value.get("kind").and_then(serde_json::Value::as_str) == Some(CONNECT_KIND)
    })
}

/// An answer to a connect card (section 9.1): Allow (an iPhone signs it with its Face ID
/// answer key) or Deny (its relay key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectChoice {
    Allow,
    Deny,
}

impl ConnectChoice {
    /// The answer `kind` and the `<choice>` line of the answer string.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Allow => ALLOW_CONNECT,
            Self::Deny => "deny",
        }
    }

    /// Allow gives authority: the answer key after Face ID signs it.
    pub fn needs_owner_check(self) -> bool {
        self == Self::Allow
    }

    /// The choice of an answer body: `allow_connect` or `deny`, with no extra field.
    pub fn from_body(body: &AnswerBody) -> Option<Self> {
        let plain = body.comment.is_none()
            && body.action.is_none()
            && body.project_key.is_none()
            && body.item_id.is_none()
            && body.environment.is_none();
        match body.kind.as_str() {
            ALLOW_CONNECT if plain => Some(Self::Allow),
            "deny" if plain => Some(Self::Deny),
            _ => None,
        }
    }
}

/// The signed text of an answer to a connect card: the answer string of section 9.3 with
/// the `<choice>` `allow_connect` or `deny` and the connect digest. `None` when a field
/// has a control character.
pub fn connect_answer_string(
    by: &str,
    team_id: &str,
    qid: &str,
    choice: ConnectChoice,
    digest: &str,
    time: u64,
) -> Option<String> {
    let fields = [by, team_id, qid, digest];
    if fields
        .iter()
        .any(|field| field.is_empty() || field.chars().any(char::is_control))
    {
        return None;
    }
    Some(format!(
        "{ANSWER_TAG}\n{by}\n{team_id}\n{qid}\n{}\n{digest}\n{time}",
        choice.kind()
    ))
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
    Approve,
    ApproveAsDevelopment,
    ApproveAsProduction,
    DenyWithComment {
        comment: String,
    },
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
            Self::Approve => "approve",
            Self::ApproveAsDevelopment => "approve_as_development",
            Self::ApproveAsProduction => "approve_as_production",
            Self::DenyWithComment { .. } => "deny_with_comment",
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
            Self::Approve
                | Self::ApproveAsDevelopment
                | Self::ApproveAsProduction
                | Self::ApproveOnce
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
            Self::DenyWithComment { comment } => {
                if *comment != crate::broker::approvals::refusal_comment(comment) {
                    return None;
                }
                format!("deny_with_comment:{}", encode_b64u(comment.as_bytes()))
            }
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
            Self::Approve
            | Self::ApproveAsDevelopment
            | Self::ApproveAsProduction
            | Self::DenyWithComment { .. } => {
                allowed_answer_kinds(question)
                    .iter()
                    .any(|kind| kind == self.kind())
                    && self.line().is_some()
            }
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
        if body.kind != "deny_with_comment" && body.comment.is_some() {
            return None;
        }
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
            "approve" => plain(Self::Approve),
            "approve_as_development" => plain(Self::ApproveAsDevelopment),
            "approve_as_production" => plain(Self::ApproveAsProduction),
            "deny_with_comment" => {
                let comment = body.comment.clone()?;
                if comment != crate::broker::approvals::refusal_comment(&comment) {
                    return None;
                }
                plain(Self::DenyWithComment { comment })
            }
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
    pub comment: Option<String>,
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
            comment: match choice {
                Choice::DenyWithComment { comment } => Some(comment.clone()),
                _ => None,
            },
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

    /// The body of an answer to a connect card, signed with `signature` (DER). The answer
    /// keeps `v` 1: its fields do not change, only the kind and the digest.
    pub fn connect(
        qid: &str,
        by: &str,
        choice: ConnectChoice,
        digest: &str,
        time: u64,
        signature: &[u8],
    ) -> Self {
        Self {
            v: VERSION,
            qid: qid.to_owned(),
            by: by.to_owned(),
            kind: choice.kind().to_owned(),
            comment: None,
            action: None,
            project_key: None,
            item_id: None,
            environment: None,
            digest: digest.to_owned(),
            time,
            signature: encode_b64u(signature),
        }
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

    #[test]
    fn current_and_legacy_answer_bodies_round_trip_without_reinterpreting_signatures() {
        for choice in [
            Choice::Approve,
            Choice::ApproveAsDevelopment,
            Choice::ApproveAsProduction,
            Choice::Deny,
            Choice::DenyWithComment {
                comment: "No".into(),
            },
            Choice::ApproveOnce,
            Choice::ApproveInProject {
                action: ActionKind::Read,
                project_key: "project".into(),
            },
            Choice::AllowProduction {
                action: ActionKind::Read,
                project_key: "project".into(),
            },
            Choice::CorrectEnvironment {
                item_id: 7,
                environment: RemoteEnvironment::Development,
            },
            Choice::CorrectEnvironment {
                item_id: 7,
                environment: RemoteEnvironment::Production,
            },
            Choice::NeverForAgent,
            Choice::AlwaysAskForAgent,
            Choice::Disconnect,
        ] {
            let body = AnswerBody::new("qid", "by", &choice, "digest", 1, &[0; 8]);
            let parsed = AnswerBody::parse(&body.to_plaintext().unwrap()).unwrap();
            assert_eq!(Choice::from_body(&parsed), Some(choice.clone()));
            assert!(answer_string("by", "team", "qid", &choice, "digest", 1).is_some());
            let mut extra = body;
            extra.comment = Some("forged".into());
            if !matches!(choice, Choice::DenyWithComment { .. }) {
                assert!(Choice::from_body(&extra).is_none());
            }
        }
        assert_eq!(
            Choice::DenyWithComment {
                comment: "No".into()
            }
            .line()
            .as_deref(),
            Some("deny_with_comment:Tm8")
        );
        for comment in [
            " No ".to_owned(),
            "No\n".into(),
            "é".repeat(501),
            "No\u{2028}".into(),
        ] {
            let body = AnswerBody::new(
                "qid",
                "by",
                &Choice::DenyWithComment { comment },
                "digest",
                1,
                &[0; 8],
            );
            assert!(Choice::from_body(&body).is_none());
        }
    }

    fn key() -> QuestionKey {
        let mut bytes = [0u8; 32];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = at as u8;
        }
        QuestionKey::from_bytes(bytes)
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
        let run = parsed.to_run().unwrap();
        for version in [1, 2] {
            let encoded = Card::from_run_with_version("q", "d", "n", 1, &run, version);
            assert_eq!(encoded.v, version);
            assert_eq!(encoded.owner_prompt.is_some(), version == 2);
            if let Some(prompt) = &encoded.owner_prompt {
                assert!(prompt.environment_known);
                assert_eq!(
                    prompt.allowed_answer_kinds,
                    ["deny", "deny_with_comment", "approve"]
                );
                assert_eq!(prompt.purpose, run.purpose);
            }
            let bytes = encoded.to_plaintext().unwrap();
            assert_eq!(Card::parse(&bytes).unwrap(), encoded);
            assert_eq!(encoded.to_run().unwrap(), run);
            let mut wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            wire.as_object_mut().unwrap().remove("owner_prompt");
            wire["v"] = 1.into();
            wire["digest"] = "x".into();
            assert_eq!(
                wire,
                serde_json::from_str::<serde_json::Value>(card).unwrap()
            );
        }
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

    fn synthetic_connect() -> CardConnect {
        CardConnect {
            id: "cr_7Hq2xN".to_owned(),
            client_name: "Grok Bot".to_owned(),
            mac_name: "Synthetic Mac mini".to_owned(),
            code: "482 913".to_owned(),
            expires_at: 1_790_000_300,
            redirect_host: None,
        }
    }

    #[test]
    fn a_connect_card_is_card_v2_with_exactly_its_fields() {
        let connect = synthetic_connect();
        let card = ConnectCard::new(
            "oKGio6SlpqeoqaqrrK2urw",
            "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
            "Synthetic Mac mini",
            1_790_000_000,
            &connect,
        );
        assert_eq!(card.v, 2);
        assert_eq!(card.kind, "connect");
        // The vector of section 20.6 of the contract.
        assert_eq!(
            card.digest,
            "414fa0828bfabc762b01548be58bda38868fd5c216a63daf70839aea21a61bcc"
        );
        assert_eq!(
            card.digest,
            connect_digest_hex("0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", &connect)
        );
        let bytes = card.to_plaintext().unwrap();
        assert_eq!(bytes.len(), 368);
        assert!(is_connect_card(&bytes));
        assert_eq!(ConnectCard::parse(&bytes).unwrap(), card);
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"v":2,"kind":"connect","qid":"oKGio6SlpqeoqaqrrK2urw","asker":{{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"Synthetic Mac mini"}},"created_at":1790000000,"connect":{{"id":"cr_7Hq2xN","client_name":"Grok Bot","mac_name":"Synthetic Mac mini","code":"482 913","expires_at":1790000300}},"digest":"{}"}}"#,
                card.digest
            )
        );
        // The run reader (every Mac and iPhone before card v2) refuses it: "Update Apassy".
        assert_eq!(Card::parse(&bytes), Err(CardError::Unreadable));
        // Each field is covered by the digest, and a card with a changed field fails.
        for (from, to) in [
            (
                r#""client_name":"Grok Bot""#,
                r#""client_name":"Grok Bot 2""#,
            ),
            (
                r#""mac_name":"Synthetic Mac mini""#,
                r#""mac_name":"Other Mac""#,
            ),
            (r#""code":"482 913""#, r#""code":"482 914""#),
            (r#""id":"cr_7Hq2xN""#, r#""id":"cr_7Hq2xM""#),
            (r#""expires_at":1790000300"#, r#""expires_at":1790000301"#),
            (
                r#""device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d""#,
                r#""device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4e""#,
            ),
        ] {
            let change = to;
            let changed = text.replacen(from, to, 1);
            assert_ne!(changed, text, "{change}");
            assert_eq!(
                ConnectCard::parse(changed.as_bytes()),
                Err(CardError::Unreadable),
                "{change}"
            );
        }
        for bad in [
            text.replace(r#""v":2"#, r#""v":3"#),
            text.replace(r#""kind":"connect""#, r#""kind":"run""#),
            text.replace(r#""created_at""#, r#""extra":1,"created_at""#),
            text.replace(r#","code":"482 913""#, ""),
        ] {
            assert_eq!(
                ConnectCard::parse(bad.as_bytes()),
                Err(CardError::Unreadable)
            );
        }
        assert!(!is_connect_card(
            text.replace(r#""kind":"connect""#, r#""kind":"run""#)
                .as_bytes()
        ));
    }

    /// Review 0.5.16: a card says where the code goes back. The digest covers the host,
    /// a card without one keeps the digest of 0.5.15, and a bad host is never posted.
    #[test]
    fn a_connect_card_names_where_the_code_goes_back() {
        let mut connect = synthetic_connect();
        connect.redirect_host = Some("grok.example".to_owned());
        assert!(connect.valid());
        let card = ConnectCard::new(
            "oKGio6SlpqeoqaqrrK2urw",
            "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
            "Synthetic Mac mini",
            1_790_000_000,
            &connect,
        );
        assert_eq!(
            card.digest,
            "920e1b31aac3c46fc4bb12a5e3f79d391663c7fa878a3dbbba328de9040b3d12"
        );
        assert_ne!(
            card.digest,
            "414fa0828bfabc762b01548be58bda38868fd5c216a63daf70839aea21a61bcc"
        );
        let bytes = card.to_plaintext().unwrap();
        assert_eq!(bytes.len(), 399);
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            text.contains(r#""expires_at":1790000300,"redirect_host":"grok.example"}"#),
            "{text}"
        );
        assert_eq!(ConnectCard::parse(&bytes).unwrap(), card);
        assert_eq!(
            card.connect.returns_to().as_deref(),
            Some("Returns to grok.example")
        );
        // Another host, or a card without the host, fails its digest.
        for changed in [
            text.replacen("grok.example", "other.example", 1),
            text.replacen(r#","redirect_host":"grok.example""#, "", 1),
        ] {
            assert_ne!(changed, text);
            assert_eq!(
                ConnectCard::parse(changed.as_bytes()),
                Err(CardError::Unreadable)
            );
        }
        // A card of a Mac before 0.5.16 has no host and no "Returns to" line.
        assert_eq!(synthetic_connect().returns_to(), None);
        for bad in ["", "grok example", "grok\u{0}.example", "gr\u{f6}k.example"] {
            let mut connect = synthetic_connect();
            connect.redirect_host = Some(bad.to_owned());
            assert!(!connect.valid(), "{bad:?}");
            let card = ConnectCard::new("oKGio6SlpqeoqaqrrK2urw", "d", "Mac", 1, &connect);
            assert_eq!(card.to_plaintext().err(), Some(CardError::TooLong));
        }
        let mut long = synthetic_connect();
        long.redirect_host = Some("a".repeat(MAX_REDIRECT_HOST_BYTES + 1));
        assert!(!long.valid());
    }

    #[test]
    fn a_loopback_redirect_host_returns_to_a_program_on_a_computer() {
        for local in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "app.localhost",
            "127.0.0.1",
            "127.8.9.10",
            "0.0.0.0",
            "[::1]",
            "::1",
            "[::]",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(is_local_redirect_host(local), "{local}");
            assert_eq!(
                connect_returns_to(local),
                "Returns to a program on a computer (localhost)"
            );
        }
        for remote in [
            "grok.example",
            "localhost.evil.example",
            "128.0.0.1",
            "[2001:db8::1]",
            "[::ffff:203.0.113.9]",
        ] {
            assert!(!is_local_redirect_host(remote), "{remote}");
            assert_eq!(connect_returns_to(remote), format!("Returns to {remote}"));
        }
        assert_eq!(
            connect_returns_to(""),
            "Returns to an address that was not given"
        );
        assert_eq!(
            LOCAL_CONNECT_WARNING,
            concat!(
                "A program on this ",
                crate::computer!(),
                " can start this request."
            )
        );
    }

    #[test]
    fn a_connect_card_refuses_bad_forms_and_never_posts_them() {
        let good = synthetic_connect();
        assert!(good.valid());
        let mut cases = Vec::new();
        for (field, value) in [
            ("id", "cr 1".to_owned()),
            ("id", String::new()),
            ("id", "a".repeat(65)),
            ("client_name", String::new()),
            ("client_name", "x".repeat(65)),
            ("client_name", "Grok\nBot".to_owned()),
            ("client_name", "Grok\u{202E}toB".to_owned()),
            // Format characters that the old list missed, and the tag block.
            ("client_name", "Grok\u{061C}Bot".to_owned()),
            ("client_name", "Grok\u{0600}Bot".to_owned()),
            ("client_name", "Grok\u{206A}Bot".to_owned()),
            ("client_name", "Grok Bot\u{E0041}\u{E0042}".to_owned()),
            ("client_name", "Grok Bot\u{E0001}".to_owned()),
            ("mac_name", "Mac\u{1D173}".to_owned()),
            ("mac_name", String::new()),
            ("code", "1".repeat(17)),
            ("code", "48\u{0}2".to_owned()),
        ] {
            let mut connect = good.clone();
            match field {
                "id" => connect.id = value,
                "client_name" => connect.client_name = value,
                "mac_name" => connect.mac_name = value,
                _ => connect.code = value,
            }
            cases.push(connect);
        }
        for connect in cases {
            assert!(!connect.valid(), "{connect:?}");
            let card = ConnectCard::new("oKGio6SlpqeoqaqrrK2urw", "d", "Mac", 1, &connect);
            assert_eq!(card.to_plaintext().err(), Some(CardError::TooLong));
        }
    }

    #[test]
    fn a_connect_answer_takes_allow_connect_or_deny_and_nothing_else() {
        let allow = AnswerBody::connect("q", "b", ConnectChoice::Allow, "d", 7, b"sig");
        let parsed = AnswerBody::parse(&allow.to_plaintext().unwrap()).unwrap();
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.kind, "allow_connect");
        assert_eq!(
            ConnectChoice::from_body(&parsed),
            Some(ConnectChoice::Allow)
        );
        // A run question never takes it: its kind is unknown there.
        assert_eq!(Choice::from_body(&parsed), None);
        let deny = AnswerBody::connect("q", "b", ConnectChoice::Deny, "d", 7, b"sig");
        assert_eq!(ConnectChoice::from_body(&deny), Some(ConnectChoice::Deny));
        for kind in ["approve_once", "approve", "allow_once", "disconnect"] {
            let mut other = allow.clone();
            other.kind = kind.to_owned();
            assert_eq!(ConnectChoice::from_body(&other), None, "{kind}");
        }
        let mut extra = allow.clone();
        extra.action = Some("read".to_owned());
        assert_eq!(ConnectChoice::from_body(&extra), None);
        let mut comment = deny;
        comment.comment = Some("no".to_owned());
        assert_eq!(ConnectChoice::from_body(&comment), None);
        assert!(ConnectChoice::Allow.needs_owner_check());
        assert!(!ConnectChoice::Deny.needs_owner_check());
        assert_eq!(
            connect_answer_string("by", "t_7k2m5q4x3c", "qid", ConnectChoice::Allow, "d", 1)
                .as_deref(),
            Some("apassy-question-answer-v1\nby\nt_7k2m5q4x3c\nqid\nallow_connect\nd\n1")
        );
        assert_eq!(
            connect_answer_string("b\ny", "t", "q", ConnectChoice::Deny, "d", 1),
            None
        );
    }

    #[test]
    fn current_offers_follow_environment_even_without_legacy_offers() {
        let mut question = QuestionInfo::default();
        question.valid_answers.clear();
        assert!(Choice::Approve.valid_for(&question));
        assert!(!Choice::ApproveOnce.valid_for(&question));
        assert!(!Choice::ApproveAsDevelopment.valid_for(&question));
        question.items.push(QuestionItem {
            item_id: 1,
            name: "No environment declaration".into(),
            production: false,
            unconfirmed: true,
            always_ask: false,
        });
        assert_eq!(
            allowed_answer_kinds(&question),
            [
                "deny",
                "deny_with_comment",
                "approve_as_development",
                "approve_as_production"
            ]
        );
        assert!(!Choice::Approve.valid_for(&question));
        assert!(Choice::ApproveAsDevelopment.valid_for(&question));
        assert!(Choice::ApproveAsProduction.valid_for(&question));
        assert!(
            !Choice::CorrectEnvironment {
                item_id: 1,
                environment: RemoteEnvironment::Development
            }
            .valid_for(&question)
        );
        assert!(Choice::Deny.valid_for(&question));
        assert!(
            Choice::DenyWithComment {
                comment: "No".into()
            }
            .valid_for(&question)
        );
    }

    /// ADR 0031, amended 2026-11-06: a run with two unlabeled items offers "Allow as dev"
    /// and "Allow as prod" for the first one, and keeps "approve" for an older iPhone.
    #[test]
    fn classify_answers_label_the_first_unconfirmed_item() {
        let item = |item_id, production, unconfirmed| QuestionItem {
            item_id,
            name: format!("item {item_id}"),
            production,
            unconfirmed,
            always_ask: false,
        };
        let mut question = QuestionInfo {
            items: vec![item(1, false, false), item(2, false, true)],
            ..QuestionInfo::default()
        };
        assert_eq!(
            allowed_answer_kinds(&question),
            [
                "deny",
                "deny_with_comment",
                "approve_as_development",
                "approve_as_production"
            ]
        );
        question.items.push(item(3, false, true));
        assert_eq!(
            allowed_answer_kinds(&question),
            [
                "deny",
                "deny_with_comment",
                "approve_as_development",
                "approve_as_production",
                "approve"
            ]
        );
        assert_eq!(question.classifiable_item().map(|i| i.item_id), Some(2));
        assert!(Choice::ApproveAsDevelopment.valid_for(&question));
        assert!(Choice::ApproveAsProduction.valid_for(&question));
        assert!(Choice::Approve.valid_for(&question));
    }
}
