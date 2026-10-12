//! Questions through the relay, the iPhone side (contract relay-questions-v1, sections
//! 5, 7, 9, 10, and 13; contract ios-core-v1 section 5.10).
//!
//! The iPhone is an answering device. It reads the open questions of the questions team
//! of the selected vault, opens each card with the question key of the vault, checks it,
//! and posts the owner's answer, sealed with the same key and signed:
//!
//! - an answer that gives authority (approve once, in the project, production, and
//!   "Development") is signed in Swift by the Secure Enclave answer key after Face ID
//!   for this answer; the core builds the exact string first (`question_answer_string`)
//!   and checks the signature with the registered answer key before it posts;
//! - an answer that takes authority away is signed here with the relay key of the
//!   membership, without Face ID.
//!
//! The questions team is the membership of the vault with the purpose `questions`, else
//! the relay sync membership. An iCloud vault gets a membership of its own with
//! `join_attach`: the iPhone joins a notifications-only team that a Mac made (plan §A7),
//! confirmed with the safety words and Touch ID on the Mac, and downloads nothing.
//!
//! The relay calls run without the vault mutex. A lock ends them ([`Core::close`]).

mod envelope;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use apassy::sync::{
    DEFAULT_RELAY_URL, PendingJoin, RelayCallError, RelayMember, SyncError, decode_b64u,
    encode_b64u, verify_signature,
};
use apassy::vault::{
    MembershipPurpose, RelayMembership, TrustedDevice, TrustedDeviceKind, Vault, VaultErrorKind,
};

use envelope::{CardRefusal, Choice};

use super::errors::{CoreError, CoreResult};
use super::wire::{Empty, Secret, ok, params};
use super::{Core, guard, now};

/// The bundle ID of the app, the relay's push topic (integrator decision 6).
const BUNDLE_ID: &str = "com.wydrox.apassy.companion";
/// A retry of an answer keeps its signature while its time is younger than this
/// (section 13, step 4).
const ANSWER_RETRY_SECONDS: u64 = 55;
/// A settled or expired question leaves the list this long after it ended.
const KEEP_ENDED_SECONDS: u64 = 600;
/// A list call reads at most this many pages of 100 questions.
const MAX_PAGES: usize = 10;
/// Display limits of a path and of a name.
const SHOWN_PATH: usize = 80;
const SHOWN_NAME: usize = 64;

const READ_FAILED: &str = "This question could not be read.";
const UPDATE: &str = "Update Apassy to read this question.";
const SYNC_FIRST: &str = "Sync this vault to read this question.";

/// The questions of the selected vault in this process. Each part is reset by a lock,
/// a suspend, and a selection.
#[derive(Default)]
pub struct State {
    /// The device of the questions team, with its key in memory.
    member: Option<Arc<RelayMember>>,
    /// The last question sequence seen (section 10.4).
    since: u64,
    /// The questions that the relay returned, by `qid`.
    records: BTreeMap<String, Record>,
    /// A join of a notifications-only team that waits for the Mac.
    attach: Option<Attaching>,
}

/// A question as the relay returned it.
#[derive(Debug, Clone, Deserialize)]
struct Record {
    qid: String,
    seq: u64,
    to: String,
    from_device_id: u64,
    #[serde(default)]
    from_device_name: String,
    key_id: String,
    nonce: String,
    ciphertext: String,
    created_at: u64,
    expires_at: u64,
    state: String,
    #[serde(default)]
    settled_at: Option<u64>,
    #[serde(default)]
    settle: Option<Sealed>,
    /// The kind of the answer this iPhone posted, for "Sent. Waiting for …".
    #[serde(skip)]
    answered: Option<&'static str>,
}

#[derive(Debug, Clone, Deserialize)]
struct Sealed {
    key_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct ListAnswer {
    seq: u64,
    #[serde(default)]
    questions: Vec<Record>,
}

/// A join of a notifications-only team.
struct Attaching {
    pending: PendingJoin,
    vault_id: String,
    team: String,
    words: Vec<String>,
    expires_at: u64,
}

impl Attaching {
    fn view(&self, state: &'static str) -> AttachOut {
        AttachOut {
            state,
            team: self.team.clone(),
            words: self.words.clone(),
            expires_at: self.expires_at,
        }
    }
}

// ---- Answers of the calls. ----

#[derive(Serialize)]
struct AttachOut {
    /// `waiting` until the Mac confirms, then `attached`.
    state: &'static str,
    team: String,
    words: Vec<String>,
    expires_at: u64,
}

#[derive(Serialize)]
struct StatusOut {
    /// Whether the vault has a questions team.
    enabled: bool,
    team_id: Option<String>,
    relay_device_id: Option<u64>,
    /// This iPhone's `trusted_device` row.
    device_uuid: Option<String>,
    /// The registered answer key, b64u, when there is one.
    answer_key: Option<String>,
    /// Whether the vault holds a question key.
    has_key: bool,
}

#[derive(Serialize)]
struct ListOut {
    status: StatusOut,
    questions: Vec<QuestionOut>,
}

#[derive(Serialize)]
struct QuestionOut {
    qid: String,
    /// `open`, `settled`, or `expired`.
    state: &'static str,
    /// The asking Mac: the card's name when the card opens, else the relay's.
    asker_name: String,
    created_at: u64,
    expires_at: u64,
    /// The text for the owner when the card cannot be shown.
    problem: Option<&'static str>,
    card: Option<CardOut>,
    settle: Option<SettleOut>,
    /// The kind of the answer this iPhone sent.
    answered: Option<&'static str>,
}

#[derive(Serialize)]
struct CardOut {
    asker_device: String,
    created_at: u64,
    run: RunOut,
    question: QuestionInfoOut,
    digest: String,
}

#[derive(Serialize)]
struct RunOut {
    id: String,
    agent: String,
    command: Vec<String>,
    cwd: String,
    env_names: Vec<String>,
    purpose: String,
    risk: String,
    user_request: String,
    request_source: String,
    agent_request: String,
    remember: Option<RememberOut>,
}

#[derive(Serialize)]
struct RememberOut {
    pattern: String,
    approvals: u32,
    needed: u32,
}

#[derive(Serialize)]
struct QuestionInfoOut {
    items: Vec<ItemOut>,
    project: Option<ProjectOut>,
    action: String,
    production: bool,
    why: String,
    valid_answers: Vec<String>,
}

#[derive(Serialize)]
struct ItemOut {
    item_id: String,
    name: String,
    production: bool,
    unconfirmed: bool,
    always_ask: bool,
}

#[derive(Serialize)]
struct ProjectOut {
    /// The key for display (shortened): the core fills in the exact key of an answer.
    key: String,
    label: String,
}

#[derive(Serialize)]
struct SettleOut {
    outcome: String,
    device_name: Option<String>,
    device_kind: Option<String>,
    kind: Option<String>,
    at: u64,
    replaced_by: Option<String>,
}

#[derive(Serialize)]
struct Waited {
    changed: bool,
}

#[derive(Serialize)]
struct Prepared {
    time: u64,
    answer_string: String,
    needs_face_id: bool,
}

#[derive(Serialize)]
struct Sent {
    id: u64,
    at: u64,
    kind: &'static str,
}

#[derive(Serialize)]
struct Registered {
    device_uuid: String,
    team_id: String,
    relay_device_id: u64,
}

#[derive(Serialize)]
struct TokenSet {
    device_id: u64,
    updated_at: u64,
}

// ---- Requests. ----

#[derive(Deserialize)]
struct Qid {
    qid: String,
}

#[derive(Deserialize)]
struct AnswerIn {
    qid: String,
    kind: String,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    project_key: Option<String>,
    #[serde(default)]
    item_id: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    time: Option<u64>,
    /// b64u DER, by the answer key (Swift, after Face ID).
    #[serde(default)]
    signature: Option<String>,
}

// ---- Errors. ----

fn no_questions() -> CoreError {
    CoreError::new(
        "no_questions",
        "Questions through the relay are off for this vault. Turn them on on the Mac, then connect this iPhone.",
    )
}

fn not_registered() -> CoreError {
    CoreError::new(
        "not_registered",
        "Turn on answers on this iPhone first: Apassy needs its answer key in the vault.",
    )
}

fn unreadable(message: &'static str) -> CoreError {
    CoreError::new("unreadable", message)
}

/// The error of a relay call for the owner (section 13, step 4).
fn call_error(error: RelayCallError) -> CoreError {
    match error {
        RelayCallError::Unreachable => SyncError::RelayUnreachable.into(),
        RelayCallError::Sync(error) => error.into(),
        RelayCallError::Relay { status, code } => match (status, code.as_str()) {
            (409, "question_settled") => {
                CoreError::new("already_answered", "Already answered on another device.")
            }
            (409, "question_expired") | (404, _) => {
                CoreError::new("expired", "This question expired.")
            }
            (403, "not_routed") => {
                CoreError::new("not_routed", "This device cannot answer this question.")
            }
            (403, "too_many_answers") => CoreError::new(
                "too_many_answers",
                "This iPhone answered this question three times. Answer on the Mac.",
            ),
            (409, "push_unavailable") => CoreError::new(
                "push_unavailable",
                "This relay sends no notifications. Questions show while Apassy is open.",
            ),
            (401, _) => SyncError::RemovedFromRelay.into(),
            (413, _) => CoreError::new("too_large", "The answer is too large for the relay."),
            (429, _) => CoreError::new(
                "rate_limited",
                "The relay asks Apassy to wait. Try again later.",
            ),
            (503, _) | (500..=599, _) => SyncError::RelayUnreachable.into(),
            _ => CoreError::internal("The relay refused the request."),
        },
    }
}

/// A random UUID (version 4), 36 lowercase characters.
fn new_uuid() -> CoreResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CoreError::io())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// The membership that carries the questions of `vault`: the one with the purpose
/// `questions`, else the relay sync membership.
fn questions_membership(vault: &Vault) -> CoreResult<Option<RelayMembership>> {
    let mut memberships = vault.relay_memberships()?;
    let at = memberships
        .iter()
        .position(|m| m.purposes.contains(&MembershipPurpose::Questions))
        .or_else(|| {
            memberships
                .iter()
                .position(|m| m.purposes.contains(&MembershipPurpose::Sync))
        });
    Ok(at.map(|at| memberships.swap_remove(at)))
}

/// This iPhone's row: the live trusted device whose `sign_key` is the key of the
/// membership.
fn own_device(vault: &Vault, sign_key: &[u8]) -> CoreResult<Option<TrustedDevice>> {
    Ok(vault
        .trusted_devices()?
        .into_iter()
        .find(|device| device.sign_key == sign_key))
}

/// The question key of the vault with its `key_id` (`Vault::question_key`, the one API
/// of the key). A row of another length is no key here: the iPhone never makes one.
fn question_key(vault: &Vault) -> CoreResult<Option<(String, Zeroizing<Vec<u8>>)>> {
    match vault.question_key() {
        Ok(key) => Ok(key.map(|key| (key.key_id(), Zeroizing::new(key.bytes().to_vec())))),
        Err(error) if error.kind() == apassy::vault::VaultErrorKind::Storage => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// What a check of the cards needs from the vault, read under the vault mutex.
struct Keys {
    team_id: String,
    device_id: u64,
    key: Option<(String, Zeroizing<Vec<u8>>)>,
    devices: Vec<TrustedDevice>,
    own: Option<TrustedDevice>,
}

/// A card that passed every check of section 7.3, with its record.
struct Opened {
    record: Record,
    card: envelope::Card,
}

impl Keys {
    /// Open and check the card of `record` (section 7.3).
    fn open(&self, record: &Record) -> Result<envelope::Card, &'static str> {
        let Some((key_id, key)) = &self.key else {
            return Err(SYNC_FIRST);
        };
        if *key_id != record.key_id {
            return Err(SYNC_FIRST);
        }
        let (Some(nonce), Some(ciphertext)) =
            (decode_b64u(&record.nonce), decode_b64u(&record.ciphertext))
        else {
            return Err(READ_FAILED);
        };
        let aad = envelope::card_aad(
            &self.team_id,
            &record.qid,
            &record.key_id,
            &record.to,
            record.expires_at,
        );
        let plaintext = envelope::open(key, &nonce, &aad, &ciphertext).ok_or(READ_FAILED)?;
        let card =
            envelope::parse_card(&plaintext, &record.qid).map_err(|refusal| match refusal {
                CardRefusal::Update => UPDATE,
                CardRefusal::Unreadable => READ_FAILED,
            })?;
        // Check 5: the asker is a live trusted device of this vault, with the relay
        // device id of the record when its row has one for this team.
        let asker_ok = self.devices.iter().any(|device| {
            device.uuid == card.asker.device
                && device
                    .relay_devices
                    .get(&self.team_id)
                    .is_none_or(|id| *id == record.from_device_id)
        });
        if !asker_ok {
            return Err(READ_FAILED);
        }
        Ok(card)
    }

    /// The settle of `record`, when it opens.
    fn settle(&self, record: &Record) -> Option<envelope::Settle> {
        let sealed = record.settle.as_ref()?;
        let (key_id, key) = self.key.as_ref()?;
        if *key_id != sealed.key_id {
            return None;
        }
        let aad = envelope::settle_aad(&self.team_id, &record.qid, &sealed.key_id);
        let plaintext = envelope::open(
            key,
            &decode_b64u(&sealed.nonce)?,
            &aad,
            &decode_b64u(&sealed.ciphertext)?,
        )?;
        envelope::parse_settle(&plaintext, &record.qid)
    }
}

fn card_out(card: &envelope::Card) -> CardOut {
    let text = |value: &str| envelope::shown(value, usize::MAX);
    CardOut {
        asker_device: card.asker.device.clone(),
        created_at: card.created_at,
        run: RunOut {
            id: card.run.id.to_string(),
            agent: envelope::shown(&card.run.agent, SHOWN_NAME),
            command: card.run.command.iter().map(|arg| text(arg)).collect(),
            cwd: envelope::shown(&card.run.cwd, SHOWN_PATH),
            env_names: card.run.env_names.iter().map(|name| text(name)).collect(),
            purpose: text(&card.run.purpose),
            risk: text(&card.run.risk),
            user_request: text(&card.run.user_request),
            request_source: text(&card.run.request_source),
            agent_request: text(&card.run.agent_request),
            remember: card.run.remember.as_ref().map(|offer| RememberOut {
                pattern: text(&offer.pattern),
                approvals: offer.approvals,
                needed: offer.needed,
            }),
        },
        question: QuestionInfoOut {
            items: card
                .question
                .items
                .iter()
                .map(|item| ItemOut {
                    item_id: item.item_id.to_string(),
                    name: envelope::shown(&item.name, SHOWN_NAME),
                    production: item.production,
                    unconfirmed: item.unconfirmed,
                    always_ask: item.always_ask,
                })
                .collect(),
            project: card.question.project.as_ref().map(|project| ProjectOut {
                key: envelope::shown(&project.key, SHOWN_PATH),
                label: envelope::shown(&project.label, SHOWN_NAME),
            }),
            action: card.question.action.clone(),
            production: card.question.production,
            why: text(&card.question.why),
            valid_answers: card.question.valid_answers.clone(),
        },
        digest: card.digest.clone(),
    }
}

/// The state of `record` on this iPhone's clock: an open question past its expiry is
/// expired.
fn state_of(record: &Record, at: u64) -> &'static str {
    match record.state.as_str() {
        "settled" => "settled",
        "open" if at < record.expires_at => "open",
        _ => "expired",
    }
}

impl Core {
    pub(super) fn questions_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "questions_list" => Ok(ok(&self.questions_list()?)),
            "questions_wait" => {
                #[derive(Deserialize)]
                struct Wait {
                    timeout: u64,
                }
                let Wait { timeout } = params(request)?;
                let changed = self.questions_fetch(Duration::from_secs(timeout.clamp(1, 25)))?;
                Ok(ok(&Waited { changed }))
            }
            "question_open" => {
                let Qid { qid } = params(request)?;
                Ok(ok(&self.question_open(&qid)?))
            }
            "question_answer_string" => {
                let answer: AnswerIn = params(request)?;
                let (prepared, _) =
                    self.prepare_answer(&answer, answer.time.unwrap_or_else(now))?;
                Ok(ok(&prepared))
            }
            "question_answer" => {
                let answer: AnswerIn = params(request)?;
                Ok(ok(&self.question_answer(&answer)?))
            }
            "answer_key_register" => {
                #[derive(Deserialize)]
                struct Register {
                    public_key: String,
                }
                let Register { public_key } = params(request)?;
                Ok(ok(&self.answer_key_register(&public_key)?))
            }
            "push_token_set" => {
                #[derive(Deserialize)]
                struct Token {
                    token: String,
                    environment: String,
                    #[serde(default)]
                    bundle_id: Option<String>,
                }
                let Token {
                    token,
                    environment,
                    bundle_id,
                } = params(request)?;
                Ok(ok(&self.push_token_set(
                    &token,
                    &environment,
                    bundle_id.as_deref().unwrap_or(BUNDLE_ID),
                )?))
            }
            "push_token_clear" => {
                let member = self.questions_member()?;
                member
                    .call("DELETE", "/v1/push/token", None, Duration::ZERO)
                    .map_err(call_error)?;
                Ok(ok(&Empty {}))
            }
            "join_attach" => {
                #[derive(Deserialize)]
                struct Start {
                    link: Secret,
                    #[serde(default)]
                    device_name: Option<String>,
                }
                let Start { link, device_name } = params(request)?;
                let name = device_name
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| self.device_name.clone());
                Ok(ok(&self.attach_start(link.expose(), &name)?))
            }
            "join_attach_poll" => Ok(ok(&self.attach_poll()?)),
            "join_attach_cancel" => {
                let attaching = guard(&self.questions).attach.take();
                if let Some(attaching) = attaching {
                    let _ = attaching.pending.cancel();
                }
                Ok(ok(&Empty {}))
            }
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    /// The vault locked, suspended, or another vault was selected: end the relay calls
    /// and forget the questions. A join that waits is given up.
    pub(super) fn questions_close(&self) {
        let (member, attach) = {
            let mut state = guard(&self.questions);
            let member = state.member.take();
            let attach = state.attach.take();
            *state = State::default();
            (member, attach)
        };
        if let Some(member) = member {
            member.close();
        }
        if let Some(attach) = attach {
            let _ = attach.pending.cancel();
        }
    }

    /// The device of the questions team: the one in memory, or one from the membership
    /// of the unlocked vault.
    fn questions_member(&self) -> CoreResult<Arc<RelayMember>> {
        if let Some(member) = guard(&self.questions).member.clone() {
            return Ok(member);
        }
        let membership = self
            .with_vault(questions_membership)?
            .ok_or_else(no_questions)?;
        let member = Arc::new(RelayMember::new(
            &membership.relay_url,
            &membership.team_id,
            membership.device_id,
            membership.key_pkcs8.clone(),
        )?);
        let mut state = guard(&self.questions);
        // Lock order: the vault before the questions; the vault is not held here, so a
        // close in between wins and this member is dropped with its key.
        Ok(Arc::clone(state.member.get_or_insert(member)))
    }

    /// What the checks need from the vault.
    fn question_keys(&self) -> CoreResult<Option<Keys>> {
        self.with_vault(|vault| {
            let Some(membership) = questions_membership(vault)? else {
                return Ok(None);
            };
            Ok(Some(Keys {
                own: own_device(vault, &membership.public_key)?,
                devices: vault.trusted_devices()?,
                key: question_key(vault)?,
                team_id: membership.team_id,
                device_id: membership.device_id,
            }))
        })
    }

    /// `GET /v1/questions` from the last sequence: the new and changed questions go into
    /// the records. Returns whether any came. A long poll of `wait`.
    fn questions_fetch(&self, wait: Duration) -> CoreResult<bool> {
        let member = match self.questions_member() {
            Ok(member) => member,
            Err(error) if error.code == "no_questions" => return Ok(false),
            Err(error) => return Err(error),
        };
        let mut changed = false;
        let mut wait = wait;
        for _ in 0..MAX_PAGES {
            let since = guard(&self.questions).since;
            let seconds = wait.as_secs();
            let path = if seconds > 0 {
                format!("/v1/questions?since={since}&wait={seconds}")
            } else {
                format!("/v1/questions?since={since}")
            };
            let answer = member.call("GET", &path, None, wait).map_err(call_error)?;
            let answer: ListAnswer = serde_json::from_value(answer)
                .map_err(|_| CoreError::from(SyncError::RelayUnreachable))?;
            let more = answer.questions.len() >= 100;
            let mut state = guard(&self.questions);
            // A close or another vault in between: this answer is of the old one.
            if !state
                .member
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &member))
            {
                return Err(CoreError::locked());
            }
            if answer.seq < state.since {
                // A relay restored from a backup: read everything again.
                state.since = 0;
                state.records.clear();
                changed = true;
                wait = Duration::ZERO;
                continue;
            }
            let mut last = state.since;
            for mut record in answer.questions {
                if !envelope::valid_qid(&record.qid) || !envelope::valid_key_id(&record.key_id) {
                    continue;
                }
                last = last.max(record.seq);
                record.answered = state.records.get(&record.qid).and_then(|old| old.answered);
                state.records.insert(record.qid.clone(), record);
                changed = true;
            }
            state.since = if more { last } else { answer.seq.max(last) };
            let at = now();
            state.records.retain(|_, record| {
                let ended = record.settled_at.unwrap_or(record.expires_at);
                record.state == "open" && at < record.expires_at + KEEP_ENDED_SECONDS
                    || ended + KEEP_ENDED_SECONDS > at
            });
            if !more {
                break;
            }
            wait = Duration::ZERO;
        }
        Ok(changed)
    }

    fn questions_list(&self) -> CoreResult<ListOut> {
        let Some(keys) = self.question_keys()? else {
            return Ok(ListOut {
                status: StatusOut {
                    enabled: false,
                    team_id: None,
                    relay_device_id: None,
                    device_uuid: None,
                    answer_key: None,
                    has_key: false,
                },
                questions: Vec::new(),
            });
        };
        self.questions_fetch(Duration::ZERO)?;
        let records: Vec<Record> = guard(&self.questions).records.values().cloned().collect();
        let at = now();
        let mut questions: Vec<QuestionOut> = records
            .iter()
            .map(|record| {
                let state = state_of(record, at);
                let opened = keys.open(record);
                let settle = keys.settle(record).map(|settle| SettleOut {
                    outcome: settle.outcome,
                    device_name: settle
                        .device_name
                        .map(|name| envelope::shown(&name, SHOWN_NAME)),
                    device_kind: settle.device_kind,
                    kind: settle.kind,
                    at: settle.at,
                    replaced_by: settle.replaced_by,
                });
                let (card, problem) = match opened {
                    Ok(card) => (Some(card), None),
                    Err(problem) => (None, Some(problem)),
                };
                QuestionOut {
                    qid: record.qid.clone(),
                    state,
                    asker_name: card.as_ref().map_or_else(
                        || envelope::shown(&record.from_device_name, SHOWN_NAME),
                        |card| envelope::shown(&card.asker.name, SHOWN_NAME),
                    ),
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    problem,
                    card: card.as_ref().map(card_out),
                    settle,
                    answered: record.answered,
                }
            })
            .collect();
        questions.sort_by(|a, b| (b.created_at, &b.qid).cmp(&(a.created_at, &a.qid)));
        Ok(ListOut {
            status: StatusOut {
                enabled: true,
                team_id: Some(keys.team_id.clone()),
                relay_device_id: Some(keys.device_id),
                device_uuid: keys.own.as_ref().map(|own| own.uuid.clone()),
                answer_key: keys
                    .own
                    .as_ref()
                    .and_then(|own| own.answer_key.as_deref())
                    .map(encode_b64u),
                has_key: keys.key.is_some(),
            },
            questions,
        })
    }

    /// An open question that passed every check of section 7.3, from the records, or
    /// from the relay when it is not there yet.
    fn opened(&self, qid: &str, keys: &Keys) -> CoreResult<Opened> {
        if !envelope::valid_qid(qid) {
            return Err(CoreError::invalid("This question is not known."));
        }
        let mut record = guard(&self.questions).records.get(qid).cloned();
        if record.is_none() {
            self.questions_fetch(Duration::ZERO)?;
            record = guard(&self.questions).records.get(qid).cloned();
        }
        let record = record.ok_or_else(|| CoreError::new("expired", "This question expired."))?;
        match state_of(&record, now()) {
            "open" => {}
            "settled" => {
                return Err(CoreError::new(
                    "already_answered",
                    "Already answered on another device.",
                ));
            }
            _ => return Err(CoreError::new("expired", "This question expired.")),
        }
        let card = keys.open(&record).map_err(unreadable)?;
        Ok(Opened { record, card })
    }

    fn question_open(&self, qid: &str) -> CoreResult<QuestionOut> {
        let keys = self.question_keys()?.ok_or_else(no_questions)?;
        let Opened { record, card } = self.opened(qid, &keys)?;
        Ok(QuestionOut {
            qid: record.qid.clone(),
            state: "open",
            asker_name: envelope::shown(&card.asker.name, SHOWN_NAME),
            created_at: record.created_at,
            expires_at: record.expires_at,
            problem: None,
            card: Some(card_out(&card)),
            settle: None,
            answered: record.answered,
        })
    }

    /// The answer string of `answer` at `time`, checked against the card.
    fn prepare_answer(&self, answer: &AnswerIn, time: u64) -> CoreResult<(Prepared, Ready)> {
        let keys = self.question_keys()?.ok_or_else(no_questions)?;
        let own = keys.own.clone().ok_or_else(not_registered)?;
        let Opened { record, card } = self.opened(&answer.qid, &keys)?;
        let choice = Choice::for_card(
            &answer.kind,
            answer.action.as_deref(),
            answer.project_key.as_deref(),
            answer.item_id.as_deref(),
            answer.environment.as_deref(),
            &card,
        )
        .map_err(CoreError::invalid)?;
        let text = envelope::answer_string(
            &own.uuid,
            &keys.team_id,
            &record.qid,
            &choice,
            &card.digest,
            time,
        )
        .ok_or_else(|| CoreError::invalid("This answer cannot be sent from this iPhone."))?;
        let prepared = Prepared {
            time,
            answer_string: text,
            needs_face_id: choice.needs_face_id(),
        };
        Ok((
            prepared,
            Ready {
                keys,
                own,
                record,
                digest: card.digest,
                choice,
            },
        ))
    }

    fn question_answer(&self, answer: &AnswerIn) -> CoreResult<Sent> {
        let at = now();
        let time = answer
            .time
            .ok_or_else(|| CoreError::invalid("The answer needs its time."))?;
        if time + ANSWER_RETRY_SECONDS < at {
            return Err(CoreError::new(
                "stale_answer",
                "This answer is too old to send. Answer again.",
            ));
        }
        if time > at + 60 {
            return Err(CoreError::invalid("The answer has a time in the future."));
        }
        let (prepared, ready) = self.prepare_answer(answer, time)?;
        let member = self.questions_member()?;
        let signature = if prepared.needs_face_id {
            let answer_key = ready.own.answer_key.as_deref().ok_or_else(not_registered)?;
            let signature = answer
                .signature
                .as_deref()
                .and_then(decode_b64u)
                .ok_or_else(|| CoreError::invalid("This answer needs Face ID."))?;
            if !verify_signature(answer_key, prepared.answer_string.as_bytes(), &signature) {
                return Err(CoreError::new(
                    "not_registered",
                    "The answer key of this iPhone changed. Turn answers off and on again on this iPhone.",
                ));
            }
            signature
        } else {
            if answer.signature.is_some() {
                return Err(CoreError::invalid("This answer is signed by the core."));
            }
            if member.public_key() != ready.own.sign_key.as_slice() {
                return Err(not_registered());
            }
            member.sign(prepared.answer_string.as_bytes())?
        };
        let (key_id, key) = ready
            .keys
            .key
            .as_ref()
            .ok_or_else(|| unreadable(SYNC_FIRST))?;
        if *key_id != ready.record.key_id {
            return Err(unreadable(SYNC_FIRST));
        }
        let plaintext = Zeroizing::new(envelope::answer_plaintext(
            &ready.record.qid,
            &ready.own.uuid,
            &ready.choice,
            &ready.digest,
            time,
            &encode_b64u(&signature),
        ));
        if plaintext.len() > envelope::MAX_ANSWER_BYTES {
            return Err(CoreError::new(
                "too_large",
                "The answer is too large for the relay.",
            ));
        }
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| CoreError::io())?;
        let aad = envelope::answer_aad(
            &ready.keys.team_id,
            &ready.record.qid,
            key_id,
            ready.keys.device_id,
        );
        let sealed = envelope::seal(key, &nonce, &aad, &plaintext)
            .ok_or_else(|| CoreError::internal("The answer cannot be sealed."))?;
        let body = json!({
            "v": 1,
            "key_id": key_id,
            "nonce": encode_b64u(&nonce),
            "ciphertext": encode_b64u(&sealed),
        });
        let path = format!("/v1/questions/{}/answers", ready.record.qid);
        let result = member
            .call("POST", &path, Some(&body), Duration::ZERO)
            .map_err(call_error)?;
        #[derive(Deserialize)]
        struct Posted {
            id: u64,
            at: u64,
        }
        let posted: Posted = serde_json::from_value(result)
            .map_err(|_| CoreError::from(SyncError::RelayUnreachable))?;
        let kind = ready.choice.kind();
        if let Some(record) = guard(&self.questions).records.get_mut(&ready.record.qid) {
            record.answered = Some(kind);
        }
        Ok(Sent {
            id: posted.id,
            at: posted.at,
            kind,
        })
    }

    /// Register this iPhone in the vault with its answer key (section 5.2): its own
    /// `trusted_device` row, kind `iphone`, with the relay key of the questions team as
    /// `sign_key` and the device number in that team. The row syncs to the Macs.
    fn answer_key_register(&self, public_key: &str) -> CoreResult<Registered> {
        self.require_app()?;
        let answer_key = decode_b64u(public_key)
            .filter(|key| key.len() == 65 && key[0] == 0x04)
            .ok_or_else(|| CoreError::invalid("The answer key is not a P-256 public key."))?;
        let name = self.device_name.clone();
        self.with_vault_mut(|vault| {
            let membership = questions_membership(vault)?.ok_or_else(no_questions)?;
            register_own(vault, &membership, &name, Some(&answer_key))
        })
    }

    fn push_token_set(
        &self,
        token: &str,
        environment: &str,
        bundle_id: &str,
    ) -> CoreResult<TokenSet> {
        let valid_token = (32..=200).contains(&token.len())
            && token
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid_token {
            return Err(CoreError::invalid("The push token is not valid."));
        }
        if !matches!(environment, "development" | "production") {
            return Err(CoreError::invalid("The push environment is not valid."));
        }
        let member = self.questions_member()?;
        let body = json!({"token": token, "environment": environment, "bundle_id": bundle_id});
        let result = member
            .call("PUT", "/v1/push/token", Some(&body), Duration::ZERO)
            .map_err(call_error)?;
        serde_json::from_value::<TokenSetWire>(result)
            .map(|wire| TokenSet {
                device_id: wire.device_id,
                updated_at: wire.updated_at,
            })
            .map_err(|_| SyncError::RelayUnreachable.into())
    }

    // ---- A notifications-only team (plan §A7). ----

    fn attach_start(&self, link: &str, device_name: &str) -> CoreResult<AttachOut> {
        self.require_app()?;
        let entry = self.selected()?;
        let has_team = self.with_vault(|vault| Ok(questions_membership(vault)?.is_some()))?;
        if has_team {
            return Err(CoreError::invalid(
                "This vault gets questions through the relay already.",
            ));
        }
        let previous = guard(&self.questions).attach.take();
        if let Some(previous) = previous {
            let _ = previous.pending.cancel();
        }
        let pending = PendingJoin::request(link, DEFAULT_RELAY_URL, device_name).map_err(
            |error| match CoreError::from(error) {
                error if matches!(error.code, "removed" | "not_found") => CoreError::new(
                    "link_invalid",
                    "This link does not work: it was used, it expired, or it is not valid. Make a new link on the Mac.",
                ),
                error => error,
            },
        )?;
        let attaching = Attaching {
            vault_id: entry.id,
            team: pending.team.clone(),
            words: pending
                .safety
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            expires_at: pending.expires_at,
            pending,
        };
        let view = attaching.view("waiting");
        guard(&self.questions).attach = Some(attaching);
        Ok(view)
    }

    fn attach_poll(&self) -> CoreResult<AttachOut> {
        self.require_app()?;
        // The relay call runs with the join taken out, as `join_poll` does.
        let attaching = guard(&self.questions).attach.take().ok_or_else(|| {
            CoreError::invalid("No connection waits. Scan the code of the Mac again.")
        })?;
        let joined = match attaching.pending.poll() {
            Ok(None) => {
                let view = attaching.view("waiting");
                let mut state = guard(&self.questions);
                if state.attach.is_none() {
                    state.attach = Some(attaching);
                } else {
                    drop(state);
                    let _ = attaching.pending.cancel();
                }
                return Ok(view);
            }
            Ok(Some(joined)) => joined,
            Err(error) => {
                let error = CoreError::from(error);
                if matches!(error.code, "join_refused" | "link_invalid") {
                    let _ = attaching.pending.cancel();
                } else {
                    guard(&self.questions).attach.get_or_insert(attaching);
                }
                return Err(error);
            }
        };
        let member = joined.member();
        let stored = (|| -> CoreResult<()> {
            if self.selected()?.id != attaching.vault_id {
                return Err(CoreError::invalid("Another vault is selected now."));
            }
            let key_pkcs8 = joined
                .key_pkcs8()
                .ok_or_else(|| CoreError::internal("The device key is missing."))?;
            let device_id = member
                .device_id()
                .ok_or_else(|| CoreError::internal("The relay gave no device number."))?;
            let name = self.device_name.clone();
            self.with_vault_mut(|vault| {
                let membership = RelayMembership {
                    team_id: member.team_id().to_owned(),
                    relay_url: member.relay_url().to_owned(),
                    device_id,
                    public_key: member.public_key().to_vec(),
                    key_pkcs8,
                    purposes: BTreeSet::from([MembershipPurpose::Questions]),
                    created_at: 0,
                };
                vault.add_relay_membership(&membership)?;
                register_own(vault, &membership, &name, None).map(|_| ())
            })
        })();
        if let Err(error) = stored {
            // The vault does not hold the key: the device leaves the team again.
            joined.cancel();
            return Err(error);
        }
        let mut state = guard(&self.questions);
        state.member = Some(Arc::new(member));
        state.since = 0;
        state.records.clear();
        Ok(attaching.view("attached"))
    }
}

#[derive(Deserialize)]
struct TokenSetWire {
    device_id: u64,
    updated_at: u64,
}

/// An answer that passed the checks, ready to sign and seal.
struct Ready {
    keys: Keys,
    own: TrustedDevice,
    record: Record,
    digest: String,
    choice: Choice,
}

/// Register or update this iPhone's own `trusted_device` row for `membership`, and its
/// device number in the team. A row of this key keeps its UUID; a new one gets a new
/// UUID. An earlier answer key stays when `answer_key` is `None`.
fn register_own(
    vault: &mut Vault,
    membership: &RelayMembership,
    name: &str,
    answer_key: Option<&[u8]>,
) -> CoreResult<Registered> {
    let existing = own_device(vault, &membership.public_key)?;
    let uuid = match &existing {
        Some(device) => device.uuid.clone(),
        None => new_uuid()?,
    };
    let answer_key = answer_key.or_else(|| {
        existing
            .as_ref()
            .and_then(|device| device.answer_key.as_deref())
    });
    vault
        .register_trusted_device(
            &uuid,
            name,
            TrustedDeviceKind::Iphone,
            &membership.public_key,
            answer_key,
        )
        .map_err(|error| match error.kind() {
            VaultErrorKind::InvalidInput => {
                CoreError::invalid("The name of this iPhone or its key cannot be saved.")
            }
            _ => error.into(),
        })?;
    vault
        .set_trusted_device_relay_id(&uuid, &membership.team_id, membership.device_id)
        .map_err(|error| match error.kind() {
            VaultErrorKind::AlreadyExists => {
                CoreError::invalid("Another device of this vault has the same number on the relay.")
            }
            _ => error.into(),
        })?;
    Ok(Registered {
        device_uuid: uuid,
        team_id: membership.team_id.clone(),
        relay_device_id: membership.device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uuids_have_the_device_form() {
        let one = new_uuid().unwrap();
        assert!(envelope::valid_device_uuid(&one), "{one}");
        assert_ne!(one, new_uuid().unwrap());
    }

    #[test]
    fn relay_refusals_have_their_codes() {
        let code = |status, code: &str| {
            call_error(RelayCallError::Relay {
                status,
                code: code.to_owned(),
            })
            .code
        };
        assert_eq!(code(409, "question_settled"), "already_answered");
        assert_eq!(code(409, "question_expired"), "expired");
        assert_eq!(code(403, "not_routed"), "not_routed");
        assert_eq!(code(403, "too_many_answers"), "too_many_answers");
        assert_eq!(code(409, "push_unavailable"), "push_unavailable");
        assert_eq!(code(503, "busy"), "relay_unreachable");
        assert_eq!(
            call_error(RelayCallError::Unreachable).code,
            "relay_unreachable"
        );
    }
}
