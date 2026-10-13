//! Questions through the relay, the iPhone side (contract relay-questions-v1, sections
//! 5, 7, 9, 10, and 13; contract ios-core-v1 section 5.10).
//!
//! The iPhone is an answering device. It reads the open questions of the questions team
//! of each vault it holds, opens each card with the question key of that vault, checks
//! it, and posts the owner's answer, sealed with the same key and signed:
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
//! One iPhone answers for several Macs with several vaults. The core holds one unlocked
//! vault, so it keeps a **context** for each vault that was unlocked in this session
//! (an `unlock`, or `questions_unlock`): the relay device of its questions team with its
//! key, the question key, the trusted devices, this iPhone's row, and the questions the
//! relay returned. A context holds no item and no passphrase. A selection keeps every
//! context; a `lock`, a `suspend`, `remove_vault`, and the end of the process drop them
//! all. The context of the selected vault is read again from the vault while it is
//! unlocked; the context of another vault keeps what its vault held when it was open.
//!
//! The iPhone never writes its own `trusted_device` row. It sends its answer key with the
//! link (in the device name, `apassy::questions::device_link`), and the Mac that confirms
//! the link writes the row during its owner check. The row reaches the iPhone with the
//! sync of the vault; until then the iPhone reads questions but cannot answer, and
//! `answer_key_register` only checks that the row holds this answer key. A removed row
//! (the owner removed this iPhone on a Mac) is final: the iPhone says so and needs a new
//! `join_attach` with a new relay key, confirmed on a Mac.
//!
//! The relay calls run without the vault mutex. A lock ends them ([`Core::close`]).

mod envelope;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use apassy::sync::{
    Cancel, DEFAULT_RELAY_URL, PendingJoin, RelayCallError, RelayMember, SyncError, decode_b64u,
    encode_b64u, verify_signature,
};
use apassy::vault::{MembershipPurpose, RelayMembership, TrustedDevice, Vault};

use envelope::{CardRefusal, Choice};

use super::config::write_private;
use super::errors::{CoreError, CoreResult};
use super::wire::{Empty, Secret, ok, params};
use super::{Core, Role, guard, now};

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
/// The vaults whose questions team may still hold the push token of this iPhone after
/// `push_token_clear`: vault IDs only, no secret. The token is cleared there when the
/// vault opens.
const PUSH_FILE: &str = "questions-push.json";

const READ_FAILED: &str = "This question could not be read.";
const UPDATE: &str = "Update Apassy to read this question.";
const SYNC_FIRST: &str = "Sync this vault to read this question.";

/// The questions of this process: a context for each vault unlocked in this session.
#[derive(Default)]
pub struct State {
    /// By vault ID.
    contexts: BTreeMap<String, Context>,
    /// A join of a notifications-only team that waits for the Mac.
    attach: Option<Attaching>,
    /// The long polls of `questions_wait` over several contexts: a drop ends them.
    waits: Vec<Arc<Cancel>>,
    /// Counts each drop of every context. A `questions_unlock` keeps its context only when
    /// no drop came during its key derivation.
    drops: u64,
    /// The push token of `push_token_set` in this process: a context made later gets it.
    push: Option<PushToken>,
    /// The vaults of [`PUSH_FILE`].
    push_clear: BTreeSet<String>,
}

/// What the questions of one vault need, kept while the app runs.
struct Context {
    /// The device of the questions team, with its key in memory.
    member: Arc<RelayMember>,
    /// What the checks of the cards need, read from the vault.
    keys: Arc<Keys>,
    /// The last question sequence seen (section 10.4).
    since: u64,
    /// The questions that the relay returned, by `qid`.
    records: BTreeMap<String, Record>,
    /// A push token change that this team still needs.
    push_due: Option<PushDue>,
    /// The code of the last failed relay call, until one works.
    error: Option<&'static str>,
}

#[derive(Clone)]
struct PushToken {
    token: String,
    environment: String,
    bundle_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PushDue {
    Set,
    Clear,
}

#[derive(Serialize, Deserialize)]
struct PushFile {
    version: u32,
    clear: BTreeSet<String>,
}

impl State {
    /// The state of a new process, with the vaults of [`PUSH_FILE`].
    pub(super) fn load(data_dir: &Path) -> Self {
        let clear = std::fs::read(data_dir.join(PUSH_FILE))
            .ok()
            .and_then(|text| serde_json::from_slice::<PushFile>(&text).ok())
            .filter(|file| file.version == 1)
            .map(|file| {
                file.clear
                    .into_iter()
                    .filter(|id| super::config::valid_id(id))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            push_clear: clear,
            ..Self::default()
        }
    }

    /// The context of `vault_id` while it still has the device `member`: a drop or a new
    /// membership in between ends the call that used it.
    fn context_mut(
        &mut self,
        vault_id: &str,
        member: &Arc<RelayMember>,
    ) -> CoreResult<&mut Context> {
        self.contexts
            .get_mut(vault_id)
            .filter(|context| Arc::ptr_eq(&context.member, member))
            .ok_or_else(CoreError::locked)
    }

    /// Keep the context of `vault_id` with new `keys`. Another device of the questions
    /// team (another membership) starts a new context.
    fn keep(
        &mut self,
        vault_id: &str,
        keys: Keys,
        public_key: &[u8],
        member: impl FnOnce() -> CoreResult<RelayMember>,
    ) -> CoreResult<()> {
        if let Some(context) = self.contexts.get_mut(vault_id)
            && context.keys.team_id == keys.team_id
            && context.keys.device_id == keys.device_id
            && context.member.public_key() == public_key
        {
            context.keys = Arc::new(keys);
            return Ok(());
        }
        self.put(vault_id, Arc::new(member()?), keys);
        Ok(())
    }

    /// A new context of `vault_id` with the device `member`.
    fn put(&mut self, vault_id: &str, member: Arc<RelayMember>, keys: Keys) {
        let push_due = if self.push.is_some() {
            Some(PushDue::Set)
        } else if self.push_clear.contains(vault_id) {
            Some(PushDue::Clear)
        } else {
            None
        };
        let context = Context {
            member,
            keys: Arc::new(keys),
            since: 0,
            records: BTreeMap::new(),
            push_due,
            error: None,
        };
        if let Some(old) = self.contexts.insert(vault_id.to_owned(), context) {
            old.member.close();
        }
    }

    /// Forget the context of `vault_id`: its vault has no questions team now. Returns
    /// whether [`PUSH_FILE`] changed.
    fn forget(&mut self, vault_id: &str) -> bool {
        if let Some(old) = self.contexts.remove(vault_id) {
            old.member.close();
        }
        self.push_clear.remove(vault_id)
    }

    /// The vaults whose context holds `qid`.
    fn owners(&self, qid: &str) -> Vec<String> {
        self.contexts
            .iter()
            .filter(|(_, context)| context.records.contains_key(qid))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// What a close took out of the questions, ended after the locks are released.
#[must_use]
pub(super) struct Ended {
    members: Vec<Arc<RelayMember>>,
    waits: Vec<Arc<Cancel>>,
    attach: Option<Attaching>,
}

impl Ended {
    pub(super) fn finish(self) {
        for member in self.members {
            member.close();
        }
        for wait in self.waits {
            wait.close();
        }
        if let Some(attach) = self.attach {
            let _ = attach.pending.cancel();
        }
    }
}

/// The selected vault, as the questions calls see it.
enum Selected {
    Unlocked(String),
    Locked(String),
    None,
}

impl Selected {
    fn id(&self) -> Option<&str> {
        match self {
            Self::Unlocked(id) | Self::Locked(id) => Some(id),
            Self::None => None,
        }
    }

    /// Why a call that needs a context of the selected vault has none.
    fn missing(&self) -> CoreError {
        match self {
            Self::Unlocked(_) => no_questions(),
            Self::Locked(_) => CoreError::locked(),
            Self::None => CoreError::no_vault(),
        }
    }
}

/// The device, the keys, and the vault of one context, for one call.
struct Using {
    vault_id: String,
    member: Arc<RelayMember>,
    keys: Arc<Keys>,
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
    /// The team of a removed membership of this iPhone that the new key replaces.
    replaces: Option<String>,
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
    /// Whether the vault holds the row of this iPhone (written by the Mac that confirmed
    /// it). Without it the iPhone cannot answer yet.
    registered: bool,
    /// The owner removed this iPhone on a Mac: it needs a new `join_attach`.
    removed: bool,
}

impl StatusOut {
    fn off() -> Self {
        Self {
            enabled: false,
            team_id: None,
            relay_device_id: None,
            device_uuid: None,
            answer_key: None,
            has_key: false,
            registered: false,
            removed: false,
        }
    }

    fn of(keys: &Keys) -> Self {
        Self {
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
            registered: keys.own.is_some(),
            removed: keys.is_removed(),
        }
    }
}

#[derive(Serialize)]
struct ListOut {
    /// The selected vault, as before several vaults (an older app reads only this).
    status: StatusOut,
    /// One entry for each context.
    vaults: Vec<VaultOut>,
    /// The questions of every context, newest first.
    questions: Vec<QuestionOut>,
}

#[derive(Serialize)]
struct VaultOut {
    vault_id: String,
    vault_name: String,
    selected: bool,
    /// The vault is open now: its keys are read from it at each call. Else they are
    /// those of its last unlock in this session.
    unlocked: bool,
    status: StatusOut,
    /// The code of the last failed relay call of this vault, until one works.
    error: Option<&'static str>,
}

#[derive(Serialize)]
struct QuestionOut {
    qid: String,
    /// The vault whose questions team carries the question; an answer goes to it.
    vault_id: String,
    vault_name: String,
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
    /// Of the selected vault when its team took the token, else of the first that did.
    device_id: u64,
    updated_at: u64,
    vaults: Vec<PushOut>,
}

#[derive(Serialize)]
struct PushOut {
    vault_id: String,
    device_id: Option<u64>,
    updated_at: Option<u64>,
    /// The code of the failure; the core tries again at the next relay call of the vault.
    error: Option<&'static str>,
}

#[derive(Serialize)]
struct TokenCleared {
    /// The vaults whose team dropped the token now.
    cleared: Vec<String>,
    /// The vaults whose team may still hold it: cleared when the vault opens.
    pending: Vec<String>,
}

#[derive(Serialize)]
struct VaultOpened {
    vault_id: String,
    status: StatusOut,
}

// ---- Requests. ----

#[derive(Deserialize)]
struct Qid {
    qid: String,
    #[serde(default)]
    vault_id: Option<String>,
}

#[derive(Deserialize)]
struct AnswerIn {
    qid: String,
    /// The vault of the question (`Question.vault_id`). Without it, the vault whose
    /// context holds `qid`.
    #[serde(default)]
    vault_id: Option<String>,
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
        "This iPhone cannot answer yet: the Mac that confirmed it writes its keys into the vault, and the vault must sync to this iPhone first.",
    )
}

fn removed() -> CoreError {
    CoreError::new(
        "removed",
        "This device was removed from questions. To answer again, connect it again with a new link from a Mac.",
    )
}

fn answer_key_changed() -> CoreError {
    CoreError::new(
        "answer_key_changed",
        "The answer key of this iPhone changed. On a Mac, remove this iPhone in Settings > Devices, then connect it again.",
    )
}

/// The `device_name` of a link that carries the answer key `answer_key` (b64u, X9.63):
/// the confirming Mac writes the row of this iPhone from it.
pub(super) fn link_name_with_key(name: &str, answer_key: &str) -> CoreResult<String> {
    decode_b64u(answer_key)
        .and_then(|key| apassy::questions::device_link::link_device_name(name, &key))
        .ok_or_else(|| CoreError::invalid("The answer key is not a P-256 public key."))
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

/// What a check of the cards needs from the vault, read under the vault mutex and kept
/// in the context of the vault.
struct Keys {
    team_id: String,
    device_id: u64,
    key: Option<(String, Zeroizing<Vec<u8>>)>,
    devices: Vec<TrustedDevice>,
    own: Option<TrustedDevice>,
    /// The key of the membership is the key of a removed device.
    removed: bool,
}

impl Keys {
    /// The key of the membership belongs to a removed row: the owner took this iPhone
    /// out, and it asks the relay nothing.
    fn is_removed(&self) -> bool {
        self.own.is_none() && self.removed
    }

    /// This iPhone's row, or why it cannot answer.
    fn own_row(&self) -> CoreResult<TrustedDevice> {
        match &self.own {
            Some(own) => Ok(own.clone()),
            None if self.removed => Err(removed()),
            None => Err(not_registered()),
        }
    }
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

fn wrong_vault() -> CoreError {
    CoreError::new(
        "wrong_vault",
        "This question is of another vault. Answer it from the list of questions.",
    )
}

/// A vault on this iPhone without a context: it was not unlocked in this session.
fn not_open(known: bool) -> CoreError {
    if known {
        CoreError::new(
            "locked",
            "Unlock this vault on this iPhone to read its questions.",
        )
    } else {
        CoreError::new("no_vault", "This vault is not on this iPhone.")
    }
}

/// The membership of the questions team of `vault` and what the checks need, or None
/// when the vault has no questions team.
fn read_keys(vault: &Vault) -> CoreResult<Option<(RelayMembership, Keys)>> {
    let Some(membership) = questions_membership(vault)? else {
        return Ok(None);
    };
    let keys = Keys {
        own: own_device(vault, &membership.public_key)?,
        removed: vault.trusted_key_removed(&membership.public_key)?,
        devices: vault.trusted_devices()?,
        key: question_key(vault)?,
        team_id: membership.team_id.clone(),
        device_id: membership.device_id,
    };
    Ok(Some((membership, keys)))
}

fn member_of(membership: &RelayMembership) -> CoreResult<RelayMember> {
    Ok(RelayMember::new(
        &membership.relay_url,
        &membership.team_id,
        membership.device_id,
        membership.key_pkcs8.clone(),
    )?)
}

fn settle_out(settle: envelope::Settle) -> SettleOut {
    SettleOut {
        outcome: settle.outcome,
        device_name: settle
            .device_name
            .map(|name| envelope::shown(&name, SHOWN_NAME)),
        device_kind: settle.device_kind,
        kind: settle.kind,
        at: settle.at,
        replaced_by: settle.replaced_by,
    }
}

/// The question of `record` in the list, with its card when every check passed.
fn question_out(
    vault_id: &str,
    vault_name: &str,
    keys: &Keys,
    record: &Record,
    at: u64,
) -> QuestionOut {
    let (card, problem) = match keys.open(record) {
        Ok(card) => (Some(card), None),
        Err(problem) => (None, Some(problem)),
    };
    QuestionOut {
        qid: record.qid.clone(),
        vault_id: vault_id.to_owned(),
        vault_name: vault_name.to_owned(),
        state: state_of(record, at),
        asker_name: card.as_ref().map_or_else(
            || envelope::shown(&record.from_device_name, SHOWN_NAME),
            |card| envelope::shown(&card.asker.name, SHOWN_NAME),
        ),
        created_at: record.created_at,
        expires_at: record.expires_at,
        problem,
        card: card.as_ref().map(card_out),
        settle: keys.settle(record).map(settle_out),
        answered: record.answered,
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
                let changed = self.questions_wait(Duration::from_secs(timeout.clamp(1, 25)))?;
                Ok(ok(&Waited { changed }))
            }
            "questions_unlock" => {
                #[derive(Deserialize)]
                struct Unlock {
                    vault_id: String,
                    passphrase: Secret,
                }
                let Unlock {
                    vault_id,
                    passphrase,
                } = params(request)?;
                Ok(ok(&self.questions_unlock(&vault_id, passphrase.expose())?))
            }
            "question_open" => {
                let Qid { qid, vault_id } = params(request)?;
                Ok(ok(&self.question_open(&qid, vault_id.as_deref())?))
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
                    #[serde(default)]
                    vault_id: Option<String>,
                }
                let Register {
                    public_key,
                    vault_id,
                } = params(request)?;
                Ok(ok(
                    &self.answer_key_register(&public_key, vault_id.as_deref())?
                ))
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
            "push_token_clear" => Ok(ok(&self.push_token_clear()?)),
            "join_attach" => {
                #[derive(Deserialize)]
                struct Start {
                    link: Secret,
                    #[serde(default)]
                    device_name: Option<String>,
                    /// The answer key (b64u, X9.63). It goes with the link: the Mac
                    /// that confirms writes the row of this iPhone from it.
                    #[serde(default)]
                    answer_key: Option<String>,
                }
                let Start {
                    link,
                    device_name,
                    answer_key,
                } = params(request)?;
                let name = device_name
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| self.device_name.clone());
                let answer_key = answer_key.ok_or_else(|| {
                    CoreError::invalid("Connecting this iPhone needs its answer key.")
                })?;
                let name = link_name_with_key(&name, &answer_key)?;
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

    // ---- The contexts. ----

    /// A lock, a suspend, a removal, or the end of the process: drop the context of
    /// every vault. Called under the vault mutex, so no context of the vault that closes
    /// comes back; the caller ends the relay calls with [`Ended::finish`] after it.
    pub(super) fn questions_drop_all(&self) -> Ended {
        let mut state = guard(&self.questions);
        state.drops += 1;
        let members = std::mem::take(&mut state.contexts)
            .into_values()
            .map(|context| context.member)
            .collect();
        Ended {
            members,
            waits: std::mem::take(&mut state.waits),
            attach: state.attach.take(),
        }
    }

    /// Another vault is selected or opens: the contexts stay, a join that waits is given
    /// up (it is of the selected vault).
    pub(super) fn questions_switch(&self) -> Ended {
        Ended {
            members: Vec::new(),
            waits: Vec::new(),
            attach: guard(&self.questions).attach.take(),
        }
    }

    /// Keep the context of the selected vault from `vault`, open and unlocked. Called
    /// under the vault mutex (lock order: the vault, the list, then the questions).
    pub(super) fn questions_capture(&self, vault: &Vault) -> CoreResult<()> {
        if self.role != Role::App {
            return Ok(());
        }
        let Some(vault_id) = guard(&self.list).selected.clone() else {
            return Ok(());
        };
        let read = read_keys(vault)?;
        let mut state = guard(&self.questions);
        match read {
            Some((membership, keys)) => state.keep(&vault_id, keys, &membership.public_key, || {
                member_of(&membership)
            }),
            None => {
                if state.forget(&vault_id) {
                    self.save_push(&state);
                }
                Ok(())
            }
        }
    }

    /// The selected vault, with its context read again from it while it is unlocked.
    fn questions_refresh(&self) -> CoreResult<Selected> {
        let slot = guard(&self.vault);
        let selected = guard(&self.list).selected.clone();
        let Some(id) = selected else {
            return Ok(Selected::None);
        };
        match slot.as_ref() {
            Some(vault) if !vault.is_locked() => {
                self.questions_capture(vault)?;
                Ok(Selected::Unlocked(id))
            }
            _ => Ok(Selected::Locked(id)),
        }
    }

    /// The context of `vault_id`, else of the selected vault.
    fn context_of(&self, vault_id: Option<&str>, selected: &Selected) -> CoreResult<Using> {
        let id = match vault_id {
            Some(id) => id,
            None => selected.id().ok_or_else(CoreError::no_vault)?,
        };
        let found = guard(&self.questions)
            .contexts
            .get(id)
            .map(|context| Using {
                vault_id: id.to_owned(),
                member: Arc::clone(&context.member),
                keys: Arc::clone(&context.keys),
            });
        match found {
            Some(using) => Ok(using),
            None if vault_id.is_none() || selected.id() == Some(id) => Err(selected.missing()),
            None => Err(not_open(guard(&self.list).get(id).is_some())),
        }
    }

    /// The context that answers `qid`: the one that holds it. `vault_id`, when given,
    /// must name that context: an answer never goes out with the keys of another vault.
    fn context_for(&self, qid: &str, vault_id: Option<&str>) -> CoreResult<Using> {
        if let Some(id) = vault_id
            && guard(&self.list).get(id).is_none()
        {
            return Err(not_open(false));
        }
        let selected = self.questions_refresh()?;
        let mut owners = guard(&self.questions).owners(qid);
        if owners.is_empty() && envelope::valid_qid(qid) {
            let any = !guard(&self.questions).contexts.is_empty();
            if any {
                self.questions_fetch(Duration::ZERO, false)?;
                owners = guard(&self.questions).owners(qid);
            }
        }
        match (vault_id, owners.as_slice()) {
            (Some(id), owners) if owners.is_empty() || owners.iter().any(|owner| owner == id) => {
                self.context_of(Some(id), &selected)
            }
            (Some(_), _) => Err(wrong_vault()),
            (None, [owner]) => self.context_of(Some(owner), &selected),
            (None, []) => {
                // A question that no context holds: the context of the selected vault
                // says why (it expired, or this iPhone was removed), else any context.
                let first = guard(&self.questions).contexts.keys().next().cloned();
                match (self.context_of(None, &selected), first) {
                    (Err(_), Some(first)) => self.context_of(Some(&first), &selected),
                    (found, _) => found,
                }
            }
            (None, _) => Err(CoreError::invalid(
                "Two vaults have a question with this ID. Name the vault of the answer.",
            )),
        }
    }

    /// Write [`PUSH_FILE`]. The app only; a failure leaves the old list (the core tries
    /// again at the next change).
    fn save_push(&self, state: &State) {
        if self.role != Role::App {
            return;
        }
        let file = PushFile {
            version: 1,
            clear: state.push_clear.clone(),
        };
        if let Ok(text) = serde_json::to_vec(&file) {
            let _ = write_private(&self.paths.data_dir, PUSH_FILE, &text);
        }
    }

    /// A context of the vault `vault_id` from its passphrase, without selecting or
    /// opening it for the other calls: the vault opens for the reads and closes again.
    fn questions_unlock(&self, vault_id: &str, passphrase: &str) -> CoreResult<VaultOpened> {
        if guard(&self.list).get(vault_id).is_none() {
            return Err(not_open(false));
        }
        let selected = self.questions_refresh()?;
        let status = |state: &State| {
            state
                .contexts
                .get(vault_id)
                .map_or_else(StatusOut::off, |context| StatusOut::of(&context.keys))
        };
        if matches!(&selected, Selected::Unlocked(id) if id == vault_id) {
            return Ok(VaultOpened {
                vault_id: vault_id.to_owned(),
                status: status(&guard(&self.questions)),
            });
        }
        let drops = guard(&self.questions).drops;
        let mut vault = Vault::open(&self.paths.vault_file(vault_id))?;
        let read = vault
            .unlock(passphrase)
            .map_err(CoreError::from)
            .and_then(|()| read_keys(&vault));
        let _ = vault.lock();
        drop(vault);
        let read = read?;
        let member = match &read {
            Some((membership, _)) => Some(member_of(membership)?),
            None => None,
        };
        let mut state = guard(&self.questions);
        if state.drops != drops {
            // A lock came during the key derivation.
            drop(state);
            if let Some(member) = member {
                member.close();
            }
            return Err(CoreError::locked());
        }
        match (read, member) {
            (Some((membership, keys)), Some(member)) => {
                let mut member = Some(member);
                state.keep(vault_id, keys, &membership.public_key, || {
                    member
                        .take()
                        .ok_or_else(|| CoreError::internal("The device is missing."))
                })?;
                if let Some(unused) = member {
                    unused.close();
                }
            }
            _ => {
                if state.forget(vault_id) {
                    self.save_push(&state);
                }
            }
        }
        Ok(VaultOpened {
            vault_id: vault_id.to_owned(),
            status: status(&state),
        })
    }

    // ---- Reading the questions. ----

    /// The contexts that ask the relay: all but those of a removed iPhone.
    fn fetch_targets(&self) -> Vec<(String, Arc<RelayMember>)> {
        guard(&self.questions)
            .contexts
            .iter()
            .filter(|(_, context)| !context.keys.is_removed())
            .map(|(id, context)| (id.clone(), Arc::clone(&context.member)))
            .collect()
    }

    /// `questions_wait`: one long poll for each context at the same time; the first
    /// that brings news ends the others.
    fn questions_wait(&self, wait: Duration) -> CoreResult<bool> {
        let selected = self.questions_refresh()?;
        if guard(&self.questions).contexts.is_empty() {
            return match selected {
                Selected::Unlocked(_) => Ok(false),
                other => Err(other.missing()),
            };
        }
        self.questions_fetch(wait, true)
    }

    /// Read the questions of every context: `GET /v1/questions` from its last sequence,
    /// with a long poll of `wait`. With `early`, the first context with news ends the
    /// long polls of the others. Returns whether any came; an error only when every
    /// context failed.
    fn questions_fetch(&self, wait: Duration, early: bool) -> CoreResult<bool> {
        let targets = self.fetch_targets();
        let drops = guard(&self.questions).drops;
        let results: Vec<(String, Arc<RelayMember>, CoreResult<bool>)> = match targets.as_slice() {
            [] => return Ok(false),
            // One context: a lock ends its call through the device.
            [(id, member)] => {
                let result = self.fetch_one(id, member, wait, None);
                vec![(id.clone(), Arc::clone(member), result)]
            }
            _ => {
                let cancel = Arc::new(Cancel::default());
                guard(&self.questions).waits.push(Arc::clone(&cancel));
                let results = std::thread::scope(|scope| {
                    let running: Vec<_> = targets
                        .iter()
                        .map(|(id, member)| {
                            let cancel = &cancel;
                            scope.spawn(move || {
                                let result = self.fetch_one(id, member, wait, Some(cancel));
                                if early && matches!(result, Ok(true)) {
                                    cancel.close();
                                }
                                match result {
                                    // Ended by the news of another context.
                                    Err(_) if cancel.is_closed() => Ok(false),
                                    other => other,
                                }
                            })
                        })
                        .collect();
                    running
                        .into_iter()
                        .zip(&targets)
                        .map(|(running, (id, member))| {
                            let result = running.join().unwrap_or_else(|_| {
                                Err(CoreError::internal("The questions could not be read."))
                            });
                            (id.clone(), Arc::clone(member), result)
                        })
                        .collect()
                });
                guard(&self.questions)
                    .waits
                    .retain(|held| !Arc::ptr_eq(held, &cancel));
                results
            }
        };
        let mut state = guard(&self.questions);
        if state.drops != drops {
            return Err(CoreError::locked());
        }
        let mut changed = false;
        let mut worked = false;
        let mut failed = None;
        for (id, member, result) in results {
            let error = match result {
                Ok(news) => {
                    changed |= news;
                    worked = true;
                    None
                }
                Err(error) => {
                    let code = error.code;
                    failed.get_or_insert(error);
                    Some(code)
                }
            };
            if let Ok(context) = state.context_mut(&id, &member) {
                context.error = error;
            }
        }
        match failed {
            Some(error) if !worked => Err(error),
            _ => Ok(changed),
        }
    }

    /// The questions of one context, as [`Self::questions_fetch`]. A push token change
    /// that the team still needs goes first.
    fn fetch_one(
        &self,
        vault_id: &str,
        member: &Arc<RelayMember>,
        wait: Duration,
        cancel: Option<&Cancel>,
    ) -> CoreResult<bool> {
        self.push_due(vault_id, member);
        let mut changed = false;
        let mut wait = wait;
        for _ in 0..MAX_PAGES {
            let since = guard(&self.questions).context_mut(vault_id, member)?.since;
            let seconds = wait.as_secs();
            let path = if seconds > 0 {
                format!("/v1/questions?since={since}&wait={seconds}")
            } else {
                format!("/v1/questions?since={since}")
            };
            let answer = member
                .call_until("GET", &path, None, wait, cancel)
                .map_err(call_error)?;
            let answer: ListAnswer = serde_json::from_value(answer)
                .map_err(|_| CoreError::from(SyncError::RelayUnreachable))?;
            let more = answer.questions.len() >= 100;
            let mut state = guard(&self.questions);
            // A close or another membership in between: this answer is of the old one.
            let context = state.context_mut(vault_id, member)?;
            if answer.seq < since {
                // A relay restored from a backup: read everything again.
                context.since = 0;
                context.records.clear();
                changed = true;
                wait = Duration::ZERO;
                continue;
            }
            let mut last = since;
            for mut record in answer.questions {
                if !envelope::valid_qid(&record.qid) || !envelope::valid_key_id(&record.key_id) {
                    continue;
                }
                last = last.max(record.seq);
                if let Some(old) = context.records.get(&record.qid) {
                    // A call that ran at the same time brought a newer state.
                    if old.seq > record.seq {
                        continue;
                    }
                    record.answered = old.answered;
                }
                context.records.insert(record.qid.clone(), record);
                changed = true;
            }
            let next = if more { last } else { answer.seq.max(last) };
            context.since = context.since.max(next);
            let at = now();
            context.records.retain(|_, record| {
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
        let selected = self.questions_refresh()?;
        if guard(&self.questions).contexts.is_empty() {
            return match selected {
                Selected::Unlocked(_) => Ok(ListOut {
                    status: StatusOut::off(),
                    vaults: Vec::new(),
                    questions: Vec::new(),
                }),
                other => Err(other.missing()),
            };
        }
        self.questions_fetch(Duration::ZERO, false)?;
        let names: BTreeMap<String, String> = guard(&self.list)
            .vaults
            .iter()
            .map(|entry| (entry.id.clone(), entry.name.clone()))
            .collect();
        // The cards open without the mutex.
        type Snapshot = (String, Arc<Keys>, Vec<Record>, Option<&'static str>);
        let copies: Vec<Snapshot> = guard(&self.questions)
            .contexts
            .iter()
            .map(|(id, context)| {
                (
                    id.clone(),
                    Arc::clone(&context.keys),
                    context.records.values().cloned().collect(),
                    context.error,
                )
            })
            .collect();
        let at = now();
        let mut status = StatusOut::off();
        let mut vaults = Vec::new();
        let mut questions = Vec::new();
        for (id, keys, records, error) in copies {
            let name = names.get(&id).cloned().unwrap_or_default();
            let is_selected = selected.id() == Some(id.as_str());
            if is_selected {
                status = StatusOut::of(&keys);
            }
            // A removed iPhone shows no question of that vault.
            if !keys.is_removed() {
                questions.extend(
                    records
                        .iter()
                        .map(|record| question_out(&id, &name, &keys, record, at)),
                );
            }
            vaults.push(VaultOut {
                unlocked: is_selected && matches!(selected, Selected::Unlocked(_)),
                selected: is_selected,
                status: StatusOut::of(&keys),
                error,
                vault_name: name,
                vault_id: id,
            });
        }
        questions.sort_by(|a, b| (b.created_at, &b.qid).cmp(&(a.created_at, &a.qid)));
        Ok(ListOut {
            status,
            vaults,
            questions,
        })
    }

    /// An open question of the context `using` that passed every check of section 7.3,
    /// from its records, or from the relay when it is not there yet.
    fn opened(&self, qid: &str, using: &Using) -> CoreResult<Opened> {
        if !envelope::valid_qid(qid) {
            return Err(CoreError::invalid("This question is not known."));
        }
        let record = |core: &Self| {
            guard(&core.questions)
                .contexts
                .get(&using.vault_id)
                .filter(|context| Arc::ptr_eq(&context.member, &using.member))
                .and_then(|context| context.records.get(qid).cloned())
        };
        let mut found = record(self);
        if found.is_none() && !using.keys.is_removed() {
            self.fetch_one(&using.vault_id, &using.member, Duration::ZERO, None)?;
            found = record(self);
        }
        let record = found.ok_or_else(|| CoreError::new("expired", "This question expired."))?;
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
        let card = using.keys.open(&record).map_err(unreadable)?;
        Ok(Opened { record, card })
    }

    fn question_open(&self, qid: &str, vault_id: Option<&str>) -> CoreResult<QuestionOut> {
        let using = self.context_for(qid, vault_id)?;
        let Opened { record, card } = self.opened(qid, &using)?;
        let vault_name = guard(&self.list)
            .get(&using.vault_id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        Ok(QuestionOut {
            qid: record.qid.clone(),
            vault_id: using.vault_id,
            vault_name,
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

    // ---- Answers. ----

    /// The answer string of `answer` at `time`, checked against the card.
    fn prepare_answer(&self, answer: &AnswerIn, time: u64) -> CoreResult<(Prepared, Ready)> {
        let using = self.context_for(&answer.qid, answer.vault_id.as_deref())?;
        let own = using.keys.own_row()?;
        let Opened { record, card } = self.opened(&answer.qid, &using)?;
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
            &using.keys.team_id,
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
                using,
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
        let member = &ready.using.member;
        let keys = &ready.using.keys;
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
        let (key_id, key) = keys.key.as_ref().ok_or_else(|| unreadable(SYNC_FIRST))?;
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
        let aad = envelope::answer_aad(&keys.team_id, &ready.record.qid, key_id, keys.device_id);
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
        if let Ok(context) = guard(&self.questions).context_mut(&ready.using.vault_id, member)
            && let Some(record) = context.records.get_mut(&ready.record.qid)
        {
            record.answered = Some(kind);
        }
        Ok(Sent {
            id: posted.id,
            at: posted.at,
            kind,
        })
    }

    /// Check that the vault holds this iPhone's row with the answer key `public_key`
    /// (section 5.2), in the context of `vault_id`, else of the selected vault. It
    /// writes nothing: the Mac that confirmed the link of this iPhone wrote the row from
    /// the keys of the link. `not_registered`: the row has not synced here yet.
    /// `removed`: the owner removed this iPhone. `answer_key_changed`: the row holds
    /// another answer key (a new Face ID enrollment made a new one, or the relay changed
    /// the link): the owner removes this iPhone and connects it again.
    fn answer_key_register(
        &self,
        public_key: &str,
        vault_id: Option<&str>,
    ) -> CoreResult<Registered> {
        self.require_app()?;
        let answer_key = decode_b64u(public_key)
            .filter(|key| key.len() == 65 && key[0] == 0x04)
            .ok_or_else(|| CoreError::invalid("The answer key is not a P-256 public key."))?;
        let selected = self.questions_refresh()?;
        let using = self.context_of(vault_id, &selected)?;
        let own = using.keys.own_row()?;
        if own.answer_key.as_deref() != Some(answer_key.as_slice()) {
            return Err(answer_key_changed());
        }
        Ok(Registered {
            device_uuid: own.uuid,
            team_id: using.keys.team_id.clone(),
            relay_device_id: using.keys.device_id,
        })
    }

    // ---- The push token (relay-questions-v1 section 14). ----

    fn put_token(member: &RelayMember, token: &PushToken) -> CoreResult<TokenSetWire> {
        let body = json!({
            "token": token.token,
            "environment": token.environment,
            "bundle_id": token.bundle_id,
        });
        let result = member
            .call("PUT", "/v1/push/token", Some(&body), Duration::ZERO)
            .map_err(call_error)?;
        serde_json::from_value::<TokenSetWire>(result)
            .map_err(|_| SyncError::RelayUnreachable.into())
    }

    fn delete_token(member: &RelayMember) -> CoreResult<()> {
        member
            .call("DELETE", "/v1/push/token", None, Duration::ZERO)
            .map(|_| ())
            .map_err(call_error)
    }

    /// The push token change that the team of `vault_id` still needs, before its next
    /// read. A failure waits for the next one.
    fn push_due(&self, vault_id: &str, member: &Arc<RelayMember>) {
        let (due, token) = {
            let mut state = guard(&self.questions);
            let token = state.push.clone();
            let Ok(context) = state.context_mut(vault_id, member) else {
                return;
            };
            (context.push_due.take(), token)
        };
        let done = match (due, token) {
            (None, _) => return,
            (Some(PushDue::Set), Some(token)) => Self::put_token(member, &token).is_ok(),
            // Notifications went off after the context was made.
            (Some(PushDue::Set), None) => true,
            (Some(PushDue::Clear), _) => Self::delete_token(member).is_ok(),
        };
        let mut state = guard(&self.questions);
        if done {
            if due == Some(PushDue::Clear) && state.push_clear.remove(vault_id) {
                self.save_push(&state);
            }
        } else if let Ok(context) = state.context_mut(vault_id, member) {
            // A newer change (`push_token_set` or `_clear`) in between wins.
            if context.push_due.is_none() {
                context.push_due = due;
            }
        }
    }

    /// `push_token_set`: the token goes to the questions team of every context, and to
    /// the team of each vault that opens later in this process.
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
        let selected = self.questions_refresh()?;
        let token = PushToken {
            token: token.to_owned(),
            environment: environment.to_owned(),
            bundle_id: bundle_id.to_owned(),
        };
        {
            let mut state = guard(&self.questions);
            state.push = Some(token.clone());
            // Notifications are on again: no team needs a clear.
            if !state.push_clear.is_empty() {
                state.push_clear.clear();
                self.save_push(&state);
            }
            for context in state.contexts.values_mut() {
                context.push_due = None;
            }
        }
        let mut targets = self.fetch_targets();
        if targets.is_empty() {
            return Err(selected.missing());
        }
        // The selected vault first: its device number is the one of the answer.
        targets.sort_by_key(|(id, _)| selected.id() != Some(id.as_str()));
        let mut vaults = Vec::new();
        let mut first: Option<(u64, u64)> = None;
        let mut failed = None;
        for (id, member) in targets {
            let out = match Self::put_token(&member, &token) {
                Ok(wire) => {
                    first.get_or_insert((wire.device_id, wire.updated_at));
                    PushOut {
                        vault_id: id,
                        device_id: Some(wire.device_id),
                        updated_at: Some(wire.updated_at),
                        error: None,
                    }
                }
                Err(error) => {
                    if let Ok(context) = guard(&self.questions).context_mut(&id, &member) {
                        context.push_due = Some(PushDue::Set);
                    }
                    let code = error.code;
                    failed.get_or_insert(error);
                    PushOut {
                        vault_id: id,
                        device_id: None,
                        updated_at: None,
                        error: Some(code),
                    }
                }
            };
            vaults.push(out);
        }
        match (first, failed) {
            (Some((device_id, updated_at)), _) => Ok(TokenSet {
                device_id,
                updated_at,
                vaults,
            }),
            (None, Some(error)) => Err(error),
            (None, None) => Err(CoreError::internal("The push token went nowhere.")),
        }
    }

    /// `push_token_clear`: the token leaves the questions team of every context. Each
    /// other vault on this iPhone, and a team that failed, goes into [`PUSH_FILE`]: its
    /// token is cleared when the vault opens.
    fn push_token_clear(&self) -> CoreResult<TokenCleared> {
        self.questions_refresh()?;
        let vault_ids: Vec<String> = guard(&self.list)
            .vaults
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        let targets = {
            let mut state = guard(&self.questions);
            state.push = None;
            for context in state.contexts.values_mut() {
                context.push_due = None;
            }
            let without: Vec<String> = vault_ids
                .into_iter()
                .filter(|id| !state.contexts.contains_key(id))
                .collect();
            state.push_clear.extend(without);
            // A removed iPhone is no device of that team any more: nothing to clear.
            state
                .contexts
                .iter()
                .filter(|(_, context)| !context.keys.is_removed())
                .map(|(id, context)| (id.clone(), Arc::clone(&context.member)))
                .collect::<Vec<_>>()
        };
        let mut cleared = Vec::new();
        for (id, member) in targets {
            match Self::delete_token(&member) {
                Ok(()) => cleared.push(id),
                Err(_) => {
                    let mut state = guard(&self.questions);
                    if let Ok(context) = state.context_mut(&id, &member) {
                        context.push_due = Some(PushDue::Clear);
                    }
                    state.push_clear.insert(id);
                }
            }
        }
        let mut state = guard(&self.questions);
        for id in &cleared {
            state.push_clear.remove(id);
        }
        self.save_push(&state);
        Ok(TokenCleared {
            cleared,
            pending: state.push_clear.iter().cloned().collect(),
        })
    }

    // ---- A notifications-only team (plan §A7). ----

    fn attach_start(&self, link: &str, device_name: &str) -> CoreResult<AttachOut> {
        self.require_app()?;
        let entry = self.selected()?;
        // A vault with a questions team on this iPhone joins again only after the owner
        // removed this iPhone: the new key replaces the removed one.
        let replaces = self.with_vault(|vault| {
            let Some(membership) = questions_membership(vault)? else {
                return Ok(None);
            };
            let removed = vault.trusted_key_removed(&membership.public_key)?;
            let questions_only = membership
                .purposes
                .iter()
                .all(|purpose| *purpose == MembershipPurpose::Questions);
            match (removed, questions_only) {
                (true, true) => Ok(Some(membership.team_id)),
                (true, false) => Err(CoreError::invalid(
                    "This iPhone was removed, and it syncs the vault through the relay: to answer again, turn sync through the relay off on this iPhone and join the vault again from a Mac.",
                )),
                (false, _) => Err(CoreError::invalid(
                    "This vault gets questions through the relay already.",
                )),
            }
        })?;
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
            replaces,
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
            let replaces = attaching.replaces.clone();
            self.with_vault_mut(|vault| {
                // The removed key goes; the row of this iPhone comes from the Mac that
                // confirmed it, through the sync of the vault.
                if let Some(team) = &replaces {
                    vault.remove_relay_membership(team)?;
                }
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
                // The new device starts the context of this vault, with its session.
                if let Some((_, keys)) = read_keys(vault)? {
                    guard(&self.questions).put(&attaching.vault_id, Arc::new(member), keys);
                }
                Ok(())
            })
        })();
        if let Err(error) = stored {
            // The vault does not hold the key: the device leaves the team again.
            joined.cancel();
            return Err(error);
        }
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
    using: Using,
    own: TrustedDevice,
    record: Record,
    digest: String,
    choice: Choice,
}

#[cfg(test)]
mod tests {
    use super::*;

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
