//! The answering device (contract relay-questions-v1, section 13): open and check a card,
//! build the answer string, and seal and post a signed answer.
//!
//! The signature comes from the caller: an iPhone signs an approving answer with its Face
//! ID answer key and every other answer with its relay key; a Mac signs every answer with
//! its relay key, an approving one only after a local Touch ID for
//! [`OwnerAction::AnswerRemoteQuestion`] ([`answer_from_mac`]). The relay accepting an
//! answer does not mean that it counted: only the settle says what happened.

use super::client::{AnswerReceipt, QuestionRecord, QuestionsClient, QuestionsError};
use super::envelope::{
    AnswerBody, Card, CardError, Choice, RemoteEnvironment, Sealed, SettleBody, VERSION,
    answer_aad, answer_string, card_aad, settle_aad,
};
use crate::broker::approvals::{OwnerAction, OwnerProof, PendingRun};
use crate::companion::digest::question_digest_v2_hex;
use crate::vault::{QuestionKey, TrustedDevice};

/// Why a card is not shown (section 7.3). Each offers no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// No key with the `key_id` of the envelope: "Sync this vault to read this question".
    NoKey,
    /// A card of another version or with other fields: "Update Apassy to read this
    /// question".
    Update,
    /// Any other failure: "This question could not be read".
    CouldNotRead,
    /// The question expired on this device's clock.
    Expired,
}

impl Unreadable {
    pub fn message(self) -> &'static str {
        match self {
            Self::NoKey => "Sync this vault to read this question.",
            Self::Update => "Update Apassy to read this question.",
            Self::CouldNotRead => "This question could not be read.",
            Self::Expired => "Expired.",
        }
    }
}

/// A card that opened and passed the checks of section 7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedQuestion {
    pub team_id: String,
    pub record: QuestionRecord,
    pub card: Card,
    /// The run as the card names it, for the digest and the local action.
    pub run: PendingRun,
    /// The trusted device of the asking Mac.
    pub asker: TrustedDevice,
}

/// The key of `keys` named `key_id`.
pub fn key_named<'a>(keys: &'a [QuestionKey], key_id: &str) -> Option<&'a QuestionKey> {
    keys.iter().find(|key| key.key_id() == key_id)
}

/// Open and check the card of `record` (section 7.3), in order: the envelope opens with
/// the key named, the JSON has exactly the fields within the limits, `v` is 1 and the
/// `qid` is the relay's, the digest v2 of the card's fields is its `digest`, the asker is a
/// live trusted device whose relay number in `team_id`, when set, is the relay's
/// `from_device_id`, and the question has not expired at `now`.
pub fn open_question(
    record: &QuestionRecord,
    team_id: &str,
    keys: &[QuestionKey],
    devices: &[TrustedDevice],
    now: u64,
) -> Result<OpenedQuestion, Unreadable> {
    let key = key_named(keys, &record.key_id).ok_or(Unreadable::NoKey)?;
    let aad = card_aad(
        team_id,
        &record.qid,
        &record.key_id,
        &record.to,
        record.expires_at,
    );
    let plaintext = record
        .card()
        .open(key, &aad)
        .ok_or(Unreadable::CouldNotRead)?;
    // A JSON object with an unknown or a missing field is a card of another version
    // (section 7.1); anything else could not be read.
    let card = Card::parse(&plaintext).map_err(|_: CardError| {
        if serde_json::from_slice::<serde_json::Value>(&plaintext)
            .is_ok_and(|value| value.is_object())
        {
            Unreadable::Update
        } else {
            Unreadable::CouldNotRead
        }
    })?;
    if card.v != VERSION {
        return Err(Unreadable::Update);
    }
    if card.qid != record.qid {
        return Err(Unreadable::CouldNotRead);
    }
    let run = card.to_run().ok_or(Unreadable::CouldNotRead)?;
    if question_digest_v2_hex(&run) != card.digest {
        return Err(Unreadable::CouldNotRead);
    }
    let asker = devices
        .iter()
        .find(|device| device.uuid == card.asker.device)
        .filter(|device| {
            device
                .relay_devices
                .get(team_id)
                .is_none_or(|id| *id == record.from_device_id)
        })
        .cloned()
        .ok_or(Unreadable::CouldNotRead)?;
    if record.expires_at <= now {
        return Err(Unreadable::Expired);
    }
    Ok(OpenedQuestion {
        team_id: team_id.to_owned(),
        record: record.clone(),
        card,
        run,
        asker,
    })
}

/// The settle of a settled question, when this device holds its key: for "Answered on
/// NAME".
pub fn open_settle(
    record: &QuestionRecord,
    team_id: &str,
    keys: &[QuestionKey],
) -> Option<SettleBody> {
    let settle = record.settle.as_ref()?.sealed();
    let key = key_named(keys, &settle.key_id)?;
    let plaintext = settle.open(key, &settle_aad(team_id, &record.qid, &settle.key_id))?;
    SettleBody::parse(&plaintext).filter(|body| body.qid == record.qid)
}

/// Why an answer was not sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerError {
    /// The question does not offer this answer, or its fields do not match the question.
    NotOffered,
    /// The answer string cannot be built (a control character).
    Unbuildable,
    /// An approving answer of a Mac needs a fresh owner check for exactly this answer.
    NeedsOwnerCheck,
    /// The signature could not be made.
    Sign,
    /// `409 question_settled`: "Already answered".
    AlreadyAnswered,
    /// `409 question_expired`: "Expired".
    Expired,
    /// `403 not_routed`: "This device cannot answer this question".
    NotRouted,
    /// `403 too_many_answers`: the relay counts the answers of a device and of a
    /// question, and the bytes of the team.
    TooManyAnswers,
    /// The question is not in the list of this Mac any more, or the questions through
    /// the relay are off or locked.
    Gone,
    /// Another failure of the relay call.
    Relay(QuestionsError),
}

impl AnswerError {
    pub fn message(&self) -> String {
        match self {
            Self::NotOffered => "This question does not offer this answer.".to_owned(),
            Self::Unbuildable => "Apassy cannot send this answer from another device.".to_owned(),
            Self::NeedsOwnerCheck => "Confirm with Touch ID to send this answer.".to_owned(),
            Self::Sign => "Apassy could not sign the answer.".to_owned(),
            Self::AlreadyAnswered => "Already answered.".to_owned(),
            Self::Expired => "Expired.".to_owned(),
            Self::NotRouted => "This device cannot answer this question.".to_owned(),
            Self::TooManyAnswers => "The relay refused the answer: too many answers.".to_owned(),
            Self::Gone => "This question no longer waits on this Mac.".to_owned(),
            Self::Relay(QuestionsError::Unreachable) => {
                "The relay did not answer. Try again.".to_owned()
            }
            Self::Relay(QuestionsError::Closed) => {
                "The vault locked. The answer was not sent.".to_owned()
            }
            Self::Relay(error) => format!("The relay did not take the answer: {error:?}."),
        }
    }
}

/// An answer that waits for its signature: the choice, the time, and the signed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAnswer {
    pub qid: String,
    pub by: String,
    pub choice: Choice,
    pub digest: String,
    pub time: u64,
    /// The answer string to sign (section 9.3).
    pub text: String,
}

/// Prepare `choice` by the device `by` at `time` (the clock before the Face ID or Touch ID
/// prompt): it must be offered by the question (`deny` always is).
pub fn prepare_answer(
    opened: &OpenedQuestion,
    by: &str,
    choice: Choice,
    time: u64,
) -> Result<PreparedAnswer, AnswerError> {
    if !choice.valid_for(&opened.run.question) {
        return Err(AnswerError::NotOffered);
    }
    let text = answer_string(
        by,
        &opened.team_id,
        &opened.record.qid,
        &choice,
        &opened.card.digest,
        time,
    )
    .ok_or(AnswerError::Unbuildable)?;
    Ok(PreparedAnswer {
        qid: opened.record.qid.clone(),
        by: by.to_owned(),
        choice,
        digest: opened.card.digest.clone(),
        time,
        text,
    })
}

/// Seal the answer with its DER `signature` for the relay device number `device_id` of
/// this device (the relay stamps it, and the asker opens with it).
pub fn seal_answer(
    prepared: &PreparedAnswer,
    signature: &[u8],
    key: &QuestionKey,
    team_id: &str,
    device_id: u64,
) -> Option<Sealed> {
    let body = AnswerBody::new(
        &prepared.qid,
        &prepared.by,
        &prepared.choice,
        &prepared.digest,
        prepared.time,
        signature,
    );
    let plaintext = body.to_plaintext()?;
    Sealed::new(
        key,
        &answer_aad(team_id, &prepared.qid, &key.key_id(), device_id),
        &plaintext,
    )
}

/// Seal and post the answer with its signature. `409` and `403 not_routed` are the
/// answers of section 13 step 4.
pub fn send_answer(
    client: &QuestionsClient,
    opened: &OpenedQuestion,
    prepared: &PreparedAnswer,
    signature: &[u8],
    keys: &[QuestionKey],
) -> Result<AnswerReceipt, AnswerError> {
    let key = key_named(keys, &opened.record.key_id).ok_or(AnswerError::Unbuildable)?;
    let device_id = client.device_id().ok_or(AnswerError::Unbuildable)?;
    let sealed = seal_answer(prepared, signature, key, &opened.team_id, device_id)
        .ok_or(AnswerError::Unbuildable)?;
    client
        .post_answer(&opened.record.qid, &sealed)
        .map_err(|error| match (&error, error.code()) {
            (_, Some("question_settled")) => AnswerError::AlreadyAnswered,
            (_, Some("question_expired")) => AnswerError::Expired,
            (_, Some("not_routed")) => AnswerError::NotRouted,
            (_, Some("too_many_answers")) => AnswerError::TooManyAnswers,
            _ => AnswerError::Relay(error),
        })
}

/// The action of the local answer that matches `choice` on the asking Mac, for the
/// Touch ID reason of a Mac. `None` for an answer that needs no owner check.
pub fn local_action(run: &PendingRun, choice: &Choice) -> Option<OwnerAction> {
    let project = || run.question.project.clone();
    match choice {
        Choice::ApproveOnce => Some(OwnerAction::ApproveRun(run.clone())),
        Choice::ApproveInProject { action, .. } => Some(OwnerAction::ApproveInProject {
            run: run.clone(),
            project: project()?,
            action: *action,
        }),
        Choice::AllowProduction { action, .. } => Some(OwnerAction::AllowProduction {
            run: run.clone(),
            project: project()?,
            action: *action,
        }),
        Choice::CorrectEnvironment {
            item_id,
            environment: RemoteEnvironment::Development,
        } => Some(OwnerAction::ChangeItemRules { item_id: *item_id }),
        _ => None,
    }
}

/// The owner action that a Mac confirms with Touch ID before it signs an approving
/// answer to `opened` (section 5.3). `None` for an answer that needs no check.
pub fn remote_owner_action(opened: &OpenedQuestion, choice: &Choice) -> Option<OwnerAction> {
    Some(OwnerAction::AnswerRemoteQuestion {
        qid: opened.record.qid.clone(),
        asker: opened.card.asker.name.clone(),
        answer: Box::new(local_action(&opened.run, choice)?),
    })
}

/// Answer `opened` from this Mac (`by`, its trusted device UUID): an approving answer
/// needs `proof` for [`remote_owner_action`] in the vault session `epoch`; every answer is
/// signed with the relay key of `client` (the `sign_key` of this Mac).
#[allow(clippy::too_many_arguments)]
pub fn answer_from_mac(
    client: &QuestionsClient,
    opened: &OpenedQuestion,
    by: &str,
    choice: Choice,
    time: u64,
    keys: &[QuestionKey],
    proof: Option<OwnerProof>,
    epoch: &[u8; 32],
) -> Result<AnswerReceipt, AnswerError> {
    let prepared = prepare_answer(opened, by, choice, time)?;
    if prepared.choice.needs_owner_check() {
        let expected =
            remote_owner_action(opened, &prepared.choice).ok_or(AnswerError::NotOffered)?;
        let proof = proof.ok_or(AnswerError::NeedsOwnerCheck)?;
        proof
            .check(&expected, epoch)
            .map_err(|_| AnswerError::NeedsOwnerCheck)?;
    }
    let signature = client
        .sign(prepared.text.as_bytes())
        .map_err(|_| AnswerError::Sign)?;
    send_answer(client, opened, &prepared, &signature, keys)
}
