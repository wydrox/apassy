//! The relay client of the questions (contract relay-questions-v1, section 10).
//!
//! A [`QuestionsClient`] is one device of the questions team on top of a
//! [`RelayMember`]: its key and, while it lasts, its access token, with the same sign-in,
//! transport, retries of `503`, and hold after a `429` as relay sync (relay-sync-v1
//! sections 3 and 5). It sends and reads sealed envelopes only; the relay never gets a
//! question, an answer, or the question key.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use zeroize::Zeroizing;

use super::envelope::{Sealed, VERSION, valid_qid};
use crate::sync::relay_http::Cancel;
use crate::sync::{RelayCallError, RelayMember, SyncError};
use crate::vault::{RelayMembership, VaultErrorKind};

/// The longest long poll that the relay holds (section 10.4).
pub const MAX_WAIT: Duration = Duration::from_secs(25);

/// Why a call of the questions failed. No variant holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuestionsError {
    /// No relay answered, the connection broke, or something that is not the relay
    /// answered. It can pass.
    Unreachable,
    /// The relay answered with an error envelope: `status` and `code`.
    Relay { status: u16, code: String },
    /// The relay refused this device (`401` after a new sign-in): it is not a live device
    /// of the team.
    Removed,
    /// The vault locked, or the client closed: the call did not start or ended.
    Closed,
    /// Another failure on this Mac.
    Local(SyncError),
}

impl QuestionsError {
    /// Whether the failure can pass by itself: the network, a busy relay, a relay error,
    /// a `429`.
    pub fn can_pass(&self) -> bool {
        match self {
            Self::Unreachable => true,
            Self::Relay { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }

    /// The error code of the relay, when it answered with one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Relay { code, .. } => Some(code),
            _ => None,
        }
    }

    fn from_call(error: RelayCallError) -> Self {
        match error {
            RelayCallError::Unreachable => Self::Unreachable,
            RelayCallError::Relay { status: 401, .. } => Self::Removed,
            RelayCallError::Relay { status, code } => Self::Relay { status, code },
            RelayCallError::Sync(SyncError::Vault(VaultErrorKind::Locked)) => Self::Closed,
            RelayCallError::Sync(SyncError::RemovedFromRelay) => Self::Removed,
            RelayCallError::Sync(error) => Self::Local(error),
        }
    }
}

/// The answer of `POST /v1/questions`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Posted {
    pub qid: String,
    pub seq: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

/// A sealed part as the relay returns it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WireSealed {
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl WireSealed {
    pub fn sealed(&self) -> Sealed {
        Sealed {
            key_id: self.key_id.clone(),
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// One question of `GET /v1/questions`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct QuestionRecord {
    pub qid: String,
    pub seq: u64,
    pub to: String,
    pub from_device_id: u64,
    #[serde(default)]
    pub from_device_name: String,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// `open`, `settled`, or `expired`.
    pub state: String,
    #[serde(default)]
    pub settled_at: Option<u64>,
    #[serde(default)]
    pub settle: Option<WireSealed>,
}

impl QuestionRecord {
    /// The sealed card.
    pub fn card(&self) -> Sealed {
        Sealed {
            key_id: self.key_id.clone(),
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// The answer of `GET /v1/questions`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct QuestionList {
    /// The team's current question sequence.
    pub seq: u64,
    pub questions: Vec<QuestionRecord>,
}

/// One answer of `GET /v1/questions/{qid}/answers`, with what the relay stamped on it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AnswerRecord {
    pub id: u64,
    /// The relay device number of the answering device.
    pub device_id: u64,
    pub member_id: u64,
    /// The member role: `owner`, `manager`, or `member`.
    pub role: String,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub at: u64,
}

impl AnswerRecord {
    pub fn sealed(&self) -> Sealed {
        Sealed {
            key_id: self.key_id.clone(),
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// The answer of `GET /v1/questions/{qid}/answers`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AnswerList {
    /// `open`, `settled`, or `expired`.
    pub state: String,
    pub expires_at: u64,
    pub answers: Vec<AnswerRecord>,
}

/// The answer of `POST /v1/questions/{qid}/answers`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AnswerReceipt {
    pub id: u64,
    pub at: u64,
}

/// One device of the questions team on one relay. A clone shares the key and the token.
#[derive(Debug, Clone)]
pub struct QuestionsClient {
    member: Arc<RelayMember>,
}

impl QuestionsClient {
    /// The device `device_id` of `team_id` on `relay_url` with its PKCS#8 key.
    pub fn new(
        relay_url: &str,
        team_id: &str,
        device_id: u64,
        key_pkcs8: Zeroizing<Vec<u8>>,
    ) -> Result<Self, SyncError> {
        Ok(Self::from_member(RelayMember::new(
            relay_url, team_id, device_id, key_pkcs8,
        )?))
    }

    /// A device that already holds its key in memory, for example the device of a join
    /// (`JoinedDevice::member`).
    pub fn from_member(member: RelayMember) -> Self {
        Self {
            member: Arc::new(member),
        }
    }

    /// The device of this Mac in the team of `membership`.
    pub fn from_membership(membership: &RelayMembership) -> Result<Self, SyncError> {
        let client = Self::new(
            &membership.relay_url,
            &membership.team_id,
            membership.device_id,
            membership.key_pkcs8.clone(),
        )?;
        if client.public_key() != membership.public_key.as_slice() {
            return Err(SyncError::Damaged);
        }
        Ok(client)
    }

    pub fn team_id(&self) -> &str {
        self.member.team_id()
    }

    /// The device number of this device in the team, once known.
    pub fn device_id(&self) -> Option<u64> {
        self.member.device_id()
    }

    /// The public key of the device (X9.63): its `sign_key` in the vault.
    pub fn public_key(&self) -> &[u8] {
        self.member.public_key()
    }

    /// A signature with the relay key of this device (DER): the `sign_key` of a Mac.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SyncError> {
        self.member.sign(message)
    }

    /// End the calls in flight and refuse every later one: the vault locked. The key
    /// goes with the last clone.
    pub fn close(&self) {
        self.member.close();
    }

    /// `POST /v1/questions` with the sealed card.
    pub fn post_question(
        &self,
        qid: &str,
        to: &str,
        expires_at: u64,
        card: &Sealed,
    ) -> Result<Posted, QuestionsError> {
        let body = serde_json::json!({
            "v": VERSION,
            "qid": qid,
            "to": to,
            "expires_at": expires_at,
            "key_id": card.key_id,
            "nonce": card.nonce,
            "ciphertext": card.ciphertext,
        });
        self.call("POST", "/v1/questions", Some(&body), Duration::ZERO, None)
    }

    /// `GET /v1/questions?since=N&wait=S`: the questions for this device after `since`.
    pub fn list(&self, since: u64, wait: Duration) -> Result<QuestionList, QuestionsError> {
        let seconds = wait.min(MAX_WAIT).as_secs();
        let path = format!("/v1/questions?since={since}&wait={seconds}");
        self.call("GET", &path, None, Duration::from_secs(seconds), None)
    }

    /// `POST /v1/questions/{qid}/answers` with a sealed answer.
    pub fn post_answer(&self, qid: &str, answer: &Sealed) -> Result<AnswerReceipt, QuestionsError> {
        let path = question_path(qid, "answers")?;
        self.call(
            "POST",
            &path,
            Some(&sealed_body(answer)),
            Duration::ZERO,
            None,
        )
    }

    /// `GET /v1/questions/{qid}/answers?after=N&wait=S`: the asker only.
    pub fn answers(
        &self,
        qid: &str,
        after: u64,
        wait: Duration,
    ) -> Result<AnswerList, QuestionsError> {
        self.answers_with(qid, after, wait, None)
    }

    /// [`Self::answers`] that `cancel` ends ([`RelayMember::call_until`]).
    pub(crate) fn answers_with(
        &self,
        qid: &str,
        after: u64,
        wait: Duration,
        cancel: Option<&Cancel>,
    ) -> Result<AnswerList, QuestionsError> {
        let seconds = wait.min(MAX_WAIT).as_secs();
        let path = format!(
            "{}?after={after}&wait={seconds}",
            question_path(qid, "answers")?
        );
        self.call("GET", &path, None, Duration::from_secs(seconds), cancel)
    }

    /// `POST /v1/questions/{qid}/settle` with a sealed settle: the asker only. The same
    /// body again answers the same.
    pub fn settle(&self, qid: &str, settle: &Sealed) -> Result<(), QuestionsError> {
        let path = question_path(qid, "settle")?;
        self.call::<serde::de::IgnoredAny>(
            "POST",
            &path,
            Some(&sealed_body(settle)),
            Duration::ZERO,
            None,
        )
        .map(|_| ())
    }

    fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
        wait: Duration,
        cancel: Option<&Cancel>,
    ) -> Result<T, QuestionsError> {
        let result = self
            .member
            .call_until(method, path, body, wait, cancel)
            .map_err(QuestionsError::from_call)?;
        // A result that does not have the shape of the contract is not the relay's.
        serde_json::from_value(result).map_err(|_| QuestionsError::Unreachable)
    }
}

fn sealed_body(sealed: &Sealed) -> Value {
    serde_json::json!({
        "v": VERSION,
        "key_id": sealed.key_id,
        "nonce": sealed.nonce,
        "ciphertext": sealed.ciphertext,
    })
}

/// `/v1/questions/{qid}/{part}` for a `qid` of the contract form.
fn question_path(qid: &str, part: &str) -> Result<String, QuestionsError> {
    if !valid_qid(qid) {
        return Err(QuestionsError::Local(SyncError::Relay(
            crate::sync::RelayRefusal::InvalidRequest,
        )));
    }
    Ok(format!("/v1/questions/{qid}/{part}"))
}
