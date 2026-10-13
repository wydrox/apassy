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
use crate::sync::relay::{ApiError, sync_error};
use crate::sync::relay_http::Cancel;
use crate::sync::{
    LinkCode, PendingLink, RelayCallError, RelayMember, RelayRefusal, SyncError, decode_b64u,
    link_code_team, safety_words,
};
use crate::vault::{RelayMembership, VaultErrorKind};

/// The longest long poll that the relay holds (section 10.4).
pub const MAX_WAIT: Duration = Duration::from_secs(25);
/// A link code works this long after the relay made it (relay-sync-v1 section 7.1).
const LINK_CODE_SECONDS: u64 = 10 * 60;

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

    /// The HTTP status of the relay, when it answered with an error envelope.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Relay { status, .. } => Some(*status),
            _ => None,
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

    /// Whether the team is a Connect team (relay-connect-v1 section 5), as the last
    /// sign-in said it. False before the first sign-in and from an older relay.
    pub fn is_connect(&self) -> bool {
        self.member.team_kind().as_deref() == Some("connect")
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
        self.list_with(since, wait, None)
    }

    /// [`Self::list`] that `cancel` ends ([`RelayMember::call_until`]).
    pub(crate) fn list_with(
        &self,
        since: u64,
        wait: Duration,
        cancel: Option<&Cancel>,
    ) -> Result<QuestionList, QuestionsError> {
        let seconds = wait.min(MAX_WAIT).as_secs();
        let path = format!("/v1/questions?since={since}&wait={seconds}");
        self.call("GET", &path, None, Duration::from_secs(seconds), cancel)
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

/// A live device of the questions team (`GET /v1/devices`), with the push state when the
/// relay tells it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TeamDevice {
    pub id: u64,
    pub name: String,
    /// Whether the relay holds a push token of the device that did not fail. `None`:
    /// the relay does not say.
    #[serde(default)]
    pub push: Option<bool>,
    #[serde(default)]
    pub last_seen_at: Option<u64>,
    #[serde(default)]
    pub current: bool,
}

/// A link of a device that asks to join (`LinkView`, relay-sync-v1 section 7.1).
#[derive(Deserialize)]
struct LinkView {
    id: u64,
    device_name: String,
    public_key: String,
    #[serde(default)]
    created_at: u64,
    #[serde(default)]
    expires_at: u64,
}

/// The device calls of a notifications-only team on the Mac that made it (plan §A7):
/// "Add an iPhone…" makes a link, shows the iPhones that ask with their safety words,
/// and confirms one after the owner check (`OwnerAction::ConfirmSyncDevice`), as relay
/// sync does for its own team (`RelaySync::create_link`). The iPhone joins with
/// `join_attach` and downloads nothing: the team carries no snapshot.
impl QuestionsClient {
    /// `POST /v1/devices/links`: a new link code for an iPhone.
    pub fn create_link(&self) -> Result<LinkCode, SyncError> {
        #[derive(Deserialize)]
        struct Created {
            secret: String,
            expires_at: u64,
        }
        let created: Created =
            self.device_call("POST", "/v1/devices/links", Some(&serde_json::json!({})))?;
        let code = Zeroizing::new(created.secret);
        if link_code_team(&code) != Some(self.team_id()) {
            return Err(SyncError::RelayUnreachable);
        }
        let link = Zeroizing::new(format!(
            "{}/link#{}",
            self.member.relay_url(),
            code.as_str()
        ));
        Ok(LinkCode {
            code,
            link,
            expires_at: created.expires_at,
        })
    }

    /// `GET /v1/devices/links`: the devices that wait for a confirmation. With the code
    /// that this Mac holds, each link that the relay made after that code gets its
    /// safety words; an older link is of an older code and can only be refused.
    pub fn pending_links(&self, held: Option<&LinkCode>) -> Result<Vec<PendingLink>, SyncError> {
        let views: Vec<LinkView> = self.device_call("GET", "/v1/devices/links", None)?;
        let team = self.team_id().to_owned();
        Ok(views
            .into_iter()
            .filter_map(|view| {
                let public_key = decode_b64u(&view.public_key)
                    .filter(|key| key.len() == 65 && key[0] == 0x04)?;
                let safety = held
                    .filter(|code| {
                        view.created_at >= code.expires_at.saturating_sub(LINK_CODE_SECONDS)
                    })
                    .map(|code| safety_words(&team, &code.code, &public_key));
                Some(PendingLink {
                    id: view.id,
                    device_name: view.device_name,
                    public_key,
                    created_at: view.created_at,
                    expires_at: view.expires_at,
                    safety,
                })
            })
            .collect())
    }

    /// `POST /v1/devices/links/{id}/confirm` with the words that this Mac computed. The
    /// caller ran the owner check first. A `409` means that the relay's record of the
    /// device differs: nothing is added.
    pub fn confirm_link(&self, link: &PendingLink) -> Result<TeamDevice, SyncError> {
        let safety = link
            .safety
            .as_deref()
            .ok_or(SyncError::Relay(RelayRefusal::Conflict))?;
        let path = format!("/v1/devices/links/{}/confirm", link.id);
        self.device_call("POST", &path, Some(&serde_json::json!({"safety": safety})))
    }

    /// `POST /v1/devices/links/{id}/refuse`.
    pub fn refuse_link(&self, link_id: u64) -> Result<(), SyncError> {
        let path = format!("/v1/devices/links/{link_id}/refuse");
        self.device_call::<serde::de::IgnoredAny>("POST", &path, Some(&serde_json::json!({})))
            .map(|_| ())
    }

    /// `GET /v1/devices`: the live devices of the team.
    pub fn devices(&self) -> Result<Vec<TeamDevice>, SyncError> {
        self.device_call("GET", "/v1/devices", None)
    }

    /// `DELETE /v1/devices/{id}`: revoke a device of the team (relay-sync-v1 section 9),
    /// after Settings > Devices removed its trusted device. The relay then routes it no
    /// question and sends it no push: a revoked device is out of every routing set. The
    /// relay has no call to clear the push token of another device (`DELETE
    /// /v1/push/token` clears the caller's own); a token of a revoked device stays unused.
    pub fn remove_device(&self, device_id: u64) -> Result<(), SyncError> {
        let path = format!("/v1/devices/{device_id}");
        self.device_call::<serde::de::IgnoredAny>("DELETE", &path, None)
            .map(|_| ())
    }

    /// One device call, with the errors of relay sync.
    fn device_call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, SyncError> {
        let result = self
            .member
            .call(method, path, body, Duration::ZERO)
            .map_err(|error| {
                sync_error(match error {
                    RelayCallError::Unreachable => ApiError::Unreachable,
                    RelayCallError::Relay { status, code } => ApiError::Relay {
                        status,
                        code,
                        retry_after: None,
                    },
                    RelayCallError::Sync(error) => ApiError::Sync(error),
                })
            })?;
        serde_json::from_value(result).map_err(|_| SyncError::RelayUnreachable)
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
