//! Connect requests through the relay (card v2 `kind = connect`, contract
//! relay-questions-v1 sections 7.4 and 12.7): the asking Mac's lane.
//!
//! A remote agent that connects with the MCP authorization flow (ADR 0037, plan "Bouncer
//! section" decision 4) makes a connect request on the node of this Mac. The node side
//! (U2b) hands it to this lane with [`super::QuestionsWorker::post_connect`]; the lane
//! seals it as a connect card with the question key and posts it to the relay, so the
//! iPhones of the vault show "<name> wants to connect". The lane reads the answers, checks
//! each one (section 12.7), and gives the first valid one to the node through the handler
//! of [`super::QuestionsWorker::set_on_connect_answer`]. Then it settles the question
//! once. A connect request that ends on this Mac (Touch ID in Decisions, a denial, the
//! expiry, a revocation) ends here with [`super::QuestionsWorker::end_connect`], and the
//! lane settles its question with that end.
//!
//! The lane never decides a connect request by itself: the node does, after the check.
//! Only an iPhone answers: an Allow needs the Face ID answer key of its `trusted_device`
//! row, a Deny its relay key. A Mac and an Apple Watch never answer a connect card.
//!
//! The run questions of the poster and the reader are not touched: run cards stay card v1.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::answer::key_named;
use super::client::{AnswerRecord, QuestionRecord};
use super::envelope::{
    AnswerBody, CardConnect, CardError, ConnectCard, ConnectChoice, Sealed, SettleBody,
    SettleOutcome, TO_MEMBER, VERSION, answer_aad, card_aad, connect_answer_string,
    is_connect_card, new_qid, settle_aad,
};
use super::worker::{Active, Shared, UNSUPPORTED, lock, unix_now};
use crate::companion::crypto::verify_ecdsa;
use crate::sync::decode_b64u;
use crate::vault::{ActivityDecision, NewActivity, QuestionKey, TrustedDevice, TrustedDeviceKind};

/// An answer counts only when its `time` is within this many seconds of this Mac's clock,
/// both ways (section 12.4).
pub const PROOF_WINDOW: u64 = 60;
/// The operation of an Activity line about a connect answer through the relay.
pub const CONNECT_ACTIVITY: &str = "connect through the relay";
/// The relay keeps ten open questions per asking device: runs, one access request, and
/// one Connect handoff come first. One connect card at a time.
const MAX_CONNECTS_IN_FLIGHT: usize = 1;
/// The waits between two posts that failed for a reason that can pass.
const RETRY_WAITS: [u64; 5] = [2, 4, 8, 16, 30];
/// How often the lane looks at its connect requests without a wake.
const STEP: Duration = Duration::from_millis(250);

const TOO_SOON: &str = "The connect request ends too soon for your other devices.";
const BUSY: &str = concat!(
    "Another connect request is on your iPhone. Answer this one on this ",
    crate::computer!(),
    "."
);
const NOT_SENT: &str = concat!(
    "This connect request could not be sent to your other devices. Answer it on this ",
    crate::computer!(),
    "."
);
const NO_KEY: &str = concat!(
    "This vault has no question key yet. Answer the connect request on this ",
    crate::computer!(),
    "."
);

/// A connect request of the node, as the lane posts it (plan type `PendingConnect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConnectCard {
    /// The connect request ID of the node: `A-Za-z0-9-_`, at most 64 bytes.
    pub id: String,
    /// The client name that the agent registered ("MCP client" without one), at most 64
    /// bytes.
    pub client_name: String,
    /// The name of this Mac, as the agent's browser page shows it, at most 64 bytes.
    pub mac_name: String,
    /// The match code of the browser page, at most 16 bytes.
    pub code: String,
    /// When the connect request ends on the node (Unix seconds).
    pub expires_at: u64,
    /// The host of the redirect URI (`PendingConnect.redirect_host`): the card says
    /// where the code goes back (review 0.5.16). `None` only when the node gave none.
    pub redirect_host: Option<String>,
}

impl PendingConnectCard {
    fn wire(&self) -> CardConnect {
        CardConnect {
            id: self.id.clone(),
            client_name: self.client_name.clone(),
            mac_name: self.mac_name.clone(),
            code: self.code.clone(),
            expires_at: self.expires_at,
            redirect_host: self.redirect_host.clone(),
        }
    }
}

/// Why [`super::QuestionsWorker::post_connect`] refused a connect request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectPostError {
    /// A field over its limit or of a bad form (section 7.4).
    Invalid,
    /// It ends within 10 seconds: the relay would not take it.
    Expired,
}

/// The owner's answer on an iPhone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectDecision {
    /// Allow, signed with the Face ID answer key of the iPhone.
    Allow,
    Deny,
}

/// An answer through the relay that passed every check of section 12.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAnswer {
    /// The connect request ID of the node.
    pub id: String,
    pub decision: ConnectDecision,
    /// The trusted device that answered (an iPhone).
    pub device_uuid: String,
    pub device_name: String,
    /// The signed time of the answer, on the iPhone's clock.
    pub time: u64,
}

/// What the node did with a verified answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectApplied {
    /// The node took the decision: the question settles as approved or denied by the
    /// iPhone.
    Applied,
    /// The connect request no longer waits (decided on this Mac, expired, or gone): the
    /// lane reads no more answers and settles when [`ConnectEnd`] comes, or at the expiry.
    NotPending,
}

/// How a connect request ended on this Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectEnd {
    /// The owner allowed it on this Mac.
    Allowed,
    /// The owner denied it on this Mac.
    Denied,
    Expired,
    /// The node dropped it (the vault locked, the client went, a revocation).
    Withdrawn,
}

/// The handler of the verified answers: the node decides the connect request.
pub type ConnectAnswerHandler = Arc<dyn Fn(&ConnectAnswer) -> ConnectApplied + Send + Sync>;

/// The connect requests that the node gave the lane, and how each ended.
#[derive(Default)]
pub(super) struct ConnectLane {
    wanted: BTreeMap<String, Wanted>,
    pub(super) handler: Option<ConnectAnswerHandler>,
}

struct Wanted {
    connect: PendingConnectCard,
    ended: Option<ConnectEnd>,
}

impl ConnectLane {
    /// Take `connect`; the same ID again replaces nothing that is already posted.
    pub(super) fn post(&mut self, connect: PendingConnectCard) -> Result<(), ConnectPostError> {
        if !connect.wire().valid() {
            return Err(ConnectPostError::Invalid);
        }
        if connect.expires_at <= unix_now().saturating_add(10) {
            return Err(ConnectPostError::Expired);
        }
        self.wanted.entry(connect.id.clone()).or_insert(Wanted {
            connect,
            ended: None,
        });
        Ok(())
    }

    /// The connect request `id` ended on this Mac. An unknown ID is ignored.
    pub(super) fn end(&mut self, id: &str, end: ConnectEnd) {
        if let Some(wanted) = self.wanted.get_mut(id) {
            wanted.ended.get_or_insert(end);
        }
    }
}

/// A connect card of this Mac on the relay.
struct Attempt {
    qid: String,
    key: QuestionKey,
    digest: String,
    expires_at: u64,
    card: Sealed,
    posted: bool,
    /// The post failed for good: the request stays on this Mac.
    failed: bool,
    tries: usize,
    next_try: Instant,
    next_poll: Instant,
    /// The last answer ID read.
    after: u64,
    /// A verified answer went to the node, or the relay ended the question: no more
    /// answers are read.
    done_reading: bool,
    /// The node said that the request no longer waits.
    not_pending: bool,
}

/// An answer that passed the checks of section 12.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verified {
    pub(crate) choice: ConnectChoice,
    pub(crate) device: TrustedDevice,
    pub(crate) time: u64,
}

/// An answer that did not count: the device as the Activity line names it, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused {
    pub(crate) device: String,
    pub(crate) reason: &'static str,
}

/// Check one answer to the connect card `qid` (section 12.7), in order: it opens with the
/// question key and the stamped device number; it is an answer v1 to this `qid` of the
/// kind `allow_connect` or `deny` with no other field; `by` is a live iPhone of the vault
/// with the stamped number; its digest is the card's; its time is within
/// [`PROOF_WINDOW`] of `now`; and the signature verifies over the rebuilt answer string,
/// with the answer key (Face ID) for Allow and the relay key for Deny.
pub(crate) fn judge_answer(
    team_id: &str,
    qid: &str,
    key: &QuestionKey,
    digest: &str,
    record: &AnswerRecord,
    devices: &[TrustedDevice],
    now: u64,
) -> Result<Verified, Refused> {
    let unknown = format!("device {}", record.device_id);
    let refuse = |device: &str, reason| {
        Err(Refused {
            device: device.to_owned(),
            reason,
        })
    };
    let aad = answer_aad(team_id, qid, &key.key_id(), record.device_id);
    let Some(plaintext) = record.sealed().open(key, &aad) else {
        return refuse(&unknown, "it could not be read");
    };
    let parsed = AnswerBody::parse(&plaintext).and_then(|body| {
        let choice = ConnectChoice::from_body(&body)?;
        let signature = decode_b64u(&body.signature)?;
        (body.qid == qid).then_some((body, choice, signature))
    });
    let Some((body, choice, signature)) = parsed else {
        return refuse(&unknown, "it has a bad form");
    };
    let Some(device) = devices
        .iter()
        .find(|device| {
            device.uuid == body.by
                && device.kind == TrustedDeviceKind::Iphone
                && device
                    .relay_devices
                    .get(team_id)
                    .is_none_or(|id| *id == record.device_id)
        })
        .cloned()
    else {
        return refuse(
            &unknown,
            "only an iPhone of this vault answers a connect request",
        );
    };
    let name = device.name.clone();
    if body.digest != digest {
        return refuse(&name, "the request changed");
    }
    if body.time.saturating_add(PROOF_WINDOW) < now || body.time > now.saturating_add(PROOF_WINDOW)
    {
        return refuse(&name, "the answer is too old");
    }
    let key = match choice {
        ConnectChoice::Allow => device.answer_key.as_deref(),
        ConnectChoice::Deny => Some(device.sign_key.as_slice()),
    };
    let text = connect_answer_string(&body.by, team_id, qid, choice, digest, body.time);
    match (key, text) {
        (Some(key), Some(text)) if verify_ecdsa(key, text.as_bytes(), &signature) => Ok(Verified {
            choice,
            device,
            time: body.time,
        }),
        _ => refuse(&name, "its signature does not verify"),
    }
}

/// Whether the card of `record` is a connect card: a Mac that lists the questions of the
/// other devices leaves it out without a problem (only iPhones answer one).
pub(super) fn is_connect_record(
    record: &QuestionRecord,
    team_id: &str,
    keys: &[QuestionKey],
) -> bool {
    let Some(key) = key_named(keys, &record.key_id) else {
        return false;
    };
    let aad = card_aad(
        team_id,
        &record.qid,
        &record.key_id,
        &record.to,
        record.expires_at,
    );
    record
        .card()
        .open(key, &aad)
        .is_some_and(|plaintext| is_connect_card(&plaintext))
}

/// The settle of a connect card (section 9.4): the outcome, and the device whose answer
/// settled it with its kind.
fn settle_body(
    qid: &str,
    outcome: SettleOutcome,
    by: Option<(&TrustedDevice, &str, ConnectChoice)>,
) -> SettleBody {
    SettleBody {
        v: VERSION,
        qid: qid.to_owned(),
        outcome: outcome.as_str().to_owned(),
        answered_by: by.map(|(device, _, _)| device.uuid.clone()),
        device_name: by.map(|(device, _, _)| device.name.clone()),
        device_kind: by.map(|(_, kind, _)| kind.to_owned()),
        kind: by.map(|(_, _, choice)| choice.kind().to_owned()),
        at: unix_now(),
        replaced_by: None,
    }
}

impl Shared {
    fn settle_connect(
        &self,
        active: &Active,
        attempt: &Attempt,
        outcome: SettleOutcome,
        by: Option<(&TrustedDevice, &str, ConnectChoice)>,
    ) {
        if !attempt.posted {
            return;
        }
        let Some(plaintext) = settle_body(&attempt.qid, outcome, by).to_plaintext() else {
            return;
        };
        let aad = settle_aad(&active.team_id, &attempt.qid, &attempt.key.key_id());
        if let Some(sealed) = Sealed::new(&attempt.key, &aad, &plaintext) {
            let _ = active.client.settle(&attempt.qid, &sealed);
        }
    }

    fn connect_activity(&self, active: &Active, agent: &str, reason: &str) {
        let mut guard = lock(&self.vault);
        if let Some(vault) = Self::vault_of(&mut guard, active) {
            let _ = vault.record_activity(&NewActivity {
                agent_id: None,
                agent_name: agent.to_owned(),
                item_id: None,
                operation: CONNECT_ACTIVITY.to_owned(),
                decision: ActivityDecision::Error,
                reason: reason.to_owned(),
            });
        }
    }

    /// Copy the posted and the local-only connect requests to the view.
    fn publish_connects(
        &self,
        attempts: &BTreeMap<String, Attempt>,
        local: &BTreeMap<String, String>,
    ) {
        let posted: BTreeMap<String, String> = attempts
            .iter()
            .filter(|(_, attempt)| attempt.posted)
            .map(|(id, attempt)| (id.clone(), attempt.qid.clone()))
            .collect();
        let mut view = lock(&self.view);
        if view.connect_posted != posted || view.connect_local_only != *local {
            view.connect_posted = posted;
            view.connect_local_only = local.clone();
            drop(view);
            self.changed();
        }
    }

    /// One step of the lane for the session `active`.
    fn connect_step(
        &self,
        active: &Active,
        attempts: &mut BTreeMap<String, Attempt>,
        local: &mut BTreeMap<String, String>,
    ) {
        let now = unix_now();
        let wanted: Vec<(PendingConnectCard, Option<ConnectEnd>)> = lock(&self.connects)
            .wanted
            .values()
            .map(|wanted| (wanted.connect.clone(), wanted.ended))
            .collect();
        // Ends first: an end on this Mac, the expiry, or a request that the node dropped.
        for (connect, ended) in &wanted {
            let end = ended.or((connect.expires_at <= now).then_some(ConnectEnd::Expired));
            let Some(end) = end else {
                continue;
            };
            if let Some(attempt) = attempts.remove(&connect.id) {
                let me = &active.me;
                let (outcome, by) = match end {
                    ConnectEnd::Allowed => (
                        SettleOutcome::Approved,
                        Some((me, "mac", ConnectChoice::Allow)),
                    ),
                    ConnectEnd::Denied => (
                        SettleOutcome::Denied,
                        Some((me, "mac", ConnectChoice::Deny)),
                    ),
                    // The node took no decision of the iPhone's answer: the request ended
                    // another way.
                    ConnectEnd::Expired if attempt.not_pending => {
                        (SettleOutcome::Invalidated, None)
                    }
                    ConnectEnd::Expired => (SettleOutcome::TimedOut, None),
                    ConnectEnd::Withdrawn => (SettleOutcome::Invalidated, None),
                };
                self.settle_connect(active, &attempt, outcome, by);
            }
            local.remove(&connect.id);
            lock(&self.connects).wanted.remove(&connect.id);
        }
        attempts.retain(|id, _| lock(&self.connects).wanted.contains_key(id));
        // New connect requests: seal and post.
        for (connect, ended) in &wanted {
            // A request that waited for a free slot or for the question key tries again; one
            // that failed for good stays on this Mac.
            let retry = local
                .get(&connect.id)
                .is_none_or(|reason| reason == BUSY || reason == NO_KEY);
            if ended.is_some()
                || connect.expires_at <= now
                || attempts.contains_key(&connect.id)
                || !retry
            {
                continue;
            }
            if connect.expires_at <= now.saturating_add(10) {
                local.insert(connect.id.clone(), TOO_SOON.to_owned());
                continue;
            }
            if attempts.values().filter(|attempt| !attempt.failed).count() >= MAX_CONNECTS_IN_FLIGHT
            {
                local.insert(connect.id.clone(), BUSY.to_owned());
                continue;
            }
            let key = {
                let mut guard = lock(&self.vault);
                Self::vault_of(&mut guard, active)
                    .and_then(|vault| vault.question_key().ok().flatten())
            };
            let Some(key) = key else {
                local.insert(connect.id.clone(), NO_KEY.to_owned());
                continue;
            };
            let Some(qid) = new_qid() else {
                continue;
            };
            let card =
                ConnectCard::new(&qid, &active.me.uuid, &active.me.name, now, &connect.wire());
            let sealed = match card.to_plaintext() {
                Ok(plaintext) => Sealed::new(
                    &key,
                    &card_aad(
                        &active.team_id,
                        &qid,
                        &key.key_id(),
                        TO_MEMBER,
                        connect.expires_at,
                    ),
                    &plaintext,
                ),
                Err(CardError::TooLong | CardError::Unreadable) => None,
            };
            let Some(sealed) = sealed else {
                local.insert(connect.id.clone(), NOT_SENT.to_owned());
                continue;
            };
            attempts.insert(
                connect.id.clone(),
                Attempt {
                    qid,
                    key,
                    digest: card.digest,
                    expires_at: connect.expires_at,
                    card: sealed,
                    posted: false,
                    failed: false,
                    tries: 0,
                    next_try: Instant::now(),
                    next_poll: Instant::now(),
                    after: 0,
                    done_reading: false,
                    not_pending: false,
                },
            );
        }
        // Post the cards that wait for a post.
        for (id, attempt) in attempts.iter_mut() {
            if attempt.posted || attempt.failed || Instant::now() < attempt.next_try {
                continue;
            }
            if attempt.expires_at <= unix_now().saturating_add(10) {
                attempt.failed = true;
                local.insert(id.clone(), TOO_SOON.to_owned());
                continue;
            }
            let result = active.client.post_question(
                &attempt.qid,
                TO_MEMBER,
                attempt.expires_at,
                &attempt.card,
            );
            attempt.tries += 1;
            match result {
                Ok(_) => attempt.posted = true,
                Err(error) if error.code() == Some("conflict") => attempt.posted = true,
                Err(error) if error.status() == Some(404) => {
                    attempt.failed = true;
                    local.insert(id.clone(), UNSUPPORTED.to_owned());
                }
                Err(error) if error.can_pass() => {
                    let wait = RETRY_WAITS[(attempt.tries - 1).min(RETRY_WAITS.len() - 1)];
                    attempt.next_try = Instant::now() + Duration::from_secs(wait);
                }
                Err(_) => {
                    attempt.failed = true;
                    local.insert(id.clone(), NOT_SENT.to_owned());
                }
            }
            if attempt.posted {
                local.remove(id);
            }
        }
        // Read the answers of the posted cards.
        let ids: Vec<String> = attempts
            .iter()
            .filter(|(_, attempt)| {
                attempt.posted && !attempt.done_reading && Instant::now() >= attempt.next_poll
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if self.read_connect(active, &id, attempts) {
                attempts.remove(&id);
                local.remove(&id);
                lock(&self.connects).wanted.remove(&id);
            }
        }
    }

    /// Read and check the new answers of the connect card `id`. True when the question
    /// settled.
    fn read_connect(
        &self,
        active: &Active,
        id: &str,
        attempts: &mut BTreeMap<String, Attempt>,
    ) -> bool {
        let Some(attempt) = attempts.get_mut(id) else {
            return false;
        };
        attempt.next_poll = Instant::now() + self.config.short_poll_every;
        let list = match active
            .client
            .answers(&attempt.qid, attempt.after, Duration::ZERO)
        {
            Ok(list) => list,
            Err(error) if error.status() == Some(404) => {
                attempt.done_reading = true;
                return false;
            }
            Err(_) => return false,
        };
        let devices = {
            let mut guard = lock(&self.vault);
            match Self::vault_of(&mut guard, active) {
                Some(vault) => vault.trusted_devices().unwrap_or_default(),
                None => return false,
            }
        };
        let client_name = lock(&self.connects)
            .wanted
            .get(id)
            .map(|wanted| wanted.connect.client_name.clone())
            .unwrap_or_default();
        let mut answers = list.answers;
        answers.sort_by_key(|answer| answer.id);
        let after = attempt.after;
        for answer in answers.iter().filter(|answer| answer.id > after) {
            attempt.after = answer.id;
            let verified = match judge_answer(
                &active.team_id,
                &attempt.qid,
                &attempt.key,
                &attempt.digest,
                answer,
                &devices,
                unix_now(),
            ) {
                Ok(verified) => verified,
                Err(refused) => {
                    self.connect_activity(
                        active,
                        &client_name,
                        &format!(
                            "An answer from {} did not count: {}.",
                            refused.device, refused.reason
                        ),
                    );
                    continue;
                }
            };
            // The first valid answer goes to the node, once: no later answer is read.
            attempt.done_reading = true;
            let handler = lock(&self.connects).handler.clone();
            let decision = match verified.choice {
                ConnectChoice::Allow => ConnectDecision::Allow,
                ConnectChoice::Deny => ConnectDecision::Deny,
            };
            let applied = handler.map_or(ConnectApplied::NotPending, |handler| {
                handler(&ConnectAnswer {
                    id: id.to_owned(),
                    decision,
                    device_uuid: verified.device.uuid.clone(),
                    device_name: verified.device.name.clone(),
                    time: verified.time,
                })
            });
            return match applied {
                ConnectApplied::Applied => {
                    let outcome = match verified.choice {
                        ConnectChoice::Allow => SettleOutcome::Approved,
                        ConnectChoice::Deny => SettleOutcome::Denied,
                    };
                    self.settle_connect(
                        active,
                        attempt,
                        outcome,
                        Some((
                            &verified.device,
                            verified.device.kind.as_str(),
                            verified.choice,
                        )),
                    );
                    true
                }
                ConnectApplied::NotPending => {
                    attempt.not_pending = true;
                    false
                }
            };
        }
        if list.state != "open" {
            attempt.done_reading = true;
        }
        false
    }
}

/// The lane: its own thread next to the poster, the reader, and the lister.
pub(super) fn run(shared: &Shared) {
    let mut attempts: BTreeMap<String, Attempt> = BTreeMap::new();
    let mut local: BTreeMap<String, String> = BTreeMap::new();
    let mut session: Option<([u8; 32], String)> = None;
    while !shared.stop.load(Ordering::SeqCst) {
        let active = lock(&shared.state).active.clone();
        match active {
            None => {
                // A lock or the questions off: the open cards expire on the relay; the
                // node still has its connect requests on this Mac.
                attempts.clear();
                local.clear();
                session = None;
                let now = unix_now();
                lock(&shared.connects)
                    .wanted
                    .retain(|_, wanted| wanted.ended.is_none() && wanted.connect.expires_at > now);
            }
            Some(active) => {
                let current = (active.epoch, active.team_id.clone());
                if session.as_ref() != Some(&current) {
                    attempts.clear();
                    local.clear();
                    session = Some(current);
                }
                shared.connect_step(&active, &mut attempts, &mut local);
            }
        }
        shared.publish_connects(&attempts, &local);
        if !shared.sleep(STEP) {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{DeviceKey, encode_b64u};

    const TEAM: &str = "t_7k2m5q4x3c";
    const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
    const NOW: u64 = 1_790_000_030;

    fn key() -> QuestionKey {
        let mut bytes = [0u8; 32];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = at as u8;
        }
        QuestionKey::from_bytes(bytes)
    }

    struct Phone {
        relay: DeviceKey,
        answer: DeviceKey,
        row: TrustedDevice,
    }

    fn phone(kind: TrustedDeviceKind) -> Phone {
        let relay = DeviceKey::generate().unwrap();
        let answer = DeviceKey::generate().unwrap();
        let row = TrustedDevice {
            uuid: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            name: "Test iPhone".to_owned(),
            kind,
            relay_devices: [(TEAM.to_owned(), 3)].into_iter().collect(),
            sign_key: relay.public_key().to_vec(),
            answer_key: Some(answer.public_key().to_vec()),
            created_at: 1,
            updated_at: 1,
            updated_by: "synthetic".to_owned(),
        };
        Phone { relay, answer, row }
    }

    fn digest() -> String {
        let connect = CardConnect {
            id: "cr_1".to_owned(),
            client_name: "Grok Bot".to_owned(),
            mac_name: "Synthetic Mac mini".to_owned(),
            code: "482 913".to_owned(),
            expires_at: NOW + 270,
            redirect_host: None,
        };
        super::super::envelope::connect_digest_hex("0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", &connect)
    }

    /// The answer record that the relay returns for `body`, sealed for `qid` and stamped
    /// with the device number `device_id`.
    fn record(body: &AnswerBody, qid: &str, device_id: u64) -> AnswerRecord {
        let key = key();
        let sealed = Sealed::new(
            &key,
            &answer_aad(TEAM, qid, &key.key_id(), device_id),
            &body.to_plaintext().unwrap(),
        )
        .unwrap();
        AnswerRecord {
            id: 1,
            device_id,
            member_id: 1,
            role: "owner".to_owned(),
            key_id: sealed.key_id,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            at: NOW,
        }
    }

    fn signed(
        phone: &Phone,
        signer: &DeviceKey,
        choice: ConnectChoice,
        digest: &str,
        time: u64,
    ) -> AnswerBody {
        let text = connect_answer_string(&phone.row.uuid, TEAM, QID, choice, digest, time).unwrap();
        let signature = signer.sign(text.as_bytes()).unwrap();
        AnswerBody::connect(QID, &phone.row.uuid, choice, digest, time, &signature)
    }

    fn judge(
        record: &AnswerRecord,
        devices: &[TrustedDevice],
        now: u64,
    ) -> Result<Verified, Refused> {
        judge_answer(TEAM, QID, &key(), &digest(), record, devices, now)
    }

    #[test]
    fn allow_needs_the_face_id_answer_key_and_deny_the_relay_key() {
        let phone = phone(TrustedDeviceKind::Iphone);
        let devices = [phone.row.clone()];
        let allow = signed(&phone, &phone.answer, ConnectChoice::Allow, &digest(), NOW);
        let verified = judge(&record(&allow, QID, 3), &devices, NOW).unwrap();
        assert_eq!(verified.choice, ConnectChoice::Allow);
        assert_eq!(verified.device.uuid, phone.row.uuid);
        assert_eq!(verified.time, NOW);
        let deny = signed(&phone, &phone.relay, ConnectChoice::Deny, &digest(), NOW);
        assert_eq!(
            judge(&record(&deny, QID, 3), &devices, NOW).unwrap().choice,
            ConnectChoice::Deny
        );
        // A forged Allow: signed with the relay key, which needs no Face ID.
        let forged = signed(&phone, &phone.relay, ConnectChoice::Allow, &digest(), NOW);
        assert_eq!(
            judge(&record(&forged, QID, 3), &devices, NOW)
                .unwrap_err()
                .reason,
            "its signature does not verify"
        );
        // A Deny signature does not make an Allow.
        let mut swapped = deny.clone();
        swapped.kind = "allow_connect".to_owned();
        assert!(judge(&record(&swapped, QID, 3), &devices, NOW).is_err());
        // A key of no device of the vault.
        let stranger = DeviceKey::generate().unwrap();
        let foreign = signed(&phone, &stranger, ConnectChoice::Allow, &digest(), NOW);
        assert!(judge(&record(&foreign, QID, 3), &devices, NOW).is_err());
        // Without an answer key, no Allow counts.
        let mut keyless = phone.row.clone();
        keyless.answer_key = None;
        assert!(judge(&record(&allow, QID, 3), &[keyless], NOW).is_err());
    }

    #[test]
    fn a_replayed_stale_or_moved_answer_does_not_count() {
        let phone = phone(TrustedDeviceKind::Iphone);
        let devices = [phone.row.clone()];
        let allow = signed(&phone, &phone.answer, ConnectChoice::Allow, &digest(), NOW);
        // In its window, both ways, and not after it.
        assert!(judge(&record(&allow, QID, 3), &devices, NOW + 60).is_ok());
        assert!(judge(&record(&allow, QID, 3), &devices, NOW - 60).is_ok());
        assert_eq!(
            judge(&record(&allow, QID, 3), &devices, NOW + 61)
                .unwrap_err()
                .reason,
            "the answer is too old"
        );
        // Replayed into another connect card: it opens there, but its qid is not that one.
        let other = "AAECAwQFBgcICQoLDA0ODw";
        assert_eq!(
            judge_answer(
                TEAM,
                other,
                &key(),
                &digest(),
                &record(&allow, other, 3),
                &devices,
                NOW
            )
            .unwrap_err()
            .reason,
            "it has a bad form"
        );
        // Moved to another device number by the relay: the AAD does not open.
        let moved = record(&allow, QID, 3);
        let mut restamped = moved.clone();
        restamped.device_id = 4;
        assert_eq!(
            judge(&restamped, &devices, NOW).unwrap_err().reason,
            "it could not be read"
        );
        // Stamped with another number than the row's.
        let mut row = phone.row.clone();
        row.relay_devices.insert(TEAM.to_owned(), 5);
        assert!(judge(&moved, &[row], NOW).is_err());
        // Another card (another digest).
        let changed = signed(
            &phone,
            &phone.answer,
            ConnectChoice::Allow,
            &"0".repeat(64),
            NOW,
        );
        assert_eq!(
            judge(&record(&changed, QID, 3), &devices, NOW)
                .unwrap_err()
                .reason,
            "the request changed"
        );
        // A run answer is no connect answer.
        let mut run = allow.clone();
        run.kind = "approve_once".to_owned();
        assert_eq!(
            judge(&record(&run, QID, 3), &devices, NOW)
                .unwrap_err()
                .reason,
            "it has a bad form"
        );
        let mut garbage = record(&allow, QID, 3);
        garbage.ciphertext = encode_b64u(b"not an envelope of this question");
        assert!(judge(&garbage, &devices, NOW).is_err());
    }

    #[test]
    fn a_mac_and_an_apple_watch_never_answer_a_connect_card() {
        for kind in [TrustedDeviceKind::Mac, TrustedDeviceKind::Watch] {
            let device = phone(kind);
            let allow = signed(
                &device,
                &device.answer,
                ConnectChoice::Allow,
                &digest(),
                NOW,
            );
            let deny = signed(&device, &device.relay, ConnectChoice::Deny, &digest(), NOW);
            for body in [allow, deny] {
                assert_eq!(
                    judge(
                        &record(&body, QID, 3),
                        std::slice::from_ref(&device.row),
                        NOW
                    )
                    .unwrap_err()
                    .reason,
                    "only an iPhone of this vault answers a connect request",
                    "{kind:?}"
                );
            }
        }
    }

    #[test]
    fn the_lane_takes_a_connect_request_once_and_its_first_end() {
        let mut lane = ConnectLane::default();
        let connect = PendingConnectCard {
            id: "cr_1".to_owned(),
            client_name: "Grok Bot".to_owned(),
            mac_name: "Synthetic Mac mini".to_owned(),
            code: "482 913".to_owned(),
            expires_at: unix_now() + 300,
            redirect_host: Some("grok.example".to_owned()),
        };
        assert_eq!(lane.post(connect.clone()), Ok(()));
        let mut again = connect.clone();
        again.code = "000 000".to_owned();
        assert_eq!(lane.post(again), Ok(()));
        assert_eq!(lane.wanted["cr_1"].connect.code, "482 913");
        lane.end("cr_1", ConnectEnd::Denied);
        lane.end("cr_1", ConnectEnd::Allowed);
        assert_eq!(lane.wanted["cr_1"].ended, Some(ConnectEnd::Denied));
        lane.end("unknown", ConnectEnd::Allowed);
        assert!(!lane.wanted.contains_key("unknown"));
        let mut soon = connect.clone();
        soon.id = "cr_2".to_owned();
        soon.expires_at = unix_now() + 5;
        assert_eq!(lane.post(soon), Err(ConnectPostError::Expired));
        let mut bad = connect.clone();
        bad.id = "cr 3".to_owned();
        assert_eq!(lane.post(bad), Err(ConnectPostError::Invalid));
        // A redirect host of a bad form stays on this Mac too (review 0.5.16).
        let mut host = connect;
        host.id = "cr_4".to_owned();
        host.redirect_host = Some("grok example".to_owned());
        assert_eq!(lane.post(host), Err(ConnectPostError::Invalid));
    }
}
