//! Questions through the relay (ADR 0025 of the core, stage 5; docs/SPEC.md section 25).
//!
//! A device of a vault posts a question of its agent broker: a sealed card. The relay
//! stores it with the asking device and member, routes it to the other live devices of
//! that member (and, for `to: "approvers"`, to the devices of the owners and managers),
//! takes their sealed answers with a stamp (device, member, role, time), and lets the
//! asker settle it once. The relay never opens an envelope: it checks forms and sizes
//! only. Every change of a question takes the next value of the team's question
//! sequence, so a device that lists with its last `seq` sees each change once.
//! Maintenance expires questions at `expires_at`, drops the ciphertexts and answers of
//! a question 10 minutes after it ended, and deletes the rest 24 hours after it was
//! posted. A post hands the push tokens of the routing set to `server::push`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

use crate::api::{
    AnswerList, AnswerView, EnvelopePost, PushTokenPut, QuestionList, QuestionPost, QuestionView,
    Role, SealedView,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::{DeviceId, MemberId};
use crate::server::Core;
use crate::server::approvals::MAX_WAIT_SECS;
use crate::server::audit::{RELAY_ACTOR, member_actor};
use crate::server::auth::{MemberAuth, device_member, parse_role, role_text};
use crate::server::push::PushTarget;
use crate::server::store::{db, to_i, to_u};

/// The largest ciphertext of a card, an answer, and a settle (plaintext + 16).
pub const MAX_CARD_BYTES: usize = 32_784;
pub const MAX_ANSWER_BYTES: usize = 8_208;
pub const MAX_SETTLE_BYTES: usize = 1_040;
/// Answers of one device to one question.
pub const MAX_ANSWERS_PER_DEVICE: u64 = 3;
/// Answers of all devices to one question.
pub const MAX_ANSWERS_PER_QUESTION: u64 = 20;
/// Questions in one list answer.
pub const MAX_LIST: u64 = 100;
/// `expires_at` is in `(now + MIN_LIFETIME_SECS, now + MAX_LIFETIME_SECS]`.
pub const MIN_LIFETIME_SECS: u64 = 10;
pub const MAX_LIFETIME_SECS: u64 = 600;
/// Maintenance deletes a question and its answers this long after `created_at`.
pub const RETENTION_SECS: u64 = 86_400;
/// Maintenance drops the card, the settle, and the answers of a question this long
/// after it was settled or expired, keeping its metadata until `RETENTION_SECS`.
pub const PURGE_AFTER_SECS: u64 = 600;
/// The length of a `qid`: base64url of 16 bytes.
const QID_LEN: usize = 22;
/// The push token: lowercase hex, 32 to 200 characters.
const MIN_TOKEN_LEN: usize = 32;
const MAX_TOKEN_LEN: usize = 200;

/// A `qid`: 22 base64url characters that decode to exactly 16 bytes. `Copy`, so a
/// route can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qid([u8; QID_LEN]);

impl Qid {
    pub fn parse(text: &str) -> Option<Self> {
        let bytes: [u8; QID_LEN] = text.as_bytes().try_into().ok()?;
        // The engine refuses another alphabet and non-canonical trailing bits.
        let decoded = decode_b64(text, 16).ok()?;
        (decoded.len() == 16).then_some(Self(bytes))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

fn invalid_qid() -> RelayError {
    RelayError::invalid("The qid is 22 base64url characters (16 bytes).")
}

/// The `qid` of a path segment: 400 when it is out of its form.
pub fn path_qid(text: &str) -> RelayResult<Qid> {
    Qid::parse(text).ok_or_else(invalid_qid)
}

/// The device of the caller. Questions are for devices only: a member token is 401.
pub(crate) fn device_of(by: &MemberAuth) -> RelayResult<DeviceId> {
    by.device
        .map(|device| device.id)
        .ok_or_else(RelayError::unauthenticated)
}

fn is_approver(role: Role) -> bool {
    matches!(role, Role::Owner | Role::Manager)
}

pub(crate) fn check_v(v: u64) -> RelayResult<()> {
    if v == 1 {
        Ok(())
    } else {
        Err(RelayError::invalid("This relay speaks version 1 (`v`: 1)."))
    }
}

/// `key_id`: exactly 16 lowercase hex characters.
pub(crate) fn check_key_id(text: &str) -> RelayResult<()> {
    if text.len() == 16 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(RelayError::invalid(
            "The key_id is 16 lowercase hex characters.",
        ))
    }
}

/// `nonce`: 12 bytes, base64url (16 characters).
pub(crate) fn nonce(text: &str) -> RelayResult<Vec<u8>> {
    decode_b64(text, 12)
        .ok()
        .filter(|bytes| bytes.len() == 12)
        .ok_or_else(|| RelayError::invalid("The nonce is 12 bytes, base64url."))
}

/// A ciphertext: base64url, not empty (400), at most `max` bytes (413).
pub(crate) fn ciphertext(text: &str, max: usize) -> RelayResult<Vec<u8>> {
    // Decoded up to the size of the largest body (a feed), so a text over `max` is 413
    // below, not 400.
    let bytes = decode_b64(text, crate::api::MAX_FEED_BODY)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| RelayError::invalid("The ciphertext is base64url and not empty."))?;
    if bytes.len() > max {
        return Err(RelayError::new(
            codes::PAYLOAD_TOO_LARGE,
            format!("The ciphertext is larger than {max} bytes."),
        ));
    }
    Ok(bytes)
}

/// The sealed envelope of an answer or a settle, checked: 400, then 413.
struct Envelope {
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn envelope(request: &EnvelopePost, max: usize) -> RelayResult<Envelope> {
    check_v(request.v)?;
    check_key_id(&request.key_id)?;
    let nonce = nonce(&request.nonce)?;
    let ciphertext = ciphertext(&request.ciphertext, max)?;
    Ok(Envelope {
        key_id: request.key_id.clone(),
        nonce,
        ciphertext,
    })
}

/// A refused question call: one `question_refused` row with the calling device,
/// rate-limited as other refusals. Called outside a transaction: it takes the store
/// itself.
fn refused(core: &Core, now: u64, device: DeviceId, error: &RelayError) {
    // One rate limit per reason, so one kind of refusal does not hide another.
    let (kind, reason) = match error.code {
        codes::NOT_ROUTED => ("question_not_routed", "not_routed"),
        codes::TOO_MANY_QUESTIONS => ("question_too_many", "too_many_questions"),
        codes::TOO_MANY_ANSWERS => ("question_too_many_answers", "too_many_answers"),
        codes::QUESTION_SETTLED => ("question_settled", "settled"),
        codes::QUESTION_EXPIRED => ("question_expired", "expired"),
        _ => return,
    };
    core.audit.refusal(
        &core.store,
        now,
        kind,
        "question_refused",
        &json!({"reason": reason, "device_id": device}),
    );
}

/// The next value of the team's question sequence.
fn next_seq(tx: &Transaction<'_>) -> RelayResult<u64> {
    tx.query_row(
        "UPDATE team SET question_seq = question_seq + 1 RETURNING question_seq",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(to_u)
    .map_err(db)
}

/// The team's question sequence now.
fn current_seq(conn: &Connection) -> RelayResult<u64> {
    conn.query_row("SELECT question_seq FROM team", [], |row| {
        row.get::<_, i64>(0)
    })
    .optional()
    .map(|seq| seq.map_or(0, to_u))
    .map_err(db)
}

/// One stored question.
struct QuestionRow {
    qid: String,
    device_id: DeviceId,
    member_id: MemberId,
    to_approvers: bool,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    seq: u64,
    created_at: u64,
    expires_at: u64,
    state: String,
    settled_at: Option<u64>,
    settle_nonce: Option<Vec<u8>>,
    settle_ciphertext: Option<Vec<u8>>,
}

const QUESTION_COLUMNS: &str = "q.qid, q.device_id, q.member_id, q.to_approvers, q.key_id, \
    q.nonce, q.ciphertext, q.seq, q.created_at, q.expires_at, q.state, q.settled_at, \
    q.settle_nonce, q.settle_ciphertext";

fn question_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuestionRow> {
    Ok(QuestionRow {
        qid: row.get(0)?,
        device_id: DeviceId(to_u(row.get(1)?)),
        member_id: MemberId(to_u(row.get(2)?)),
        to_approvers: row.get(3)?,
        key_id: row.get(4)?,
        nonce: row.get(5)?,
        ciphertext: row.get(6)?,
        seq: to_u(row.get(7)?),
        created_at: to_u(row.get(8)?),
        expires_at: to_u(row.get(9)?),
        state: row.get(10)?,
        settled_at: row.get::<_, Option<i64>>(11)?.map(to_u),
        settle_nonce: row.get(12)?,
        settle_ciphertext: row.get(13)?,
    })
}

fn load(conn: &Connection, qid: &Qid) -> RelayResult<Option<QuestionRow>> {
    conn.query_row(
        &format!("SELECT {QUESTION_COLUMNS} FROM question q WHERE q.qid = ?1"),
        params![qid.as_str()],
        question_row,
    )
    .optional()
    .map_err(db)
}

impl QuestionRow {
    /// The state at `now`: an open question past `expires_at` is expired, also before
    /// maintenance marks it.
    fn state_at(&self, now: u64) -> &'static str {
        match self.state.as_str() {
            "settled" => "settled",
            "open" if self.expires_at > now => "open",
            _ => "expired",
        }
    }

    /// True when `device` of `by` is in the routing set (section 25.3). The caller is a
    /// live device of a live member: the token was just checked.
    fn routes_to(&self, device: DeviceId, by: &MemberAuth) -> bool {
        device != self.device_id
            && (by.id == self.member_id || (self.to_approvers && is_approver(by.role)))
    }
}

/// The live devices of the routing set of a question (section 25.3), read now.
fn routing_set(
    conn: &Connection,
    asker: DeviceId,
    member: MemberId,
    to_approvers: bool,
) -> RelayResult<Vec<DeviceId>> {
    let mut statement = conn
        .prepare(
            "SELECT d.id FROM device d JOIN member m ON m.id = d.member_id \
             WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL AND d.id <> ?1 \
             AND (m.id = ?2 OR (?3 AND m.role IN ('owner','manager'))) ORDER BY d.id",
        )
        .map_err(db)?;
    let rows = statement
        .query_map(
            params![to_i(asker.0), to_i(member.0), to_approvers],
            |row| Ok(DeviceId(to_u(row.get(0)?))),
        )
        .map_err(db)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)
}

/// The push tokens of `devices` that did not fail.
fn push_targets(conn: &Connection, devices: &[DeviceId]) -> RelayResult<Vec<PushTarget>> {
    let mut statement = conn
        .prepare(
            "SELECT token, environment FROM push_token WHERE device_id = ?1 AND failed_at IS NULL",
        )
        .map_err(db)?;
    let mut targets = Vec::new();
    for device in devices {
        let row = statement
            .query_row(params![to_i(device.0)], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .optional()
            .map_err(db)?;
        if let Some((token, environment)) = row {
            targets.push(PushTarget {
                device: *device,
                token: String::from_utf8_lossy(&token).into_owned(),
                environment,
            });
        }
    }
    Ok(targets)
}

/// The posted fields of a question, checked: 400, then 413.
struct NewQuestion {
    qid: Qid,
    to_approvers: bool,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn checked_post(request: &QuestionPost, now: u64) -> RelayResult<NewQuestion> {
    check_v(request.v)?;
    let qid = Qid::parse(&request.qid).ok_or_else(invalid_qid)?;
    let to_approvers = match request.to.as_str() {
        "member" => false,
        "approvers" => true,
        _ => return Err(RelayError::invalid("`to` is member or approvers.")),
    };
    if request.expires_at <= now.saturating_add(MIN_LIFETIME_SECS)
        || request.expires_at > now.saturating_add(MAX_LIFETIME_SECS)
    {
        return Err(RelayError::invalid(format!(
            "expires_at is more than {MIN_LIFETIME_SECS} and at most {MAX_LIFETIME_SECS} seconds from now on the relay clock ({now})."
        )));
    }
    check_key_id(&request.key_id)?;
    let nonce = nonce(&request.nonce)?;
    let ciphertext = ciphertext(&request.ciphertext, MAX_CARD_BYTES)?;
    Ok(NewQuestion {
        qid,
        to_approvers,
        nonce,
        ciphertext,
    })
}

/// 403 `too_many_questions`, with a `limit_reached` row (at most one per kind and ten
/// seconds) on the transaction, which the caller commits.
fn too_many_questions(
    core: &Core,
    conn: &Connection,
    now: u64,
    kind: &'static str,
) -> RelayResult<RelayError> {
    core.limit_error_on(conn, now, kind)?;
    Ok(RelayError::new(
        codes::TOO_MANY_QUESTIONS,
        format!("The team's {kind} limit is reached. The question stays on the asking device."),
    ))
}

/// The bytes of ciphertext that the team's file holds now: cards, settles, and
/// answers (the `question_bytes` limit).
fn stored_bytes(conn: &Connection) -> RelayResult<u64> {
    conn.query_row(
        "SELECT (SELECT coalesce(sum(length(ciphertext) + coalesce(length(settle_ciphertext), 0)), 0) \
         FROM question) + (SELECT coalesce(sum(length(ciphertext)), 0) FROM question_answer)",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(to_u)
    .map_err(db)
}

/// The question counts that the limits of a post read, at `now`: open questions and
/// questions of the last hour, of the team, of `member`, and of `device`.
struct Counts {
    open: u64,
    hour: u64,
    member_open: u64,
    member_hour: u64,
    device_open: u64,
    device_hour: u64,
}

fn counts_for(
    conn: &Connection,
    member: MemberId,
    device: DeviceId,
    now: u64,
) -> RelayResult<Counts> {
    conn.query_row(
        "SELECT coalesce(sum(state = 'open' AND expires_at > ?1), 0), \
         coalesce(sum(created_at > ?2), 0), \
         coalesce(sum(member_id = ?3 AND state = 'open' AND expires_at > ?1), 0), \
         coalesce(sum(member_id = ?3 AND created_at > ?2), 0), \
         coalesce(sum(device_id = ?4 AND state = 'open' AND expires_at > ?1), 0), \
         coalesce(sum(device_id = ?4 AND created_at > ?2), 0) FROM question",
        params![
            to_i(now),
            to_i(now.saturating_sub(3600)),
            to_i(member.0),
            to_i(device.0)
        ],
        |row| {
            Ok(Counts {
                open: to_u(row.get(0)?),
                hour: to_u(row.get(1)?),
                member_open: to_u(row.get(2)?),
                member_hour: to_u(row.get(3)?),
                device_open: to_u(row.get(4)?),
                device_hour: to_u(row.get(5)?),
            })
        },
    )
    .map_err(db)
}

/// One thread of the question lane held by a long poll of this team. Dropping it
/// gives the seat back.
pub(crate) struct LaneSeat<'a>(&'a AtomicUsize);

impl Drop for LaneSeat<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A seat of `held`, or `None` when `max` are held.
pub(crate) fn take_seat(held: &AtomicUsize, max: usize) -> Option<LaneSeat<'_>> {
    held.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        (count < max).then_some(count + 1)
    })
    .ok()
    .map(|_| LaneSeat(held))
}

/// A seat of the team's share of the question lane (`question_long_polls_per_team`, and
/// for a Connect team at most `connect::TEAM_QUESTION_POLLS`), or `None` when the team
/// holds all of its share: then the poll answers at once.
fn lane_seat(core: &Core) -> Option<LaneSeat<'_>> {
    let mut max = core.config.limits.question_long_polls_per_team;
    if core.kind == crate::api::TeamKind::Connect {
        max = max.min(crate::server::connect::TEAM_QUESTION_POLLS);
    }
    take_seat(&core.question_lane, max)
}

/// The caller read again at each turn of a long poll: 401 when its device or its
/// member was revoked, or its role changed, since the request began. The role routes
/// questions, so a poll does not go on with an old one.
fn still_the_caller(conn: &Connection, by: &MemberAuth, device: DeviceId) -> RelayResult<()> {
    let current = device_member(conn, device)?;
    if current.id != by.id || current.role != by.role {
        return Err(RelayError::unauthenticated());
    }
    Ok(())
}

/// `POST /v1/questions`.
pub fn post(core: &Core, by: &MemberAuth, request: &QuestionPost, now: u64) -> RelayResult<Value> {
    let device = device_of(by)?;
    let new = checked_post(request, now)?;
    if new.to_approvers && !core.config.questions_to_approvers {
        // Until shared vaults (integrator decision 1) approvers cannot open a question.
        let error = RelayError::new(
            codes::NOT_ROUTED,
            "This relay does not route questions to approvers yet. Ask with to: member.",
        );
        refused(core, now, device, &error);
        return Err(error);
    }
    let limits = core.limits();
    // A refusal commits too: its `limit_reached` row stays.
    let outcome = core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM question WHERE qid = ?1)",
                params![new.qid.as_str()],
                |row| row.get(0),
            )
            .map_err(db)?;
        if exists {
            return Ok(Err(RelayError::new(
                codes::CONFLICT,
                "A question with this qid exists in the team.",
            )));
        }
        let counts = counts_for(tx, by.id, device, now)?;
        // The team's limits, then the shares of one member and of one device, so one
        // device cannot use the whole team's quota; then the bytes the file holds.
        for (count, limit, kind) in [
            (counts.open, limits.open_questions, "open_questions"),
            (counts.hour, limits.questions_per_hour, "questions_per_hour"),
            (
                counts.member_open,
                limits.member_open_questions,
                "member_open_questions",
            ),
            (
                counts.member_hour,
                limits.member_questions_per_hour,
                "member_questions_per_hour",
            ),
            (
                counts.device_open,
                limits.device_open_questions,
                "device_open_questions",
            ),
            (
                counts.device_hour,
                limits.device_questions_per_hour,
                "device_questions_per_hour",
            ),
        ] {
            if count >= limit {
                return Ok(Err(too_many_questions(core, tx, now, kind)?));
            }
        }
        let bytes = stored_bytes(tx)?.saturating_add(new.ciphertext.len() as u64);
        if bytes > limits.question_bytes {
            return Ok(Err(too_many_questions(core, tx, now, "question_bytes")?));
        }
        let seq = next_seq(tx)?;
        tx.execute(
            "INSERT INTO question (qid, device_id, member_id, to_approvers, key_id, nonce, \
             ciphertext, seq, created_at, expires_at, state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'open')",
            params![
                new.qid.as_str(),
                to_i(device.0),
                to_i(by.id.0),
                new.to_approvers,
                request.key_id,
                new.nonce,
                new.ciphertext,
                to_i(seq),
                to_i(now),
                to_i(request.expires_at),
            ],
        )
        .map_err(db)?;
        let routed = routing_set(tx, device, by.id, new.to_approvers)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "question_posted",
            None,
            &json!({"device_id": device, "to_approvers": new.to_approvers, "routed": routed.len()}),
        )?;
        Ok(Ok((seq, push_targets(tx, &routed)?)))
    })?;
    let (seq, targets) = outcome.inspect_err(|error| refused(core, now, device, error))?;
    core.notify.notify();
    core.push
        .trigger(core, new.qid.as_str(), targets, request.expires_at, now);
    Ok(json!({
        "qid": new.qid.as_str(),
        "seq": seq,
        "created_at": now,
        "expires_at": request.expires_at,
    }))
}

fn question_view(row: QuestionRow, device_name: String, now: u64) -> QuestionView {
    let state = row.state_at(now).to_string();
    let settle = match (&row.settle_nonce, &row.settle_ciphertext) {
        (Some(nonce), Some(ciphertext)) if state == "settled" => Some(SealedView {
            key_id: row.key_id.clone(),
            nonce: encode_b64(nonce),
            ciphertext: encode_b64(ciphertext),
        }),
        _ => None,
    };
    QuestionView {
        qid: row.qid,
        seq: row.seq,
        to: if row.to_approvers {
            "approvers"
        } else {
            "member"
        }
        .to_string(),
        from_device_id: row.device_id,
        from_device_name: device_name,
        key_id: row.key_id,
        nonce: encode_b64(&row.nonce),
        ciphertext: encode_b64(&row.ciphertext),
        created_at: row.created_at,
        expires_at: row.expires_at,
        settled_at: row.settled_at.filter(|_| state == "settled"),
        state,
        settle,
    }
}

/// The questions routed to `device` of `by` with `seq > since`, oldest first.
fn list_now(
    conn: &Connection,
    by: &MemberAuth,
    device: DeviceId,
    since: u64,
    now: u64,
) -> RelayResult<QuestionList> {
    let seq = current_seq(conn)?;
    let mut statement = conn
        .prepare(&format!(
            "SELECT {QUESTION_COLUMNS}, coalesce(d.name, '') FROM question q \
             LEFT JOIN device d ON d.id = q.device_id \
             WHERE q.seq > ?1 AND q.device_id <> ?2 AND length(q.ciphertext) > 0 \
             AND (q.member_id = ?3 OR (q.to_approvers = 1 AND ?4)) \
             ORDER BY q.seq LIMIT ?5"
        ))
        .map_err(db)?;
    let rows = statement
        .query_map(
            params![
                to_i(since),
                to_i(device.0),
                to_i(by.id.0),
                is_approver(by.role),
                to_i(MAX_LIST)
            ],
            |row| Ok((question_row(row)?, row.get::<_, String>(14)?)),
        )
        .map_err(db)?;
    let questions = rows
        .map(|row| row.map(|(row, name)| question_view(row, name, now)))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    Ok(QuestionList { seq, questions })
}

/// `GET /v1/questions?since=N&wait=S`. While no question is routed to the caller after
/// `since`, holds the answer up to `wait` seconds on the team notifier. A device has at
/// most one such poll, and `hold` is false when the relay's question lane is full: then
/// the answer comes at once, as with `wait=0`, and so does a poll over the team's share
/// of the lane. Each turn reads the caller again (401 when revoked or its role changed).
pub fn list(
    core: &Core,
    by: &MemberAuth,
    since: u64,
    wait_secs: u64,
    hold: bool,
) -> RelayResult<QuestionList> {
    let device = device_of(by)?;
    let poll = if wait_secs > 0 && hold {
        core.question_polls.enter(device.0)
    } else {
        None
    };
    let lane = poll.as_ref().and_then(|_| lane_seat(core));
    // The relay's seat of a Connect team is taken only when the team's seat was.
    let seat = lane.as_ref().and_then(|_| core.poll_seat());
    let wait_secs = if seat.is_some() { wait_secs } else { 0 };
    let deadline = Instant::now() + Duration::from_secs(wait_secs.min(MAX_WAIT_SECS));
    loop {
        let seen = core.notify.current();
        let list = core.store.with(|conn| {
            still_the_caller(conn, by, device)?;
            list_now(conn, by, device, since, crate::now_unix())
        })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        // A sequence below `since` (a restored relay) answers at once too.
        if !list.questions.is_empty() || list.seq < since || remaining.is_zero() || core.stopping()
        {
            return Ok(list);
        }
        core.notify
            .wait_from(seen, remaining.min(Duration::from_millis(500)));
    }
}

/// `POST /v1/questions/{qid}/answers`. The checks of section 25.4, in order. The relay
/// stamps the answer and does not settle the question.
pub fn answer(
    core: &Core,
    by: &MemberAuth,
    qid: Qid,
    request: &EnvelopePost,
    now: u64,
) -> RelayResult<Value> {
    let device = device_of(by)?;
    let sealed = envelope(request, MAX_ANSWER_BYTES)?;
    let outcome = core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let question = load(tx, &qid)?.ok_or_else(|| RelayError::not_found("question"))?;
        if !question.routes_to(device, by) {
            return Ok(Err(RelayError::new(
                codes::NOT_ROUTED,
                "This device cannot answer this question.",
            )));
        }
        match question.state_at(now) {
            "settled" => {
                return Ok(Err(RelayError::new(
                    codes::QUESTION_SETTLED,
                    "The question is already answered.",
                )));
            }
            "expired" => {
                return Ok(Err(RelayError::new(
                    codes::QUESTION_EXPIRED,
                    "The question has expired.",
                )));
            }
            _ => {}
        }
        if sealed.key_id != question.key_id {
            return Err(RelayError::invalid(
                "The key_id is not the key_id of the question.",
            ));
        }
        let given: i64 = tx
            .query_row(
                "SELECT count(*) FROM question_answer WHERE qid = ?1 AND device_id = ?2",
                params![qid.as_str(), to_i(device.0)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(given) >= MAX_ANSWERS_PER_DEVICE {
            return Ok(Err(RelayError::new(
                codes::TOO_MANY_ANSWERS,
                "This device already sent 3 answers to this question.",
            )));
        }
        let all: i64 = tx
            .query_row(
                "SELECT count(*) FROM question_answer WHERE qid = ?1",
                params![qid.as_str()],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(all) >= MAX_ANSWERS_PER_QUESTION {
            return Ok(Err(RelayError::new(
                codes::TOO_MANY_ANSWERS,
                format!("This question already has {MAX_ANSWERS_PER_QUESTION} answers."),
            )));
        }
        let bytes = stored_bytes(tx)?.saturating_add(sealed.ciphertext.len() as u64);
        if bytes > core.limits().question_bytes {
            core.limit_error_on(tx, now, "question_bytes")?;
            return Ok(Err(RelayError::new(
                codes::TOO_MANY_ANSWERS,
                "The team's question_bytes limit is reached.",
            )));
        }
        tx.execute(
            "INSERT INTO question_answer (qid, device_id, member_id, role, key_id, nonce, \
             ciphertext, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                qid.as_str(),
                to_i(device.0),
                to_i(by.id.0),
                role_text(by.role),
                sealed.key_id,
                sealed.nonce,
                sealed.ciphertext,
                to_i(now),
            ],
        )
        .map_err(db)?;
        let id = to_u(tx.last_insert_rowid());
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "question_answered",
            None,
            &json!({"device_id": device, "asker_device_id": question.device_id}),
        )?;
        Ok(Ok(id))
    })?;
    let id = outcome.inspect_err(|error| refused(core, now, device, error))?;
    core.notify.notify();
    Ok(json!({"id": id, "at": now}))
}

/// The question of `qid` if `device` asked it: 404 for any other device, as a link of
/// another member.
fn own_question(conn: &Connection, qid: &Qid, device: DeviceId) -> RelayResult<QuestionRow> {
    load(conn, qid)?
        .filter(|question| question.device_id == device)
        .ok_or_else(|| RelayError::not_found("question"))
}

fn answers_now(
    conn: &Connection,
    qid: &Qid,
    device: DeviceId,
    after: u64,
    now: u64,
) -> RelayResult<AnswerList> {
    let question = own_question(conn, qid, device)?;
    let mut statement = conn
        .prepare(
            "SELECT id, device_id, member_id, role, key_id, nonce, ciphertext, at \
             FROM question_answer WHERE qid = ?1 AND id > ?2 ORDER BY id",
        )
        .map_err(db)?;
    let rows = statement
        .query_map(params![qid.as_str(), to_i(after)], |row| {
            Ok(AnswerView {
                id: to_u(row.get(0)?),
                device_id: DeviceId(to_u(row.get(1)?)),
                member_id: MemberId(to_u(row.get(2)?)),
                role: parse_role(&row.get::<_, String>(3)?),
                key_id: row.get(4)?,
                nonce: encode_b64(&row.get::<_, Vec<u8>>(5)?),
                ciphertext: encode_b64(&row.get::<_, Vec<u8>>(6)?),
                at: to_u(row.get(7)?),
            })
        })
        .map_err(db)?;
    let answers = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)?;
    Ok(AnswerList {
        state: question.state_at(now).to_string(),
        expires_at: question.expires_at,
        answers,
    })
}

/// `GET /v1/questions/{qid}/answers?after=N&wait=S`, for the asking device only. While
/// there is no answer after `after` and the question is open, holds up to `wait`
/// seconds. One such poll per device; `hold`, the team's share, and the caller read at
/// each turn as in `list`.
pub fn answers(
    core: &Core,
    by: &MemberAuth,
    qid: Qid,
    after: u64,
    wait_secs: u64,
    hold: bool,
) -> RelayResult<AnswerList> {
    let device = device_of(by)?;
    let poll = if wait_secs > 0 && hold {
        core.answer_polls.enter(device.0)
    } else {
        None
    };
    let lane = poll.as_ref().and_then(|_| lane_seat(core));
    // The relay's seat of a Connect team is taken only when the team's seat was.
    let seat = lane.as_ref().and_then(|_| core.poll_seat());
    let wait_secs = if seat.is_some() { wait_secs } else { 0 };
    let deadline = Instant::now() + Duration::from_secs(wait_secs.min(MAX_WAIT_SECS));
    loop {
        let seen = core.notify.current();
        let list = core.store.with(|conn| {
            still_the_caller(conn, by, device)?;
            answers_now(conn, &qid, device, after, crate::now_unix())
        })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !list.answers.is_empty()
            || list.state != "open"
            || remaining.is_zero()
            || core.stopping()
        {
            return Ok(list);
        }
        core.notify
            .wait_from(seen, remaining.min(Duration::from_millis(500)));
    }
}

/// `POST /v1/questions/{qid}/settle`, for the asking device only. The same envelope
/// again answers the same (a retry); another one after a settle is 409.
pub fn settle(
    core: &Core,
    by: &MemberAuth,
    qid: Qid,
    request: &EnvelopePost,
    now: u64,
) -> RelayResult<Value> {
    let device = device_of(by)?;
    let sealed = envelope(request, MAX_SETTLE_BYTES)?;
    let outcome = core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let question = own_question(tx, &qid, device)?;
        if question.state == "settled" {
            let same = sealed.key_id == question.key_id
                && question.settle_nonce.as_deref() == Some(sealed.nonce.as_slice())
                && question.settle_ciphertext.as_deref() == Some(sealed.ciphertext.as_slice());
            return Ok(if same {
                Ok((question.settled_at.unwrap_or(now), false))
            } else {
                Err(RelayError::new(
                    codes::QUESTION_SETTLED,
                    "The question is already settled with another envelope.",
                ))
            });
        }
        if question.state_at(now) == "expired" {
            return Ok(Err(RelayError::new(
                codes::QUESTION_EXPIRED,
                "The question has expired.",
            )));
        }
        if sealed.key_id != question.key_id {
            return Err(RelayError::invalid(
                "The key_id is not the key_id of the question.",
            ));
        }
        let seq = next_seq(tx)?;
        tx.execute(
            "UPDATE question SET state = 'settled', settled_at = ?2, settle_nonce = ?3, \
             settle_ciphertext = ?4, seq = ?5 WHERE qid = ?1",
            params![
                qid.as_str(),
                to_i(now),
                sealed.nonce,
                sealed.ciphertext,
                to_i(seq)
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "question_settled",
            None,
            &json!({"device_id": device}),
        )?;
        Ok(Ok((now, true)))
    })?;
    let (settled_at, changed) = outcome.inspect_err(|error| refused(core, now, device, error))?;
    if changed {
        core.notify.notify();
    }
    Ok(json!({"qid": qid.as_str(), "state": "settled", "settled_at": settled_at}))
}

/// Best-effort restart replay from existing open questions: no schema/outbox change.
/// APNs' constant collapse id coalesces duplicates after a restart.
pub fn recover_push(core: &Core, now: u64) -> RelayResult<()> {
    if core.push.topic().is_none() {
        return Ok(());
    }
    let pending = core.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT qid, device_id, member_id, to_approvers, expires_at FROM question \
             WHERE state = 'open' AND expires_at > ?1 ORDER BY created_at DESC LIMIT 256",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([to_i(now)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    DeviceId(to_u(row.get(1)?)),
                    MemberId(to_u(row.get(2)?)),
                    row.get::<_, bool>(3)?,
                    to_u(row.get(4)?),
                ))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        let mut pending = Vec::new();
        for (qid, device, member, approvers, expiry) in rows {
            let routing = routing_set(conn, device, member, approvers)?;
            pending.push((qid, expiry, push_targets(conn, &routing)?));
        }
        Ok(pending)
    })?;
    for (qid, expiry, targets) in pending {
        core.push.trigger(core, &qid, targets, expiry, now);
    }
    Ok(())
}

/// `PUT /v1/push/token`: one token per device, replaced on each call; clears a failed
/// mark. A `push_token_set` row only when the token, environment, or bundle id changes.
/// 409 `push_unavailable` on a relay without push.
pub fn push_token_put(
    core: &Core,
    by: &MemberAuth,
    request: &PushTokenPut,
    now: u64,
) -> RelayResult<Value> {
    let device = device_of(by)?;
    let Some(topic) = core.push.topic() else {
        return Err(RelayError::new(
            codes::PUSH_UNAVAILABLE,
            "This relay does not send push notifications.",
        ));
    };
    let token = request.token.as_str();
    if !(MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
        || !token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(RelayError::invalid(
            "The push token is lowercase hex, 32 to 200 characters.",
        ));
    }
    if !matches!(request.environment.as_str(), "development" | "production") {
        return Err(RelayError::invalid(
            "The environment is development or production.",
        ));
    }
    if request.bundle_id != topic {
        return Err(RelayError::invalid(
            "The bundle id is not the app of this relay's push notifications.",
        ));
    }
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        // The same token again (the app sends it at each start) moves its time and clears
        // a failed mark, but writes no new audit row.
        let same: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM push_token WHERE device_id = ?1 AND token = ?2 \
                 AND environment = ?3 AND bundle_id = ?4)",
                params![
                    to_i(device.0),
                    token.as_bytes(),
                    request.environment,
                    request.bundle_id
                ],
                |row| row.get(0),
            )
            .map_err(db)?;
        tx.execute(
            "INSERT INTO push_token (device_id, token, environment, bundle_id, updated_at, failed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL) ON CONFLICT(device_id) DO UPDATE SET \
             token = excluded.token, environment = excluded.environment, \
             bundle_id = excluded.bundle_id, updated_at = excluded.updated_at, failed_at = NULL",
            params![
                to_i(device.0),
                token.as_bytes(),
                request.environment,
                request.bundle_id,
                to_i(now)
            ],
        )
        .map_err(db)?;
        if !same {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "push_token_set",
                None,
                &json!({"device_id": device, "environment": request.environment}),
            )?;
        }
        Ok(json!({"device_id": device, "updated_at": now}))
    })
}

/// `DELETE /v1/push/token`: removes the token of the calling device. No token: the same
/// answer.
pub fn push_token_delete(core: &Core, by: &MemberAuth, now: u64) -> RelayResult<Value> {
    let device = device_of(by)?;
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let removed = tx
            .execute(
                "DELETE FROM push_token WHERE device_id = ?1",
                params![to_i(device.0)],
            )
            .map_err(db)?;
        if removed > 0 {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "push_token_removed",
                None,
                &json!({"device_id": device}),
            )?;
        }
        Ok(json!({"device_id": device}))
    })
}

/// Every 5 seconds, per team: open questions past `expires_at` become `expired`, each
/// with the next sequence value and a `question_expired` row; 10 minutes after a
/// question was settled or expired its answers, card, and settle go (no list shows it
/// again); questions posted more than 24 hours ago go with their answers. Wakes the
/// long polls on an expiry or a deletion.
pub fn maintenance(core: &Core, now: u64) -> RelayResult<()> {
    // The deletions first, in a transaction of their own that writes no row: a Connect
    // team at its file cap (section 26.4) still frees the pages of its old questions,
    // even when the expiry rows below no longer fit.
    let deleted = core.store.tx(|tx| {
        // Ten minutes after a question ended, only its metadata stays: the answers go,
        // and so do the card and the settle (an empty card marks the question purged).
        let ended = "(state = 'settled' AND settled_at <= ?1) OR (state <> 'settled' AND expires_at <= ?1)";
        let purge = to_i(now.saturating_sub(PURGE_AFTER_SECS));
        tx.execute(
            &format!(
                "DELETE FROM question_answer WHERE qid IN (SELECT qid FROM question WHERE {ended})"
            ),
            params![purge],
        )
        .map_err(db)?;
        tx.execute(
            &format!(
                "UPDATE question SET ciphertext = x'', settle_nonce = NULL, \
                 settle_ciphertext = NULL WHERE length(ciphertext) > 0 AND ({ended})"
            ),
            params![purge],
        )
        .map_err(db)?;
        let cutoff = to_i(now.saturating_sub(RETENTION_SECS));
        tx.execute(
            "DELETE FROM question_answer WHERE qid IN (SELECT qid FROM question WHERE created_at <= ?1)",
            params![cutoff],
        )
        .map_err(db)?;
        let deleted = tx
            .execute(
                "DELETE FROM question WHERE created_at <= ?1",
                params![cutoff],
            )
            .map_err(db)?;
        Ok(deleted)
    })?;
    let expired = core.store.tx(|tx| {
        let expired: Vec<(String, i64)> = {
            let mut statement = tx
                .prepare(
                    "SELECT qid, device_id FROM question WHERE state = 'open' AND expires_at <= ?1 \
                     ORDER BY seq",
                )
                .map_err(db)?;
            statement
                .query_map(params![to_i(now)], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)?
        };
        for (qid, device) in &expired {
            let seq = next_seq(tx)?;
            tx.execute(
                "UPDATE question SET state = 'expired', seq = ?2 WHERE qid = ?1",
                params![qid, to_i(seq)],
            )
            .map_err(db)?;
            core.audit.write_on(
                tx,
                now,
                RELAY_ACTOR,
                "question_expired",
                None,
                &json!({"device_id": to_u(*device)}),
            )?;
        }
        Ok(expired.len())
    });
    if deleted > 0 || expired.as_ref().is_ok_and(|expired| *expired > 0) {
        core.notify.notify();
    }
    expired.map(drop)
}

/// The counts that the operator sees for a team: open questions and push tokens.
pub fn counts(conn: &Connection, now: u64) -> RelayResult<(u64, u64)> {
    conn.query_row(
        "SELECT (SELECT count(*) FROM question WHERE state = 'open' AND expires_at > ?1), \
         (SELECT count(*) FROM push_token)",
        params![to_i(now)],
        |row| Ok((to_u(row.get(0)?), to_u(row.get(1)?))),
    )
    .map_err(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values of the contract's test vectors (relay-questions-v1 section 20).
    #[test]
    fn the_vector_forms_pass() {
        let qid = Qid::parse("oKGio6SlpqeoqaqrrK2urw").unwrap();
        assert_eq!(qid.as_str(), "oKGio6SlpqeoqaqrrK2urw");
        assert_eq!(
            decode_b64(qid.as_str(), 16).unwrap(),
            (0xa0..=0xafu8).collect::<Vec<_>>()
        );
        check_key_id("630dcd2966c43366").unwrap();
        for (text, first) in [
            ("AAECAwQFBgcICQoL", 0x00u8),
            ("EBESExQVFhcYGRob", 0x10),
            ("ICEiIyQlJicoKSor", 0x20),
        ] {
            assert_eq!(
                nonce(text).unwrap(),
                (first..first + 12).collect::<Vec<_>>()
            );
        }
        // The vector card, answer, and settle ciphertexts are 1154, 386, and 221 bytes.
        for (len, max) in [
            (1154, MAX_CARD_BYTES),
            (386, MAX_ANSWER_BYTES),
            (221, MAX_SETTLE_BYTES),
        ] {
            assert_eq!(
                ciphertext(&encode_b64(&vec![7; len]), max).unwrap().len(),
                len
            );
        }
    }

    #[test]
    fn forms_out_of_their_grammar_are_refused() {
        for bad in [
            "",
            "oKGio6SlpqeoqaqrrK2ur",
            "oKGio6SlpqeoqaqrrK2urwA",
            "oKGio6SlpqeoqaqrrK2urx",
            "oKGio6SlpqeoqaqrrK2u+w",
            "oKGio6SlpqeoqaqrrK2u/w",
            "oKGio6SlpqeoqaqrrK2u=w",
        ] {
            assert!(Qid::parse(bad).is_none(), "{bad}");
        }
        for bad in [
            "630DCD2966C43366",
            "630dcd2966c4336",
            "630dcd2966c433666",
            "630dcd2966c4336g",
        ] {
            assert!(check_key_id(bad).is_err(), "{bad}");
        }
        for bad in [
            "",
            "AAECAwQFBgcICQo",
            "AAECAwQFBgcICQoLDA",
            "AAECAwQFBgcICQo+",
        ] {
            assert!(nonce(bad).is_err(), "{bad}");
        }
        assert_eq!(ciphertext("", 10).unwrap_err().code, codes::INVALID_REQUEST);
        assert_eq!(
            ciphertext("a+b", 10).unwrap_err().code,
            codes::INVALID_REQUEST
        );
        assert_eq!(
            ciphertext(&encode_b64(&[1; 11]), 10).unwrap_err().code,
            codes::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ciphertext(&encode_b64(&vec![1; MAX_CARD_BYTES + 1]), MAX_CARD_BYTES)
                .unwrap_err()
                .code,
            codes::PAYLOAD_TOO_LARGE
        );
        assert!(check_v(2).is_err());
        assert!(check_v(0).is_err());
    }

    #[test]
    fn expiry_bounds_are_open_below_and_closed_above() {
        let now = 1_790_000_000;
        let post = |expires_at: u64| QuestionPost {
            v: 1,
            qid: "oKGio6SlpqeoqaqrrK2urw".into(),
            to: "member".into(),
            expires_at,
            key_id: "630dcd2966c43366".into(),
            nonce: "AAECAwQFBgcICQoL".into(),
            ciphertext: encode_b64(&[1; 17]),
        };
        assert!(checked_post(&post(now + 10), now).is_err());
        assert!(checked_post(&post(now + 11), now).is_ok());
        assert!(checked_post(&post(now + 600), now).is_ok());
        assert!(checked_post(&post(now + 601), now).is_err());
        let mut to = post(now + 300);
        to.to = "everyone".into();
        assert!(checked_post(&to, now).is_err());
        to.to = "approvers".into();
        assert!(checked_post(&to, now).unwrap().to_approvers);
    }

    /// The card AAD of the contract (section 20.2) is built from values the relay
    /// stores and returns in clear: the team id, `qid`, `key_id`, `to`, and
    /// `expires_at`. The relay returns them byte for byte as they were posted.
    #[test]
    fn the_vector_card_aad_comes_from_the_clear_fields() {
        let aad = [
            "apassy-question-v1",
            "card",
            "t_7k2m5q4x3c",
            "oKGio6SlpqeoqaqrrK2urw",
            "630dcd2966c43366",
            "member",
            "1790000300",
        ]
        .join("\0");
        assert_eq!(
            crate::sync_head::hex(aad.as_bytes()),
            "6170617373792d7175657374696f6e2d7631006361726400745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636006d656d6265720031373930303030333030"
        );
    }
}
