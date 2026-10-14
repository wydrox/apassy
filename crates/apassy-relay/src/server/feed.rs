//! The feeds of the Macs and their actions (relay-feed-v1 of the core; docs/SPEC.md
//! section 27).
//!
//! A device of a vault (a Mac) keeps one sealed feed of its agents on the relay; each
//! `PUT` replaces it. The other live devices of the same member (the iPhones) read the
//! feeds of their member with the team's feed counter, and send one kind of sealed
//! action back to one of those devices, which settles it once. The relay never opens a
//! feed, an action, or a settle: it checks forms, sizes, routing, and limits, stamps the
//! sender, and stores the envelopes as given. Feeds count in their own budget,
//! `feed_bytes`, not in `question_bytes`, and one member uses at most its share of the
//! feed and action limits (`member_share`). No audit row is written per feed update: a
//! Mac publishes up to every 10 s, and a Connect team never deletes audit rows; a loop
//! of `PUT` and `DELETE` writes at most one `feed_started` and one `feed_deleted` per
//! device and hour. A device reads all of its member's feeds again at most
//! `FULL_READS_PER_MINUTE` times a minute.
//! Maintenance expires actions at `expires_at`, drops their envelopes 10 minutes after
//! they ended, deletes them 24 hours after they were posted, and deletes a feed 30 days
//! after its last update.

use std::sync::PoisonError;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

use crate::api::{
    ActionList, ActionPost, ActionSettle, ActionStatus, ActionView, FeedList, FeedPut, FeedView,
    SealedView,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::encode_b64;
use crate::ids::DeviceId;
use crate::server::Core;
use crate::server::approvals::{LongPolls, MAX_WAIT_SECS};
use crate::server::audit::member_actor;
use crate::server::auth::{MemberAuth, device_member};
use crate::server::questions::{
    LaneSeat, Qid, check_key_id, check_v, ciphertext, device_of, nonce, take_seat,
};
use crate::server::store::{db, to_i, to_u};

/// The largest ciphertext of a feed, an action, and a settle (plaintext + 16).
pub const MAX_FEED_BYTES: usize = 262_144;
pub const MAX_ACTION_BYTES: usize = 4_112;
pub const MAX_SETTLE_BYTES: usize = 1_040;
/// The largest `seq`: 2^53 - 1, so every client reads it as an exact number.
pub const MAX_SEQ: u64 = (1 << 53) - 1;
/// One accepted feed per device in this many seconds (relay clock).
pub const FEED_INTERVAL_SECS: u64 = 10;
/// A feed list stops adding feeds once the base64url ciphertexts of its answer reach
/// this many characters; it always adds one.
pub const MAX_LIST_TEXT: usize = 1_048_576;
/// Actions in one list answer.
pub const MAX_ACTION_LIST: u64 = 20;
/// `expires_at` of an action: this long after it was posted.
pub const ACTION_LIFETIME_SECS: u64 = 300;
/// Open actions of the team, and of one sending device.
pub const OPEN_ACTIONS: u64 = 20;
pub const DEVICE_OPEN_ACTIONS: u64 = 10;
/// Maintenance drops the envelopes of an action this long after it was settled or
/// expired (it is then unknown, 404), and deletes the rest this long after it was posted.
pub const PURGE_AFTER_SECS: u64 = 600;
pub const ACTION_RETENTION_SECS: u64 = 86_400;
/// Maintenance deletes a feed this long after its last update.
pub const FEED_RETENTION_SECS: u64 = 30 * 86_400;
/// At most one `feed_started` and one `feed_deleted` row (reason `deleted`) per device in
/// this many seconds, so a loop of `PUT` and `DELETE` cannot grow a Connect team's audit,
/// which is never trimmed. Revocations always write their row.
pub const FEED_AUDIT_SECS: u64 = 3600;
/// Full feed reads of one device in one minute (`take_full_read`). A read over it is 429
/// `rate_limited` with `Retry-After`: the seconds to the next minute.
pub const FULL_READS_PER_MINUTE: u64 = 6;

/// The share of one member in a team's feed limit `limit` (`feed_bytes`,
/// `feed_actions_per_hour`, `OPEN_ACTIONS`): three quarters of it, as the question limits
/// of a member are (15 of 20, 225 of 300), so one member at its share leaves room for the
/// others. A team of at most one member (the `members` limit, as a Connect team's) gives
/// it the whole limit.
pub fn member_share(limit: u64, members: u64) -> u64 {
    if members <= 1 {
        limit
    } else {
        limit - limit / 4
    }
}

/// The seats of a team's feed lane share `share` that the readers' polls (the feed list
/// and the action status) may hold together: the share less a quarter (at least one
/// seat), so readers that come first never leave the Macs' action polls
/// (`GET /v1/feed/actions`) without a seat. An action poll may take any free seat of the
/// share. A share of 1 keeps no seat back.
pub fn reader_seats(share: usize) -> usize {
    if share < 2 {
        share
    } else {
        share - (share / 4).max(1)
    }
}

/// The full feed reads of one device: those of the current minute, and the newest feed
/// counter that its last answer gave it (`Core::feed_reads`).
#[derive(Debug, Default, Clone, Copy)]
pub struct FeedReads {
    minute: u64,
    count: u64,
    given: Option<u64>,
}

impl FeedReads {
    /// Counts one read with `since` at `now` when it is a full read (`take_full_read`).
    /// `Err(seconds)` over `FULL_READS_PER_MINUTE` in this minute.
    pub fn take(&mut self, since: u64, now: u64) -> Result<(), u64> {
        let full = since == 0 || self.given.is_some_and(|given| since < given);
        if !full {
            return Ok(());
        }
        let minute = now / 60;
        if self.minute != minute {
            (self.minute, self.count) = (minute, 0);
        }
        if self.count >= FULL_READS_PER_MINUTE {
            return Err(60 - now % 60);
        }
        self.count += 1;
        Ok(())
    }
}

/// Counts one `GET /v1/feed` of `device` when it is a full read: `since` is 0, or below
/// the newest counter that the device was given (it reads again what it had). A read
/// that goes on from its last answer (`since` = the top-level `change`, or the `change`
/// of the last entry after `more`) is never one. `Err(seconds)` when the device made
/// `FULL_READS_PER_MINUTE` already in this minute: the seconds to the next one. In memory
/// only: a restart forgets the counts.
pub fn take_full_read(core: &Core, device: DeviceId, since: u64, now: u64) -> Result<(), u64> {
    core.feed_reads
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(device.0)
        .or_default()
        .take(since, now)
}

/// 429 `rate_limited` of a full feed read over `FULL_READS_PER_MINUTE`.
pub fn reads_limited() -> RelayError {
    RelayError::new(
        codes::RATE_LIMITED,
        format!(
            "This device read all of its feeds {FULL_READS_PER_MINUTE} times this minute. Read on from the last change, or try again in a moment."
        ),
    )
}

/// The newest feed counter that an answer gave `device`: the `change` of its last entry
/// when there is more, else the top-level `change`.
fn record_given(core: &Core, device: DeviceId, list: &FeedList) {
    let given = match (list.more, list.feeds.last()) {
        (true, Some(last)) => last.change,
        _ => list.change,
    };
    core.feed_reads
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(device.0)
        .or_default()
        .given = Some(given);
}

/// Whether the `action` row (`feed_started`, or `feed_deleted` of a `DELETE`) of `device`
/// is written at `now`: when none was in the last `FEED_AUDIT_SECS`.
fn feed_audit_due(core: &Core, device: DeviceId, action: &'static str, now: u64) -> bool {
    let mut last = core
        .feed_audit
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let due = last
        .get(&(device.0, action))
        .is_none_or(|at| now >= at.saturating_add(FEED_AUDIT_SECS));
    if due {
        last.insert((device.0, action), now);
    }
    due
}

/// An `action_id`: the form of a `qid`, 22 base64url characters of 16 bytes. `Copy`, so
/// a route can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionId(Qid);

impl ActionId {
    pub fn parse(text: &str) -> Option<Self> {
        Qid::parse(text).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn invalid_action_id() -> RelayError {
    RelayError::invalid("The action_id is 22 base64url characters (16 bytes).")
}

/// The `action_id` of a path segment: 400 when it is out of its form.
pub fn path_action_id(text: &str) -> RelayResult<ActionId> {
    ActionId::parse(text).ok_or_else(invalid_action_id)
}

/// The caller read again at each turn of a long poll: 401 when its device or its member
/// was revoked since the request began. Feeds route by member only, so a role change
/// does not end a feed poll.
fn still_the_caller(conn: &Connection, by: &MemberAuth, device: DeviceId) -> RelayResult<()> {
    if device_member(conn, device)?.id != by.id {
        return Err(RelayError::unauthenticated());
    }
    Ok(())
}

/// A seat of the team's share of the feed lane for a feed long poll: for an operator
/// team one of `feed_long_polls_per_team`, for a Connect team one of
/// `connect::TEAM_FEED_POLLS`; a reader's poll also takes one of `reader_seats` of it
/// (`Core::feed_readers`). Feed polls never take a question seat. `None` when they are
/// all held: then the poll answers at once.
fn lane_seat(core: &Core, action_poll: bool) -> Option<(LaneSeat<'_>, Option<LaneSeat<'_>>)> {
    let mut share = core.config.limits.feed_long_polls_per_team;
    if core.kind == crate::api::TeamKind::Connect {
        share = share.min(crate::server::connect::TEAM_FEED_POLLS);
    }
    let reader = if action_poll {
        None
    } else {
        Some(take_seat(&core.feed_readers, reader_seats(share))?)
    };
    // A reader's seat that was taken goes back when the team's share is full.
    take_seat(&core.feed_lane, share).map(|seat| (seat, reader))
}

/// Runs a feed long poll: `turn` reads the answer and says whether it is final. While it
/// is not, holds up to `wait_secs` on the team notifier. A device has at most one poll of
/// each kind (`polls`), and `hold` is false when the relay's feed lane is full: then, and
/// over the team's share (`lane_seat`) or the Connect bound (`Core::feed_poll_seat`), the
/// answer comes at once, as with `wait=0`. Each turn reads the caller again.
fn long_poll<T>(
    core: &Core,
    by: &MemberAuth,
    polls: &LongPolls,
    action_poll: bool,
    wait_secs: u64,
    hold: bool,
    mut turn: impl FnMut(&Connection, DeviceId, u64) -> RelayResult<(T, bool)>,
) -> RelayResult<T> {
    let device = device_of(by)?;
    let poll = if wait_secs > 0 && hold {
        polls.enter(device.0)
    } else {
        None
    };
    let lane = poll.as_ref().and_then(|_| lane_seat(core, action_poll));
    // The relay's seat of a Connect team is taken only when the team's seat was.
    let seat = lane.as_ref().and_then(|_| core.feed_poll_seat());
    let wait_secs = if seat.is_some() { wait_secs } else { 0 };
    let deadline = Instant::now() + Duration::from_secs(wait_secs.min(MAX_WAIT_SECS));
    loop {
        let seen = core.notify.current();
        let (answer, done) = core.store.with(|conn| {
            still_the_caller(conn, by, device)?;
            turn(conn, device, crate::now_unix())
        })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if done || remaining.is_zero() || core.stopping() {
            return Ok(answer);
        }
        core.notify
            .wait_from(seen, remaining.min(Duration::from_millis(500)));
    }
}

/// The next value of the team's feed counter.
fn next_change(tx: &Transaction<'_>) -> RelayResult<u64> {
    tx.query_row(
        "UPDATE team SET feed_change = feed_change + 1 RETURNING feed_change",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(to_u)
    .map_err(db)
}

/// The team's feed counter and action sequence now.
fn counters(conn: &Connection) -> RelayResult<(u64, u64)> {
    conn.query_row("SELECT feed_change, feed_action_seq FROM team", [], |row| {
        Ok((to_u(row.get(0)?), to_u(row.get(1)?)))
    })
    .optional()
    .map(|counters| counters.unwrap_or((0, 0)))
    .map_err(db)
}

/// 403 `feed_limit` naming `kind`.
fn feed_limit(message: String) -> RelayError {
    RelayError::new(codes::FEED_LIMIT, message)
}

/// `PUT /v1/feed`. Forms (400) and the size (413) first; then in one transaction a
/// `seq` above the stored one (409 `seq_not_newer`, before the pace, so a retry of a feed
/// that landed gets 409), the pace of one feed per 10 s (403 `feed_limit`), and the
/// team's `feed_bytes`, then the member's share of it, with the old feed of the caller
/// left out (403 `feed_limit` with a `limit_reached` row). The feed replaces the caller's
/// one with the next feed counter. A `feed_started` row only for the first feed of a
/// device, at most one per device and `FEED_AUDIT_SECS`.
pub fn put(core: &Core, by: &MemberAuth, request: &FeedPut, now: u64) -> RelayResult<Value> {
    let device = device_of(by)?;
    check_v(request.v)?;
    if !(1..=MAX_SEQ).contains(&request.seq) {
        return Err(RelayError::invalid("The seq is from 1 to 2^53 - 1."));
    }
    check_key_id(&request.key_id)?;
    let nonce = nonce(&request.nonce)?;
    let ciphertext = ciphertext(&request.ciphertext, MAX_FEED_BYTES)?;
    let limits = core.limits();
    let last_put = core
        .feed_times
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&device.0)
        .copied();
    // A refusal commits too: its `limit_reached` row stays.
    let outcome = core.store.tx(|tx| {
        let old: Option<(u64, u64)> = tx
            .query_row(
                "SELECT seq, updated_at FROM feed WHERE device_id = ?1",
                params![to_i(device.0)],
                |row| Ok((to_u(row.get(0)?), to_u(row.get(1)?))),
            )
            .optional()
            .map_err(db)?;
        if let Some((seq, _)) = old
            && request.seq <= seq
        {
            return Ok(Err(RelayError::new(
                codes::SEQ_NOT_NEWER,
                format!("The relay has a feed of this device with seq {seq}."),
            )));
        }
        let last = old.map(|(_, at)| at).max(last_put);
        if let Some(last) = last
            && now < last.saturating_add(FEED_INTERVAL_SECS)
        {
            // A pace, not a team limit: no audit row (a correct Mac never meets it).
            return Ok(Err(feed_limit(format!(
                "This device sent a feed less than {FEED_INTERVAL_SECS} seconds ago; send the next one at {}.",
                last.saturating_add(FEED_INTERVAL_SECS)
            ))));
        }
        // The other devices' feeds, of the team and of the caller's member.
        let (others, member_others): (i64, i64) = tx
            .query_row(
                "SELECT coalesce(sum(length(ciphertext)), 0), \
                 coalesce(sum(CASE WHEN member_id = ?2 THEN length(ciphertext) ELSE 0 END), 0) \
                 FROM feed WHERE device_id <> ?1",
                params![to_i(device.0), to_i(by.id.0)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db)?;
        let new = ciphertext.len() as u64;
        for (held, limit, kind) in [
            (others, limits.feed_bytes, "feed_bytes"),
            (
                member_others,
                member_share(limits.feed_bytes, limits.members),
                "member_feed_bytes",
            ),
        ] {
            if to_u(held).saturating_add(new) > limit {
                core.limit_error_on(tx, now, kind)?;
                return Ok(Err(feed_limit(format!(
                    "The team's {kind} limit is reached."
                ))));
            }
        }
        let change = next_change(tx)?;
        tx.execute(
            "INSERT INTO feed (device_id, member_id, seq, key_id, nonce, ciphertext, change_seq, \
             created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8) \
             ON CONFLICT(device_id) DO UPDATE SET member_id = excluded.member_id, \
             seq = excluded.seq, key_id = excluded.key_id, nonce = excluded.nonce, \
             ciphertext = excluded.ciphertext, change_seq = excluded.change_seq, \
             updated_at = excluded.updated_at",
            params![
                to_i(device.0),
                to_i(by.id.0),
                to_i(request.seq),
                request.key_id,
                nonce,
                ciphertext,
                to_i(change),
                to_i(now),
            ],
        )
        .map_err(db)?;
        if old.is_none() && feed_audit_due(core, device, "feed_started", now) {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "feed_started",
                None,
                &json!({"device_id": device}),
            )?;
        }
        Ok(Ok(change))
    })?;
    let change = outcome?;
    core.feed_times
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(device.0, now);
    core.notify.notify();
    Ok(json!({"device_id": device, "seq": request.seq, "change": change, "updated_at": now}))
}

/// Deletes the feeds of `devices` on the transaction, with one new feed counter value
/// when there was one, and expires the open actions to them (and, with `senders`, from
/// them). One `feed_deleted` row per feed, with `reason`; for the reason `deleted` (the
/// device's own `DELETE`) at most one per device and `FEED_AUDIT_SECS`. Returns the
/// counter now. The caller wakes the long polls.
pub fn drop_devices(
    core: &Core,
    tx: &Transaction<'_>,
    devices: &[DeviceId],
    senders: bool,
    actor: &str,
    reason: &str,
    now: u64,
) -> RelayResult<u64> {
    let mut removed = Vec::new();
    for device in devices {
        let id = to_i(device.0);
        tx.execute(
            "UPDATE feed_action SET state = 'expired', expires_at = min(expires_at, ?2) \
             WHERE state = 'open' AND (to_device = ?1 OR (?3 AND from_device = ?1))",
            params![id, to_i(now), senders],
        )
        .map_err(db)?;
        if tx
            .execute("DELETE FROM feed WHERE device_id = ?1", params![id])
            .map_err(db)?
            > 0
        {
            removed.push(*device);
        }
    }
    if removed.is_empty() {
        return counters(tx).map(|(change, _)| change);
    }
    let change = next_change(tx)?;
    for device in removed {
        // A revocation always writes its row; a device's own delete at most once an hour.
        if reason == "deleted" && !feed_audit_due(core, device, "feed_deleted", now) {
            continue;
        }
        core.audit.write_on(
            tx,
            now,
            actor,
            "feed_deleted",
            None,
            &json!({"device_id": device, "reason": reason}),
        )?;
    }
    Ok(change)
}

/// `DELETE /v1/feed`: removes the caller's feed; its open actions expire. No feed: the
/// same answer with the counter as it is.
pub fn delete(core: &Core, by: &MemberAuth, now: u64) -> RelayResult<Value> {
    let device = device_of(by)?;
    let change = core.store.tx(|tx| {
        drop_devices(
            core,
            tx,
            &[device],
            false,
            &member_actor(by.id.0),
            "deleted",
            now,
        )
    })?;
    core.notify.notify();
    Ok(json!({"device_id": device, "change": change}))
}

/// The feeds of the caller's member with `change > since`, oldest first, up to
/// `MAX_LIST_TEXT` of ciphertext text, and the devices of the member with a feed.
fn feeds_now(conn: &Connection, by: &MemberAuth, since: u64) -> RelayResult<FeedList> {
    let (change, _) = counters(conn)?;
    // Only live devices of the caller's member: a feed of a revoked device is deleted
    // at the revocation, and the join makes sure of it.
    let live = "FROM feed f JOIN device d ON d.id = f.device_id JOIN member m ON m.id = d.member_id \
         WHERE f.member_id = ?1 AND d.member_id = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL";
    let present = {
        let mut statement = conn
            .prepare(&format!("SELECT f.device_id {live} ORDER BY f.device_id"))
            .map_err(db)?;
        statement
            .query_map(params![to_i(by.id.0)], |row| {
                Ok(DeviceId(to_u(row.get(0)?)))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?
    };
    let mut statement = conn
        .prepare(&format!(
            "SELECT f.device_id, d.name, f.seq, f.change_seq, f.key_id, f.nonce, f.ciphertext, \
             f.updated_at {live} AND f.change_seq > ?2 ORDER BY f.change_seq"
        ))
        .map_err(db)?;
    let mut rows = statement
        .query(params![to_i(by.id.0), to_i(since)])
        .map_err(db)?;
    let (mut feeds, mut text, mut more) = (Vec::new(), 0usize, false);
    while let Some(row) = rows.next().map_err(db)? {
        if text >= MAX_LIST_TEXT {
            more = true;
            break;
        }
        let ciphertext = encode_b64(&row.get::<_, Vec<u8>>(6).map_err(db)?);
        text = text.saturating_add(ciphertext.len());
        feeds.push(FeedView {
            device_id: DeviceId(to_u(row.get(0).map_err(db)?)),
            device_name: row.get(1).map_err(db)?,
            seq: to_u(row.get(2).map_err(db)?),
            change: to_u(row.get(3).map_err(db)?),
            key_id: row.get(4).map_err(db)?,
            nonce: encode_b64(&row.get::<_, Vec<u8>>(5).map_err(db)?),
            ciphertext,
            updated_at: to_u(row.get(7).map_err(db)?),
        });
    }
    Ok(FeedList {
        change,
        more,
        present,
        feeds,
    })
}

/// `GET /v1/feed?since=N&wait=S`. While no feed of the member changed after `since`,
/// holds up to `wait` seconds; it also answers when a feed of the member left (`present`
/// changed) or the counter is below `since` (a restored relay). The HTTP layer counts a
/// full read first (`take_full_read`); the answer sets the counter the device was given.
pub fn list(
    core: &Core,
    by: &MemberAuth,
    since: u64,
    wait_secs: u64,
    hold: bool,
) -> RelayResult<FeedList> {
    let mut first: Option<Vec<DeviceId>> = None;
    let list = long_poll(
        core,
        by,
        &core.feed_polls,
        false,
        wait_secs,
        hold,
        |conn, _, _| {
            let list = feeds_now(conn, by, since)?;
            let present = first.get_or_insert_with(|| list.present.clone());
            let done = !list.feeds.is_empty() || list.change < since || *present != list.present;
            Ok((list, done))
        },
    )?;
    record_given(core, device_of(by)?, &list);
    Ok(list)
}

/// One stored action.
struct ActionRow {
    action_id: String,
    seq: u64,
    from_device: DeviceId,
    to_device: DeviceId,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    created_at: u64,
    expires_at: u64,
    state: String,
    outcome: Option<String>,
    settled_at: Option<u64>,
    settle_key_id: Option<String>,
    settle_nonce: Option<Vec<u8>>,
    settle_ciphertext: Option<Vec<u8>>,
}

const ACTION_COLUMNS: &str = "action_id, seq, from_device, to_device, key_id, nonce, ciphertext, \
    created_at, expires_at, state, outcome, settled_at, settle_key_id, settle_nonce, settle_ciphertext";

fn action_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActionRow> {
    Ok(ActionRow {
        action_id: row.get(0)?,
        seq: to_u(row.get(1)?),
        from_device: DeviceId(to_u(row.get(2)?)),
        to_device: DeviceId(to_u(row.get(3)?)),
        key_id: row.get(4)?,
        nonce: row.get(5)?,
        ciphertext: row.get(6)?,
        created_at: to_u(row.get(7)?),
        expires_at: to_u(row.get(8)?),
        state: row.get(9)?,
        outcome: row.get(10)?,
        settled_at: row.get::<_, Option<i64>>(11)?.map(to_u),
        settle_key_id: row.get(12)?,
        settle_nonce: row.get(13)?,
        settle_ciphertext: row.get(14)?,
    })
}

impl ActionRow {
    /// The state at `now`: an open action past `expires_at` is expired, also before
    /// maintenance marks it.
    fn state_at(&self, now: u64) -> &'static str {
        match self.state.as_str() {
            "settled" => "settled",
            "open" if self.expires_at > now => "open",
            _ => "expired",
        }
    }
}

/// The action of `id` for which `owns` holds: 404 for any other, and for a purged one
/// (its envelope is gone), as an unknown `action_id`.
fn own_action(
    conn: &Connection,
    id: &ActionId,
    owns: impl Fn(&ActionRow) -> bool,
) -> RelayResult<ActionRow> {
    conn.query_row(
        &format!("SELECT {ACTION_COLUMNS} FROM feed_action WHERE action_id = ?1"),
        params![id.as_str()],
        action_row,
    )
    .optional()
    .map_err(db)?
    .filter(|row| !row.ciphertext.is_empty() && owns(row))
    .ok_or_else(|| RelayError::not_found("action"))
}

/// 403 `too_many_actions` naming `kind`, with a `limit_reached` row (at most one per kind
/// and ten seconds) on the transaction, which the caller commits.
fn too_many_actions(
    core: &Core,
    conn: &Connection,
    now: u64,
    kind: &'static str,
) -> RelayResult<RelayError> {
    core.limit_error_on(conn, now, kind)?;
    Ok(RelayError::new(
        codes::TOO_MANY_ACTIONS,
        format!("The team's {kind} limit is reached."),
    ))
}

/// `POST /v1/feed/actions`. Forms (400) and the size (413) first; then in one
/// transaction: `to_device` is a live device of the caller's member and not the caller
/// (403 `not_routed`), it has a feed (404), the `action_id` is new in the team (409
/// `conflict`: a retry of a post that landed), and the limits (403 `too_many_actions`):
/// the team's, then the member's share of them (`member_share`), then the sender's. The
/// relay stamps the caller's device and member and the next action sequence value.
pub fn post_action(
    core: &Core,
    by: &MemberAuth,
    request: &ActionPost,
    now: u64,
) -> RelayResult<Value> {
    let device = device_of(by)?;
    check_v(request.v)?;
    let action_id = ActionId::parse(&request.action_id).ok_or_else(invalid_action_id)?;
    if request.to_device == 0 {
        return Err(RelayError::invalid("to_device is a device id."));
    }
    check_key_id(&request.key_id)?;
    let nonce = nonce(&request.nonce)?;
    let ciphertext = ciphertext(&request.ciphertext, MAX_ACTION_BYTES)?;
    let limits = core.limits();
    let to = DeviceId(request.to_device);
    let expires_at = now.saturating_add(ACTION_LIFETIME_SECS);
    let outcome = core.store.tx(|tx| {
        let routed: bool = to != device
            && tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM device d JOIN member m ON m.id = d.member_id \
                     WHERE d.id = ?1 AND d.member_id = ?2 AND d.revoked_at IS NULL \
                     AND m.revoked_at IS NULL)",
                    params![to_i(to.0), to_i(by.id.0)],
                    |row| row.get(0),
                )
                .map_err(db)?;
        if !routed {
            return Ok(Err(RelayError::new(
                codes::NOT_ROUTED,
                "An action goes to another live device of your member.",
            )));
        }
        let has_feed: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM feed WHERE device_id = ?1)",
                params![to_i(to.0)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if !has_feed {
            return Ok(Err(RelayError::new(
                codes::NOT_FOUND,
                "The device has no feed.",
            )));
        }
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM feed_action WHERE action_id = ?1)",
                params![action_id.as_str()],
                |row| row.get(0),
            )
            .map_err(db)?;
        if exists {
            return Ok(Err(RelayError::new(
                codes::CONFLICT,
                "An action with this action_id exists in the team.",
            )));
        }
        let counts: [i64; 5] = tx
            .query_row(
                "SELECT coalesce(sum(created_at > ?2), 0), \
                 coalesce(sum(state = 'open' AND expires_at > ?1), 0), \
                 coalesce(sum(member_id = ?4 AND created_at > ?2), 0), \
                 coalesce(sum(member_id = ?4 AND state = 'open' AND expires_at > ?1), 0), \
                 coalesce(sum(from_device = ?3 AND state = 'open' AND expires_at > ?1), 0) \
                 FROM feed_action",
                params![
                    to_i(now),
                    to_i(now.saturating_sub(3600)),
                    to_i(device.0),
                    to_i(by.id.0)
                ],
                |row| {
                    Ok([
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ])
                },
            )
            .map_err(db)?;
        let [hour, open, member_hour, member_open, device_open] = counts;
        let members = limits.members;
        for (count, limit, kind) in [
            (hour, limits.feed_actions_per_hour, "feed_actions_per_hour"),
            (open, OPEN_ACTIONS, "open_feed_actions"),
            (
                member_hour,
                member_share(limits.feed_actions_per_hour, members),
                "member_feed_actions_per_hour",
            ),
            (
                member_open,
                member_share(OPEN_ACTIONS, members),
                "member_open_feed_actions",
            ),
            (device_open, DEVICE_OPEN_ACTIONS, "device_open_feed_actions"),
        ] {
            if to_u(count) >= limit {
                return Ok(Err(too_many_actions(core, tx, now, kind)?));
            }
        }
        let seq = tx
            .query_row(
                "UPDATE team SET feed_action_seq = feed_action_seq + 1 RETURNING feed_action_seq",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(to_u)
            .map_err(db)?;
        tx.execute(
            "INSERT INTO feed_action (action_id, seq, from_device, to_device, member_id, key_id, \
             nonce, ciphertext, created_at, expires_at, state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'open')",
            params![
                action_id.as_str(),
                to_i(seq),
                to_i(device.0),
                to_i(to.0),
                to_i(by.id.0),
                request.key_id,
                nonce,
                ciphertext,
                to_i(now),
                to_i(expires_at),
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "feed_action_posted",
            None,
            &json!({"device_id": device, "to_device_id": to}),
        )?;
        Ok(Ok(seq))
    })?;
    let seq = outcome?;
    core.notify.notify();
    Ok(json!({
        "action_id": action_id.as_str(),
        "seq": seq,
        "created_at": now,
        "expires_at": expires_at,
    }))
}

/// The open actions to `device` with `seq > after`, oldest first.
fn actions_now(
    conn: &Connection,
    device: DeviceId,
    after: u64,
    now: u64,
) -> RelayResult<ActionList> {
    let (_, seq) = counters(conn)?;
    let mut statement = conn
        .prepare(&format!(
            "SELECT {ACTION_COLUMNS} FROM feed_action WHERE to_device = ?1 AND seq > ?2 \
             AND state = 'open' AND expires_at > ?3 AND length(ciphertext) > 0 \
             ORDER BY seq LIMIT ?4"
        ))
        .map_err(db)?;
    let actions = statement
        .query_map(
            params![
                to_i(device.0),
                to_i(after),
                to_i(now),
                to_i(MAX_ACTION_LIST)
            ],
            action_row,
        )
        .map_err(db)?
        .map(|row| {
            row.map(|row| ActionView {
                action_id: row.action_id,
                seq: row.seq,
                from_device_id: row.from_device,
                key_id: row.key_id,
                nonce: encode_b64(&row.nonce),
                ciphertext: encode_b64(&row.ciphertext),
                created_at: row.created_at,
                expires_at: row.expires_at,
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    Ok(ActionList { seq, actions })
}

/// `GET /v1/feed/actions?after=N&wait=S`, for the target: while no open action to the
/// caller came after `after`, holds up to `wait` seconds. A sequence below `after` (a
/// restored relay) answers at once.
pub fn actions(
    core: &Core,
    by: &MemberAuth,
    after: u64,
    wait_secs: u64,
    hold: bool,
) -> RelayResult<ActionList> {
    long_poll(
        core,
        by,
        &core.feed_action_polls,
        true,
        wait_secs,
        hold,
        |conn, device, now| {
            let list = actions_now(conn, device, after, now)?;
            let done = !list.actions.is_empty() || list.seq < after;
            Ok((list, done))
        },
    )
}

/// `POST /v1/feed/actions/{id}/settle`, for the target only (404 for any other device).
/// The same body again answers the same (a retry); another one after a settle is 409
/// `action_settled`; after `expires_at`, 409 `action_expired`. The settle may be sealed
/// under another `key_id` than the action: a target that cannot open an action settles
/// it with its current key.
pub fn settle(
    core: &Core,
    by: &MemberAuth,
    id: ActionId,
    request: &ActionSettle,
    now: u64,
) -> RelayResult<Value> {
    let device = device_of(by)?;
    check_v(request.v)?;
    if !matches!(request.outcome.as_str(), "applied" | "refused" | "stale") {
        return Err(RelayError::invalid(
            "The outcome is applied, refused, or stale.",
        ));
    }
    check_key_id(&request.key_id)?;
    let nonce = nonce(&request.nonce)?;
    let ciphertext = ciphertext(&request.ciphertext, MAX_SETTLE_BYTES)?;
    let (settled_at, changed) = core.store.tx(|tx| {
        let action = own_action(tx, &id, |row| row.to_device == device)?;
        if action.state == "settled" {
            let same = action.outcome.as_deref() == Some(request.outcome.as_str())
                && action.settle_key_id.as_deref() == Some(request.key_id.as_str())
                && action.settle_nonce.as_deref() == Some(nonce.as_slice())
                && action.settle_ciphertext.as_deref() == Some(ciphertext.as_slice());
            return if same {
                Ok((action.settled_at.unwrap_or(now), false))
            } else {
                Err(RelayError::new(
                    codes::ACTION_SETTLED,
                    "The action is already settled with another body.",
                ))
            };
        }
        if action.state_at(now) == "expired" {
            return Err(RelayError::new(
                codes::ACTION_EXPIRED,
                "The action has expired.",
            ));
        }
        tx.execute(
            "UPDATE feed_action SET state = 'settled', outcome = ?2, settled_at = ?3, \
             settle_key_id = ?4, settle_nonce = ?5, settle_ciphertext = ?6 WHERE action_id = ?1",
            params![
                id.as_str(),
                request.outcome,
                to_i(now),
                request.key_id,
                nonce,
                ciphertext,
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "feed_action_settled",
            None,
            &json!({"device_id": device, "from_device_id": action.from_device,
                "outcome": request.outcome}),
        )?;
        Ok((now, true))
    })?;
    if changed {
        core.notify.notify();
    }
    Ok(json!({
        "action_id": id.as_str(),
        "state": "settled",
        "outcome": request.outcome,
        "settled_at": settled_at,
    }))
}

fn status_now(
    conn: &Connection,
    id: &ActionId,
    device: DeviceId,
    now: u64,
) -> RelayResult<ActionStatus> {
    let action = own_action(conn, id, |row| row.from_device == device)?;
    let state = action.state_at(now);
    let settled = state == "settled";
    let settle = match (
        &action.settle_key_id,
        &action.settle_nonce,
        &action.settle_ciphertext,
    ) {
        (Some(key_id), Some(nonce), Some(ciphertext)) if settled => Some(SealedView {
            key_id: key_id.clone(),
            nonce: encode_b64(nonce),
            ciphertext: encode_b64(ciphertext),
        }),
        _ => None,
    };
    Ok(ActionStatus {
        action_id: action.action_id,
        to_device: action.to_device,
        state: state.to_string(),
        created_at: action.created_at,
        expires_at: action.expires_at,
        outcome: action.outcome.filter(|_| settled),
        settled_at: action.settled_at.filter(|_| settled),
        settle,
    })
}

/// `GET /v1/feed/actions/{id}?wait=S`, for the sender only (404 for any other device):
/// while the action is open, holds up to `wait` seconds.
pub fn status(
    core: &Core,
    by: &MemberAuth,
    id: ActionId,
    wait_secs: u64,
    hold: bool,
) -> RelayResult<ActionStatus> {
    long_poll(
        core,
        by,
        &core.feed_status_polls,
        false,
        wait_secs,
        hold,
        |conn, device, now| {
            let status = status_now(conn, &id, device, now)?;
            let done = status.state != "open";
            Ok((status, done))
        },
    )
}

/// Every 5 seconds, per team, in one transaction that writes no audit row (a Connect
/// team at its file cap still frees its pages): open actions past `expires_at` become
/// `expired`; 10 minutes after an action was settled or expired its envelopes go (it is
/// then unknown); actions posted 24 hours ago go; a feed not updated for 30 days goes,
/// with one new feed counter value, and its open actions expire. Wakes the long polls
/// on a change.
pub fn maintenance(core: &Core, now: u64) -> RelayResult<()> {
    let changed = core.store.tx(|tx| {
        let expired = tx
            .execute(
                "UPDATE feed_action SET state = 'expired' WHERE state = 'open' AND expires_at <= ?1",
                params![to_i(now)],
            )
            .map_err(db)?;
        tx.execute(
            "UPDATE feed_action SET nonce = x'', ciphertext = x'', settle_nonce = NULL, \
             settle_ciphertext = NULL WHERE length(ciphertext) > 0 AND \
             ((state = 'settled' AND settled_at <= ?1) OR (state <> 'settled' AND expires_at <= ?1))",
            params![to_i(now.saturating_sub(PURGE_AFTER_SECS))],
        )
        .map_err(db)?;
        tx.execute(
            "DELETE FROM feed_action WHERE created_at <= ?1",
            params![to_i(now.saturating_sub(ACTION_RETENTION_SECS))],
        )
        .map_err(db)?;
        let stale = to_i(now.saturating_sub(FEED_RETENTION_SECS));
        tx.execute(
            "UPDATE feed_action SET state = 'expired', expires_at = min(expires_at, ?2) \
             WHERE state = 'open' AND to_device IN (SELECT device_id FROM feed WHERE updated_at <= ?1)",
            params![stale, to_i(now)],
        )
        .map_err(db)?;
        let feeds = tx
            .execute("DELETE FROM feed WHERE updated_at <= ?1", params![stale])
            .map_err(db)?;
        if feeds > 0 {
            next_change(tx)?;
        }
        Ok(expired > 0 || feeds > 0)
    })?;
    if changed {
        core.notify.notify();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkeys::decode_b64;

    /// The AAD of relay-feed-v1 section 6.1: the fields joined with one zero byte.
    fn aad(parts: &[&str]) -> Vec<u8> {
        parts.join("\0").into_bytes()
    }

    /// The forms of the contract's test vectors (section 17) pass the relay's checks, and
    /// the clear values that the relay stores and returns build the vector AADs byte for
    /// byte: the team id, the publisher's device id `2`, `seq`, `key_id`, the sender's
    /// device id `3`, the `action_id`, and the outcome.
    #[test]
    fn the_vector_aads_come_from_the_clear_fields() {
        let (team, key_id, seq) = ("t_7k2m5q4x3c", "630dcd2966c43366", 1_790_000_040u64);
        let action_id = ActionId::parse("sLGys7S1tre4ubq7vL2-vw").unwrap();
        assert_eq!(
            decode_b64(action_id.as_str(), 16).unwrap(),
            (0xb0..=0xbfu8).collect::<Vec<_>>()
        );
        check_key_id(key_id).unwrap();
        assert!((1..=MAX_SEQ).contains(&seq));
        for (text, first) in [
            ("MDEyMzQ1Njc4OTo7", 0x30u8),
            ("QEFCQ0RFRkdISUpL", 0x40),
            ("UFFSU1RVVldYWVpb", 0x50),
        ] {
            assert_eq!(
                nonce(text).unwrap(),
                (first..first + 12).collect::<Vec<_>>()
            );
        }
        let (publisher, sender) = (DeviceId(2), DeviceId(3));
        let feed = aad(&[
            "apassy-feed-v1",
            "feed",
            team,
            &publisher.0.to_string(),
            &seq.to_string(),
            key_id,
        ]);
        assert_eq!(feed.len(), 62);
        assert_eq!(
            crate::sync_head::hex(&feed),
            "6170617373792d666565642d7631006665656400745f376b326d357134783363003200313739303030303034300036333064636432393636633433333636"
        );
        let action = aad(&[
            "apassy-feed-v1",
            "action",
            team,
            action_id.as_str(),
            key_id,
            &sender.0.to_string(),
            &publisher.0.to_string(),
        ]);
        assert_eq!(action.len(), 78);
        assert_eq!(
            crate::sync_head::hex(&action),
            "6170617373792d666565642d763100616374696f6e00745f376b326d35713478336300734c4779733753317472653475627137764c322d7677003633306463643239363663343333363600330032"
        );
        let settle = aad(&[
            "apassy-feed-v1",
            "settle",
            team,
            action_id.as_str(),
            key_id,
            "applied",
        ]);
        assert_eq!(settle.len(), 82);
        assert_eq!(
            crate::sync_head::hex(&settle),
            "6170617373792d666565642d763100736574746c6500745f376b326d35713478336300734c4779733753317472653475627137764c322d76770036333064636432393636633433333636006170706c696564"
        );
        // No clear field holds a zero byte, so the join is unambiguous.
        for part in [
            team,
            action_id.as_str(),
            key_id,
            "applied",
            "refused",
            "stale",
        ] {
            assert!(!part.contains('\0'));
        }
    }

    #[test]
    fn the_sizes_of_the_contract() {
        // Section 6.3: plaintext + 16; the body holds the b64u of the largest feed.
        assert_eq!(MAX_FEED_BYTES, 262_128 + 16);
        assert_eq!(MAX_ACTION_BYTES, 4096 + 16);
        assert_eq!(MAX_SETTLE_BYTES, 1024 + 16);
        let text = encode_b64(&vec![0; MAX_FEED_BYTES]).len();
        assert_eq!(text, 349_526);
        // The JSON around it fits too.
        assert!(text + 200 < crate::api::MAX_FEED_BODY);
        assert_eq!(crate::api::MAX_FEED_BODY, 360_448);
        // The vector ciphertexts: 943 (feed), 435 (action), 130 (settle) bytes.
        for (len, max) in [
            (943, MAX_FEED_BYTES),
            (435, MAX_ACTION_BYTES),
            (130, MAX_SETTLE_BYTES),
            (MAX_FEED_BYTES, MAX_FEED_BYTES),
        ] {
            assert_eq!(
                ciphertext(&encode_b64(&vec![7; len]), max).unwrap().len(),
                len
            );
        }
        for max in [MAX_FEED_BYTES, MAX_ACTION_BYTES, MAX_SETTLE_BYTES] {
            assert_eq!(
                ciphertext(&encode_b64(&vec![7; max + 1]), max)
                    .unwrap_err()
                    .code,
                codes::PAYLOAD_TOO_LARGE
            );
        }
        assert_eq!(MAX_SEQ, 9_007_199_254_740_991);
    }

    #[test]
    fn full_reads_are_counted_per_minute_and_reads_that_go_on_are_free() {
        let mut reads = FeedReads::default();
        // Before any answer only `since=0` is a full read.
        reads.take(5, 600).unwrap();
        for _ in 0..FULL_READS_PER_MINUTE {
            reads.take(0, 600).unwrap();
        }
        assert_eq!(reads.take(0, 615), Err(45));
        // At the counter it was given, or above it, a device goes on; below it, it reads
        // again what it had.
        reads.given = Some(9);
        for since in [9, 9, 12] {
            reads.take(since, 615).unwrap();
        }
        assert_eq!(reads.take(8, 615), Err(45));
        assert_eq!(reads.take(0, 659), Err(1));
        // The next minute starts again.
        reads.take(0, 660).unwrap();
        assert_eq!(reads.count, 1);
    }

    #[test]
    fn a_member_gets_three_quarters_of_a_team_limit_unless_it_is_alone() {
        assert_eq!(member_share(4_194_304, 50), 3_145_728);
        assert_eq!(member_share(1_048_576, 2), 786_432);
        assert_eq!(member_share(OPEN_ACTIONS, 50), 15);
        assert_eq!(member_share(60, 50), 45);
        assert_eq!(member_share(1, 50), 1);
        // A team of one member (a Connect team) gives it the whole limit.
        assert_eq!(member_share(1_048_576, 1), 1_048_576);
        assert_eq!(member_share(OPEN_ACTIONS, 1), OPEN_ACTIONS);
        // At the default limits a member's ten devices fit in its share of feed_bytes.
        assert!(10 * MAX_FEED_BYTES as u64 <= member_share(4_194_304, 50));
    }

    #[test]
    fn action_ids_out_of_their_form_are_refused() {
        for bad in [
            "",
            "sLGys7S1tre4ubq7vL2-v",
            "sLGys7S1tre4ubq7vL2-vwA",
            "sLGys7S1tre4ubq7vL2+vw",
            "sLGys7S1tre4ubq7vL2/vw",
            "sLGys7S1tre4ubq7vL2-vx",
        ] {
            assert!(ActionId::parse(bad).is_none(), "{bad}");
            assert_eq!(
                path_action_id(bad).unwrap_err().code,
                codes::INVALID_REQUEST
            );
        }
    }
}
