//! The reader of the feeds of the other Macs of the vault (contract relay-feed-v1, with a
//! Mac as a reader, section 7.4).
//!
//! The agents, the activity, and the decisions of a Mac are local rows (`LOCAL_TABLES`):
//! they never sync. Each Mac publishes them as a sealed feed (`super::feed`). This thread
//! of the questions waiter reads the feeds of the other Macs, so that a Mac shows the
//! agents of the whole vault. It works as the reader of the iPhone
//! (`ios/ApassyCore/src/core/feed.rs`):
//!
//! - It long-polls `GET /v1/feed` of the questions team while the open vault is unlocked,
//!   the questions are on, and the vault has another live Mac in the team; with no other
//!   Mac it reads nothing. It follows `more`, reads again from 0 when the relay's
//!   `change` goes back, waits a whole minute after `403 feed_rate`, 5 minutes after a
//!   `404`, 2 s doubling to 30 s after another error, and 5 s doubling to 60 s after an
//!   early empty answer; a cycle takes at least 2 s.
//! - For each feed of another relay device it runs the checks of section 7.4 in order
//!   ([`read_feed`], [`Reader::take`]): the envelope opens with the question key and the
//!   AAD of the relay's device id and `seq`; the plaintext has exactly the fields of
//!   section 7.1, of v1 or of v2 (section 7.5) ([`Feed::parse`]); `seq` equals the relay's; `mac.device` is a live
//!   `trusted_device` of kind `mac`, not this Mac, whose `relay_devices[team]` is the
//!   relay's `device_id`; `seq` is above the highest one accepted of that device.
//! - It keeps the last good feed of each Mac, and the text of a failed step 1 or 2 for a
//!   known Mac with no good feed: [`OtherFeed::NeedsSync`] or [`OtherFeed::NeedsUpdate`].
//!   A later record that fails step 1 or 2 keeps the good feed on the screen with the
//!   text of the step ([`OtherMac::problem`]) until a newer good feed comes. A failed
//!   step 4 or 5 is ignored, with no text. A device that leaves `present`, and a
//!   Mac whose row goes, leave the list.
//! - Everything is in memory only: the feeds, and the highest `seq` of each Mac (kept
//!   across a lock while the app runs). A lock, another vault, and the questions going off
//!   drop the feeds (`Shared::forget_feeds`). `OtherMacs` carries them to the window
//!   (`QuestionsWorker::with_other_macs`), with the vault session that read them.
//!
//! A Mac only reads: it sends no action of the feed in this version. Nothing here logs a
//! feed or a part of one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::client::{FeedList, FeedRecord, MAX_WAIT, QuestionsError};
use super::envelope::valid_key_id;
use super::feed::{EARLY_WAIT_MOST, Feed, MAX_SEQ, UNSUPPORTED_WAIT, feed_aad, jitter};
use super::worker::{Active, Shared, lock, unix_now};
use crate::vault::{QuestionKey, TrustedDevice, TrustedDeviceKind};

/// The longest feed ciphertext (section 6.3, 256 KiB) as b64u without padding.
const MAX_CIPHERTEXT_TEXT: usize = 349_526;
/// One step reads at most this many answers of `GET /v1/feed`.
const MAX_PAGES: usize = 16;
/// The waits after a call that failed for a reason that can pass.
const RETRY_WAITS: [u64; 5] = [2, 4, 8, 16, 30];
/// The step of a wait: a lock or a stop ends it soon.
const WAIT_STEP: Duration = Duration::from_secs(1);
/// With no other Mac in the team, the reader looks at the vault again this often.
const IDLE_EVERY: Duration = Duration::from_secs(2);

/// What this Mac can show of the feed of another Mac (section 7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtherFeed {
    /// The last feed that opened and passed the checks.
    Ready(Feed),
    /// Step 1: the question key of this vault does not open the feed. "Sync this vault to
    /// see the agents of <Mac>".
    NeedsSync,
    /// Steps 2 and 3: the feed has a form that this version does not read. "Update Apassy
    /// to see the agents of <Mac>".
    NeedsUpdate,
}

/// Another Mac of the vault and its feed, as the view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherMac {
    /// The `trusted_device` UUID of the Mac (the feed's `mac.device`).
    pub device: String,
    /// The device number of the Mac in the questions team.
    pub relay_device_id: u64,
    /// The name of its `trusted_device` row on this Mac's copy of the vault.
    pub name: String,
    pub feed: OtherFeed,
    /// When this Mac received the feed, or the record that it could not show, in Unix
    /// seconds.
    pub received_at: u64,
    /// The failed step of a record that came after the good feed in `feed` (section 7.4):
    /// the screen keeps that feed and shows the text of the step. `None` while the feed
    /// is the newest one, and with no good feed (then `feed` is the text).
    pub problem: Option<Problem>,
}

/// What the reader shows of the other Macs, with the vault session that read them.
#[derive(Default)]
pub(super) struct OtherMacs {
    pub(super) epoch: Option<[u8; 32]>,
    pub(super) macs: Vec<OtherMac>,
}

/// Why the last feed of a Mac cannot be shown (section 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// Step 1: the envelope does not open (another key, or a damaged one).
    Sync,
    /// Steps 2 and 3: the plaintext is not of this version.
    Update,
}

/// What one record of `GET /v1/feed` is (section 7.4, steps 1 to 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Good(Feed),
    Problem(Problem),
    /// Not of the forms of the relay: no text.
    Ignore,
}

/// Open and check the feed of `record` of the team `team_id` with `key`, the question key
/// of the vault (section 7.4, steps 1 to 3).
pub fn read_feed(record: &FeedRecord, team_id: &str, key: Option<&QuestionKey>) -> Read {
    if !(1..=MAX_SEQ).contains(&record.seq) || !valid_key_id(&record.key_id) {
        return Read::Ignore;
    }
    // 1. The envelope opens with the key that it names and the AAD of the relay's values.
    let Some(key) = key.filter(|key| key.key_id() == record.key_id) else {
        return Read::Problem(Problem::Sync);
    };
    if record.ciphertext.len() > MAX_CIPHERTEXT_TEXT {
        return Read::Problem(Problem::Sync);
    }
    let aad = feed_aad(team_id, record.device_id, record.seq, &record.key_id);
    let Some(plaintext) = record.sealed().open(key, &aad) else {
        return Read::Problem(Problem::Sync);
    };
    // 2. and 3. Exactly the fields of section 7.1 (and 7.5 for v2) within their limits,
    // `v` 1 or 2, and the relay's `seq`.
    match Feed::parse(&plaintext) {
        Some(feed) if feed.seq == record.seq => Read::Good(feed),
        _ => Read::Problem(Problem::Update),
    }
}

/// The publisher of a feed of the relay device `device_id` that names `uuid` (section 7.4,
/// step 4): a live trusted Mac of the vault, not `me`, whose device number in `team_id` is
/// `device_id`. A row without that number publishes nothing there.
pub fn publisher<'a>(
    devices: &'a [TrustedDevice],
    team_id: &str,
    me: &str,
    uuid: &str,
    device_id: u64,
) -> Option<&'a TrustedDevice> {
    devices.iter().find(|device| {
        device.kind == TrustedDeviceKind::Mac
            && device.uuid == uuid
            && device.uuid != me
            && device.relay_devices.get(team_id) == Some(&device_id)
    })
}

/// The live trusted Mac, not `me`, with the device number `device_id` in `team_id`.
fn mac_of<'a>(
    devices: &'a [TrustedDevice],
    team_id: &str,
    me: &str,
    device_id: u64,
) -> Option<&'a TrustedDevice> {
    devices.iter().find(|device| {
        device.kind == TrustedDeviceKind::Mac
            && device.uuid != me
            && device.relay_devices.get(team_id) == Some(&device_id)
    })
}

/// The device numbers of the other live Macs of the vault in `team_id`: the devices whose
/// feeds this Mac reads. `me_id` is this Mac's own number.
pub fn other_macs(devices: &[TrustedDevice], team_id: &str, me: &str, me_id: u64) -> BTreeSet<u64> {
    devices
        .iter()
        .filter(|device| device.kind == TrustedDeviceKind::Mac && device.uuid != me)
        .filter_map(|device| device.relay_devices.get(team_id).copied())
        .filter(|id| *id != me_id)
        .collect()
}

/// The vault and the team whose feeds this Mac reads, for the reader that this Mac is.
pub struct Me<'a> {
    pub team_id: &'a str,
    /// The `trusted_device` UUID of this Mac.
    pub uuid: &'a str,
    /// The device number of this Mac in the team.
    pub device_id: u64,
    pub key: Option<&'a QuestionKey>,
    pub devices: &'a [TrustedDevice],
}

/// What the reader holds of one other Mac, by relay device id.
struct Shown {
    /// The `trusted_device` UUID that the feed or the row names.
    device: String,
    /// The last good feed and when it came.
    good: Option<(Feed, u64)>,
    /// The failed step of the last record, and when it came.
    problem: Option<(Problem, u64)>,
}

/// The feeds of the other Macs in one vault session, kept by the reader. No `Debug`, so
/// that no feed reaches a log.
#[derive(Default)]
pub struct Reader {
    /// The vault session and the team of the feeds below.
    session: Option<(PathBuf, [u8; 32], String)>,
    /// Ends an answer that came for a session that went.
    generation: u64,
    /// The last `change` of the team's feeds seen (section 10.4).
    since: u64,
    /// The other Macs of the vault when the reader last looked: a new one reads from 0.
    macs: BTreeSet<u64>,
    shown: BTreeMap<u64, Shown>,
    /// The highest `seq` accepted of each Mac, by team and relay device id (section 8).
    /// In memory only: it stays across a lock while the app runs.
    marks: BTreeMap<String, BTreeMap<u64, u64>>,
    /// No feed call before this time: a wait after an error, `403 feed_rate`, a `404`, or
    /// an early empty answer.
    next_try: Option<Instant>,
    tries: usize,
    early_wait: Option<Duration>,
}

impl Reader {
    /// Drop the feeds and start again for `session`. The marks stay.
    fn reset(&mut self, session: Option<(PathBuf, [u8; 32], String)>) {
        *self = Self {
            session,
            generation: self.generation.wrapping_add(1),
            marks: std::mem::take(&mut self.marks),
            ..Self::default()
        };
    }

    fn mark(&self, team_id: &str, device_id: u64) -> u64 {
        self.marks
            .get(team_id)
            .and_then(|devices| devices.get(&device_id))
            .copied()
            .unwrap_or(0)
    }

    fn raise(&mut self, team_id: &str, device_id: u64, seq: u64) {
        let mark = self
            .marks
            .entry(team_id.to_owned())
            .or_default()
            .entry(device_id)
            .or_insert(0);
        *mark = (*mark).max(seq);
    }

    /// The other Macs of the vault are `macs` now. A Mac that was not among them before
    /// reads from 0: its feed may be older than `since`. One that went leaves the list.
    pub fn look_at(&mut self, macs: BTreeSet<u64>) {
        if macs.iter().any(|id| !self.macs.contains(id)) {
            self.since = 0;
        }
        self.shown.retain(|id, _| macs.contains(id));
        self.macs = macs;
    }

    /// Take one answer of `GET /v1/feed?since=since` (section 7.4 for each feed, section
    /// 10.4 for `present`, `more`, and `change`). Returns whether the reader should read
    /// again at once: `more`, or a relay restored from a backup.
    pub fn take(&mut self, list: &FeedList, since: u64, me: &Me<'_>, now: u64) -> bool {
        if list.change < since {
            // A relay restored from a backup: read everything again.
            self.since = 0;
            return true;
        }
        let mut last = since;
        for record in &list.feeds {
            last = last.max(record.change);
            let device_id = record.device_id;
            // The feed of this Mac is the publisher's (section 8), not a feed to show.
            if device_id == me.device_id {
                continue;
            }
            let mark = self.mark(me.team_id, device_id);
            match read_feed(record, me.team_id, me.key) {
                Read::Good(feed) => {
                    // 4. A live trusted Mac of this vault, not this Mac.
                    if publisher(me.devices, me.team_id, me.uuid, &feed.mac.device, device_id)
                        .is_none()
                    {
                        continue;
                    }
                    // 5. Above the highest `seq` accepted. The same `seq` is the same feed
                    // (the AAD binds it): it shows again after a lock, when it does not
                    // show now.
                    let showing = self
                        .shown
                        .get(&device_id)
                        .and_then(|shown| shown.good.as_ref())
                        .map(|(feed, _)| feed.seq);
                    if feed.seq < mark || (feed.seq == mark && showing.is_some()) {
                        continue;
                    }
                    if showing.is_some_and(|seq| seq >= feed.seq) {
                        continue;
                    }
                    self.raise(me.team_id, device_id, feed.seq);
                    self.shown.insert(
                        device_id,
                        Shown {
                            device: feed.mac.device.clone(),
                            good: Some((feed, now)),
                            problem: None,
                        },
                    );
                }
                Read::Problem(problem) => {
                    // The last good feed stays; a record at or below the mark is an old
                    // one. A device that is no Mac of the vault gets no text.
                    if record.seq <= mark {
                        continue;
                    }
                    if let Some(shown) = self.shown.get_mut(&device_id) {
                        shown.problem = Some((problem, now));
                    } else if let Some(row) = mac_of(me.devices, me.team_id, me.uuid, device_id) {
                        self.shown.insert(
                            device_id,
                            Shown {
                                device: row.uuid.clone(),
                                good: None,
                                problem: Some((problem, now)),
                            },
                        );
                    }
                }
                Read::Ignore => {}
            }
        }
        // A device without a feed on the relay leaves the list.
        let present: BTreeSet<u64> = list.present.iter().copied().collect();
        self.shown.retain(|id, _| present.contains(id));
        let next = if list.more {
            last
        } else {
            list.change.max(last)
        };
        self.since = self.since.max(next);
        list.more
    }

    /// What the window shows: each other Mac with a feed or a text, named by its row as
    /// the vault holds it now, by name. A Mac whose row went, or whose row no longer has
    /// that device number, is not in it.
    pub fn macs(&self, me: &Me<'_>) -> Vec<OtherMac> {
        let mut out: Vec<OtherMac> = self
            .shown
            .iter()
            .filter_map(|(device_id, shown)| {
                let row = publisher(me.devices, me.team_id, me.uuid, &shown.device, *device_id)?;
                // A failed record after a good feed keeps that feed, with its text.
                let (feed, received_at, problem) = match (&shown.good, shown.problem) {
                    (Some((feed, at)), problem) => (
                        OtherFeed::Ready(feed.clone()),
                        *at,
                        problem.map(|(problem, _)| problem),
                    ),
                    (None, Some((Problem::Sync, at))) => (OtherFeed::NeedsSync, at, None),
                    (None, Some((Problem::Update, at))) => (OtherFeed::NeedsUpdate, at, None),
                    (None, None) => return None,
                };
                Some(OtherMac {
                    device: row.uuid.clone(),
                    relay_device_id: *device_id,
                    name: row.name.clone(),
                    feed,
                    received_at,
                    problem,
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.name, &a.device).cmp(&(&b.name, &b.device)));
        out
    }

    /// The waits after a call that failed for a reason that can pass: 2 s doubling to
    /// 30 s, with jitter.
    fn back_off(&mut self) {
        let wait = RETRY_WAITS[self.tries.min(RETRY_WAITS.len() - 1)];
        self.tries += 1;
        self.wait(jitter(Duration::from_secs(wait)));
    }

    /// No feed call before `wait` passed (or a later time that is set already).
    fn wait(&mut self, wait: Duration) {
        let at = Instant::now() + wait;
        self.next_try = Some(self.next_try.map_or(at, |next| next.max(at)));
    }
}

impl Shared {
    /// The feeds of the other Macs go: the vault locked, changed, or the questions went
    /// off.
    pub(super) fn forget_feeds(&self) {
        let mut reader = lock(&self.feed_reader);
        reader.reset(None);
        let mut shown = lock(&self.other_macs);
        let changed = !shown.macs.is_empty() || shown.epoch.is_some();
        *shown = OtherMacs::default();
        drop(shown);
        drop(reader);
        if changed {
            self.changed();
        }
    }

    /// Copy what `reader` shows for the window, for the vault session of `active`.
    fn publish_feeds(&self, reader: &Reader, me: &Me<'_>, active: &Active) {
        let macs = reader.macs(me);
        let mut shown = lock(&self.other_macs);
        let changed = shown.macs != macs || shown.epoch != Some(active.epoch);
        shown.macs = macs;
        shown.epoch = Some(active.epoch);
        drop(shown);
        if changed {
            self.changed();
        }
    }

    /// Read the vault of `active` and bring the reader to it. `None`: nothing to read now
    /// (the vault is locked or another one, or it has no other Mac); the window is told.
    /// Else the generation and the `since` of the next call.
    fn reader_look(&self, active: &Active, me_id: u64) -> Option<(u64, u64)> {
        // The vault first, then the reader, then what it shows: the order of the lister.
        let mut guard = lock(&self.vault);
        let read = Self::vault_of(&mut guard, active)
            .map(|vault| (vault.trusted_devices(), vault.question_key()));
        let Some((devices, key)) = read else {
            drop(guard);
            self.forget_feeds();
            return None;
        };
        let devices = devices.ok()?;
        let key = key.ok().flatten();
        let me = Me {
            team_id: &active.team_id,
            uuid: &active.me.uuid,
            device_id: me_id,
            key: key.as_ref(),
            devices: &devices,
        };
        let mut reader = lock(&self.feed_reader);
        let session = (active.path.clone(), active.epoch, active.team_id.clone());
        if reader.session.as_ref() != Some(&session) {
            reader.reset(Some(session));
        }
        let macs = other_macs(&devices, &active.team_id, &active.me.uuid, me_id);
        let idle = macs.is_empty();
        reader.look_at(macs);
        self.publish_feeds(&reader, &me, active);
        (!idle).then_some((reader.generation, reader.since))
    }

    /// Take one answer for the session of `generation`, under the vault lock, so that a
    /// lock never lets an older list reach the window. `None`: the session went. Else
    /// whether to read again at once, and the `since` to read from.
    fn reader_take(
        &self,
        active: &Active,
        me_id: u64,
        generation: u64,
        since: u64,
        list: &FeedList,
    ) -> Option<(bool, u64)> {
        let mut guard = lock(&self.vault);
        let read = Self::vault_of(&mut guard, active)
            .map(|vault| (vault.trusted_devices(), vault.question_key()));
        let Some((devices, key)) = read else {
            drop(guard);
            self.forget_feeds();
            return None;
        };
        let devices = devices.ok()?;
        let key = key.ok().flatten();
        let me = Me {
            team_id: &active.team_id,
            uuid: &active.me.uuid,
            device_id: me_id,
            key: key.as_ref(),
            devices: &devices,
        };
        let mut reader = lock(&self.feed_reader);
        if reader.generation != generation {
            return None;
        }
        let again = reader.take(list, since, &me, unix_now());
        self.publish_feeds(&reader, &me, active);
        Some((again, reader.since))
    }

    /// A feed read failed.
    fn reader_error(&self, error: &QuestionsError) {
        let mut reader = lock(&self.feed_reader);
        if error.status() == Some(404) {
            // A relay without the feed (section 14.2): the publisher says so in Settings.
            reader.wait(UNSUPPORTED_WAIT);
        } else if error.code() == Some("feed_rate") {
            // `403 feed_rate` (section 10.2): no feed read for a whole minute.
            reader.wait(self.config.feed_rate_wait);
        } else if !matches!(error, QuestionsError::Closed) {
            reader.back_off();
        }
    }

    /// One step of the reader: one long poll of `GET /v1/feed` with the pages that follow
    /// it, then the checks of each feed (section 7.4).
    pub(super) fn feed_read_step(&self) {
        let active = lock(&self.state)
            .active
            .clone()
            .filter(|_| self.config.feed);
        let Some((active, me_id)) =
            active.and_then(|active| active.client.device_id().map(|id| (active, id)))
        else {
            if lock(&self.feed_reader).session.is_some() {
                self.forget_feeds();
            }
            self.sleep(WAIT_STEP);
            return;
        };
        let Some((generation, mut since)) = self.reader_look(&active, me_id) else {
            self.sleep(IDLE_EVERY);
            return;
        };
        let waiting = lock(&self.feed_reader)
            .next_try
            .and_then(|at| at.checked_duration_since(Instant::now()))
            .filter(|left| !left.is_zero());
        if let Some(left) = waiting {
            self.sleep(left.min(WAIT_STEP));
            return;
        }
        let started = Instant::now();
        let mut wait = MAX_WAIT;
        let mut news = false;
        for _ in 0..MAX_PAGES {
            let result = active.client.feeds(since, wait);
            if self.stop.load(Ordering::SeqCst) {
                return;
            }
            let list = match result {
                Ok(list) => list,
                Err(error) => {
                    self.reader_error(&error);
                    return;
                }
            };
            news |= !list.feeds.is_empty() || list.change < since;
            let Some((again, next)) = self.reader_take(&active, me_id, generation, since, &list)
            else {
                return;
            };
            if !again {
                break;
            }
            since = next;
            wait = Duration::ZERO;
        }
        let every = self.config.short_poll_every;
        let mut reader = lock(&self.feed_reader);
        if reader.generation != generation {
            return;
        }
        reader.tries = 0;
        reader.next_try = None;
        if !news && started.elapsed() + Duration::from_secs(2) < MAX_WAIT {
            // An early empty answer (section 10.10): 5 s, doubling to 60 s, with jitter.
            let early = reader
                .early_wait
                .map_or(self.config.feed_early_wait, |wait| {
                    (wait * 2).min(EARLY_WAIT_MOST)
                });
            reader.early_wait = Some(early);
            reader.wait(jitter(early));
        } else {
            reader.early_wait = None;
            // A relay may answer at once with news: a cycle takes at least 2 s.
            reader.wait(every.saturating_sub(started.elapsed()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::questions::envelope::Sealed;
    use crate::questions::feed::{FeedMac, FeedWeek};

    const TEAM: &str = "t_7k2m5q4x3c";
    const ME: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
    const OTHER: &str = "1c8f6d4b-0e2a-4b3c-9d7e-5f1a2b3c4d5e";
    const PHONE: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
    const ME_ID: u64 = 2;
    const OTHER_ID: u64 = 4;
    const PHONE_ID: u64 = 3;

    fn key() -> QuestionKey {
        QuestionKey::from_bytes(std::array::from_fn(|at| at as u8))
    }

    fn row(uuid: &str, name: &str, kind: TrustedDeviceKind, id: Option<u64>) -> TrustedDevice {
        TrustedDevice {
            uuid: uuid.to_owned(),
            name: name.to_owned(),
            kind,
            relay_devices: id.map(|id| (TEAM.to_owned(), id)).into_iter().collect(),
            sign_key: Vec::new(),
            answer_key: None,
            created_at: 1,
            updated_at: 1,
            updated_by: String::new(),
        }
    }

    fn devices() -> Vec<TrustedDevice> {
        vec![
            row(
                ME,
                concat!("This ", crate::computer!()),
                TrustedDeviceKind::Mac,
                Some(ME_ID),
            ),
            row(OTHER, "Studio Mac", TrustedDeviceKind::Mac, Some(OTHER_ID)),
            row(
                PHONE,
                "Test iPhone",
                TrustedDeviceKind::Iphone,
                Some(PHONE_ID),
            ),
        ]
    }

    fn feed(uuid: &str, seq: u64) -> Feed {
        Feed {
            v: 1,
            mac: FeedMac {
                device: uuid.to_owned(),
                name: "Studio Mac".to_owned(),
            },
            seq,
            generated_at: seq,
            truncated: false,
            remote_access: None,
            week: FeedWeek {
                by_you: 1,
                automatic: 2,
                days: Vec::new(),
                answer_p50_secs: None,
            },
            agents: Vec::new(),
        }
    }

    fn record_of(
        device_id: u64,
        seq: u64,
        change: u64,
        key: &QuestionKey,
        plaintext: &[u8],
    ) -> FeedRecord {
        let aad = feed_aad(TEAM, device_id, seq, &key.key_id());
        let sealed = Sealed::new(key, &aad, plaintext).expect("sealed");
        FeedRecord {
            device_id,
            device_name: String::new(),
            seq,
            change,
            key_id: sealed.key_id,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            updated_at: seq,
        }
    }

    fn record(device_id: u64, feed: &Feed, change: u64) -> FeedRecord {
        record_of(device_id, feed.seq, change, &key(), &feed.to_plaintext())
    }

    fn list(feeds: Vec<FeedRecord>) -> FeedList {
        FeedList {
            change: feeds.iter().map(|feed| feed.change).max().unwrap_or(0),
            more: false,
            present: feeds.iter().map(|feed| feed.device_id).collect(),
            feeds,
        }
    }

    fn take(reader: &mut Reader, answer: &FeedList, devices: &[TrustedDevice]) -> Vec<OtherMac> {
        let key = key();
        let me = Me {
            team_id: TEAM,
            uuid: ME,
            device_id: ME_ID,
            key: Some(&key),
            devices,
        };
        let since = reader.since;
        reader.take(answer, since, &me, 1_790_000_100);
        reader.macs(&me)
    }

    #[test]
    fn a_feed_opens_only_with_its_key_its_aad_and_its_form() {
        let good = feed(OTHER, 1_790_000_040);
        let record = record(OTHER_ID, &good, 1);
        assert_eq!(
            read_feed(&record, TEAM, Some(&key())),
            Read::Good(good.clone())
        );
        // The mark of v2 actions (a line feed) is white space after the object.
        let mut marked = good.to_plaintext().to_vec();
        marked.push(b'\n');
        let with_mark = record_of(OTHER_ID, good.seq, 1, &key(), &marked);
        assert_eq!(
            read_feed(&with_mark, TEAM, Some(&key())),
            Read::Good(good.clone())
        );
        // Step 1: no key, another key, another team, another device, another `seq`.
        let sync = Read::Problem(Problem::Sync);
        assert_eq!(read_feed(&record, TEAM, None), sync);
        let other_key = QuestionKey::from_bytes([7; 32]);
        assert_eq!(read_feed(&record, TEAM, Some(&other_key)), sync);
        assert_eq!(read_feed(&record, "t_otherteam1", Some(&key())), sync);
        let mut moved = record.clone();
        moved.device_id = PHONE_ID;
        assert_eq!(read_feed(&moved, TEAM, Some(&key())), sync);
        let mut renumbered = record.clone();
        renumbered.seq += 1;
        assert_eq!(read_feed(&renumbered, TEAM, Some(&key())), sync);
        // Step 2: an unknown field; step 3: a `seq` that is not the relay's.
        let mut value = serde_json::to_value(&good).unwrap();
        value["extra"] = serde_json::json!(1);
        let unknown = record_of(
            OTHER_ID,
            good.seq,
            1,
            &key(),
            &serde_json::to_vec(&value).unwrap(),
        );
        assert_eq!(
            read_feed(&unknown, TEAM, Some(&key())),
            Read::Problem(Problem::Update)
        );
        let other_seq = record_of(OTHER_ID, good.seq + 1, 1, &key(), &good.to_plaintext());
        assert_eq!(
            read_feed(&other_seq, TEAM, Some(&key())),
            Read::Problem(Problem::Update)
        );
        // Not of the relay's forms: no text.
        let mut zero = record.clone();
        zero.seq = 0;
        assert_eq!(read_feed(&zero, TEAM, Some(&key())), Read::Ignore);
        let mut bad_key_id = record;
        bad_key_id.key_id = "not-a-key-id".to_owned();
        assert_eq!(read_feed(&bad_key_id, TEAM, Some(&key())), Read::Ignore);
    }

    /// `feed` as a feed of v2 with one remote agent.
    fn feed_v2(uuid: &str, seq: u64) -> Feed {
        use crate::questions::feed::{FEED_DAYS, FEED_VERSION, FeedAgentDay, FeedDay};
        let mut two = feed(uuid, seq);
        two.v = FEED_VERSION;
        two.remote_access = Some("off".to_owned());
        two.week.days = vec![FeedDay { runs: 4, asked: 1 }; FEED_DAYS];
        two.week.answer_p50_secs = Some(12);
        let text = r#"{"id":"9","name":"Grok Bot","host":"other","where":"remote","connected_at":1790000000,"revoked":false,"token_expires_at":1797776000,"last_use_at":null,"uses_this_week":0,"projects":[],"note":"","restricted":true,"actions":[],"exceptions":[],"recent":[]}"#;
        let mut agent: crate::questions::feed::FeedAgent = serde_json::from_str(text).unwrap();
        agent.days = vec![
            FeedAgentDay {
                runs: 2,
                asked: 2,
                not_allowed: 1
            };
            FEED_DAYS
        ];
        two.agents.push(agent);
        two
    }

    #[test]
    fn the_reader_takes_a_feed_of_v1_or_v2_and_refuses_v3() {
        let one = feed(OTHER, 1_790_000_040);
        assert_eq!(
            read_feed(&record(OTHER_ID, &one, 1), TEAM, Some(&key())),
            Read::Good(one.clone())
        );
        let two = feed_v2(OTHER, 1_790_000_041);
        let Read::Good(read) = read_feed(&record(OTHER_ID, &two, 2), TEAM, Some(&key())) else {
            panic!("a feed of v2 reads");
        };
        assert_eq!(read, two);
        assert_eq!(read.remote_access.as_deref(), Some("off"));
        assert_eq!(read.week.answer_p50_secs, Some(12));
        assert_eq!(read.agents[0].place, "remote");
        assert_eq!(read.agents[0].days.len(), 7);
        // v3: "Update Apassy to see the agents of <Mac>".
        let text = String::from_utf8(two.to_plaintext().to_vec()).unwrap();
        let three = text.replacen(r#""v":2"#, r#""v":3"#, 1);
        assert_eq!(
            read_feed(
                &record_of(OTHER_ID, two.seq, 3, &key(), three.as_bytes()),
                TEAM,
                Some(&key())
            ),
            Read::Problem(Problem::Update)
        );
    }

    #[test]
    fn the_reader_shows_another_mac_only_and_never_an_older_feed() {
        let devices = devices();
        let mut reader = Reader::default();
        reader.look_at(other_macs(&devices, TEAM, ME, ME_ID));
        // Its own feed, a feed of the iPhone, and a feed that names the other Mac from the
        // device number of the iPhone: none shows.
        let own = record(ME_ID, &feed(ME, 1_790_000_010), 1);
        let phone = record(PHONE_ID, &feed(PHONE, 1_790_000_011), 2);
        let posing = record(PHONE_ID, &feed(OTHER, 1_790_000_012), 3);
        let mut answer = list(vec![own, phone, posing]);
        answer.present = vec![ME_ID, PHONE_ID];
        assert!(take(&mut reader, &answer, &devices).is_empty());
        // The other Mac: named by its row.
        let first = feed(OTHER, 1_790_000_040);
        let shown = take(
            &mut reader,
            &list(vec![record(OTHER_ID, &first, 4)]),
            &devices,
        );
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].device, OTHER);
        assert_eq!(shown[0].relay_device_id, OTHER_ID);
        assert_eq!(shown[0].name, "Studio Mac");
        assert_eq!(shown[0].feed, OtherFeed::Ready(first.clone()));
        // An older or the same `seq` is ignored; the last good feed stays.
        for seq in [first.seq - 1, first.seq] {
            let mut older = feed(OTHER, seq);
            older.week.by_you = 99;
            let shown = take(
                &mut reader,
                &list(vec![record(OTHER_ID, &older, 5)]),
                &devices,
            );
            assert_eq!(shown[0].feed, OtherFeed::Ready(first.clone()), "seq {seq}");
        }
        // A record that does not open keeps the last good feed.
        let wrong = record_of(
            OTHER_ID,
            first.seq + 5,
            6,
            &QuestionKey::from_bytes([7; 32]),
            b"{}",
        );
        let shown = take(&mut reader, &list(vec![wrong]), &devices);
        assert_eq!(shown[0].feed, OtherFeed::Ready(first.clone()));
        // A newer one replaces it.
        let newer = feed(OTHER, first.seq + 10);
        let shown = take(
            &mut reader,
            &list(vec![record(OTHER_ID, &newer, 7)]),
            &devices,
        );
        assert_eq!(shown[0].feed, OtherFeed::Ready(newer.clone()));
        // After a lock the same feed shows again, but never an older one.
        reader.reset(None);
        let older = feed(OTHER, first.seq + 9);
        assert!(
            take(
                &mut reader,
                &list(vec![record(OTHER_ID, &older, 8)]),
                &devices
            )
            .is_empty()
        );
        let again = take(
            &mut reader,
            &list(vec![record(OTHER_ID, &newer, 9)]),
            &devices,
        );
        assert_eq!(again[0].feed, OtherFeed::Ready(newer));
        // Not in `present`: it leaves the list.
        let mut gone = list(Vec::new());
        gone.change = 10;
        assert!(take(&mut reader, &gone, &devices).is_empty());
    }

    #[test]
    fn a_mac_without_a_good_feed_gets_the_text_of_the_failed_step() {
        let devices = devices();
        let mut reader = Reader::default();
        reader.look_at(other_macs(&devices, TEAM, ME, ME_ID));
        let seq = 1_790_000_040;
        let wrong = record_of(OTHER_ID, seq, 1, &QuestionKey::from_bytes([7; 32]), b"{}");
        let shown = take(&mut reader, &list(vec![wrong]), &devices);
        assert_eq!(shown[0].feed, OtherFeed::NeedsSync);
        assert_eq!(shown[0].name, "Studio Mac");
        let mut value = serde_json::to_value(feed(OTHER, seq + 1)).unwrap();
        value["agents_v2"] = serde_json::json!([]);
        let unknown = record_of(
            OTHER_ID,
            seq + 1,
            2,
            &key(),
            &serde_json::to_vec(&value).unwrap(),
        );
        let shown = take(&mut reader, &list(vec![unknown]), &devices);
        assert_eq!(shown[0].feed, OtherFeed::NeedsUpdate);
        // A device that is no Mac of the vault gets no text.
        let phone = record_of(PHONE_ID, seq, 3, &QuestionKey::from_bytes([7; 32]), b"{}");
        let mut answer = list(vec![phone]);
        answer.present = vec![OTHER_ID, PHONE_ID];
        let shown = take(&mut reader, &answer, &devices);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].relay_device_id, OTHER_ID);
    }

    /// Section 7.4: the first failure keeps the last good feed of that Mac on the screen
    /// and shows the text of the step. The reader kept the feed but showed no text, so a
    /// Mac whose feed opened once and then no longer opened looked current.
    #[test]
    fn a_later_record_that_fails_keeps_the_feed_with_the_text_of_its_step() {
        let devices = devices();
        let mut reader = Reader::default();
        reader.look_at(other_macs(&devices, TEAM, ME, ME_ID));
        let first = feed(OTHER, 1_790_000_040);
        let shown = take(
            &mut reader,
            &list(vec![record(OTHER_ID, &first, 1)]),
            &devices,
        );
        assert_eq!(shown[0].feed, OtherFeed::Ready(first.clone()));
        assert_eq!(shown[0].problem, None, "the newest feed");
        // Another key (the question key rotated): the feed stays, with "Sync…".
        let rotated = record_of(
            OTHER_ID,
            first.seq + 1,
            2,
            &QuestionKey::from_bytes([7; 32]),
            b"{}",
        );
        let shown = take(&mut reader, &list(vec![rotated]), &devices);
        assert_eq!(shown[0].feed, OtherFeed::Ready(first.clone()));
        assert_eq!(shown[0].problem, Some(Problem::Sync));
        // A newer form: the feed stays, with "Update…".
        let mut value = serde_json::to_value(feed(OTHER, first.seq + 2)).unwrap();
        value["agents_v2"] = serde_json::json!([]);
        let newer_form = record_of(
            OTHER_ID,
            first.seq + 2,
            3,
            &key(),
            &serde_json::to_vec(&value).unwrap(),
        );
        let shown = take(&mut reader, &list(vec![newer_form]), &devices);
        assert_eq!(shown[0].feed, OtherFeed::Ready(first.clone()));
        assert_eq!(shown[0].problem, Some(Problem::Update));
        // A newer good feed ends the text.
        let newer = feed(OTHER, first.seq + 3);
        let shown = take(
            &mut reader,
            &list(vec![record(OTHER_ID, &newer, 4)]),
            &devices,
        );
        assert_eq!(shown[0].feed, OtherFeed::Ready(newer.clone()));
        assert_eq!(shown[0].problem, None);
        // A failed record at or below the mark is an old one: no text.
        let old = record_of(
            OTHER_ID,
            newer.seq,
            5,
            &QuestionKey::from_bytes([7; 32]),
            b"{}",
        );
        let shown = take(&mut reader, &list(vec![old]), &devices);
        assert_eq!(shown[0].feed, OtherFeed::Ready(newer));
        assert_eq!(shown[0].problem, None);
    }

    #[test]
    fn a_mac_whose_row_goes_leaves_and_a_new_one_reads_from_the_start() {
        let key = key();
        let mut devices = devices();
        let mut reader = Reader::default();
        reader.look_at(other_macs(&devices, TEAM, ME, ME_ID));
        let first = feed(OTHER, 1_790_000_040);
        let shown = take(
            &mut reader,
            &list(vec![record(OTHER_ID, &first, 4)]),
            &devices,
        );
        assert_eq!(shown.len(), 1);
        assert_eq!(reader.since, 4);
        devices.retain(|device| device.uuid != OTHER);
        reader.look_at(other_macs(&devices, TEAM, ME, ME_ID));
        let me = Me {
            team_id: TEAM,
            uuid: ME,
            device_id: ME_ID,
            key: Some(&key),
            devices: &devices,
        };
        assert!(reader.macs(&me).is_empty());
        // The row syncs in again: the reader reads from 0, so the feed that is on the relay
        // already shows.
        devices.push(row(
            OTHER,
            "Studio Mac",
            TrustedDeviceKind::Mac,
            Some(OTHER_ID),
        ));
        reader.look_at(other_macs(&devices, TEAM, ME, ME_ID));
        assert_eq!(reader.since, 0);
        // A relay whose `change` went back: read again from 0.
        reader.since = 9;
        let mut back = list(Vec::new());
        back.change = 3;
        let me = Me {
            team_id: TEAM,
            uuid: ME,
            device_id: ME_ID,
            key: Some(&key),
            devices: &devices,
        };
        assert!(reader.take(&back, 9, &me, 1));
        assert_eq!(reader.since, 0);
    }
}
