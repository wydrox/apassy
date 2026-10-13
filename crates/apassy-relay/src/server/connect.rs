//! The guards of codeless Connect teams (docs/SPEC.md section 26) that live in memory
//! only: the Connect teams of one client prefix in a day, the requests of one Connect
//! team in a minute, and the long polls that Connect teams hold.
//!
//! Nothing here is written to disk. The client prefix (an IPv6 /48 or an IPv4 /24, from
//! the Worker's `X-Apassy-Client-Prefix`) is kept only as an HMAC-SHA256 under a random
//! salt that is made in memory and replaced at each UTC day; the counters go with it. A
//! restart forgets everything, and no audit row names a prefix.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{RelayError, RelayResult, codes};

/// Connect teams that one client prefix makes in one UTC day, at most.
pub const PREFIX_TEAMS_PER_DAY: u64 = 5;
/// No prefix makes more than this share (1/n) of `APASSY_RELAY_CONNECT_TEAMS_PER_DAY`.
pub const PREFIX_SHARE_DIVISOR: u64 = 10;
/// Prefixes counted at once. A new prefix beyond it gets 503 `busy` until the day ends.
pub const MAX_PREFIXES: usize = 65_536;
/// The prefix of a request without `X-Apassy-Client-Prefix` (a Worker from before it):
/// all such requests share one count.
pub const UNKNOWN_PREFIX: &str = "unknown";
/// The longest prefix text that is read; a longer one counts as `UNKNOWN_PREFIX`.
pub const MAX_PREFIX_LEN: usize = 64;
/// Requests of a Connect team in one minute, for each member its limits allow.
pub const REQUESTS_PER_MINUTE: u64 = 300;
/// The question long polls of one Connect team at once, out of
/// `Limits::question_long_polls_per_team`.
pub const TEAM_QUESTION_POLLS: usize = 8;

const DAY: u64 = 86_400;

/// The Connect teams of one prefix in a day: `PREFIX_TEAMS_PER_DAY`, and no more than
/// a tenth of the daily cap (at least 1).
pub fn per_prefix(per_day: u64) -> u64 {
    (per_day / PREFIX_SHARE_DIVISOR).clamp(1, PREFIX_TEAMS_PER_DAY)
}

/// Seconds until the next UTC day, when the counts start again.
pub fn until_tomorrow(now: u64) -> u64 {
    DAY - now % DAY
}

/// 429 `rate_limited` for a prefix that made its Connect teams of the day.
pub fn prefix_limited() -> RelayError {
    RelayError::new(
        codes::RATE_LIMITED,
        "This network made its new teams for today. Try again tomorrow.",
    )
}

struct PrefixState {
    /// The UTC day of `salt` and `counts`.
    day: u64,
    salt: Option<hmac::Key>,
    /// Teams made, or being made, today, by the salted hash of the prefix.
    counts: HashMap<[u8; 32], u64>,
}

/// The Connect teams of each client prefix today.
pub struct PrefixLimiter {
    state: Mutex<PrefixState>,
}

impl Default for PrefixLimiter {
    fn default() -> Self {
        Self {
            state: Mutex::new(PrefixState {
                day: 0,
                salt: None,
                counts: HashMap::new(),
            }),
        }
    }
}

/// One Connect team reserved for a prefix. Dropped without `keep`, it gives the count
/// back (the team was not made).
pub struct PrefixTicket<'a> {
    limiter: &'a PrefixLimiter,
    tag: [u8; 32],
    day: u64,
    kept: bool,
}

impl PrefixTicket<'_> {
    /// The team was made: the count stays.
    pub fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for PrefixTicket<'_> {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.day != self.day {
            return;
        }
        if let Some(count) = state.counts.get_mut(&self.tag) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.counts.remove(&self.tag);
            }
        }
    }
}

impl PrefixState {
    /// A new salt and no counts at the first call of a UTC day.
    fn roll(&mut self, now: u64) -> RelayResult<()> {
        let day = now / DAY;
        if self.salt.is_some() && self.day == day {
            return Ok(());
        }
        let mut salt = [0u8; 32];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| RelayError::internal("The system has no random source."))?;
        self.salt = Some(hmac::Key::new(hmac::HMAC_SHA256, &salt));
        self.day = day;
        self.counts.clear();
        Ok(())
    }

    fn tag(&self, prefix: &str) -> [u8; 32] {
        let mut tag = [0u8; 32];
        if let Some(salt) = &self.salt {
            tag.copy_from_slice(hmac::sign(salt, prefix.as_bytes()).as_ref());
        }
        tag
    }
}

impl PrefixLimiter {
    /// Reserves one Connect team for `prefix` today: 429 `rate_limited` when it made
    /// `per_prefix(per_day)` already, 503 `busy` when the table is full.
    pub fn reserve(&self, prefix: &str, per_day: u64, now: u64) -> RelayResult<PrefixTicket<'_>> {
        let prefix = checked_prefix(prefix);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.roll(now)?;
        let tag = state.tag(prefix);
        let count = state.counts.get(&tag).copied().unwrap_or(0);
        if count >= per_prefix(per_day) {
            return Err(prefix_limited());
        }
        if count == 0 && state.counts.len() >= MAX_PREFIXES {
            return Err(crate::server::directory::connect_busy());
        }
        state.counts.insert(tag, count + 1);
        Ok(PrefixTicket {
            limiter: self,
            tag,
            day: state.day,
            kept: false,
        })
    }
}

/// The prefix as it is counted: the Worker's text, or `UNKNOWN_PREFIX` when there is
/// none or it is too long.
pub fn checked_prefix(prefix: &str) -> &str {
    let prefix = prefix.trim();
    if prefix.is_empty() || prefix.len() > MAX_PREFIX_LEN {
        UNKNOWN_PREFIX
    } else {
        prefix
    }
}

/// The requests of one Connect team in the current minute.
#[derive(Default)]
pub struct RequestRate(Mutex<(u64, u64)>);

impl RequestRate {
    /// Counts one request. `Err(seconds)` when the team made `per_minute` already in
    /// this minute: the seconds until the next one.
    pub fn take(&self, per_minute: u64, now: u64) -> Result<(), u64> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let minute = now / 60;
        if state.0 != minute {
            *state = (minute, 0);
        }
        if state.1 >= per_minute {
            return Err(60 - now % 60);
        }
        state.1 += 1;
        Ok(())
    }
}

/// 429 `rate_limited` for a Connect team over its requests of the minute.
pub fn requests_limited() -> RelayError {
    RelayError::new(
        codes::RATE_LIMITED,
        "This team sent too many requests this minute. Try again in a moment.",
    )
}

/// One long poll that a Connect team holds, out of `Limits::connect_long_polls` for all
/// of them. An operator team's poll holds nothing. Dropping it gives the seat back.
pub struct PollSeat<'a>(Option<&'a AtomicUsize>);

impl PollSeat<'_> {
    /// A seat that counts nothing (an operator team).
    pub fn free() -> Self {
        Self(None)
    }
}

impl<'a> PollSeat<'a> {
    /// A seat of `held`, or `None` when `max` are held: then the poll answers at once.
    pub fn take(held: &'a AtomicUsize, max: usize) -> Option<Self> {
        held.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < max).then_some(count + 1)
        })
        .ok()
        .map(|_| Self(Some(held)))
    }
}

impl Drop for PollSeat<'_> {
    fn drop(&mut self) {
        if let Some(held) = self.0 {
            held.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOON: u64 = 20_000 * DAY + DAY / 2;

    #[test]
    fn a_prefix_makes_five_teams_a_day_and_a_tenth_of_the_cap_at_most() {
        assert_eq!(per_prefix(200), 5);
        assert_eq!(per_prefix(30), 3);
        assert_eq!(per_prefix(5), 1);
        assert_eq!(per_prefix(0), 1);
        let limiter = PrefixLimiter::default();
        for _ in 0..5 {
            limiter
                .reserve("2001:db8:1::/48", 200, NOON)
                .unwrap()
                .keep();
        }
        let refused = limiter.reserve("2001:db8:1::/48", 200, NOON).err().unwrap();
        assert_eq!(refused.code, codes::RATE_LIMITED);
        assert_eq!(refused.status(), 429);
        // Another prefix has its own count; a lower cap lowers the share.
        limiter
            .reserve("198.51.100.0/24", 200, NOON)
            .unwrap()
            .keep();
        limiter.reserve("203.0.113.0/24", 20, NOON).unwrap().keep();
        limiter.reserve("203.0.113.0/24", 20, NOON).unwrap().keep();
        assert!(limiter.reserve("203.0.113.0/24", 20, NOON).is_err());
    }

    #[test]
    fn a_ticket_that_is_not_kept_gives_its_count_back() {
        let limiter = PrefixLimiter::default();
        for _ in 0..20 {
            drop(limiter.reserve("198.51.100.0/24", 200, NOON).unwrap());
        }
        for _ in 0..5 {
            limiter
                .reserve("198.51.100.0/24", 200, NOON)
                .unwrap()
                .keep();
        }
        assert!(limiter.reserve("198.51.100.0/24", 200, NOON).is_err());
        // A ticket of yesterday does not touch today's count.
        let limiter = PrefixLimiter::default();
        let old = limiter.reserve("198.51.100.0/24", 200, NOON).unwrap();
        for _ in 0..5 {
            limiter
                .reserve("198.51.100.0/24", 200, NOON + DAY)
                .unwrap()
                .keep();
        }
        drop(old);
        assert!(limiter.reserve("198.51.100.0/24", 200, NOON + DAY).is_err());
    }

    #[test]
    fn the_salt_and_the_counts_change_at_each_utc_day() {
        let limiter = PrefixLimiter::default();
        for _ in 0..5 {
            limiter
                .reserve("2001:db8:1::/48", 200, NOON)
                .unwrap()
                .keep();
        }
        let tag_today = {
            let state = limiter.state.lock().unwrap();
            assert_eq!(state.counts.len(), 1);
            // Only the salted hash is kept, never the prefix.
            assert!(!state.counts.contains_key(&[0u8; 32]));
            state.tag("2001:db8:1::/48")
        };
        // The last second of the day still counts; the first of the next does not.
        let last = (NOON / DAY + 1) * DAY - 1;
        assert!(limiter.reserve("2001:db8:1::/48", 200, last).is_err());
        assert_eq!(until_tomorrow(last), 1);
        limiter
            .reserve("2001:db8:1::/48", 200, last + 1)
            .unwrap()
            .keep();
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.counts.len(), 1);
        assert_ne!(state.tag("2001:db8:1::/48"), tag_today);
        assert_eq!(state.counts.values().copied().collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn missing_and_long_prefixes_share_one_count() {
        assert_eq!(checked_prefix(""), UNKNOWN_PREFIX);
        assert_eq!(checked_prefix("  "), UNKNOWN_PREFIX);
        assert_eq!(checked_prefix(&"a".repeat(65)), UNKNOWN_PREFIX);
        assert_eq!(checked_prefix(" 10.0.0.0/24 "), "10.0.0.0/24");
        let limiter = PrefixLimiter::default();
        for prefix in ["", "unknown", &"b".repeat(100), " ", "unknown"] {
            limiter.reserve(prefix, 200, NOON).unwrap().keep();
        }
        assert!(limiter.reserve("", 200, NOON).is_err());
    }

    #[test]
    fn the_table_of_prefixes_is_bounded() {
        let limiter = PrefixLimiter::default();
        {
            let mut state = limiter.state.lock().unwrap();
            state.roll(NOON).unwrap();
            for index in 0..MAX_PREFIXES as u32 {
                let mut tag = [0u8; 32];
                tag[..4].copy_from_slice(&index.to_be_bytes());
                tag[31] = 1;
                state.counts.insert(tag, 1);
            }
        }
        let full = limiter.reserve("192.0.2.0/24", 200, NOON).err().unwrap();
        assert_eq!(full.code, codes::BUSY);
    }

    #[test]
    fn a_team_makes_its_requests_of_a_minute() {
        let rate = RequestRate::default();
        for _ in 0..3 {
            rate.take(3, 600).unwrap();
        }
        assert_eq!(rate.take(3, 615), Err(45));
        rate.take(3, 660).unwrap();
    }

    #[test]
    fn poll_seats_are_bounded_and_given_back() {
        let held = AtomicUsize::new(0);
        let one = PollSeat::take(&held, 2).unwrap();
        let two = PollSeat::take(&held, 2).unwrap();
        assert!(PollSeat::take(&held, 2).is_none());
        drop(one);
        let three = PollSeat::take(&held, 2).unwrap();
        drop((two, three));
        assert_eq!(held.load(Ordering::Relaxed), 0);
        drop(PollSeat::free());
        assert_eq!(held.load(Ordering::Relaxed), 0);
    }
}
