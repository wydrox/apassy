//! The pace of the question long polls (contract relay-connect-v1, section 5).
//!
//! A relay may answer `GET /v1/questions?wait=…` and `GET /v1/questions/{qid}/answers?wait=…`
//! early with nothing new: a Connect team holds at most 2 waiting question polls. After
//! such an answer the device waits before it polls again: 5 s, then 10, 20, 40, and 60 s
//! at most, each ±20% at random. A poll that waited its full time or brought something
//! ends the pause: the next poll goes at once, as before. The Mac (the asker and the
//! lister of [`super::worker`]) and the iPhone core use the same rule.
//!
//! [`PollBackoff`] takes the time from its caller, so a test drives it with a fake clock.

use std::time::{Duration, Instant};

/// The first pause after an early empty answer.
pub const FIRST_PAUSE: Duration = Duration::from_secs(5);
/// The longest pause, before the jitter.
pub const LONGEST_PAUSE: Duration = Duration::from_secs(60);
/// The jitter of a pause, in thousandths, each way.
const JITTER_PERMILLE: u64 = 200;
/// A poll that came back this much or more before its wait ended came back early: a
/// network delay or a relay timer a little short does not count.
pub const EARLY_SLACK: Duration = Duration::from_secs(1);

/// Whether a long poll that asked to wait `wait`, took `took`, and brought `news` came
/// back early with nothing new. A poll with no wait is never early.
pub fn early_empty(wait: Duration, took: Duration, news: bool) -> bool {
    !news && took.saturating_add(EARLY_SLACK) < wait
}

/// The pause after `early` early empty answers in a row (1 or more), with `jitter` a
/// random number: [`FIRST_PAUSE`] doubled for each one after the first, at most
/// [`LONGEST_PAUSE`], then ±20% by `jitter`.
pub fn pause_after(early: u32, jitter: u32) -> Duration {
    let doublings = early.saturating_sub(1).min(16);
    let base = FIRST_PAUSE
        .saturating_mul(1 << doublings)
        .min(LONGEST_PAUSE);
    // 800 to 1200 thousandths of the base.
    let permille = 1000 - JITTER_PERMILLE + u64::from(jitter) % (2 * JITTER_PERMILLE + 1);
    let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(millis.saturating_mul(permille) / 1000)
}

/// A random number for [`pause_after`]. Without a random source it takes the clock.
pub fn random_jitter() -> u32 {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_ok() {
        return u32::from_le_bytes(bytes);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos())
}

/// The pause of one long poll loop.
#[derive(Debug, Clone, Default)]
pub struct PollBackoff {
    /// Early empty answers in a row.
    early: u32,
    /// No poll before this time.
    until: Option<Instant>,
}

impl PollBackoff {
    /// The time left at `now` before the next poll may go. Zero: it goes now.
    pub fn left(&self, now: Instant) -> Duration {
        self.until
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    /// Early empty answers in a row so far.
    pub fn early(&self) -> u32 {
        self.early
    }

    /// A poll ended at `now`: it asked to wait `wait`, took `took`, and brought `news`
    /// (a question, an answer, or another state). Returns the pause before the next
    /// poll: zero after a poll that waited its full time or brought something, else the
    /// next step of the backoff with `jitter` ([`random_jitter`]).
    pub fn polled(
        &mut self,
        now: Instant,
        wait: Duration,
        took: Duration,
        news: bool,
        jitter: u32,
    ) -> Duration {
        if !early_empty(wait, took, news) {
            self.reset();
            return Duration::ZERO;
        }
        self.early = self.early.saturating_add(1);
        let pause = pause_after(self.early, jitter);
        self.until = Some(now + pause);
        pause
    }

    /// Forget the early answers: the next poll goes at once.
    pub fn reset(&mut self) {
        self.early = 0;
        self.until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake clock: the instants of a test, in seconds after its start.
    struct Clock(Instant);

    impl Clock {
        fn at(&self, seconds: u64) -> Instant {
            self.0 + Duration::from_secs(seconds)
        }
    }

    const NO_JITTER: u32 = 200; // 1000 thousandths: the base itself.
    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn pauses_double_from_five_to_sixty_seconds() {
        let steps: Vec<u64> = (1..=7)
            .map(|early| pause_after(early, NO_JITTER).as_secs())
            .collect();
        assert_eq!(steps, [5, 10, 20, 40, 60, 60, 60]);
        assert_eq!(pause_after(u32::MAX, NO_JITTER), S(60));
    }

    #[test]
    fn the_jitter_stays_within_twenty_percent() {
        assert_eq!(pause_after(1, 0), Duration::from_millis(4000));
        assert_eq!(pause_after(1, 400), Duration::from_millis(6000));
        assert_eq!(pause_after(5, 0), S(48));
        assert_eq!(pause_after(5, 400), S(72));
        for jitter in [1, 77, 199, 201, 399, 401, 12_345, u32::MAX] {
            let pause = pause_after(3, jitter);
            assert!(pause >= S(16) && pause <= S(24), "{pause:?}");
        }
        let random = pause_after(1, random_jitter());
        assert!(random >= S(4) && random <= S(6));
    }

    #[test]
    fn only_an_early_answer_without_news_is_early_empty() {
        assert!(early_empty(S(25), S(0), false));
        assert!(early_empty(S(25), Duration::from_millis(23_900), false));
        // Within a second of the wait: the relay held the poll.
        assert!(!early_empty(S(25), S(24), false));
        assert!(!early_empty(S(25), S(26), false));
        // Something new is never early empty.
        assert!(!early_empty(S(25), S(0), true));
        // A poll that asked for no wait.
        assert!(!early_empty(Duration::ZERO, Duration::ZERO, false));
        assert!(!early_empty(S(1), Duration::ZERO, false));
    }

    #[test]
    fn early_empty_answers_back_off_and_a_full_poll_resets() {
        let clock = Clock(Instant::now());
        let mut pace = PollBackoff::default();
        assert_eq!(pace.left(clock.at(0)), Duration::ZERO);

        // Early empty at t=0: 5 s.
        assert_eq!(
            pace.polled(clock.at(0), S(25), S(0), false, NO_JITTER),
            S(5)
        );
        assert_eq!(pace.left(clock.at(0)), S(5));
        assert_eq!(pace.left(clock.at(3)), S(2));
        assert_eq!(pace.left(clock.at(5)), Duration::ZERO);
        // Then 10, 20, 40, 60, 60.
        let mut at = 5;
        for expected in [10, 20, 40, 60, 60] {
            assert_eq!(
                pace.polled(clock.at(at), S(25), S(0), false, NO_JITTER),
                S(expected)
            );
            assert_eq!(pace.left(clock.at(at)), S(expected));
            at += expected;
        }
        assert_eq!(pace.early(), 6);

        // A poll that waited its full time: the next goes at once, and the step starts over.
        assert_eq!(
            pace.polled(clock.at(at), S(25), S(25), false, NO_JITTER),
            Duration::ZERO
        );
        assert_eq!(pace.left(clock.at(at)), Duration::ZERO);
        assert_eq!(pace.early(), 0);
        assert_eq!(
            pace.polled(clock.at(at), S(25), S(0), false, NO_JITTER),
            S(5)
        );
    }

    #[test]
    fn a_poll_with_news_resets_the_pause() {
        let clock = Clock(Instant::now());
        let mut pace = PollBackoff::default();
        pace.polled(clock.at(0), S(25), S(0), false, NO_JITTER);
        pace.polled(clock.at(5), S(25), S(0), false, NO_JITTER);
        assert_eq!(pace.left(clock.at(5)), S(10));
        // An early answer with a question in it.
        assert_eq!(
            pace.polled(clock.at(15), S(25), S(1), true, NO_JITTER),
            Duration::ZERO
        );
        assert_eq!(pace.early(), 0);
        assert_eq!(pace.left(clock.at(15)), Duration::ZERO);
    }

    #[test]
    fn reset_lets_the_next_poll_go_at_once() {
        let clock = Clock(Instant::now());
        let mut pace = PollBackoff::default();
        pace.polled(clock.at(0), S(25), S(0), false, NO_JITTER);
        pace.reset();
        assert_eq!(pace.left(clock.at(0)), Duration::ZERO);
        assert_eq!(
            pace.polled(clock.at(0), S(25), S(0), false, NO_JITTER),
            S(5)
        );
    }
}
