//! The agent feeds of the other Macs of this vault (contract relay-feed-v1, with a Mac as
//! a reader). The agents, the activity, and the decisions of a Mac are local rows
//! (`LOCAL_TABLES`): they never sync. Each Mac publishes them as a sealed feed through the
//! relay. This Mac reads the feeds of the other Macs of the vault, so that Agents and
//! Decisions show the whole vault, not only this Mac.
//!
//! The reader keeps the last good feed of each Mac in [`RemoteMac`]. A later record of that
//! Mac that fails step 1 or 2 of section 7.4 keeps the feed on the screen with the text of
//! the step ([`RemoteMac::problem`]), until a newer good feed comes. The agents of another
//! Mac are read-only here: a change is made on that Mac.
//!
//! The reader is a thread of the questions waiter (`crate::questions::feed_reader`): it
//! long-polls the feeds, runs the checks of section 7.4, and keeps the result with the
//! vault session that read it (`QuestionsWorker::with_other_macs`). Each frame,
//! [`DesktopApp::poll_remote_feeds`] copies the result of the open vault session into
//! [`DesktopApp::remote_macs`] when it changed. A lock and a vault switch clear it at once;
//! the waiter clears its own copy when the vault locks, changes, or the questions go off.
//! Nothing is kept on disk.

use std::collections::BTreeSet;

use crate::desktop::DesktopApp;
use crate::desktop::ui::bouncer::{self, Environment};
use crate::questions::feed::Feed;
use crate::questions::feed_reader::Problem;
use crate::questions::{OtherFeed, OtherMac};
use crate::vault::{TrustedDevice, TrustedDeviceKind};

/// What this Mac can show of the feed of another Mac (section 7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteFeedState {
    /// The feed opened and passed the checks.
    Ready(Feed),
    /// The question key of this vault does not open the feed: "Sync this vault to see the
    /// agents of <Mac>".
    NeedsSync,
    /// The feed has a form that this version does not read: "Update Apassy to see the
    /// agents of <Mac>".
    NeedsUpdate,
}

/// Why this Mac cannot show the newest feed of another Mac (section 7.4). The screen
/// keeps the last good feed and shows the text of the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedProblem {
    /// Step 1: the envelope does not open. "Sync this vault to see the agents of <Mac>".
    NeedsSync,
    /// Steps 2 and 3: a form that this version does not read. "Update Apassy to see the
    /// agents of <Mac>".
    NeedsUpdate,
}

impl From<Problem> for FeedProblem {
    fn from(problem: Problem) -> Self {
        match problem {
            Problem::Sync => Self::NeedsSync,
            Problem::Update => Self::NeedsUpdate,
        }
    }
}

/// Another Mac of this vault and its feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteMac {
    /// The `trusted_device` id of the Mac (the feed's `mac.device`).
    pub(crate) device: String,
    /// The name of the Mac from its `trusted_device` row.
    pub(crate) name: String,
    pub(crate) state: RemoteFeedState,
    /// When this Mac received the feed, in Unix seconds.
    pub(crate) received_at: u64,
    /// A record of the Mac that came after the feed of [`RemoteFeedState::Ready`] and
    /// failed: the screen keeps that feed and shows the text of the step. `None` while
    /// the feed is the newest one, and with no good feed (then `state` is the text).
    pub(crate) problem: Option<FeedProblem>,
}

/// The scope of the Bouncer pages. It lives with the pages (`ui::bouncer`), so the demo
/// build has it too.
pub(crate) use crate::desktop::ui::bouncer::{ActivityScope, DeviceScope};

impl From<&OtherFeed> for RemoteFeedState {
    fn from(feed: &OtherFeed) -> Self {
        match feed {
            OtherFeed::Ready(feed) => Self::Ready(feed.clone()),
            OtherFeed::NeedsSync => Self::NeedsSync,
            OtherFeed::NeedsUpdate => Self::NeedsUpdate,
        }
    }
}

impl From<&OtherMac> for RemoteMac {
    fn from(mac: &OtherMac) -> Self {
        Self {
            device: mac.device.clone(),
            name: mac.name.clone(),
            state: RemoteFeedState::from(&mac.feed),
            received_at: mac.received_at,
            problem: mac.problem.map(FeedProblem::from),
        }
    }
}

impl RemoteMac {
    /// Whether this row shows `mac` as the reader has it, without a copy.
    fn shows(&self, mac: &OtherMac) -> bool {
        self.device == mac.device
            && self.name == mac.name
            && self.received_at == mac.received_at
            && self.problem == mac.problem.map(FeedProblem::from)
            && match (&self.state, &mac.feed) {
                (RemoteFeedState::Ready(shown), OtherFeed::Ready(read)) => shown == read,
                (RemoteFeedState::NeedsSync, OtherFeed::NeedsSync)
                | (RemoteFeedState::NeedsUpdate, OtherFeed::NeedsUpdate) => true,
                _ => false,
            }
    }
}

/// The rows of `macs`, or `None` when `shown` already shows them.
fn changed_rows(shown: &[RemoteMac], macs: &[OtherMac]) -> Option<Vec<RemoteMac>> {
    let same = shown.len() == macs.len() && shown.iter().zip(macs).all(|(row, mac)| row.shows(mac));
    (!same).then(|| macs.iter().map(RemoteMac::from).collect())
}

impl DesktopApp {
    /// Each frame: the other Macs of the open vault session and their feeds, as the reader
    /// of the questions waiter has them. Nothing while the vault is locked.
    pub(crate) fn poll_remote_feeds(&mut self) {
        #[cfg(test)]
        if self.remote_macs_pinned {
            return;
        }
        let epoch = self.owner_ui.session.epoch();
        let changed = match &self.owner.questions {
            Some(questions) => questions.with_other_macs(|read_by, macs| {
                // Only what the open, unlocked vault session read.
                let macs: &[OtherMac] = if epoch.is_some() && read_by == epoch {
                    macs
                } else {
                    &[]
                };
                changed_rows(&self.remote_macs, macs)
            }),
            None => changed_rows(&self.remote_macs, &[]),
        };
        if let Some(rows) = changed {
            self.remote_macs = rows;
            self.ui.bouncer.feeds_changed();
        }
    }

    /// The vault locked, or another one opens: the other Macs go at once.
    pub(crate) fn forget_remote_feeds(&mut self) {
        self.remote_macs.clear();
    }
}

/// The environments of the scope bar (implementation-plan-bouncer-section §1): this Mac
/// first, then every live `trusted_device` of kind `mac` of the vault with the age of its
/// feed, then the Macs that never reported, dimmed.
///
/// `this_name` is the name of this Mac's own `trusted_device` row ("This Mac" when it has
/// none), and `own` the UUIDs of this Mac's rows: they are never another environment. A
/// Mac with a feed but without a row (a row that did not sync yet) still shows, by the
/// name of its feed.
pub(crate) fn environments(
    this_name: &str,
    own: &BTreeSet<String>,
    devices: &[TrustedDevice],
    macs: &[RemoteMac],
) -> Vec<Environment> {
    let mut envs = vec![Environment::this_mac(this_name)];
    for mac in macs.iter().filter(|mac| !own.contains(&mac.device)) {
        envs.push(environment_of(mac));
    }
    for device in devices {
        if device.kind != TrustedDeviceKind::Mac
            || own.contains(&device.uuid)
            || macs.iter().any(|mac| mac.device == device.uuid)
        {
            continue;
        }
        envs.push(Environment {
            scope: DeviceScope::Other(device.uuid.clone()),
            name: shown_name(&device.name, None),
            reported_at: None,
            never_reported: true,
            note: None,
        });
    }
    bouncer::sort_environments(&mut envs);
    envs
}

/// The environment of a Mac with a feed: the age is the feed's `generated_at` (a time in
/// the future reads as now); a feed that this Mac cannot open counts from its arrival.
fn environment_of(mac: &RemoteMac) -> Environment {
    let (reported_at, feed, note) = match &mac.state {
        RemoteFeedState::Ready(feed) => (feed.generated_at, Some(feed), None),
        RemoteFeedState::NeedsSync => (mac.received_at, None, Some("Sync this vault to see")),
        RemoteFeedState::NeedsUpdate => (mac.received_at, None, Some("Update Apassy to see")),
    };
    let name = shown_name(&mac.name, feed);
    Environment {
        scope: DeviceScope::Other(mac.device.clone()),
        note: note.map(|start| format!("{start} the agents of {name}.")),
        name,
        reported_at: Some(reported_at),
        never_reported: false,
    }
}

/// The name of another Mac: its `trusted_device` row, else the name in its feed.
fn shown_name(row: &str, feed: Option<&Feed>) -> String {
    match (row.trim(), feed) {
        ("", Some(feed)) if !feed.mac.name.trim().is_empty() => bouncer::clip(&feed.mac.name),
        ("", _) => "Another Mac".to_owned(),
        (name, _) => bouncer::clip(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::questions::feed::{FeedMac, FeedWeek};

    const OTHER: &str = "1c8f6d4b-0e2a-4b3c-9d7e-5f1a2b3c4d5e";

    fn feed() -> Feed {
        Feed {
            v: 1,
            mac: FeedMac {
                device: OTHER.to_owned(),
                name: "Studio Mac".to_owned(),
            },
            seq: 1_790_000_040,
            generated_at: 1_790_000_040,
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

    fn other(state: OtherFeed) -> OtherMac {
        OtherMac {
            device: OTHER.to_owned(),
            relay_device_id: 4,
            name: "Studio Mac".to_owned(),
            feed: state,
            received_at: 1_790_000_041,
            problem: None,
        }
    }

    #[test]
    fn the_rows_follow_the_reader_and_change_only_when_it_does() {
        let read = vec![
            other(OtherFeed::Ready(feed())),
            OtherMac {
                device: "2d9a7e5c-1f3b-4c4d-8e8f-6a2b3c4d5e6f".to_owned(),
                name: "Old Mac".to_owned(),
                feed: OtherFeed::NeedsUpdate,
                ..other(OtherFeed::NeedsSync)
            },
        ];
        let rows = changed_rows(&[], &read).expect("new rows");
        assert_eq!(
            rows[0],
            RemoteMac {
                device: OTHER.to_owned(),
                name: "Studio Mac".to_owned(),
                state: RemoteFeedState::Ready(feed()),
                received_at: 1_790_000_041,
                problem: None,
            }
        );
        assert_eq!(rows[1].state, RemoteFeedState::NeedsUpdate);
        assert_eq!(changed_rows(&rows, &read), None, "the same rows");
        let mut newer = feed();
        newer.seq += 1;
        let read = vec![other(OtherFeed::Ready(newer.clone()))];
        let rows = changed_rows(&rows, &read).expect("a newer feed");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, RemoteFeedState::Ready(newer));
        assert_eq!(
            changed_rows(&rows, &[]).expect("none any more"),
            Vec::<RemoteMac>::new()
        );
        let sync = changed_rows(&[], &[other(OtherFeed::NeedsSync)]).expect("a text");
        assert_eq!(sync[0].state, RemoteFeedState::NeedsSync);
    }

    /// A Mac whose feed opened once and whose later record no longer opens (or has a
    /// newer form) keeps its last good feed, marked with the text of the step (section
    /// 7.4); the window showed the old feed as if it were current. A newer good feed
    /// ends the mark.
    #[test]
    fn a_later_failure_keeps_the_feed_and_marks_it() {
        let ready = changed_rows(&[], &[other(OtherFeed::Ready(feed()))]).expect("a feed");
        assert_eq!(ready[0].problem, None);
        for (problem, shown) in [
            (Problem::Sync, FeedProblem::NeedsSync),
            (Problem::Update, FeedProblem::NeedsUpdate),
        ] {
            let failed = OtherMac {
                problem: Some(problem),
                ..other(OtherFeed::Ready(feed()))
            };
            let rows =
                changed_rows(&ready, std::slice::from_ref(&failed)).expect("the failure is news");
            assert_eq!(
                rows[0].state,
                RemoteFeedState::Ready(feed()),
                "the feed stays"
            );
            assert_eq!(rows[0].problem, Some(shown));
            assert_eq!(rows[0].received_at, ready[0].received_at);
            assert_eq!(
                changed_rows(&rows, std::slice::from_ref(&failed)),
                None,
                "the same rows"
            );
            let mut newer = feed();
            newer.seq += 1;
            let rows = changed_rows(&rows, &[other(OtherFeed::Ready(newer.clone()))])
                .expect("a newer feed");
            assert_eq!(rows[0].state, RemoteFeedState::Ready(newer));
            assert_eq!(rows[0].problem, None, "the newest feed again");
        }
    }

    #[test]
    fn a_lock_a_vault_switch_and_a_locked_vault_clear_the_other_macs() {
        let row = RemoteMac::from(&other(OtherFeed::Ready(feed())));
        let mut app = DesktopApp::new();
        app.remote_macs = vec![row.clone()];
        app.lock_vault(None);
        assert!(app.remote_macs.is_empty(), "a lock");
        app.remote_macs = vec![row.clone()];
        app.reset_vault_state(None);
        assert!(app.remote_macs.is_empty(), "a vault switch");
        // No unlocked vault: the frame brings no other Mac.
        app.remote_macs = vec![row];
        app.poll_remote_feeds();
        assert!(app.remote_macs.is_empty(), "no vault session");
    }

    fn trusted(uuid: &str, name: &str, kind: TrustedDeviceKind) -> TrustedDevice {
        TrustedDevice {
            uuid: uuid.to_owned(),
            name: name.to_owned(),
            kind,
            relay_devices: Default::default(),
            sign_key: Vec::new(),
            answer_key: None,
            created_at: 1_790_000_000,
            updated_at: 0,
            updated_by: String::new(),
        }
    }

    /// The scope bar lists this Mac first, then each other Mac with the age of its
    /// feed, then a Mac of the vault that never reported, last and dimmed. An iPhone is
    /// no environment, and this Mac's own row is not another Mac.
    #[test]
    fn the_environments_are_this_mac_then_reporting_macs_then_never_reported_ones() {
        let me = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
        let never = "3e0b8f6c-2a4c-4d5e-9f9a-7b3c4d5e6f70";
        let devices = vec![
            trusted(me, "Mac mini (office)", TrustedDeviceKind::Mac),
            trusted(never, "iMac (home)", TrustedDeviceKind::Mac),
            trusted(OTHER, "Studio Mac", TrustedDeviceKind::Mac),
            trusted(
                "4f1c9a7d-3b5d-4e6f-8a0b-8c4d5e6f7081",
                "Test iPhone",
                TrustedDeviceKind::Iphone,
            ),
        ];
        let own: BTreeSet<String> = [me.to_owned()].into();
        let macs = vec![RemoteMac::from(&other(OtherFeed::Ready(feed())))];
        let envs = environments("Mac mini (office)", &own, &devices, &macs);
        let names: Vec<&str> = envs.iter().map(|env| env.name.as_str()).collect();
        assert_eq!(names, ["Mac mini (office)", "Studio Mac", "iMac (home)"]);
        assert_eq!(envs[0].scope, DeviceScope::ThisMac);
        assert_eq!(envs[1].reported_at, Some(feed().generated_at));
        assert!(envs[2].never_reported);
        let now = feed().generated_at + 60;
        assert!(envs[2].dimmed(now), "never reported is dimmed");
        assert!(!envs[1].dimmed(now));
        assert_eq!(envs[0].menu_detail(now, 0), "This Mac");
        assert_eq!(envs[2].menu_detail(now, 0), "Never reported");
        assert_eq!(envs[1].menu_detail(now, 0), "1 min ago");
        // A feed older than 24 hours is dimmed everywhere.
        let later = feed().generated_at + 24 * 3_600 + 1;
        assert!(envs[1].dimmed(later));
        assert!(envs[1].stale(later));
    }

    /// With one Mac, the list still has it: the menu shows (frame 12b).
    #[test]
    fn one_mac_is_one_environment() {
        let envs = environments("", &BTreeSet::new(), &[], &[]);
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].name, "This Mac");
        assert!(envs[0].is_this_mac());
    }

    /// A feed this Mac cannot open still names its Mac, with the text that says why.
    #[test]
    fn an_unreadable_feed_is_an_environment_with_a_note() {
        let macs = vec![RemoteMac::from(&other(OtherFeed::NeedsUpdate))];
        let envs = environments("Here", &BTreeSet::new(), &[], &macs);
        assert_eq!(envs.len(), 2);
        assert_eq!(
            envs[1].note.as_deref(),
            Some("Update Apassy to see the agents of Studio Mac.")
        );
        assert_eq!(envs[1].reported_at, Some(1_790_000_041));
    }
}
