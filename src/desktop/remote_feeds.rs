//! The agent feeds of the other Macs of this vault (contract relay-feed-v1, with a Mac as
//! a reader). The agents, the activity, and the decisions of a Mac are local rows
//! (`LOCAL_TABLES`): they never sync. Each Mac publishes them as a sealed feed through the
//! relay. This Mac reads the feeds of the other Macs of the vault, so that Agents and
//! Decisions show the whole vault, not only this Mac.
//!
//! The reader keeps the last good feed of each Mac in [`RemoteMac`]. The agents of another
//! Mac are read-only here: a change is made on that Mac.
//!
//! The reader is a thread of the questions waiter (`crate::questions::feed_reader`): it
//! long-polls the feeds, runs the checks of section 7.4, and keeps the result with the
//! vault session that read it (`QuestionsWorker::with_other_macs`). Each frame,
//! [`DesktopApp::poll_remote_feeds`] copies the result of the open vault session into
//! [`DesktopApp::remote_macs`] when it changed. A lock and a vault switch clear it at once;
//! the waiter clears its own copy when the vault locks, changes, or the questions go off.
//! Nothing is kept on disk.

use crate::desktop::DesktopApp;
use crate::questions::feed::Feed;
use crate::questions::{OtherFeed, OtherMac};

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
}

/// The devices that Agents and Decisions show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum DeviceScope {
    /// This Mac and every other Mac with a feed.
    #[default]
    All,
    /// This Mac only.
    ThisMac,
    /// One other Mac, by its `trusted_device` id.
    Other(String),
}

/// The scope of Agents and Decisions: "Showing [devices] in [projects]".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActivityScope {
    pub(crate) device: DeviceScope,
    /// One project label, or `None` for all projects.
    pub(crate) project: Option<String>,
}

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
        }
    }
}

impl RemoteMac {
    /// Whether this row shows `mac` as the reader has it, without a copy.
    fn shows(&self, mac: &OtherMac) -> bool {
        self.device == mac.device
            && self.name == mac.name
            && self.received_at == mac.received_at
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
        }
    }

    /// The vault locked, or another one opens: the other Macs go at once.
    pub(crate) fn forget_remote_feeds(&mut self) {
        self.remote_macs.clear();
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
            week: FeedWeek {
                by_you: 1,
                automatic: 2,
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
}
