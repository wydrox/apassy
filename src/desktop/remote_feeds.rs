//! The agent feeds of the other Macs of this vault (contract relay-feed-v1, with a Mac as
//! a reader). The agents, the activity, and the decisions of a Mac are local rows
//! (`LOCAL_TABLES`): they never sync. Each Mac publishes them as a sealed feed through the
//! relay. This Mac reads the feeds of the other Macs of the vault, so that Agents and
//! Decisions show the whole vault, not only this Mac.
//!
//! The reader keeps the last good feed of each Mac in [`RemoteMac`]. The agents of another
//! Mac are read-only here: a change is made on that Mac.

use crate::questions::feed::Feed;

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
