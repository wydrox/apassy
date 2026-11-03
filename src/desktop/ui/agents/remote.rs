//! The agents of another Mac, from the feed of that Mac (relay-feed-v1 section 7). Their
//! page (`agents_page::draw_agent`) only shows: a change is made on that Mac.

use crate::desktop::remote_feeds::{RemoteFeedState, RemoteMac};
use crate::questions::feed::FeedAgent;

/// A selected agent of another Mac, with what its page needs of the feed.
pub(in crate::desktop::ui) struct Selected {
    pub(in crate::desktop::ui) agent: FeedAgent,
}

/// Text from another Mac as plain text: control and direction characters become `?`
/// (section 7.2).
pub(in crate::desktop::ui) fn plain(text: &str) -> String {
    crate::broker::approvals::shown_path(text, usize::MAX)
}

/// The agent `id` of the Mac `device`, when its feed is ready and has it.
pub(in crate::desktop::ui) fn find(
    macs: &[RemoteMac],
    (device, id): &(String, String),
) -> Option<Selected> {
    let mac = macs.iter().find(|mac| &mac.device == device)?;
    let RemoteFeedState::Ready(feed) = &mac.state else {
        return None;
    };
    let agent = feed.agents.iter().find(|agent| &agent.id == id)?;
    Some(Selected {
        agent: agent.clone(),
    })
}

/// The connected agents of the other Macs, for the count of the sidebar.
pub(in crate::desktop::ui) fn connected(macs: &[RemoteMac]) -> usize {
    macs.iter()
        .map(|mac| match &mac.state {
            RemoteFeedState::Ready(feed) => {
                feed.agents.iter().filter(|agent| !agent.revoked).count()
            }
            RemoteFeedState::NeedsSync | RemoteFeedState::NeedsUpdate => 0,
        })
        .sum()
}
