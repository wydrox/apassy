//! The page of an agent of another Mac, from the feed of that Mac (relay-feed-v1
//! section 7). It has the layout of the page of an agent of this Mac, and it only shows:
//! no field and no button changes the agent. A change is made on that Mac.

use std::collections::BTreeMap;

use eframe::egui::{self, Label};

use super::super::kit::{self, Font, Icon, Tone};
use super::{
    actions_group, exception_words, fact_rows, group_label, header, page_line, recent_group,
    sees_words, token_row,
};
use crate::broker::action_kind::ActionKind;
use crate::desktop::DesktopApp;
use crate::desktop::owner_store::{ActionUse, RecentUse};
use crate::desktop::remote_feeds::{RemoteFeedState, RemoteMac};
use crate::questions::feed::{FeedAgent, FeedUse};
use crate::vault::exceptions::ExceptionKind;
use crate::vault::usage::{ItemUse, UseDecidedBy, UseOutcome};

/// The name of a credential that is gone (section 7.1).
const DELETED: &str = "A deleted credential";

/// A selected agent of another Mac, with what its page needs of the feed.
pub(in crate::desktop::ui) struct Selected {
    /// The name of the Mac, as the page shows it.
    pub(in crate::desktop::ui) mac: String,
    /// When this Mac received the feed, in Unix seconds.
    pub(in crate::desktop::ui) received_at: u64,
    /// The Mac left something out of the feed to fit.
    pub(in crate::desktop::ui) truncated: bool,
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
        mac: plain(&mac.name),
        received_at: mac.received_at,
        truncated: feed.truncated,
        agent: agent.clone(),
    })
}

/// The connected agents of the other Macs, for the count of the sidebar and the list.
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

/// The page: the header with the Mac and the time of its feed, the facts, the actions
/// this week, the newest uses, the note, the exceptions, and where to change the agent.
pub(in crate::desktop::ui) fn draw_agent(app: &DesktopApp, ui: &mut egui::Ui, selected: &Selected) {
    let now = super::now();
    let agent = &selected.agent;
    let mac = &selected.mac;
    let name = plain(&agent.name);
    header(
        ui,
        &name,
        &format!(
            "{mac} · updated {}",
            kit::relative_time(selected.received_at, now)
        ),
    );
    if agent.revoked {
        kit::notice(
            ui,
            Tone::Neutral,
            "Disconnected. The token does not work.",
            Some(format!("Connect the agent again on {mac}.").as_str()),
            |_| {},
        );
        return;
    }
    // The titles of this Mac's copies of the items, by uuid: a feed names items by uuid.
    let titles: BTreeMap<String, String> = if agent.recent.is_empty() && agent.exceptions.is_empty()
    {
        BTreeMap::new()
    } else {
        app.owner_ui
            .session
            .with_vault(|vault| vault.item_refs())
            .and_then(Result::ok)
            .map(|refs| {
                refs.into_values()
                    .map(|item| (item.uuid, item.title))
                    .collect()
            })
            .unwrap_or_default()
    };
    let projects: Vec<String> = agent.projects.iter().map(|p| plain(p)).collect();
    // "Only these items": the agent sees the items listed with `only` (section 7.1).
    let sees = sees_words(agent.restricted.then(|| {
        agent
            .exceptions
            .iter()
            .filter(|exception| exception.kind == ExceptionKind::Only.as_str())
            .count()
    }));
    kit::section(ui, None, None, |s| {
        fact_rows(
            s,
            usize::try_from(agent.uses_this_week).unwrap_or(usize::MAX),
            &projects,
            &sees,
        );
        if now >= agent.token_expires_at {
            token_row(
                s,
                &format!(
                    "Expired {}. Reconnect on {mac}.",
                    kit::relative_time(agent.token_expires_at, now)
                ),
                false,
            );
        }
    });
    actions_group(ui, &actions(agent));
    recent_group(ui, &recent(agent, &titles), now);
    if selected.truncated {
        page_line(ui, &format!("Some older uses are on {mac} only."));
    }
    let note = plain(agent.note.trim());
    if !note.is_empty() {
        group_label(ui, "Note for the bouncer");
        kit::section(ui, None, None, |s| {
            s.row(|ui| {
                ui.add(Label::new(kit::text(&note, Font::Body).color(kit::LABEL)).wrap());
            });
        });
    }
    exceptions_group(ui, agent, &titles);
    page_line(ui, &format!("Change this agent on {mac}."));
}

/// The kinds of action of the feed, as the page of this Mac has them.
fn actions(agent: &FeedAgent) -> Vec<ActionUse> {
    agent
        .actions
        .iter()
        .filter_map(|action| {
            Some(ActionUse {
                action: ActionKind::parse(&action.action)?,
                allowed: usize::try_from(action.allowed).unwrap_or(usize::MAX),
                not_allowed: usize::try_from(action.not_allowed).unwrap_or(usize::MAX),
                projects: action.projects.iter().map(|p| plain(p)).collect(),
            })
        })
        .collect()
}

/// The name of an item of the feed: this Mac's title of the item with the same uuid,
/// else the title in the feed. A gone item is "A deleted credential".
fn item_name(titles: &BTreeMap<String, String>, item: Option<&str>, title: &str) -> String {
    let Some(uuid) = item else {
        return DELETED.to_owned();
    };
    match titles.get(uuid) {
        Some(title) => title.clone(),
        None if title.is_empty() => DELETED.to_owned(),
        None => plain(title),
    }
}

/// The newest uses of the feed, as the uses of this Mac, for the "Recent" group. The
/// reader checked the words of the feed (section 7.4); a word that this version does not
/// know reads as the strictest one.
fn recent(agent: &FeedAgent, titles: &BTreeMap<String, String>) -> Vec<RecentUse> {
    agent
        .recent
        .iter()
        .map(|entry| RecentUse {
            item_name: item_name(titles, entry.item.as_deref(), &entry.item_title),
            item_use: item_use(entry),
        })
        .collect()
}

fn item_use(entry: &FeedUse) -> ItemUse {
    ItemUse {
        id: 0,
        at: entry.at,
        item_id: 0,
        agent_id: None,
        agent_name: String::new(),
        project_key: String::new(),
        project_label: plain(&entry.project),
        action: ActionKind::parse(&entry.action).unwrap_or(ActionKind::Delete),
        command_summary: plain(&entry.command),
        hosts: Vec::new(),
        outcome: match entry.outcome.as_str() {
            "allowed" => UseOutcome::Allowed,
            "denied" => UseOutcome::Denied,
            "timed_out" => UseOutcome::TimedOut,
            _ => UseOutcome::Refused,
        },
        decided_by: match entry.decided_by.as_str() {
            "pattern" => UseDecidedBy::Pattern,
            "answer" => UseDecidedBy::Answer,
            "owner" => UseDecidedBy::Owner,
            "rule" => UseDecidedBy::Rule,
            _ => UseDecidedBy::Bouncer,
        },
        answered_on: plain(&entry.answered_on),
        decision_log_id: None,
    }
}

/// The exceptions of the agent, read-only: no "Remove". With none, one gray line.
fn exceptions_group(ui: &mut egui::Ui, agent: &FeedAgent, titles: &BTreeMap<String, String>) {
    if agent.exceptions.is_empty() {
        super::no_exceptions(ui);
        return;
    }
    group_label(ui, "Exceptions");
    kit::section(ui, None, None, |s| {
        for exception in &agent.exceptions {
            let words = ExceptionKind::parse(&exception.kind).map_or_else(
                || plain(&exception.kind),
                |kind| exception_words(kind).to_owned(),
            );
            let name = item_name(titles, exception.item.as_deref(), &exception.item_title);
            s.row(|ui| {
                ui.horizontal(|ui| {
                    kit::tile(ui, &kit::Tile::icon(Tone::Neutral.mark(), Icon::Key), 20.0);
                    ui.add(
                        Label::new(
                            kit::text(format!("{words}: {name}"), Font::Body).color(kit::LABEL),
                        )
                        .truncate(),
                    );
                });
            });
        }
    });
}
