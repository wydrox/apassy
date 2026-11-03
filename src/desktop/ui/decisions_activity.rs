//! Decisions for the whole vault: the counts of the week of this Mac and of the feeds of
//! the other Macs (relay-feed-v1, with a Mac as a reader).
//!
//! - The line under the title adds the week of this Mac and the `week` of each feed in
//!   the scope. The project scope does not change it.
//! - With nothing waiting, the detail shows the week: the totals, one row per
//!   environment, and the most active agents (frame 10a); a new vault shows its totals
//!   only (frame 9c).
//! - History (`decisions_bouncer.rs`) and Bouncer > Logs (`logs.rs`) show the runs.
//!
//! The rows of another Mac show what its feed says, nothing more. Its texts come from
//! agents, so they show as plain text, never as a link.

use eframe::egui;

use super::columns;
use super::kit::{self, Font, Icon, Tone};
use crate::broker::approvals::shown_path;
use crate::desktop::DesktopApp;
use crate::desktop::owner_store::{AgentActivity, WeekCounts};
use crate::desktop::remote_feeds::{DeviceScope, FeedProblem, RemoteFeedState, RemoteMac};
use crate::questions::feed::Feed;

/// The newest uses of each agent of this Mac that the counts read.
pub(super) const RECENT: usize = 20;
/// The agents of "Most active".
const TOP_AGENTS: usize = 5;
/// The name of this Mac in the scope and in the rows.
pub(super) const THIS_MAC: &str = "This Mac";
/// The longest name of a Mac, an agent, or a credential in a row.
const SHOWN_NAME: usize = 40;
/// The longest task of "Why".
const SHOWN_TASK: usize = 400;

/// Where a decision or a count comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Source {
    ThisMac,
    /// Another Mac of the vault, by its `trusted_device` id, with its name.
    Other {
        device: String,
        name: String,
    },
}

impl Source {
    pub(super) fn name(&self) -> &str {
        match self {
            Self::ThisMac => THIS_MAC,
            Self::Other { name, .. } => name,
        }
    }

    pub(super) fn in_scope(&self, scope: &DeviceScope) -> bool {
        match (scope, self) {
            (DeviceScope::All, _) | (DeviceScope::ThisMac, Self::ThisMac) => true,
            (DeviceScope::Other(wanted), Self::Other { device, .. }) => wanted == device,
            _ => false,
        }
    }
}

/// Why a past decision of this Mac went as it did: its decision log entry, which the
/// question showed you as the reason.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PastWhy {
    /// The run waited for you.
    pub(super) asked: bool,
    /// The reason of the question, or the note of the bouncer.
    pub(super) note: String,
    /// The task that the bouncer compared the command with, and where it came from.
    pub(super) task: String,
    pub(super) flags: Vec<String>,
    /// The answers of the bouncer brain, from 0 to 1.
    pub(super) brain: Vec<(String, f64)>,
}

impl PastWhy {
    pub(super) fn of(entry: &crate::vault::DecisionEntry) -> Self {
        use crate::vault::RequestSource;
        let request = entry.user_request.trim();
        let task = match entry.user_request_source {
            _ if request.is_empty() => "The agent sent no task.".to_owned(),
            RequestSource::Host => format!(
                "From the prompt hook: \u{201c}{}\u{201d}",
                shown_path(request, SHOWN_TASK)
            ),
            RequestSource::Agent | RequestSource::None => format!(
                "Sent by the agent: \u{201c}{}\u{201d}",
                shown_path(request, SHOWN_TASK)
            ),
        };
        Self {
            asked: entry.asked,
            note: entry.note.trim().to_owned(),
            task,
            flags: entry.rule_flags.clone(),
            brain: entry.model_facts.clone(),
        }
    }

    /// "fits the task 69% · changes state 6%". Empty: the brain did not answer.
    pub(super) fn brain_line(&self) -> String {
        self.brain
            .iter()
            .map(|(name, p)| {
                let label = match name.as_str() {
                    "task_match" => "fits the task",
                    "writes" => "changes state",
                    "remote" => "remote",
                    "leak" => "shows a secret",
                    "destroy" => "destroys data",
                    "rule_break" => "breaks your rule",
                    other => other,
                };
                format!("{label} {:.0}%", p * 100.0)
            })
            .collect::<Vec<_>>()
            .join(" \u{b7} ")
    }
}

/// The counts of the week of one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeviceWeek {
    pub(super) source: Source,
    /// `None`: this Mac could not read them.
    pub(super) counts: Option<WeekCounts>,
}

/// The uses of the week of one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AgentWeek {
    pub(super) source: Source,
    pub(super) name: String,
    pub(super) uses: u64,
}

/// Another Mac whose feed this Mac cannot show, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Unavailable {
    pub(super) name: String,
    pub(super) note: String,
}

/// The activity of the vault: this Mac and the other Macs with a feed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct VaultActivity {
    pub(super) weeks: Vec<DeviceWeek>,
    pub(super) agents: Vec<AgentWeek>,
    /// The other Macs whose feed left out older uses.
    pub(super) truncated: Vec<Source>,
    /// The other Macs whose newest feed this Mac cannot show: the activity is that of
    /// their last good feed (relay-feed-v1 section 7.4).
    pub(super) stale: Vec<(Source, FeedProblem)>,
    pub(super) unavailable: Vec<Unavailable>,
}

impl VaultActivity {
    /// The counts of the week of the devices in `scope`, added. `None` when no device in
    /// the scope has counts.
    pub(super) fn week(&self, scope: &DeviceScope) -> Option<WeekCounts> {
        self.weeks
            .iter()
            .filter(|week| week.source.in_scope(scope))
            .filter_map(|week| week.counts)
            .reduce(|sum, counts| WeekCounts {
                by_you: sum.by_you.saturating_add(counts.by_you),
                automatic: sum.automatic.saturating_add(counts.automatic),
            })
    }

    /// The agents with a use this week in the device scope, the most uses first.
    pub(super) fn top_agents(&self, scope: &DeviceScope) -> Vec<&AgentWeek> {
        let mut agents: Vec<&AgentWeek> = self
            .agents
            .iter()
            .filter(|agent| agent.uses > 0 && agent.source.in_scope(scope))
            .collect();
        agents.sort_by(|a, b| b.uses.cmp(&a.uses).then_with(|| a.name.cmp(&b.name)));
        agents.truncate(TOP_AGENTS);
        agents
    }

    /// The notes of the other Macs in the scope: "Sync this vault to see the activity of
    /// MAC." (or "Update Apassy …") for each Mac whose newest feed this Mac cannot show,
    /// then "Some older uses are on MAC only." for each Mac whose feed left out older
    /// uses.
    pub(super) fn feed_notes(&self, scope: &DeviceScope) -> Vec<String> {
        let stale = self
            .stale
            .iter()
            .filter(|(source, _)| source.in_scope(scope))
            .map(|(source, problem)| match problem {
                FeedProblem::NeedsSync => {
                    format!("Sync this vault to see the activity of {}.", source.name())
                }
                FeedProblem::NeedsUpdate => {
                    format!("Update Apassy to see the activity of {}.", source.name())
                }
            });
        let truncated = self
            .truncated
            .iter()
            .filter(|source| source.in_scope(scope))
            .map(|source| format!("Some older uses are on {} only.", source.name()));
        stale.chain(truncated).collect()
    }
}

/// The name of another Mac: its `trusted_device` row, else the name in its feed.
fn mac_name(remote: &RemoteMac, feed: Option<&Feed>) -> String {
    let name = match (remote.name.trim(), feed) {
        ("", Some(feed)) => feed.mac.name.as_str(),
        ("", None) => "another Mac",
        (name, _) => name,
    };
    shown_path(name, SHOWN_NAME)
}

/// The activity of the vault from the week and the agents of this Mac and the other
/// Macs. `local_week` is `None` when this Mac could not read its counts.
pub(super) fn gather(
    local_week: Option<WeekCounts>,
    local: &[AgentActivity],
    remote_macs: &[RemoteMac],
) -> VaultActivity {
    let mut activity = VaultActivity {
        weeks: vec![DeviceWeek {
            source: Source::ThisMac,
            counts: local_week,
        }],
        ..VaultActivity::default()
    };
    for agent in local {
        activity.agents.push(AgentWeek {
            source: Source::ThisMac,
            name: agent.agent.name.clone(),
            uses: u64::try_from(agent.uses_this_week).unwrap_or(u64::MAX),
        });
    }
    for remote in remote_macs {
        let feed = match &remote.state {
            RemoteFeedState::Ready(feed) => feed,
            RemoteFeedState::NeedsSync => {
                let name = mac_name(remote, None);
                activity.unavailable.push(Unavailable {
                    note: format!("Sync this vault to see the activity of {name}."),
                    name,
                });
                continue;
            }
            RemoteFeedState::NeedsUpdate => {
                let name = mac_name(remote, None);
                activity.unavailable.push(Unavailable {
                    note: format!("Update Apassy to see the activity of {name}."),
                    name,
                });
                continue;
            }
        };
        let name = mac_name(remote, Some(feed));
        let source = Source::Other {
            device: remote.device.clone(),
            name,
        };
        activity.weeks.push(DeviceWeek {
            source: source.clone(),
            counts: Some(WeekCounts {
                by_you: feed.week.by_you,
                automatic: feed.week.automatic,
            }),
        });
        if let Some(problem) = remote.problem {
            activity.stale.push((source.clone(), problem));
        }
        if feed.truncated {
            activity.truncated.push(source.clone());
        }
        for agent in &feed.agents {
            activity.agents.push(AgentWeek {
                source: source.clone(),
                name: shown_path(&agent.name, SHOWN_NAME),
                uses: agent.uses_this_week,
            });
        }
    }
    activity
}

/// The activity of the vault as this Mac sees it now.
pub(super) fn load(app: &DesktopApp) -> VaultActivity {
    let session = &app.owner_ui.session;
    let week = session.week_counts().ok();
    let agents = session.agents_activity(RECENT).unwrap_or_default();
    gather(week, &agents, &app.remote_macs)
}

// ---- The detail. ----

/// The detail with nothing selected: "All clear" when nothing waits for sure, then the
/// week of the environments in the scope: the totals, one row per environment, and the
/// most active agents (frame 10a). `first_run`: no agent anywhere yet, so the totals only
/// (frame 9c).
pub(super) fn week_summary(
    ui: &mut egui::Ui,
    activity: &VaultActivity,
    scope: &DeviceScope,
    clear: bool,
    first_run: bool,
) {
    if clear && !first_run {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            kit::paint_icon_in(ui, Icon::CheckCircle, 16.0, Tone::Good.mark());
            ui.label(kit::medium("All clear", Font::Body).color(kit::palette().label));
        });
        ui.add_space(14.0);
    }
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(kit::text("This week", Font::Title3).color(kit::palette().label));
    });
    ui.add_space(6.0);
    let week = activity.week(scope).unwrap_or_default();
    let width = ((ui.available_width() - 8.0) / 2.0).floor();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        kit::stat_tile(
            ui,
            width,
            "By you",
            &week.by_you.to_string(),
            "Questions and checks you answered",
        );
        kit::stat_tile(
            ui,
            width,
            "Automatic",
            &week.automatic.to_string(),
            "Allowed without a question",
        );
    });
    ui.add_space(20.0);
    if first_run {
        return;
    }
    let all = *scope == DeviceScope::All;
    kit::section(ui, Some("Environments"), None, |s| {
        for week in activity
            .weeks
            .iter()
            .filter(|week| week.source.in_scope(scope))
        {
            let counts = week.counts.map_or_else(
                || "No counts".to_owned(),
                |counts| format!("{} by you · {} automatic", counts.by_you, counts.automatic),
            );
            s.labeled(week.source.name(), counts);
        }
        if all {
            for mac in &activity.unavailable {
                s.status(
                    &mac.name,
                    Some(mac.note.as_str()),
                    kit::text("No counts", Font::Body).color(kit::palette().secondary),
                );
            }
        }
    });
    let agents = activity.top_agents(scope);
    kit::section(ui, Some("Most active"), None, |s| {
        if agents.is_empty() {
            s.row(|ui| kit::note(ui, "No agent used a credential this week."));
        }
        for agent in agents {
            let uses = usize::try_from(agent.uses).unwrap_or(usize::MAX);
            s.labeled(
                &agent.name,
                format!(
                    "{} · {}",
                    columns::count_label(uses, "use", "uses"),
                    agent.source.name()
                ),
            );
        }
    });
}
