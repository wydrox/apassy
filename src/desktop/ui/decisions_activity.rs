//! Decisions for the whole vault: the decisions of this Mac and those in the feeds of the
//! other Macs (relay-feed-v1, with a Mac as a reader).
//!
//! - The line under the title adds the week of this Mac and the `week` of each feed in
//!   the device scope. The project scope does not change it.
//! - With nothing waiting, the list shows the newest decisions in the scope by day, and
//!   the detail shows the week: the totals, one row per device, and the most active
//!   agents. A click on a decision shows its facts, read-only.
//! - Bouncer > Logs shows every run of this Mac and of the feeds (`logs.rs`).
//!
//! The rows of another Mac show what its feed says, nothing more. Its texts come from
//! agents, so they show as plain text, never as a link.

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};

use eframe::egui::{
    self, Label, Margin, Pos2, Rect, RichText, Sense, TextStyle, TextWrapMode, Vec2, WidgetInfo,
    WidgetText, WidgetType,
};

use super::columns::{self, Group};
use super::kit::{self, Font, Icon, Tone};
use crate::broker::approvals::shown_path;
use crate::desktop::DesktopApp;
use crate::desktop::owner_store::{AgentActivity, WeekCounts};
use crate::desktop::remote_feeds::{
    ActivityScope, DeviceScope, FeedProblem, RemoteFeedState, RemoteMac,
};
use crate::questions::feed::{Feed, FeedAgent, FeedUse};
use crate::vault::format_utc;

/// The decisions that the list shows.
pub(super) const RECENT: usize = 20;
/// The agents of "Most active agents".
const TOP_AGENTS: usize = 5;
/// The name of this Mac in the scope and in the rows.
pub(super) const THIS_MAC: &str = "This Mac";
/// The longest name of a Mac, an agent, or a credential in a row.
const SHOWN_NAME: usize = 40;
/// The longest project label.
const SHOWN_PROJECT: usize = 120;
/// The longest command summary.
const SHOWN_COMMAND: usize = 600;
/// The longest task of "Why".
const SHOWN_TASK: usize = 400;
/// The height of a row of a decision: three lines.
const ROW_HEIGHT: f32 = 64.0;

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

/// One decision of the past: a use of a credential that was allowed or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PastDecision {
    /// A key for the selection, the same in each frame.
    pub(super) id: u64,
    pub(super) source: Source,
    pub(super) at: u64,
    pub(super) agent: String,
    pub(super) item: String,
    /// "Read", "Change", "Deploy", "Delete".
    pub(super) action: String,
    /// Empty: no project.
    pub(super) project: String,
    /// The command summary as the use log or the feed gives it.
    pub(super) command: String,
    /// `allowed`, `denied`, `refused`, or `timed_out`.
    pub(super) outcome: String,
    /// `bouncer`, `pattern`, `answer`, `owner`, or `rule`.
    pub(super) decided_by: String,
    /// The device that answered, or empty.
    pub(super) answered_on: String,
    /// The decision log entry of a decision of this Mac, for "Why". `None` for another
    /// Mac and for an older use.
    pub(super) decision_log_id: Option<u64>,
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

impl PastDecision {
    pub(super) fn allowed(&self) -> bool {
        self.outcome == "allowed"
    }

    /// "Claude Code · API token".
    pub(super) fn title(&self) -> String {
        format!("{} · {}", self.agent, self.item)
    }

    pub(super) fn project_text(&self) -> &str {
        if self.project.is_empty() {
            "No project"
        } else {
            &self.project
        }
    }

    /// "Allowed" or "Not allowed".
    pub(super) fn outcome_text(&self) -> &'static str {
        if self.allowed() {
            "Allowed"
        } else {
            "Not allowed"
        }
    }

    /// The outcome with its kind, for the detail.
    fn outcome_detail(&self) -> String {
        match self.outcome.as_str() {
            "allowed" => "Allowed".to_owned(),
            "denied" => "Not allowed: denied".to_owned(),
            "refused" => "Not allowed: refused".to_owned(),
            "timed_out" => "Not allowed: no answer in time".to_owned(),
            other => format!("Not allowed: {}", shown_path(other, SHOWN_NAME)),
        }
    }

    /// "By you", "Answered on DEVICE", "Automatic", or "No answer in time".
    pub(super) fn decided_text(&self) -> String {
        match (self.outcome.as_str(), self.decided_by.as_str()) {
            ("timed_out", _) => "No answer in time".to_owned(),
            (_, "owner") if !self.answered_on.is_empty() => {
                format!("Answered on {}", self.answered_on)
            }
            (_, "owner") => "By you".to_owned(),
            _ => "Automatic".to_owned(),
        }
    }

    /// Who decided, for the detail.
    fn decided_detail(&self) -> String {
        if self.outcome == "timed_out" {
            return self.decided_text();
        }
        let how = match self.decided_by.as_str() {
            "owner" => return self.decided_text(),
            "bouncer" => "the bouncer",
            "pattern" => "a remembered pattern",
            "answer" => "your remembered answer",
            "rule" => "a rule",
            _ => return "Automatic".to_owned(),
        };
        format!("Automatic: {how}")
    }

    /// "Deploy · synthetic-shop · on MacBook Pro". A row of this Mac names it only when
    /// the list can have rows of other Macs.
    fn place_line(&self, name_this_mac: bool) -> String {
        let mut line = format!("{} · {}", self.action, self.project_text());
        if name_this_mac || self.source != Source::ThisMac {
            line.push_str(&format!(" · on {}", self.source.name()));
        }
        line
    }

    /// "Allowed · By you".
    fn result_line(&self) -> String {
        format!("{} · {}", self.outcome_text(), self.decided_text())
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
    /// The choices of the scope bar after "All devices": this Mac, then each other Mac
    /// with a feed.
    pub(super) devices: Vec<(DeviceScope, String)>,
    /// The project labels of the agents, sorted.
    pub(super) projects: Vec<String>,
    pub(super) weeks: Vec<DeviceWeek>,
    pub(super) agents: Vec<AgentWeek>,
    /// All decisions that this Mac has, newest first.
    pub(super) recent: Vec<PastDecision>,
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

    /// The newest [`RECENT`] decisions in the scope.
    pub(super) fn recent_in(&self, scope: &ActivityScope) -> Vec<&PastDecision> {
        self.recent
            .iter()
            .filter(|decision| in_scope(decision, scope))
            .take(RECENT)
            .collect()
    }

    /// The decision with this key, when it is in the scope.
    pub(super) fn find(&self, id: u64, scope: &ActivityScope) -> Option<&PastDecision> {
        self.recent
            .iter()
            .find(|decision| decision.id == id && in_scope(decision, scope))
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

fn in_scope(decision: &PastDecision, scope: &ActivityScope) -> bool {
    decision.source.in_scope(&scope.device)
        && scope
            .project
            .as_ref()
            .is_none_or(|project| *project == decision.project)
}

fn key(parts: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    parts.hash(&mut hasher);
    hasher.finish()
}

/// "read" as "Read". An unknown action shows as the feed gives it.
fn action_word(action: &str) -> String {
    use crate::broker::action_kind::ActionKind;
    let known = match action {
        "read" => Some(ActionKind::Read),
        "change" => Some(ActionKind::Change),
        "deploy" => Some(ActionKind::Deploy),
        "delete" => Some(ActionKind::Delete),
        _ => None,
    };
    known.map_or_else(
        || shown_path(action, SHOWN_NAME),
        |action| super::decisions::action_label(action).to_owned(),
    )
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

fn remote_decision(source: &Source, agent: &FeedAgent, item_use: &FeedUse) -> PastDecision {
    let device = match source {
        Source::Other { device, .. } => device.as_str(),
        Source::ThisMac => "",
    };
    let item = if item_use.item_title.trim().is_empty() {
        "A credential".to_owned()
    } else {
        shown_path(&item_use.item_title, SHOWN_NAME)
    };
    PastDecision {
        id: key((
            "feed",
            device,
            &agent.id,
            item_use.at,
            &item_use.item,
            &item_use.item_title,
            &item_use.action,
            &item_use.command,
            &item_use.outcome,
        )),
        source: source.clone(),
        at: item_use.at,
        agent: shown_path(&agent.name, SHOWN_NAME),
        item,
        action: action_word(&item_use.action),
        project: shown_path(&item_use.project, SHOWN_PROJECT),
        command: shown_path(&item_use.command, SHOWN_COMMAND),
        outcome: item_use.outcome.clone(),
        decided_by: item_use.decided_by.clone(),
        answered_on: shown_path(&item_use.answered_on, SHOWN_NAME),
        decision_log_id: None,
    }
}

/// The activity of the vault from the week and the agents of this Mac and the other
/// Macs. `local_week` is `None` when this Mac could not read its counts.
pub(super) fn gather(
    local_week: Option<WeekCounts>,
    local: &[AgentActivity],
    remote_macs: &[RemoteMac],
) -> VaultActivity {
    let mut activity = VaultActivity {
        devices: vec![(DeviceScope::ThisMac, THIS_MAC.to_owned())],
        weeks: vec![DeviceWeek {
            source: Source::ThisMac,
            counts: local_week,
        }],
        ..VaultActivity::default()
    };
    let mut projects = BTreeSet::new();
    for agent in local {
        projects.extend(agent.projects.iter().cloned());
        activity.agents.push(AgentWeek {
            source: Source::ThisMac,
            name: agent.agent.name.clone(),
            uses: u64::try_from(agent.uses_this_week).unwrap_or(u64::MAX),
        });
        for entry in &agent.recent {
            let item_use = &entry.item_use;
            activity.recent.push(PastDecision {
                id: key(("this-mac", item_use.id)),
                source: Source::ThisMac,
                at: item_use.at,
                agent: agent.agent.name.clone(),
                item: entry.item_name.clone(),
                action: super::decisions::action_label(item_use.action).to_owned(),
                project: item_use.project_label.clone(),
                command: item_use.command_summary.clone(),
                outcome: item_use.outcome.as_str().to_owned(),
                decided_by: item_use.decided_by.as_str().to_owned(),
                answered_on: item_use.answered_on.clone(),
                decision_log_id: item_use.decision_log_id,
            });
        }
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
            name: name.clone(),
        };
        activity
            .devices
            .push((DeviceScope::Other(remote.device.clone()), name));
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
            projects.extend(
                agent
                    .projects
                    .iter()
                    .map(|project| shown_path(project, SHOWN_PROJECT)),
            );
            activity.agents.push(AgentWeek {
                source: source.clone(),
                name: shown_path(&agent.name, SHOWN_NAME),
                uses: agent.uses_this_week,
            });
            for item_use in &agent.recent {
                activity
                    .recent
                    .push(remote_decision(&source, agent, item_use));
            }
        }
    }
    for decision in &activity.recent {
        projects.insert(decision.project.clone());
    }
    projects.remove("");
    activity.projects = projects.into_iter().collect();
    // Newest first; a stable sort keeps this Mac first at the same second.
    activity
        .recent
        .sort_by_key(|decision| std::cmp::Reverse(decision.at));
    activity
}

/// The activity of the vault as this Mac sees it now.
pub(super) fn load(app: &DesktopApp) -> VaultActivity {
    let session = &app.owner_ui.session;
    let week = session.week_counts().ok();
    let agents = session.agents_activity(RECENT).unwrap_or_default();
    gather(week, &agents, &app.remote_macs)
}

/// A device that has no feed now leaves the scope: it shows all devices again.
pub(super) fn fit_scope(scope: &mut ActivityScope, devices: &[(DeviceScope, String)]) {
    if matches!(scope.device, DeviceScope::Other(_))
        && !devices.iter().any(|(device, _)| *device == scope.device)
    {
        scope.device = DeviceScope::All;
    }
}

// ---- Days. ----

/// The group of a decision in the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Day {
    Today,
    Yesterday,
    Earlier,
}

impl Day {
    fn title(self) -> &'static str {
        match self {
            Self::Today => "Today",
            Self::Yesterday => "Yesterday",
            Self::Earlier => "Earlier",
        }
    }
}

/// The day of `at` seen at `now`, with the local time `offset` seconds from UTC. A time
/// after `now` (the clock of another Mac) is today.
pub(super) fn day_of(at: u64, now: u64, offset: i64) -> Day {
    let day = |time: u64| {
        i64::try_from(time)
            .unwrap_or(i64::MAX)
            .saturating_add(offset)
            .div_euclid(86_400)
    };
    match day(now).saturating_sub(day(at)) {
        ..=0 => Day::Today,
        1 => Day::Yesterday,
        _ => Day::Earlier,
    }
}

/// The offset of the local time from UTC at `now`, in seconds. 0 when macOS does not
/// say.
fn local_offset(now: u64) -> i64 {
    i64::try_from(now)
        .ok()
        .and_then(|now| time::OffsetDateTime::from_unix_timestamp(now).ok())
        .and_then(|at| time::UtcOffset::local_offset_at(at).ok())
        .map_or(0, |offset| i64::from(offset.whole_seconds()))
}

/// The decisions in groups by day, in their order.
pub(super) fn by_day<'a>(
    decisions: &[&'a PastDecision],
    now: u64,
    offset: i64,
) -> Vec<Group<&'a PastDecision>> {
    let mut groups: Vec<Group<&PastDecision>> = Vec::new();
    for &decision in decisions {
        let title = day_of(decision.at, now, offset).title();
        match groups.last_mut() {
            Some(group) if group.title == title => group.rows.push(decision),
            _ => groups.push(Group {
                title: title.to_owned(),
                rows: vec![decision],
            }),
        }
    }
    groups
}

// ---- The list. ----

/// The list with nothing waiting: one line that says so (only when it is sure), then
/// the newest decisions in the scope by day, and a note for each Mac whose feed left out
/// older uses. Returns the key of the decision that the owner clicked.
pub(super) fn empty_list(
    ui: &mut egui::Ui,
    activity: &VaultActivity,
    scope: &ActivityScope,
    selected: Option<u64>,
    clear: bool,
) -> Option<u64> {
    let now = kit::now();
    egui::Frame::NONE
        .inner_margin(Margin {
            left: 16,
            right: 12,
            top: 6,
            bottom: 4,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 2.0;
            if clear {
                ui.add(
                    Label::new(
                        kit::medium("Nothing waits for you.", Font::Body)
                            .color(kit::palette().label),
                    )
                    .wrap(),
                );
                ui.add(
                    Label::new(
                        kit::text(
                            "A new question also shows as a macOS notification.",
                            Font::Footnote,
                        )
                        .color(kit::palette().secondary),
                    )
                    .wrap(),
                );
                ui.add_space(10.0);
            }
            ui.label(kit::text("Recent decisions", Font::Headline).color(kit::palette().label));
        });
    let recent = activity.recent_in(scope);
    let groups = by_day(&recent, now, local_offset(now));
    let name_this_mac = activity.devices.len() > 1;
    let notes = activity.feed_notes(&scope.device);
    let mut chosen = None;
    columns::grouped_rows(
        ui,
        "decisions-recent",
        &groups,
        true,
        |ui, decision| {
            let response = ui
                .push_id(("past-decision", decision.id), |ui| {
                    past_row(
                        ui,
                        decision,
                        selected == Some(decision.id),
                        name_this_mac,
                        now,
                    )
                })
                .inner;
            if response.clicked() {
                chosen = Some(decision.id);
            }
        },
        |ui| {
            if groups.is_empty() {
                columns::list_note(ui, "No decisions yet.");
            }
            for note in &notes {
                columns::list_note(ui, note);
            }
        },
    );
    chosen
}

/// One past decision in the list: the agent and the credential with the time at the
/// right, the action, the project, and the Mac, then the outcome and who decided.
fn past_row(
    ui: &mut egui::Ui,
    decision: &PastDecision,
    selected: bool,
    name_this_mac: bool,
    now: u64,
) -> egui::Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, ROW_HEIGHT), Sense::click());
    let title = decision.title();
    let place = decision.place_line(name_this_mac);
    let result = decision.result_line();
    let when = kit::relative_time(decision.at, now);
    let name = format!("{title}, {place}, {result}, {when}");
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, &name));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, 8, kit::palette().selection);
    } else if response.hovered() {
        painter.rect_filled(rect, 8, kit::palette().list_hover);
    }
    if response.has_focus() {
        kit::inner_focus_ring(painter, rect, 8);
    }
    let avatar = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.top() + 10.0),
        Vec2::splat(28.0),
    );
    kit::paint_avatar(ui, avatar, &decision.agent);
    kit::paint_tile_ring(painter, avatar, true, selected);
    let (title_color, sub_color, result_color) = if selected {
        let white = kit::palette().on_accent;
        (white, kit::palette().on_selection_secondary, white)
    } else if decision.allowed() {
        (
            kit::palette().label,
            kit::palette().secondary,
            Tone::Good.text(),
        )
    } else {
        (
            kit::palette().label,
            kit::palette().secondary,
            Tone::Critical.text(),
        )
    };
    let galley = |value: RichText, max: f32| {
        WidgetText::from(value).into_galley(ui, Some(TextWrapMode::Truncate), max, TextStyle::Body)
    };
    let right = rect.right() - 8.0;
    let left = avatar.right() + 10.0;
    let top = rect.top() + 8.0;
    let when = galley(kit::text(when, Font::Footnote).color(sub_color), 90.0);
    let when_width = when.size().x;
    painter.galley(Pos2::new(right - when_width, top + 2.0), when, sub_color);
    let text_width = (right - left).max(10.0);
    let lines = [
        (
            galley(
                kit::row_title(title).color(title_color),
                (text_width - when_width - 8.0).max(10.0),
            ),
            title_color,
        ),
        (
            galley(kit::text(place, Font::Callout).color(sub_color), text_width),
            sub_color,
        ),
        (
            galley(
                kit::text(result, Font::Footnote).color(result_color),
                text_width,
            ),
            result_color,
        ),
    ];
    let mut y = top;
    for (line, color) in lines {
        let height = line.size().y;
        painter.galley(Pos2::new(left, y), line, color);
        y += height;
    }
    response
}

// ---- The detail. ----

/// The detail with nothing selected: "All clear" when nothing waits for sure, then the
/// week of the devices in the scope: the totals, one row per device, and the most active
/// agents.
pub(super) fn week_summary(
    ui: &mut egui::Ui,
    activity: &VaultActivity,
    scope: &DeviceScope,
    clear: bool,
) {
    if clear {
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
    if let Some(week) = activity.week(scope) {
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
    }
    let all = *scope == DeviceScope::All;
    kit::section(ui, Some("Devices"), None, |s| {
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
    kit::section(ui, Some("Most active agents"), None, |s| {
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

/// The facts of one past decision, read-only.
pub(super) fn past_detail(ui: &mut egui::Ui, decision: &PastDecision, why: Option<&PastWhy>) {
    let now = kit::now();
    let when = kit::relative_time(decision.at, now);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        kit::avatar(ui, &decision.agent, 56.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(
                Label::new(
                    kit::text(decision.title(), Font::Title)
                        .size(20.0)
                        .color(kit::palette().label),
                )
                .wrap(),
            );
            ui.add(
                Label::new(
                    kit::text(
                        format!("{} · {when}", decision.outcome_text()),
                        Font::Callout,
                    )
                    .color(kit::palette().secondary),
                )
                .wrap(),
            );
        });
    });
    ui.add_space(22.0);
    kit::section(ui, Some("Decision"), None, |s| {
        s.labeled("Mac", decision.source.name());
        s.labeled("Agent", decision.agent.as_str());
        s.labeled("Credential", decision.item.as_str());
        s.labeled("Action", decision.action.as_str());
        s.labeled("Project", decision.project_text());
        s.labeled("Outcome", decision.outcome_detail());
        s.labeled("Decided", decision.decided_detail());
        s.labeled("Time", format!("{when} ({})", format_utc(decision.at)));
    });
    if let Some(why) = why {
        let title = if why.asked {
            "Why Apassy asked you"
        } else {
            "Why it ran"
        };
        kit::section(ui, Some(title), None, |s| {
            if !why.note.is_empty() {
                s.row(|ui| {
                    ui.add(
                        Label::new(kit::text(&why.note, Font::Body).color(kit::palette().label))
                            .wrap(),
                    );
                });
            }
            s.labeled("Task", why.task.as_str());
            if !why.flags.is_empty() {
                s.labeled("Rule flags", why.flags.join(", "));
            }
            let brain = why.brain_line();
            if !brain.is_empty() {
                s.labeled("Bouncer brain", brain);
            }
        });
    }
    if !decision.command.is_empty() {
        kit::section(ui, Some("Command"), None, |s| {
            s.row(|ui| {
                ui.add(
                    Label::new(
                        kit::text(&decision.command, Font::Mono).color(kit::palette().label),
                    )
                    .wrap(),
                );
            });
        });
    }
    if let Source::Other { name, .. } = &decision.source {
        kit::note(
            ui,
            format!("This decision was made on {name}. A change to the agent is made there."),
        );
    }
}
