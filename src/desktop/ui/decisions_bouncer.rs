//! The parts of Decisions of the Bouncer section, in both builds
//! (implementation-plan-bouncer-section §6; mockup frames 5, 5b, 9c, and 10a):
//!
//! - **History** under Waiting: the runs of this Mac (`Vault::bouncer_log`, through the
//!   Bouncer cache) and of the other Macs (their feeds, read-only), by day, with the
//!   filters All / Asked You / Automatic / Denied and one agent.
//! - **The connect card** of a remote agent: "<name> wants to connect", the Mac, the time
//!   left, the code of the browser page, one warning line, Deny and Allow (Touch ID).
//! - **The cloud run card**: "<agent> wants to use <credential>", the rows Credential,
//!   Agent ("Remote"), Sends To, and Request ("Not verified"), the command, Deny and Allow
//!   Once. Every remote run asks you; nothing is remembered.
//!
//! The views are plain data; the vault build fills them in `decisions.rs`, the demo
//! build from fixtures. The draw functions return what the owner chose.
// The demo build draws the pages from fixtures and uses part of this module.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::{
    self, Frame, Label, Margin, Pos2, Rect, Sense, TextStyle, TextWrapMode, Ui, Vec2, WidgetInfo,
    WidgetText, WidgetType,
};

use super::bouncer::{self, ActivityScope, BouncerData, LogEvent, LogKind, LogOutcome, LogSource};
use super::kit::{self, Font, Icon, Style, Tone};
#[cfg(feature = "vault")]
use crate::questions::envelope::LOCAL_CONNECT_WARNING;
/// `questions::envelope::LOCAL_CONNECT_WARNING` for the demo build, which has no vault.
#[cfg(not(feature = "vault"))]
const LOCAL_CONNECT_WARNING: &str = concat!(
    "A program on this ",
    crate::computer!(),
    " can start this request."
);

/// The rows of History at most.
pub(crate) const HISTORY_ROWS: usize = 200;

// ---- History. ----

/// The segmented choice of History.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum HistoryFilter {
    #[default]
    All,
    AskedYou,
    Automatic,
    Denied,
}

impl HistoryFilter {
    pub(crate) const ALL: [Self; 4] = [Self::All, Self::AskedYou, Self::Automatic, Self::Denied];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::AskedYou => "Asked You",
            Self::Automatic => "Automatic",
            Self::Denied => "Denied",
        }
    }

    pub(crate) fn matches(self, outcome: &LogOutcome) -> bool {
        match self {
            Self::All => true,
            Self::AskedYou => asked_you(outcome),
            Self::Automatic => matches!(
                outcome,
                LogOutcome::AllowedByBouncer | LogOutcome::DeniedByBouncer
            ),
            Self::Denied => outcome.denied(),
        }
    }
}

/// The run asked you (you answered, or it waited and no answer came).
pub(crate) fn asked_you(outcome: &LogOutcome) -> bool {
    matches!(
        outcome,
        LogOutcome::AllowedByYou
            | LogOutcome::AllowedOn(_)
            | LogOutcome::DeniedByYou
            | LogOutcome::DeniedOn(_)
            | LogOutcome::NoAnswer
    )
}

/// The state of History in both builds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) filter: HistoryFilter,
    /// One agent by name, or `None` for all agents.
    pub(crate) agent: Option<String>,
    /// The row that the detail shows, by [`LogEvent::key`].
    pub(crate) selected: Option<u64>,
}

/// One row of History.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HistoryRow {
    pub(crate) key: u64,
    pub(crate) agent: String,
    pub(crate) remote: bool,
    /// "Claude Code · Shop database".
    pub(crate) title: String,
    pub(crate) env_name: String,
    pub(crate) outcome: String,
    pub(crate) denied: bool,
    /// "14:14" today and yesterday, the weekday this week, else the day.
    pub(crate) meta: String,
    /// The short reason of a decision of this Mac (ADR 0046). Empty for a run of
    /// another Mac, which shows its environment instead.
    pub(crate) reason: String,
}

/// What History shows for one scope at one time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HistoryView {
    /// "Today", "Yesterday", "Earlier", each with its rows, newest first.
    pub(crate) groups: Vec<(String, Vec<HistoryRow>)>,
    /// The agents of the runs in the scope, for the agent menu.
    pub(crate) agents: Vec<String>,
    /// No run in the scope at all, before the filters: "No decisions yet".
    pub(crate) none_yet: bool,
}

/// The runs of the history: this Mac's decision rows and the other Macs' feed rows.
fn is_history(event: &LogEvent) -> bool {
    event.kind == LogKind::Run
        && matches!(event.source, LogSource::Decision(_) | LogSource::Feed(_))
}

fn in_scope(event: &LogEvent, scope: &ActivityScope) -> bool {
    scope.device.covers(&event.env)
        && scope
            .project
            .as_ref()
            .is_none_or(|project| event.project == *project)
}

/// The runs of the history in the scope and the filters, newest first.
pub(crate) fn history_events<'a>(
    data: &'a BouncerData,
    scope: &ActivityScope,
    state: &State,
) -> Vec<&'a LogEvent> {
    let mut events: Vec<&LogEvent> = data
        .events
        .iter()
        .filter(|event| is_history(event) && in_scope(event, scope))
        .filter(|event| state.filter.matches(&event.outcome))
        .filter(|event| {
            state
                .agent
                .as_ref()
                .is_none_or(|agent| event.agent.as_ref() == Some(agent))
        })
        .collect();
    events.sort_by_key(|event| std::cmp::Reverse(event.at));
    events.truncate(HISTORY_ROWS);
    events
}

/// The run of the history with `key`, when it is in the scope.
pub(crate) fn find<'a>(
    data: &'a BouncerData,
    scope: &ActivityScope,
    key: u64,
) -> Option<&'a LogEvent> {
    data.events
        .iter()
        .find(|event| is_history(event) && in_scope(event, scope) && event.key() == key)
}

impl HistoryView {
    pub(crate) fn of(
        data: &BouncerData,
        scope: &ActivityScope,
        state: &State,
        now: u64,
        offset: i64,
    ) -> Self {
        let mut agents: Vec<String> = data
            .events
            .iter()
            .filter(|event| is_history(event) && in_scope(event, scope))
            .filter_map(|event| event.agent.clone())
            .collect();
        agents.sort_by_key(|name| name.to_lowercase());
        agents.dedup();
        let none_yet = agents.is_empty();
        let mut groups: Vec<(String, Vec<HistoryRow>)> = Vec::new();
        for event in history_events(data, scope, state) {
            let title = match bouncer::days_ago(event.at, now, offset) {
                0 => "Today",
                1 => "Yesterday",
                _ => "Earlier",
            };
            let mut row = HistoryRow::of(event, now, offset);
            if let LogSource::Decision(id) = &event.source
                && let Some(reason) = data.reasons.get(id)
            {
                row.reason.clone_from(reason);
            }
            match groups.last_mut() {
                Some((group, rows)) if group == title => rows.push(row),
                _ => groups.push((title.to_owned(), vec![row])),
            }
        }
        Self {
            groups,
            agents,
            none_yet,
        }
    }
}

impl HistoryRow {
    pub(crate) fn of(event: &LogEvent, now: u64, offset: i64) -> Self {
        let agent = event.agent.clone().unwrap_or_else(|| "An agent".to_owned());
        let credential = event
            .credential
            .clone()
            .unwrap_or_else(|| "A credential".to_owned());
        let meta = match bouncer::days_ago(event.at, now, offset) {
            0 | 1 => bouncer::clock(event.at, offset),
            2..=6 => bouncer::weekday(event.at, offset).to_owned(),
            _ => bouncer::day_month(event.at, offset),
        };
        Self {
            key: event.key(),
            title: format!("{agent} · {credential}"),
            agent,
            remote: event.remote_agent,
            env_name: event.env_name.clone(),
            outcome: event.outcome.text(),
            denied: event.outcome.denied(),
            meta,
            reason: String::new(),
        }
    }
}

/// What the owner chose in History.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HistoryAction {
    Filter(HistoryFilter),
    Agent(Option<String>),
    Select(u64),
}

/// "All | Asked You | Automatic | Denied" in the width of the list column: equal
/// segments, the choice on a white thumb, each segment its own control for VoiceOver.
/// Returns the new choice.
fn filter_control(ui: &mut Ui, value: HistoryFilter) -> Option<HistoryFilter> {
    use egui::{
        Pos2, Rect, Sense, TextStyle, TextWrapMode, Vec2, WidgetInfo, WidgetText, WidgetType,
    };
    let count = HistoryFilter::ALL.len() as f32;
    let segment = ((ui.available_width() - 4.0) / count).floor().max(24.0);
    let height = 22.0;
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(segment * count + 4.0, height), Sense::hover());
    ui.painter().rect_filled(rect, 7, kit::palette().fill);
    let mut chosen = None;
    for (index, filter) in HistoryFilter::ALL.iter().enumerate() {
        let segment_rect = Rect::from_min_size(
            Pos2::new(rect.left() + 2.0 + segment * index as f32, rect.top() + 2.0),
            Vec2::new(segment, height - 4.0),
        );
        let response = ui.interact(
            segment_rect,
            ui.id().with(("history-filter", index)),
            Sense::click(),
        );
        let selected = *filter == value;
        response.widget_info(|| {
            WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, filter.label())
        });
        let painter = ui.painter();
        if selected {
            painter.rect_filled(segment_rect, 5, kit::palette().surface);
        }
        if response.has_focus() {
            kit::inner_focus_ring(painter, segment_rect, 5);
        }
        let galley =
            WidgetText::from(kit::text(filter.label(), Font::Footnote).color(kit::palette().label))
                .into_galley(
                    ui,
                    Some(TextWrapMode::Truncate),
                    segment - 4.0,
                    TextStyle::Body,
                );
        ui.painter().galley(
            segment_rect.center() - galley.size() / 2.0,
            galley,
            kit::palette().label,
        );
        if response.clicked() && !selected {
            chosen = Some(*filter);
        }
    }
    chosen
}

/// The height of a row of History: three lines.
const ROW_HEIGHT: f32 = 62.0;

/// "History", the filters, and the rows by day. With nothing waiting, `nothing_waits`
/// says so first. Returns what the owner chose.
pub(crate) fn draw_history(
    ui: &mut Ui,
    view: &HistoryView,
    state: &State,
    nothing_waits: bool,
    notes: &[String],
) -> Option<HistoryAction> {
    let mut action = None;
    if nothing_waits && !view.none_yet {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(kit::medium("Nothing waits for you", Font::Body).color(kit::palette().label));
        });
    }
    if view.none_yet && state.filter == HistoryFilter::All && state.agent.is_none() {
        // Frame 9c: nothing waits and nothing happened yet.
        if nothing_waits {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(kit::text("No decisions yet", Font::Title3).color(kit::palette().label));
            });
        }
        for note in notes {
            super::columns::list_note(ui, note);
        }
        return None;
    }
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        ui.label(kit::medium("History", Font::Callout).color(kit::palette().secondary));
    });
    ui.add_space(4.0);
    Frame::NONE
        .inner_margin(Margin {
            left: 8,
            right: 8,
            top: 0,
            bottom: 4,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if let Some(filter) = filter_control(ui, state.filter) {
                action = Some(HistoryAction::Filter(filter));
            }
            ui.add_space(6.0);
            let shown = state
                .agent
                .clone()
                .unwrap_or_else(|| "All Agents".to_owned());
            let mut chosen = state.agent.clone();
            let mut choices: Vec<(Option<String>, String)> = vec![(None, "All Agents".to_owned())];
            choices.extend(
                view.agents
                    .iter()
                    .map(|agent| (Some(agent.clone()), agent.clone())),
            );
            if let Some(agent) = state.agent.as_ref().filter(|a| !view.agents.contains(*a)) {
                choices.push((Some(agent.clone()), agent.clone()));
            }
            kit::picker(
                ui,
                "history-agent",
                &mut chosen,
                &choices,
                shown.as_str(),
                200.0,
            );
            if chosen != state.agent {
                action = Some(HistoryAction::Agent(chosen));
            }
        });
    if view.groups.is_empty() {
        super::columns::list_note(ui, "No decisions match.");
    }
    for (title, rows) in &view.groups {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(kit::medium(title, Font::Footnote).color(kit::palette().secondary));
        });
        for row in rows {
            let response = ui
                .push_id(("history-row", row.key), |ui| {
                    history_row(ui, row, state.selected == Some(row.key))
                })
                .inner;
            if response.clicked() {
                action = Some(HistoryAction::Select(row.key));
            }
        }
    }
    for note in notes {
        super::columns::list_note(ui, note);
    }
    action
}

fn history_row(ui: &mut Ui, row: &HistoryRow, selected: bool) -> egui::Response {
    use egui::{
        Pos2, Rect, Sense, TextStyle, TextWrapMode, Vec2, WidgetInfo, WidgetText, WidgetType,
    };
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, ROW_HEIGHT), Sense::click());
    let mut name = format!(
        "{}, {}, {}, {}",
        row.title, row.env_name, row.outcome, row.meta
    );
    if !row.reason.is_empty() {
        name.push_str(", ");
        name.push_str(&row.reason);
    }
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
    kit::paint_avatar(ui, avatar, &row.agent);
    if row.remote {
        kit::paint_cloud_badge(painter, avatar);
    }
    kit::paint_tile_ring(painter, avatar, true, selected);
    let white = kit::palette().on_accent;
    let (title_color, sub_color, outcome_color) = if selected {
        (white, kit::palette().on_selection_secondary, white)
    } else if row.denied {
        (
            kit::palette().label,
            kit::palette().secondary,
            Tone::Critical.text(),
        )
    } else {
        (
            kit::palette().label,
            kit::palette().secondary,
            kit::palette().secondary,
        )
    };
    let galley = |value: egui::RichText, max: f32| {
        WidgetText::from(value).into_galley(ui, Some(TextWrapMode::Truncate), max, TextStyle::Body)
    };
    let right = rect.right() - 8.0;
    let left = avatar.right() + 10.0;
    let top = rect.top() + 8.0;
    let meta = galley(kit::text(&row.meta, Font::Footnote).color(sub_color), 70.0);
    let meta_width = meta.size().x;
    painter.galley(Pos2::new(right - meta_width, top + 2.0), meta, sub_color);
    let text_width = (right - left).max(10.0);
    let lines = [
        (
            galley(
                kit::row_title(&row.title).color(title_color),
                (text_width - meta_width - 8.0).max(10.0),
            ),
            title_color,
        ),
        (
            galley(
                kit::text(&row.outcome, Font::Callout).color(outcome_color),
                text_width,
            ),
            outcome_color,
        ),
        // The reason of a decision of this Mac; the environment of another Mac's run.
        (
            galley(
                kit::text(
                    if row.reason.is_empty() {
                        &row.env_name
                    } else {
                        &row.reason
                    },
                    Font::Footnote,
                )
                .color(sub_color),
                text_width,
            ),
            sub_color,
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

/// The facts of one run of the history, read-only. `top` draws under the header ("Why"
/// and "Next time" of a decision of this computer), `bottom` after it ("Details"); the
/// vault build fills them, the demo passes nothing. With `facts_in_details` the
/// "Decision" table is not drawn at rest: `bottom` draws it inside "Details"
/// ([`decision_facts`]).
pub(crate) fn history_detail(
    ui: &mut Ui,
    event: &LogEvent,
    now: u64,
    facts_in_details: bool,
    top: impl FnOnce(&mut Ui),
    bottom: impl FnOnce(&mut Ui),
) {
    let offset = bouncer::local_offset(now);
    let agent = event.agent.clone().unwrap_or_else(|| "An agent".to_owned());
    let credential = event
        .credential
        .clone()
        .unwrap_or_else(|| "A credential".to_owned());
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        kit::agent_avatar(ui, &agent, 56.0, event.remote_agent);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(
                Label::new(
                    kit::text(format!("{agent} · {credential}"), Font::Title)
                        .size(20.0)
                        .color(kit::palette().label),
                )
                .wrap(),
            );
            let when = bouncer::ago(event.at, now, offset);
            let line = if event.project.is_empty() {
                format!("{} · {when}", event.outcome.text())
            } else {
                format!("{} · {} · {when}", event.outcome.text(), event.project)
            };
            ui.label(kit::text(line, Font::Callout).color(kit::palette().secondary));
        });
    });
    ui.add_space(22.0);
    top(ui);
    if !facts_in_details {
        decision_facts(ui, event, now);
    }
    if !event.command.is_empty() {
        kit::section(ui, Some("Command"), None, |s| {
            s.row(|ui| {
                ui.add(
                    Label::new(kit::text(&event.command, Font::Mono).color(kit::palette().label))
                        .wrap(),
                );
            });
        });
    }
    bottom(ui);
    if matches!(event.source, LogSource::Feed(_)) {
        kit::note(ui, format!("Change on {}.", event.env_name));
    }
}

/// The "Decision" table of a run of the history: where, who, what, the project, the
/// outcome, and the time.
pub(crate) fn decision_facts(ui: &mut Ui, event: &LogEvent, now: u64) {
    let offset = bouncer::local_offset(now);
    let agent = event.agent.clone().unwrap_or_else(|| "An agent".to_owned());
    let credential = event
        .credential
        .clone()
        .unwrap_or_else(|| "A credential".to_owned());
    kit::section(ui, Some("Decision"), None, |s| {
        s.labeled("Environment", event.env_name.as_str());
        s.labeled("Agent", agent.as_str());
        s.labeled("Credential", credential.as_str());
        s.labeled(
            "Project",
            if event.project.is_empty() {
                "No project"
            } else {
                event.project.as_str()
            },
        );
        s.labeled("Outcome", event.outcome.text());
        s.labeled(
            "Time",
            format!(
                "{}, {}",
                bouncer::day_month_year(event.at, offset),
                bouncer::clock(event.at, offset)
            ),
        );
    });
}

// ---- The cards. ----

/// The answer of a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardAnswer {
    Deny,
    /// Allow (a connect, with Touch ID) or Allow Once (a cloud run).
    Allow,
}

/// A connect request of a remote agent (frame 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectCard {
    pub(crate) name: String,
    pub(crate) mac: String,
    /// "4:31".
    pub(crate) left: String,
    pub(crate) code: String,
    /// "Returns to <host>": where the code goes back (`crate::node::connect_returns_to`).
    pub(crate) returns_to: String,
    /// The code goes back to a program on a computer (`crate::node::connect_is_local`):
    /// the line is a warning, with [`LOCAL_CONNECT_WARNING`].
    pub(crate) local: bool,
}

/// The time left of a request that ends at `expires_at`: "4:31".
pub(crate) fn left_text(expires_at: u64, now: u64) -> String {
    let left = expires_at.saturating_sub(now);
    format!("{}:{:02}", left / 60, left % 60)
}

/// The header of a card: the avatar with the cloud badge, the title, and "MAC · 4:31 left".
fn card_header(ui: &mut Ui, agent: &str, title: &str, mac: &str, left: &str) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        kit::agent_avatar(ui, agent, 56.0, true);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(
                Label::new(
                    kit::text(title, Font::Title)
                        .size(20.0)
                        .color(kit::palette().label),
                )
                .wrap(),
            );
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.label(
                    kit::text(format!("{mac} · "), Font::Body).color(kit::palette().secondary),
                );
                ui.label(
                    kit::text(format!("{left} left"), Font::Body)
                        .variation(b"wght", 500.0)
                        .color(kit::palette().countdown),
                );
            });
        });
    });
    ui.add_space(22.0);
}

/// The body of a connect card.
pub(crate) fn connect_card(ui: &mut Ui, card: &ConnectCard) {
    card_header(
        ui,
        &card.name,
        &format!("{} wants to connect", card.name),
        &card.mac,
        &card.left,
    );
    kit::section(ui, None, None, |s| {
        s.labeled(
            "Code",
            kit::text(&card.code, Font::Mono).color(kit::palette().label),
        );
    });
    if card.local {
        // Two sentences, as in the Touch ID prompt of the same request.
        warning_line(ui, &format!("{}. {LOCAL_CONNECT_WARNING}", card.returns_to));
    } else {
        ui.horizontal(|ui| {
            ui.add_space(2.0);
            ui.add(
                Label::new(
                    kit::text(&card.returns_to, Font::Callout).color(kit::palette().secondary),
                )
                .wrap(),
            );
        });
    }
    ui.add_space(6.0);
    warning_line(
        ui,
        &format!("Deny unless you just added Apassy to {}.", card.name),
    );
}

/// A line of a card with the warning mark, in the warning color.
fn warning_line(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        kit::paint_icon_in(ui, Icon::Warning, 14.0, Tone::Warning.mark());
        ui.add(Label::new(kit::text(text, Font::Callout).color(Tone::Warning.text())).wrap());
    });
}

/// A run of a remote agent (frame 5b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudCard {
    pub(crate) agent: String,
    pub(crate) credential: String,
    /// "Production", "Development", or none, with red for production.
    pub(crate) environment: Option<(String, bool)>,
    pub(crate) mac: String,
    pub(crate) left: String,
    /// The hosts of the command, or empty.
    pub(crate) sends_to: String,
    /// What the agent says that you asked for. The relay cannot check it.
    pub(crate) request: String,
    pub(crate) command: String,
}

/// The body of a cloud run card.
pub(crate) fn cloud_card(ui: &mut Ui, card: &CloudCard) {
    card_header(
        ui,
        &card.agent,
        &format!("{} wants to use {}", card.agent, card.credential),
        &card.mac,
        &card.left,
    );
    kit::section(ui, None, None, |s| {
        s.row(|ui| {
            ui.horizontal(|ui| {
                ui.label(kit::text("Credential", Font::Body).color(kit::palette().label));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if let Some((label, red)) = &card.environment {
                        kit::cap(ui, label, *red);
                    }
                    ui.add(
                        Label::new(
                            kit::text(&card.credential, Font::Body).color(kit::palette().label),
                        )
                        .truncate(),
                    );
                    kit::tile(ui, &kit::Tile::icon(Tone::Neutral.mark(), Icon::Key), 20.0);
                });
            });
        });
        s.row(|ui| {
            ui.horizontal(|ui| {
                ui.label(kit::text("Agent", Font::Body).color(kit::palette().label));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    kit::remote_cap(ui);
                    ui.label(kit::text(&card.agent, Font::Body).color(kit::palette().label));
                });
            });
        });
        if !card.sends_to.is_empty() {
            s.labeled(
                "Sends To",
                kit::text(&card.sends_to, Font::Body).color(kit::palette().secondary),
            );
        }
        s.row(|ui| {
            ui.horizontal(|ui| {
                ui.label(kit::text("Request", Font::Body).color(kit::palette().label));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    kit::cap_toned(ui, "Not verified", Tone::Warning);
                    let request = if card.request.trim().is_empty() {
                        "No request given".to_owned()
                    } else {
                        format!("\"{}\"", card.request.trim())
                    };
                    ui.add(
                        Label::new(kit::text(request, Font::Body).color(kit::palette().label))
                            .truncate(),
                    );
                });
            });
        });
    });
    kit::group_heading(ui, "Command", None, "");
    kit::section(ui, None, None, |s| {
        s.row(|ui| {
            Frame::NONE
                .fill(kit::palette().code)
                .corner_radius(6)
                .inner_margin(Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(
                        Label::new(
                            kit::text(&card.command, Font::Mono).color(kit::palette().label),
                        )
                        .wrap(),
                    );
                });
        });
    });
}

/// The bar at the bottom of a card: Deny at the left, the allow button at the right.
/// `allow`: "Allow" (a connect, Touch ID) or "Allow Once" (a cloud run).
pub(crate) fn card_bar(
    ui: &mut Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    allow: &str,
    touch_id: bool,
) -> Option<CardAnswer> {
    let mut answer = None;
    egui::Panel::bottom(egui::Id::new(("card-bar", id)))
        .resizable(false)
        .show_separator_line(true)
        .frame(
            Frame::NONE
                .fill(kit::palette().detail)
                .inner_margin(Margin::symmetric(16, 10)),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if kit::button(ui, "Deny", Style::Destructive).clicked() {
                    answer = Some(CardAnswer::Deny);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let response = kit::button(ui, allow, Style::Prominent);
                    let response = if touch_id {
                        response.on_hover_text(concat!("Asks for ", crate::owner_check!(), "."))
                    } else {
                        response
                    };
                    if response.clicked() {
                        answer = Some(CardAnswer::Allow);
                    }
                });
            });
        });
    answer
}

#[cfg(test)]
#[path = "decisions_bouncer_tests.rs"]
mod tests;

// ---- The rows of what waits (both builds: the demo draws its waiting rows with them). ----

/// The time left in the orange of the mockup, at weight 500.
pub(crate) fn timer_text(value: impl Into<String>, font: Font) -> egui::RichText {
    kit::text(value, font).variation(b"wght", 500.0)
}

/// The mark at the left of a row or a header: the round avatar of the agent that asks,
/// or the tile of the credential of a suggestion.
#[derive(Clone)]
pub(crate) enum Mark {
    Agent(String),
    Tile(kit::Tile),
}

/// One row of the list.
pub(crate) struct DecisionRow<'a> {
    pub(crate) mark: &'a Mark,
    pub(crate) remote: bool,
    pub(crate) title: &'a str,
    pub(crate) subtitle: &'a str,
    pub(crate) production: bool,
    /// The time left of a question, in orange.
    pub(crate) left: Option<&'a str>,
    pub(crate) selected: bool,
}

/// A row of the list as [`kit::list_row`], with the time left in orange at the right
/// and the red dot of production before it.
pub(crate) fn decision_row(ui: &mut egui::Ui, row: &DecisionRow<'_>) -> egui::Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 48.0), Sense::click());
    let name = format!(
        "{}, {}{}{}",
        row.title,
        row.subtitle,
        if row.production { ", production" } else { "" },
        row.left
            .map_or_else(String::new, |left| format!(", {left} left"))
    );
    response.widget_info(|| {
        WidgetInfo::selected(WidgetType::SelectableLabel, true, row.selected, &name)
    });
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter();
    if row.selected {
        painter.rect_filled(rect, 8, kit::palette().selection);
    } else if response.hovered() {
        painter.rect_filled(rect, 8, kit::palette().list_hover);
    }
    if response.has_focus() {
        kit::inner_focus_ring(painter, rect, 8);
    }
    // An agent has a round avatar of 28 points, a credential a tile of 32, as in the
    // mockup.
    let side = match row.mark {
        Mark::Agent(_) => 28.0,
        Mark::Tile(_) => 32.0,
    };
    let tile_rect = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.center().y - side / 2.0),
        Vec2::splat(side),
    );
    match row.mark {
        Mark::Agent(name) => kit::paint_avatar(ui, tile_rect, name),
        Mark::Tile(tile) => kit::paint_tile(ui, tile_rect, tile),
    }
    if row.remote {
        kit::paint_cloud_badge(painter, tile_rect);
    }
    let round = match row.mark {
        Mark::Agent(_) => true,
        Mark::Tile(tile) => tile.round,
    };
    kit::paint_tile_ring(painter, tile_rect, round, row.selected);
    let (title_color, sub_color, time_color, dot) = if row.selected {
        let white = kit::palette().on_accent;
        (white, kit::palette().on_selection_secondary, white, white)
    } else {
        (
            kit::palette().label,
            kit::palette().secondary,
            kit::palette().countdown,
            kit::palette().production,
        )
    };
    let galley = |value: egui::RichText, max: f32| {
        WidgetText::from(value).into_galley(ui, Some(TextWrapMode::Truncate), max, TextStyle::Body)
    };
    let mut right = rect.right() - 8.0;
    if let Some(left) = row.left {
        let time = galley(timer_text(left, Font::Callout).color(time_color), 60.0);
        right -= time.size().x;
        painter.galley(
            Pos2::new(right, rect.center().y - time.size().y / 2.0),
            time,
            time_color,
        );
        right -= 6.0;
    }
    if row.production {
        painter.circle_filled(Pos2::new(right - 3.5, rect.center().y), 3.5, dot);
        right -= 13.0;
    }
    let left = tile_rect.right() + 10.0;
    let text_width = (right - left).max(10.0);
    let title = galley(kit::row_title(row.title).color(title_color), text_width);
    let subtitle = galley(
        kit::text(row.subtitle, Font::Callout).color(sub_color),
        text_width,
    );
    let top = rect.center().y - (title.size().y + subtitle.size().y) / 2.0;
    let title_height = title.size().y;
    painter.galley(Pos2::new(left, top), title, title_color);
    painter.galley(Pos2::new(left, top + title_height), subtitle, sub_color);
    response
}
