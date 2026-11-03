//! Bouncer > Overview (implementation-plan-bouncer-section §3; mockup frames 1, 9a, 10b,
//! and 11b): the numbers of the last 7 days, the runs per day, what needs attention, the
//! agents, and the environments, for the scope of the bar.
//!
//! [`OverviewView::of`] makes what the page shows from the cached [`BouncerData`]; it
//! reads no vault. [`draw`] draws it and returns what the owner chose.
// The demo build draws the pages from fixtures and uses part of this module.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::{self, Ui};

use super::bouncer::{
    self, ActivityScope, AgentLine, Attention, BouncerData, DeviceScope, OverviewEmpty, Severity,
    Totals,
};
use super::columns;
use super::kit::{self, Cell, ChartBar, Column, EmptyChoice, Font, Icon, Tone};
use super::shell::Pending;
use crate::desktop::{DesktopApp, Place};

/// What the Overview shows, for one scope at one time.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct OverviewView {
    pub(super) totals: Totals,
    pub(super) empty: Option<OverviewEmpty>,
    pub(super) bars: Vec<ChartBar>,
    pub(super) attention: Vec<Attention>,
    pub(super) agents: Vec<AgentLine>,
    pub(super) environments: Vec<EnvRow>,
    /// More than one environment: the agent table names each one's Mac.
    pub(super) several: bool,
    pub(super) remote_access_on: bool,
}

/// One row of "Environments".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EnvRow {
    pub(super) scope: DeviceScope,
    pub(super) name: String,
    pub(super) this_mac: bool,
    /// "215 runs", "40 runs · 1 Nov", "Never reported", "—".
    pub(super) value: String,
    pub(super) dimmed: bool,
}

impl OverviewView {
    pub(super) fn of(data: &BouncerData, scope: &ActivityScope, now: u64, offset: i64) -> Self {
        let totals = data.totals(&scope.device);
        // Oldest at the left, today at the right.
        let bars = (0..7)
            .rev()
            .map(|index| {
                let at = now.saturating_sub(index as u64 * bouncer::DAY);
                let bar = totals.days[index];
                ChartBar {
                    label: if index == 0 {
                        "Today".to_owned()
                    } else {
                        bouncer::weekday(at, offset).to_owned()
                    },
                    automatic: bar.runs.saturating_sub(bar.asked),
                    asked: bar.asked,
                }
            })
            .collect();
        let environments = data
            .environments_in(&scope.device)
            .into_iter()
            .map(|env| {
                let stats = data
                    .stats
                    .get(&env.scope)
                    .filter(|stats| !stats.days.is_empty());
                let runs = stats.map(|stats| format!("{} runs", stats.runs));
                let value = match (runs, env.never_reported) {
                    (_, true) => "Never reported".to_owned(),
                    (Some(runs), _) if env.stale(now) => format!(
                        "{runs} · {}",
                        bouncer::day_month(env.reported_at.unwrap_or(now), offset)
                    ),
                    (Some(runs), _) => runs,
                    // A feed this Mac cannot open says why.
                    (None, _) => env.note.clone().unwrap_or_else(|| "—".to_owned()),
                };
                EnvRow {
                    scope: env.scope.clone(),
                    name: env.name.clone(),
                    this_mac: env.is_this_mac(),
                    value,
                    dimmed: env.dimmed(now),
                }
            })
            .collect();
        Self {
            empty: bouncer::overview_empty(data, scope),
            bars,
            attention: data.attention(scope, now),
            agents: data.agents_in(scope).into_iter().cloned().collect(),
            environments,
            several: data.environments.len() > 1,
            remote_access_on: data.remote_access_on,
            totals,
        }
    }
}

impl OverviewView {
    /// `count` questions and requests wait for the owner: the first item of "Needs
    /// attention".
    pub(super) fn add_waiting(&mut self, count: usize) {
        if count > 0 {
            self.attention.insert(0, Attention::Waiting { count });
        }
    }
}

/// What the owner chose on the Overview.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Action {
    ConnectAgent,
    TurnOnRemoteAccess,
    ShowAllProjects,
    /// An attention item: Logs for its agent, in its environment; a silent Mac: that Mac.
    Attention(Attention),
    /// An agent row: its page on Agents, in its environment.
    Agent(DeviceScope, Option<super::bouncer::AgentRef>),
    /// An environment row: that environment.
    Environment(DeviceScope),
}

pub(super) fn wide_pane(app: &mut DesktopApp, ui: &mut Ui, pending: &Pending) {
    let now = now();
    let offset = bouncer::local_offset(now);
    #[cfg(feature = "vault")]
    columns::wide_toolbar(ui, "Overview", "Last 7 days", |_| {});
    // The demo picks the frame of the mockup that the page shows.
    #[cfg(not(feature = "vault"))]
    columns::wide_toolbar(ui, "Overview", "Last 7 days", |ui| {
        super::demo::frame_picker(app, ui)
    });
    let changed = columns::wide_inset(ui, |ui| {
        super::scope_bar::bouncer_bar(
            ui,
            &mut app.ui.activity_scope,
            &app.ui.bouncer.data.environments,
            &app.ui.bouncer.data.projects,
            now,
            offset,
        )
    });
    if changed {
        ui.ctx().request_repaint();
    }
    #[cfg(not(feature = "vault"))]
    let _ = pending;
    #[allow(unused_mut)]
    let mut view = OverviewView::of(&app.ui.bouncer.data, &app.ui.activity_scope, now, offset);
    // What waits for you comes first: the banner above names it, so "Needs attention"
    // never says "Nothing needs you" under it.
    #[cfg(feature = "vault")]
    view.add_waiting(super::decisions::badge_count(app, pending));
    let mut action = None;
    columns::wide_body(ui, "bouncer-overview", |ui| {
        #[cfg(feature = "vault")]
        super::shell::banners(app, ui, pending);
        action = draw(ui, &view, now, offset);
    });
    if let Some(action) = action {
        let ctx = ui.ctx().clone();
        apply(app, &ctx, action);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Do what the owner chose.
fn apply(app: &mut DesktopApp, ctx: &egui::Context, action: Action) {
    match action {
        Action::ConnectAgent => {
            #[cfg(feature = "vault")]
            super::agent_onboarding::open(app);
            #[cfg(not(feature = "vault"))]
            super::sidebar::navigate(app, Place::Agents);
        }
        // Touch ID, then the route goes on; Agents shows the address (frame 2).
        Action::TurnOnRemoteAccess => {
            #[cfg(feature = "vault")]
            if app.cloud_node().is_some() {
                app.ask_remote_access_on(Some(ctx));
                return;
            }
            let _ = ctx;
            super::sidebar::navigate(app, Place::Agents);
        }
        Action::ShowAllProjects => app.ui.activity_scope.project = None,
        Action::Attention(Attention::Silent { scope, .. }) | Action::Environment(scope) => {
            app.ui.activity_scope.device = scope;
        }
        Action::Attention(Attention::Waiting { .. }) => {
            super::sidebar::navigate(app, Place::Decisions);
        }
        Action::Attention(item) => {
            let agent = match &item {
                Attention::Production(found) => Some(found.agent.clone()),
                Attention::AsksOften { agent, .. } => Some(agent.clone()),
                Attention::Silent { .. } | Attention::Waiting { .. } => None,
            };
            app.ui.activity_scope.device = item.scope().clone();
            super::logs::show_agent(app, agent);
            super::sidebar::navigate(app, Place::Logs);
        }
        Action::Agent(scope, agent) => {
            app.ui.activity_scope.device = scope;
            super::sidebar::navigate(app, Place::Agents);
            app.ui.agent_page.open = agent;
        }
    }
}

/// The columns of the agent table, with and without the environment.
const AGENT_COLUMNS: [Column; 5] = [
    Column {
        share: 2.2,
        right: false,
    },
    Column {
        share: 1.8,
        right: false,
    },
    Column {
        share: 0.8,
        right: true,
    },
    Column {
        share: 0.9,
        right: true,
    },
    Column {
        share: 1.3,
        right: false,
    },
];
const AGENT_COLUMNS_ONE_MAC: [Column; 4] = [
    Column {
        share: 2.6,
        right: false,
    },
    Column {
        share: 0.8,
        right: true,
    },
    Column {
        share: 0.9,
        right: true,
    },
    Column {
        share: 1.3,
        right: false,
    },
];

/// Draw the Overview. Returns what the owner chose.
pub(super) fn draw(ui: &mut Ui, view: &OverviewView, now: u64, offset: i64) -> Option<Action> {
    let mut action = None;
    if let Some(OverviewEmpty::Project { project, last }) = &view.empty {
        // Frame 11b: a project without runs this week.
        let line = bouncer::last_run_line(last.as_ref(), offset);
        if kit::empty_block(
            ui,
            &format!("No runs in {}", bouncer::clip(project)),
            Some(&line),
            Some("Show All Projects"),
            None,
        ) == EmptyChoice::Button
        {
            action = Some(Action::ShowAllProjects);
        }
        return action;
    }
    figures(ui, &view.totals);
    if view.empty == Some(OverviewEmpty::FirstRun) {
        // Frame 9a: one Mac, no agents, no runs.
        ui.add_space(14.0);
        let link = (!view.remote_access_on).then_some("Turn On Remote Access");
        match kit::empty_block(
            ui,
            "No runs yet",
            Some("Connect an agent to see its runs here."),
            Some("Connect an Agent…"),
            link,
        ) {
            EmptyChoice::Button => action = Some(Action::ConnectAgent),
            EmptyChoice::Link => action = Some(Action::TurnOnRemoteAccess),
            EmptyChoice::None => {}
        }
        return action;
    }
    ui.columns(2, |cols| {
        kit::group_heading(&mut cols[0], "Runs per day", None, "");
        kit::table_group(&mut cols[0], |ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin {
                    left: 14,
                    right: 14,
                    top: 12,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    kit::day_chart(ui, &view.bars);
                });
        });
        if let Some(chosen) = attention(&mut cols[1], &view.attention, offset) {
            action = Some(chosen);
        }
    });
    if let Some(chosen) = agents(ui, view, now, offset) {
        action = Some(chosen);
    }
    if view.several
        && let Some(chosen) = environments(ui, &view.environments)
    {
        action = Some(chosen);
    }
    let mut notes = vec![
        "Allowed by bouncer: runs that did not ask you.",
        "Median answer: the time you took to answer.",
    ];
    if view.several {
        notes.push("Across Macs the median is each Mac's median, weighted by its answers.");
        notes.push("Other Macs count from their reports; allowed runs are approximate.");
    }
    if view.totals.partial {
        notes.push("A Mac on an older Apassy reports no numbers: it counts as —.");
    }
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        kit::help_button(ui, "About these numbers", &notes);
        ui.label(kit::text("The last 7 days", Font::Footnote).color(kit::TERTIARY));
    });
    action
}

/// The five figure tiles.
fn figures(ui: &mut Ui, totals: &Totals) {
    let known = totals.runs.is_some();
    let value = |n: u64| {
        if known {
            n.to_string()
        } else {
            "—".to_owned()
        }
    };
    let gap = 8.0;
    let width = ((ui.available_width() - 4.0 * gap) / 5.0).floor();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        kit::figure_tile(ui, width, "Runs", &value(totals.runs.unwrap_or(0)), None);
        let allowed = totals.share(totals.allowed_by_bouncer);
        kit::figure_tile(
            ui,
            width,
            "Allowed by bouncer",
            &value(totals.allowed_by_bouncer),
            allowed.as_deref(),
        );
        let asked = totals.share(totals.asked);
        kit::figure_tile(
            ui,
            width,
            "Asked you",
            &value(totals.asked),
            asked.as_deref(),
        );
        kit::figure_tile(ui, width, "Denied", &value(totals.denied), None);
        kit::figure_tile(ui, width, "Median answer", &totals.median_text(), None);
    });
}

/// "Needs attention": each item with its mark, or one line when nothing does.
fn attention(ui: &mut Ui, items: &[Attention], offset: i64) -> Option<Action> {
    let mut action = None;
    let count = (!items.is_empty()).then_some(items.len());
    kit::group_heading(ui, "Needs attention", count, "");
    kit::section(ui, None, None, |s| {
        if items.is_empty() {
            s.row(|ui| {
                ui.horizontal(|ui| {
                    kit::paint_icon_in(ui, Icon::CheckCircle, 14.0, Tone::Good.mark());
                    ui.label(kit::text("Nothing needs you", Font::Body).color(kit::LABEL));
                });
            });
        }
        for (index, item) in items.iter().enumerate() {
            let title = item.title();
            let detail = item.detail(offset);
            let response = s.clickable_row(&format!("{title}, {detail}"), |ui| {
                ui.push_id(("attention", index), |ui| {
                    ui.horizontal_top(|ui| {
                        let tone = match item.severity() {
                            Severity::Critical => Tone::Critical,
                            Severity::Warning => Tone::Warning,
                            Severity::Off => Tone::Neutral,
                        };
                        let icon = match item.severity() {
                            Severity::Off => Icon::Clock,
                            _ => Icon::Warning,
                        };
                        kit::icon_tile(ui, icon, tone.mark());
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.horizontal(|ui| {
                                ui.label(kit::medium(&title, Font::Body).color(kit::LABEL));
                                if matches!(item, Attention::Production(_)) {
                                    kit::cap(ui, "Production", true);
                                }
                            });
                            ui.label(kit::text(&detail, Font::Callout).color(kit::SECONDARY));
                        });
                    });
                });
            });
            if response.clicked() {
                action = Some(Action::Attention(item.clone()));
            }
        }
    });
    action
}

/// The agent table: Agent, Environment, Runs, Asks You, Last Active.
fn agents(ui: &mut Ui, view: &OverviewView, now: u64, offset: i64) -> Option<Action> {
    let mut action = None;
    kit::group_heading(ui, "Agents", Some(view.agents.len()), "");
    kit::table_group(ui, |ui| {
        let columns: &[Column] = if view.several {
            &AGENT_COLUMNS
        } else {
            &AGENT_COLUMNS_ONE_MAC
        };
        let mut titles = vec!["Agent"];
        if view.several {
            titles.push("Environment");
        }
        titles.extend(["Runs", "Asks You", "Last Active"]);
        kit::table_header(ui, columns, &titles);
        if view.agents.is_empty() {
            ui.add_space(10.0);
            ui.vertical_centered(|ui| {
                ui.label(kit::text("No agent in this scope", Font::Callout).color(kit::SECONDARY));
            });
            ui.add_space(12.0);
        }
        for (index, agent) in view.agents.iter().enumerate() {
            let rate = agent.ask_rate_text();
            let rate = if agent.asks_often() {
                Cell::Text(kit::medium(rate, Font::Body).color(Tone::Warning.text()))
            } else {
                Cell::plain(rate)
            };
            let status = agent.status_text(now, offset);
            // Frame 1: a dot for "Waits for you" (orange) and "Active now" (green).
            let status = if agent.waits {
                Cell::Status {
                    text: status,
                    tone: Tone::Warning,
                }
            } else if status == "Active now" {
                Cell::Status {
                    text: status,
                    tone: Tone::Good,
                }
            } else {
                Cell::secondary(status)
            };
            let mut cells = vec![Cell::Agent {
                name: agent.name.clone(),
                remote: agent.remote,
                label: agent.name.clone(),
            }];
            if view.several {
                cells.push(Cell::secondary(&agent.env_name));
            }
            cells.extend([
                Cell::plain(agent.runs.map_or_else(|| "—".to_owned(), |n| n.to_string())),
                rate,
                status,
            ]);
            let response = ui
                .push_id(("overview-agent", index), |ui| {
                    kit::table_row(ui, columns, &cells, false, false)
                })
                .inner;
            if response.clicked() {
                action = Some(Action::Agent(agent.env.clone(), agent.id.clone()));
            }
        }
    });
    action
}

/// "Environments": one row per Mac with its runs; a silent Mac dimmed with its date.
fn environments(ui: &mut Ui, rows: &[EnvRow]) -> Option<Action> {
    let mut action = None;
    kit::group_heading(ui, "Environments", None, "");
    kit::section(ui, None, None, |s| {
        for row in rows {
            let response = s.clickable_row(&format!("{}, {}", row.name, row.value), |ui| {
                kit::dimmed(ui, row.dimmed, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(kit::text(&row.name, Font::Body).color(kit::LABEL));
                        if row.this_mac {
                            kit::cap_toned(ui, "This Mac", Tone::Accent);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(kit::text(&row.value, Font::Body).color(kit::SECONDARY));
                        });
                    });
                });
            });
            if response.clicked() {
                action = Some(Action::Environment(row.scope.clone()));
            }
        }
    });
    action
}
