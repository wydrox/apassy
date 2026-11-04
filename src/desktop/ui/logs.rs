//! Bouncer > Logs (implementation-plan-bouncer-section §7; mockup frames 6, 9d, and 14):
//! every run, connect, disconnect, and change of remote access of the environments in the
//! scope, newest first, by day.
//!
//! This Mac: its decision log with the credential uses (200 rows, then "Load More"), its
//! activity lines of the node, and what waits for you now. Other Macs: the runs in their
//! feeds, read-only. Opening a cloud run of this Mac shows its proxied requests from the
//! relay audit: time, method, host, and status, never a path, a header, a body, or a
//! value. Everything comes from the Bouncer cache; opening a row reads the audit once.
// The demo build draws the pages from fixtures and uses part of this module.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::{self, Ui, Vec2};

use super::bouncer::{
    self, ActivityScope, BouncerData, DeviceScope, LogEvent, LogFilter, LogKindFilter, LogOutcome,
    LogSource, ProxyRow,
};
use super::columns;
use super::kit::{self, Cell, Column, EmptyChoice, Font, Tone};
use super::shell::Pending;
use crate::desktop::{DesktopApp, Place};

/// The filters, the selection, and the open row of Logs.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(super) filter: LogFilter,
    /// The selected row, by [`LogEvent::key`].
    selected: Option<u64>,
    /// A notification asked for this activity line: Logs selects it when it shows.
    activity_id: Option<u64>,
    /// The open row and the proxied requests of its cloud run, read when it opened.
    expanded: Option<(u64, Vec<ProxyRow>)>,
}

impl State {
    /// The activity line that a notification asked for.
    pub(crate) fn activity_id(&self) -> Option<u64> {
        self.activity_id
    }

    pub(crate) fn has_selection(&self) -> bool {
        self.selected.is_some() || self.expanded.is_some()
    }

    pub(crate) fn clear_selection(&mut self) {
        self.selected = None;
        self.expanded = None;
        self.activity_id = None;
    }

    pub(super) fn selected(&self) -> Option<u64> {
        self.selected
    }

    pub(super) fn expanded(&self) -> Option<u64> {
        self.expanded.as_ref().map(|(key, _)| *key)
    }
}

/// A notification of a blocked request (`EventKey::Activity`) opens Logs with its row
/// selected, in all environments and without filters: the row is of this Mac.
pub(crate) fn open_activity(app: &mut DesktopApp, id: u64) {
    app.ui.logs = State {
        activity_id: Some(id),
        ..State::default()
    };
    if app.ui.activity_scope.device != DeviceScope::ThisMac {
        app.ui.activity_scope.device = DeviceScope::All;
    }
    app.ui.activity_scope.project = None;
    app.ui.bouncer.invalidate();
    app.place = Place::Logs;
    app.ui.sidebar_float = false;
}

/// Show the rows of one agent (an attention item of the Overview).
pub(super) fn show_agent(app: &mut DesktopApp, agent: Option<String>) {
    app.ui.logs.filter = LogFilter {
        agent,
        ..LogFilter::default()
    };
    app.ui.logs.clear_selection();
}

/// What Logs shows instead of rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogsEmpty {
    /// Frame 9d: nothing happened yet in the scope.
    NoActivity,
    /// Frame 14: filters are set and nothing matches.
    NoMatches,
}

/// What Logs shows, for one scope and filter at one time.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct LogsView<'a> {
    /// The rows by local day: "Today", "Yesterday", "1 Nov".
    pub(super) groups: Vec<(String, Vec<&'a LogEvent>)>,
    /// More than one environment: the rows name their Mac.
    pub(super) several: bool,
    /// This Mac has older rows: "Load More".
    pub(super) more: bool,
    pub(super) empty: Option<LogsEmpty>,
}

impl<'a> LogsView<'a> {
    pub(super) fn of(
        data: &'a BouncerData,
        scope: &ActivityScope,
        filter: &LogFilter,
        now: u64,
        offset: i64,
    ) -> Self {
        let shown = bouncer::filter_events(&data.events, scope, filter);
        let mut groups: Vec<(String, Vec<&LogEvent>)> = Vec::new();
        for event in shown {
            let title = bouncer::day_title(event.at, now, offset);
            match groups.last_mut() {
                Some((last, rows)) if *last == title => rows.push(event),
                _ => groups.push((title, vec![event])),
            }
        }
        let empty = groups.is_empty().then_some(
            if filter.is_set() || scope.project.is_some() || scope.device != DeviceScope::All {
                LogsEmpty::NoMatches
            } else {
                LogsEmpty::NoActivity
            },
        );
        Self {
            groups,
            several: data.environments.len() > 1,
            more: data.more_events && scope.device.covers(&DeviceScope::ThisMac),
            empty,
        }
    }

    /// The row of an activity line, by its key.
    fn activity_row(&self, id: u64) -> Option<u64> {
        self.groups
            .iter()
            .flat_map(|(_, rows)| rows.iter())
            .find(|event| event.source == LogSource::Activity(id))
            .map(|event| event.key())
    }
}

/// What the owner chose in Logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Action {
    /// A click on a row: select it, and open or close it.
    Toggle {
        key: u64,
        relay_run: Option<u64>,
    },
    LoadMore,
    ClearFilters,
}

pub(super) fn wide_pane(app: &mut DesktopApp, ui: &mut Ui, pending: &Pending) {
    let now = now();
    let offset = bouncer::local_offset(now);
    #[cfg(feature = "vault")]
    columns::wide_toolbar(ui, "Logs", "", |_| {});
    // The demo picks the frame of the mockup that the page shows.
    #[cfg(not(feature = "vault"))]
    columns::wide_toolbar(ui, "Logs", "", |ui| super::demo::frame_picker(app, ui));
    let state = &mut app.ui;
    let changed = columns::wide_inset(ui, |ui| {
        let changed = super::scope_bar::bouncer_bar(
            ui,
            &mut state.activity_scope,
            &state.bouncer.data.environments,
            &state.bouncer.data.projects,
            now,
            offset,
        );
        ui.add_space(6.0);
        let agents = state.bouncer.data.log_agents(&state.activity_scope.device);
        filter_bar(ui, &mut state.logs.filter, &agents) || changed
    });
    if changed {
        state.logs.selected = None;
        state.logs.expanded = None;
        ui.ctx().request_repaint();
    }
    #[cfg(feature = "vault")]
    super::shell::banners(app, ui, pending);
    #[cfg(not(feature = "vault"))]
    let _ = pending;
    let state = &mut app.ui;
    let view = LogsView::of(
        &state.bouncer.data,
        &state.activity_scope,
        &state.logs.filter,
        now,
        offset,
    );
    // A notification selects its row once it is here.
    if let Some(id) = state.logs.activity_id
        && state.logs.selected.is_none()
        && let Some(key) = view.activity_row(id)
    {
        state.logs.selected = Some(key);
    }
    let mut action = None;
    columns::wide_body(ui, "bouncer-logs", |ui| {
        action = draw(ui, &view, &state.logs, &state.bouncer.data, now, offset);
    });
    if let Some(action) = action {
        apply(app, action);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn apply(app: &mut DesktopApp, action: Action) {
    match action {
        Action::Toggle { key, relay_run } => {
            let logs = &mut app.ui.logs;
            logs.activity_id = None;
            if logs.expanded() == Some(key) {
                logs.expanded = None;
                logs.selected = Some(key);
                return;
            }
            logs.selected = Some(key);
            let requests = relay_run
                .map(|run| proxied_requests(app, run))
                .unwrap_or_default();
            app.ui.logs.expanded = Some((key, requests));
        }
        Action::LoadMore => app.ui.bouncer.load_more(),
        Action::ClearFilters => {
            app.ui.logs.filter = LogFilter::default();
            app.ui.logs.clear_selection();
            app.ui.activity_scope = ActivityScope::default();
        }
    }
}

/// The proxied requests of a cloud run of this Mac.
fn proxied_requests(app: &DesktopApp, relay_run: u64) -> Vec<ProxyRow> {
    #[cfg(feature = "vault")]
    {
        super::bouncer_load::proxied_requests(app, relay_run)
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = app;
        super::demo::proxied_requests(relay_run)
    }
}

/// "All | Runs | Connections | Denied", the agent menu, and the filter field. Returns
/// true when a filter changed.
fn filter_bar(ui: &mut Ui, filter: &mut LogFilter, agents: &[String]) -> bool {
    let before = filter.clone();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        kit::segmented(
            ui,
            "logs-kind",
            &mut filter.kind,
            &[
                (LogKindFilter::All, "All"),
                (LogKindFilter::Runs, "Runs"),
                (LogKindFilter::Connections, "Connections"),
                (LogKindFilter::Denied, "Denied"),
            ],
        );
        let mut options = vec![(None, "All Agents".to_owned())];
        options.extend(
            agents
                .iter()
                .map(|agent| (Some(agent.clone()), agent.clone())),
        );
        if let Some(agent) = filter
            .agent
            .as_ref()
            .filter(|agent| !agents.contains(*agent))
        {
            options.push((Some(agent.clone()), agent.clone()));
        }
        let shown = filter
            .agent
            .clone()
            .unwrap_or_else(|| "All Agents".to_owned());
        kit::picker(ui, "logs-agent", &mut filter.agent, &options, shown, 140.0);
        ui.allocate_ui(Vec2::new(230.0, 28.0), |ui| {
            kit::search_field(ui, &mut filter.text, "logs-filter", "Filter");
        });
    });
    *filter != before
}

/// The columns of the table of rows, with and without the environment.
const COLUMNS: [Column; 6] = [
    Column {
        share: 0.7,
        right: false,
    },
    Column {
        share: 1.5,
        right: false,
    },
    Column {
        share: 1.6,
        right: false,
    },
    Column {
        share: 1.1,
        right: false,
    },
    Column {
        share: 1.6,
        right: false,
    },
    Column {
        share: 1.5,
        right: false,
    },
];
const COLUMNS_ONE_MAC: [Column; 5] = [
    Column {
        share: 0.7,
        right: false,
    },
    Column {
        share: 1.7,
        right: false,
    },
    Column {
        share: 1.2,
        right: false,
    },
    Column {
        share: 1.8,
        right: false,
    },
    Column {
        share: 1.6,
        right: false,
    },
];
const PROXY_COLUMNS: [Column; 4] = [
    Column {
        share: 1.0,
        right: false,
    },
    Column {
        share: 0.7,
        right: false,
    },
    Column {
        share: 2.2,
        right: false,
    },
    Column {
        share: 1.4,
        right: false,
    },
];

fn titles(several: bool) -> Vec<&'static str> {
    let mut titles = vec!["Time"];
    if several {
        titles.push("Environment");
    }
    titles.extend(["Agent", "Event", "Credential", "Outcome"]);
    titles
}

/// Draw Logs. Returns what the owner chose.
pub(super) fn draw(
    ui: &mut Ui,
    view: &LogsView<'_>,
    state: &State,
    data: &BouncerData,
    now: u64,
    offset: i64,
) -> Option<Action> {
    let mut action = None;
    let columns: &[Column] = if view.several {
        &COLUMNS
    } else {
        &COLUMNS_ONE_MAC
    };
    if let Some(empty) = view.empty {
        ui.add_space(4.0);
        kit::table_group(ui, |ui| {
            kit::table_header(ui, columns, &titles(view.several));
        });
        let (title, button) = match empty {
            LogsEmpty::NoActivity => ("No activity yet", None),
            LogsEmpty::NoMatches => ("No matches", Some("Clear Filters")),
        };
        if kit::empty_block(ui, title, None, button, None) == EmptyChoice::Button {
            action = Some(Action::ClearFilters);
        }
        return action;
    }
    for (title, rows) in &view.groups {
        // A day whose rows are all of a silent Mac is dimmed with them.
        let dim_day = rows.iter().all(|event| dimmed(data, event, now));
        kit::dimmed(ui, dim_day, |ui| {
            kit::group_heading(ui, title, None, "");
        });
        kit::table_group(ui, |ui| {
            if title == "Today" {
                kit::table_header(ui, columns, &titles(view.several));
            }
            for (index, event) in rows.iter().enumerate() {
                let key = event.key();
                let open = state.expanded() == Some(key);
                let cells = cells(event, view.several, open, offset);
                let response = ui
                    .push_id(("log-row", key), |ui| {
                        kit::dimmed(ui, dimmed(data, event, now), |ui| {
                            kit::table_row(
                                ui,
                                columns,
                                &cells,
                                index == 0 && title != "Today",
                                state.selected() == Some(key),
                            )
                        })
                    })
                    .inner;
                if response.clicked() {
                    action = Some(Action::Toggle {
                        key,
                        relay_run: event.relay_run,
                    });
                }
                if open && event.expandable() {
                    let requests = state
                        .expanded
                        .as_ref()
                        .map(|(_, rows)| rows.as_slice())
                        .unwrap_or_default();
                    expansion(ui, event, requests, offset);
                }
            }
        });
    }
    if view.more {
        ui.add_space(8.0);
        ui.vertical_centered(|ui| {
            if kit::button(ui, "Load More", kit::Style::Bordered).clicked() {
                action = Some(Action::LoadMore);
            }
        });
    }
    action
}

/// A row of a Mac silent for 24 hours is dimmed.
fn dimmed(data: &BouncerData, event: &LogEvent, now: u64) -> bool {
    data.environment(&event.env)
        .is_some_and(|env| env.dimmed(now))
}

/// The cells of one row.
fn cells(event: &LogEvent, several: bool, open: bool, offset: i64) -> Vec<Cell> {
    let mut cells = vec![Cell::secondary(bouncer::clock(event.at, offset))];
    if several {
        cells.push(Cell::plain(&event.env_name));
    }
    cells.push(match &event.agent {
        Some(agent) => Cell::Agent {
            name: agent.clone(),
            remote: event.remote_agent,
            label: agent.clone(),
        },
        None => Cell::secondary("—"),
    });
    cells.push(Cell::plain(event.kind.label()));
    cells.push(match &event.credential {
        Some(credential) if event.production => {
            Cell::Production(kit::text(credential, Font::Body).color(kit::palette().label))
        }
        Some(credential) => Cell::plain(credential),
        None => Cell::secondary("—"),
    });
    let open = open && event.expandable();
    let text = event.outcome.text();
    let tone = match &event.outcome {
        LogOutcome::WaitsForYou => Some(Tone::Warning),
        outcome if outcome.denied() => Some(Tone::Critical),
        _ => None,
    };
    let value = match tone {
        Some(tone) => kit::medium(text, Font::Body).color(tone.text()),
        None => kit::text(text, Font::Body).color(kit::palette().label),
    };
    cells.push(Cell::Disclosure { value, open });
    cells
}

/// The open row: its command, then the proxied requests of a cloud run.
fn expansion(ui: &mut Ui, event: &LogEvent, requests: &[ProxyRow], offset: i64) {
    egui::Frame::NONE
        .inner_margin(egui::Margin {
            left: 24,
            right: 14,
            top: 4,
            bottom: 12,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 4.0;
            if !event.command.is_empty() {
                egui::Frame::NONE
                    .fill(kit::palette().code)
                    .corner_radius(6)
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.add(
                            egui::Label::new(
                                kit::text(&event.command, Font::Mono).color(kit::palette().label),
                            )
                            .wrap(),
                        );
                    });
            }
            if event.relay_run.is_none() {
                return;
            }
            let span = match (requests.first(), requests.last()) {
                (Some(first), Some(last)) if last.at > first.at => {
                    bouncer::duration_text(last.at - first.at)
                }
                _ => String::new(),
            };
            kit::group_heading(ui, "Proxied requests", None, &span);
            kit::table_group(ui, |ui| {
                kit::table_header(ui, &PROXY_COLUMNS, &["Time", "Method", "Host", "Status"]);
                if requests.is_empty() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui.label(
                            kit::text("No proxied requests", Font::Callout)
                                .color(kit::palette().secondary),
                        );
                    });
                    ui.add_space(10.0);
                }
                for (index, request) in requests.iter().enumerate() {
                    let status = if request.refused {
                        Cell::Text(
                            kit::text(&request.result, Font::Body).color(Tone::Critical.text()),
                        )
                    } else {
                        Cell::plain(&request.result)
                    };
                    let cells = [
                        Cell::secondary(bouncer::clock_seconds(request.at, offset)),
                        Cell::Text(
                            kit::text(&request.method, Font::Mono).color(kit::palette().label),
                        ),
                        Cell::Text(
                            kit::text(&request.host, Font::Mono).color(kit::palette().label),
                        ),
                        status,
                    ];
                    ui.push_id(("proxy-row", index), |ui| {
                        kit::table_row(ui, &PROXY_COLUMNS, &cells, false, false)
                    });
                }
            });
        });
}

/// Open a row with the proxied requests that the relay audit gave, as a click does.
#[cfg(test)]
pub(super) fn open_row_for_test(app: &mut DesktopApp, key: u64, requests: Vec<ProxyRow>) {
    app.ui.logs.selected = Some(key);
    app.ui.logs.expanded = Some((key, requests));
}
