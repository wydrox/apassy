//! Decisions (ADR 0026 §2): what blocks an agent, and the history.
//!
//! A stub of the layout: the list column has the runs that wait, the open access
//! requests of agents, and two rows for the history, "Activity" and "Learning". The
//! detail column draws the Activity view (with the approval cards) or the Learning view
//! as they were. The Decisions view of ADR 0026 replaces both.

use eframe::egui;

use super::columns::{self, Group};
use super::kit::{self, Icon, Tone};
use crate::broker::approvals::PendingRun;
use crate::desktop::DesktopApp;

/// The pane of the detail column.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum Pane {
    #[default]
    Activity,
    Learning,
}

/// One row of the list.
enum Row {
    Run { agent: String, command: String },
    Request { title: String, reason: String },
    Pane(Pane),
}

/// The list column.
pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    let requests = app
        .owner_ui
        .session
        .access_requests(true)
        .unwrap_or_default();
    let waiting = pending.len() + requests.len();
    let subtitle = if waiting == 0 {
        "Nothing needs you".to_owned()
    } else {
        format!("{waiting} waiting")
    };
    columns::list_toolbar(ui, "Decisions", &subtitle, |_| {});
    let mut groups = Vec::new();
    if !pending.is_empty() {
        groups.push(Group {
            title: "Waiting".to_owned(),
            rows: pending
                .iter()
                .map(|run| Row::Run {
                    agent: run.agent.clone(),
                    command: super::activity::shell_words(&run.command),
                })
                .collect(),
        });
    }
    if !requests.is_empty() {
        groups.push(Group {
            title: "Requests".to_owned(),
            rows: requests
                .iter()
                .map(|request| Row::Request {
                    title: format!("{} asks for {}", request.agent_name, request.item_name),
                    reason: request.reason.clone(),
                })
                .collect(),
        });
    }
    groups.push(Group {
        title: "History".to_owned(),
        rows: vec![Row::Pane(Pane::Activity), Row::Pane(Pane::Learning)],
    });
    let mut chosen = None;
    let pane = app.ui.decisions_pane;
    columns::grouped_rows(
        ui,
        "decisions-list",
        &groups,
        true,
        |ui, row| {
            let response = match row {
                Row::Run { agent, command } => kit::list_row(
                    ui,
                    &kit::ListRow {
                        tile: kit::Tile::icon(Tone::Warning.mark(), Icon::Clock),
                        title: agent,
                        subtitle: command,
                        meta: None,
                        production: false,
                        selected: false,
                    },
                ),
                Row::Request { title, reason } => kit::list_row(
                    ui,
                    &kit::ListRow {
                        tile: kit::Tile::icon(kit::ACCENT, Icon::Agent),
                        title,
                        subtitle: reason,
                        meta: None,
                        production: false,
                        selected: false,
                    },
                ),
                Row::Pane(option) => {
                    let (title, subtitle, icon) = match option {
                        Pane::Activity => ("Activity", "Every agent request", Icon::Tray),
                        Pane::Learning => {
                            ("Learning", "What Apassy decides without you", Icon::Chart)
                        }
                    };
                    kit::list_row(
                        ui,
                        &kit::ListRow {
                            tile: kit::Tile::icon(Tone::Neutral.mark(), icon),
                            title,
                            subtitle,
                            meta: None,
                            production: false,
                            selected: pane == *option,
                        },
                    )
                }
            };
            if response.clicked() {
                // A run or a request has its card in Activity.
                chosen = Some(match row {
                    Row::Pane(option) => *option,
                    _ => Pane::Activity,
                });
            }
        },
        |_| {},
    );
    if let Some(pane) = chosen {
        app.ui.decisions_pane = pane;
    }
}

/// The detail column: Activity or Learning.
pub(super) fn detail_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    columns::detail_toolbar(ui, |_| {});
    let pane = app.ui.decisions_pane;
    columns::detail_body(ui, ("decisions", pane), |ui| {
        super::shell::banners(app, ui, pending);
        match pane {
            Pane::Activity => super::activity::draw(app, ui, pending),
            Pane::Learning => crate::desktop::learning_ui::draw(app, ui),
        }
    });
}
