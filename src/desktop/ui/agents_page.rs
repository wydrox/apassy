//! Bouncer > Agents as one wide page (implementation-plan-bouncer-section §5; mockup
//! frames 2, 3, 4, 8a–8d, 9b, 11a, 12, and 13), and the page of one agent.
//!
//! The page has a group for each environment in the scope: its header ("This Mac" or
//! "Read-only", the age of its report, "Remote access off" of another Mac), the remote
//! access block of this Mac, a table (Agent, Project, Status, Runs Today, Asks You), and
//! "Disconnected (n)". A click on a row opens the page of the agent: its header with the
//! "Remote" cap and an ⓘ, four tiles, its five newest runs, what it can see with "Choose
//! Credentials…", and "Disconnect…" last. An agent of another Mac has a compact page that
//! only shows ("Change on <Mac>.").
//!
//! [`AgentsView::of`] and [`AgentPage::of`] make what the pages show from the cached
//! [`BouncerData`] and plain facts of this Mac; they read no vault and run no command.
//! The vault build gives the facts (`agents.rs`), the demo build fixtures (`demo.rs`).
//! [`draw_page`] and [`draw_agent`] draw and return what the owner chose.
// The demo build draws the pages from fixtures and uses part of this module.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use std::collections::BTreeSet;

use eframe::egui::{self, Label, Ui};

use super::bouncer::{
    self, ActivityScope, AgentLine, AgentRef, BouncerData, DeviceScope, Environment, LogEvent,
    LogOutcome, RemoteAccessWord,
};
use super::kit::{self, Cell, Column, EmptyChoice, Font, Icon, Style, Tone};

/// The runs of the agent page.
pub(crate) const RECENT_RUNS: usize = 5;
/// The download page of Tailscale ("Get Tailscale…", frame 8a).
pub(crate) const TAILSCALE_DOWNLOAD: &str = "https://tailscale.com/download/mac";
/// The access controls of the tailnet ("Open Admin Console…", frame 8c) when Tailscale's
/// message gave no link.
pub(crate) const TAILSCALE_ADMIN: &str = "https://login.tailscale.com/admin/acls/file";

/// The state of Agents in both builds: the open agent page and the open "Disconnected
/// (n)" groups.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The agent page that shows ("‹ Agents" and ⌘[ close it).
    pub(crate) open: Option<AgentRef>,
    /// The environments whose "Disconnected (n)" is open.
    pub(crate) disconnected: BTreeSet<DeviceScope>,
    /// "Edit Note…" of the "⋯" menu opened the note of this agent.
    pub(crate) note_open: Option<u64>,
}

// ---- The remote access block. ----

/// Why remote access does not work (frames 8a–8d), in the words of the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccessProblem {
    /// 8a: "Get Tailscale…".
    NotInstalled,
    /// 8b: "Check Again".
    NotConnected,
    /// 8c: "Open Admin Console…", to the link of Tailscale's message or the admin page.
    Policy { link: Option<String> },
    /// 8d: another program has the Funnel port; "Use Port 10000" when there is another.
    PortTaken { port: u16, alternative: Option<u16> },
    /// The Serve handler on 443 of the owner is public.
    HttpsPublic,
    /// Another failure, in its own words.
    Failed(String),
}

/// The button of a problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProblemButton {
    GetTailscale,
    CheckAgain,
    AdminConsole(String),
    UsePort(u16),
}

impl AccessProblem {
    /// The one line of the problem.
    pub(crate) fn line(&self) -> String {
        match self {
            Self::NotInstalled => "Tailscale is not installed.".to_owned(),
            Self::NotConnected => "Tailscale is not connected.".to_owned(),
            Self::Policy { .. } => "Your tailnet policy blocks Funnel.".to_owned(),
            Self::PortTaken { port, .. } => format!("Another app uses port {port}."),
            Self::HttpsPublic => concat!(
                "Port 443 of this ",
                crate::computer!(),
                " is public through Funnel."
            )
            .to_owned(),
            Self::Failed(message) => bouncer::clip(message),
        }
    }

    pub(crate) fn tone(&self) -> Tone {
        match self {
            Self::Policy { .. } | Self::HttpsPublic => Tone::Critical,
            _ => Tone::Warning,
        }
    }

    /// The button of the problem, with its label.
    pub(crate) fn button(&self) -> Option<(String, ProblemButton)> {
        match self {
            Self::NotInstalled => Some(("Get Tailscale…".to_owned(), ProblemButton::GetTailscale)),
            Self::NotConnected | Self::HttpsPublic | Self::Failed(_) => {
                Some(("Check Again".to_owned(), ProblemButton::CheckAgain))
            }
            Self::Policy { link } => Some((
                "Open Admin Console…".to_owned(),
                ProblemButton::AdminConsole(
                    link.clone()
                        .filter(|link| link.starts_with("https://"))
                        .unwrap_or_else(|| TAILSCALE_ADMIN.to_owned()),
                ),
            )),
            Self::PortTaken {
                alternative: Some(port),
                ..
            } => Some((format!("Use Port {port}"), ProblemButton::UsePort(*port))),
            Self::PortTaken {
                alternative: None, ..
            } => None,
        }
    }

    /// A problem of frames 8a–8d: the switch is off and disabled, and the button of the
    /// problem is the way on. Nothing is reachable meanwhile: the node does not run.
    pub(crate) fn disables_switch(&self) -> bool {
        matches!(
            self,
            Self::NotInstalled | Self::NotConnected | Self::Policy { .. } | Self::PortTaken { .. }
        )
    }
}

/// The remote access block of this Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessView {
    pub(crate) on: bool,
    /// The MCP address, while Tailscale knows the name of this Mac.
    pub(crate) address: Option<String>,
    pub(crate) problem: Option<AccessProblem>,
    /// The route is on and no remote agent connected yet (frame 13b).
    pub(crate) no_remote_agents: bool,
    /// The first read of the block has not ended.
    pub(crate) reading: bool,
}

impl AccessView {
    /// A problem of frames 8a–8d holds the switch while the route setting is off
    /// (mockup frame 8: "switch disabled"): the problem's button is the way on. While the
    /// setting is on, the switch stays usable, so the owner can always turn the route off.
    fn held(&self) -> bool {
        !self.on
            && self
                .problem
                .as_ref()
                .is_some_and(AccessProblem::disables_switch)
    }

    /// The switch takes a click: not while the first read runs, and not in a problem of
    /// frames 8a–8d while the setting is off. A route that is on can always go off.
    pub(crate) fn switch_enabled(&self) -> bool {
        !self.reading && !self.held()
    }

    /// What the switch shows: the route setting (a held switch is off).
    pub(crate) fn switch_on(&self) -> bool {
        self.on && !self.held()
    }
}

/// The ⓘ of remote access (frame 2).
const ACCESS_HELP: [&str; 4] = [
    "Tailscale Funnel opens only the MCP endpoint and the proxy.",
    concat!("Credential values stay on this ", crate::computer!(), "."),
    "Give a cloud agent the address. It asks to connect; you approve it in Decisions.",
    if cfg!(target_os = "linux") {
        "Switching on needs the passphrase or system authentication. Keep this computer unlocked and awake."
    } else {
        concat!(
            "Switching on needs Touch ID. Keep this ",
            crate::computer!(),
            " unlocked and awake."
        )
    },
];

// ---- The page of all agents. ----

/// One row of a table of agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentRow {
    pub(crate) agent: Option<AgentRef>,
    pub(crate) name: String,
    pub(crate) remote: bool,
    /// "apassy, acme-billing", or "—".
    pub(crate) projects: String,
    pub(crate) status: String,
    pub(crate) tone: Tone,
    pub(crate) runs_today: String,
    pub(crate) asks: String,
    pub(crate) asks_often: bool,
}

impl AgentRow {
    pub(crate) fn of(line: &AgentLine, now: u64, offset: i64) -> Self {
        let status = line.status_text(now, offset);
        let tone = if line.waits {
            Tone::Warning
        } else if status == "Active now" {
            Tone::Good
        } else {
            Tone::Neutral
        };
        Self {
            agent: line.id.clone(),
            name: line.name.clone(),
            remote: line.remote,
            projects: if line.projects.is_empty() {
                "—".to_owned()
            } else {
                line.projects.join(", ")
            },
            status,
            tone,
            runs_today: line.runs_today_text(),
            asks: line.ask_rate_text(),
            asks_often: line.asks_often(),
        }
    }
}

/// What an environment without agents shows (frames 9b, 11a, 12a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SectionEmpty {
    /// 9b: this Mac has no agent.
    ThisMac,
    /// 11a: another Mac without agents. `link`: "Show All Environments" (the scope is
    /// that Mac).
    OtherMac { name: String, link: bool },
    /// 12a: a Mac of the vault that never reported.
    NeverReported,
    /// The scope has a project and no agent of any Mac of the scope is in it: one block
    /// for the page ([`AgentsView::empty`]), not one per Mac.
    NoneInProject(String),
}

/// One environment of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvSection {
    pub(crate) scope: DeviceScope,
    pub(crate) name: String,
    pub(crate) this_mac: bool,
    /// "1 min ago", "Remote access off · 1 min ago", "Last report 1 Nov", "Never reported".
    pub(crate) detail: String,
    pub(crate) dimmed: bool,
    /// Why its agents do not show: "Update Apassy to see …".
    pub(crate) note: Option<String>,
    pub(crate) rows: Vec<AgentRow>,
    pub(crate) disconnected: Vec<AgentRow>,
    pub(crate) empty: Option<SectionEmpty>,
}

/// What Agents shows for one scope at one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentsView {
    pub(crate) sections: Vec<EnvSection>,
    /// The connected agents in the scope: "8 agents".
    pub(crate) count: usize,
    pub(crate) access: Option<AccessView>,
    /// No agent of the scope is in its project: one empty block under the sections.
    pub(crate) empty: Option<SectionEmpty>,
}

impl AgentsView {
    pub(crate) fn of(
        data: &BouncerData,
        scope: &ActivityScope,
        access: Option<AccessView>,
        now: u64,
        offset: i64,
    ) -> Self {
        let project = scope.project.as_deref();
        let one = !matches!(scope.device, DeviceScope::All);
        let mut count = 0;
        let sections = data
            .environments_in(&scope.device)
            .into_iter()
            .map(|env| {
                let rows: Vec<AgentRow> = data
                    .agents
                    .iter()
                    .filter(|agent| agent.env == env.scope && agent.in_project(project))
                    .map(|agent| AgentRow::of(agent, now, offset))
                    .collect();
                let disconnected: Vec<AgentRow> = data
                    .disconnected
                    .iter()
                    .filter(|agent| agent.env == env.scope && agent.in_project(project))
                    .map(|agent| AgentRow::of(agent, now, offset))
                    .collect();
                count += rows.len();
                let empty = (rows.is_empty() && disconnected.is_empty())
                    .then(|| section_empty(env, project, one))
                    .flatten();
                Some(EnvSection {
                    scope: env.scope.clone(),
                    name: env.name.clone(),
                    this_mac: env.is_this_mac(),
                    detail: env_detail(env, data.remote_access_of.get(&env.scope), now, offset),
                    dimmed: env.dimmed(now),
                    note: env.note.clone(),
                    rows,
                    disconnected,
                    empty,
                })
            })
            .collect::<Vec<_>>();
        let mut sections: Vec<EnvSection> = sections.into_iter().flatten().collect();
        let mut empty = None;
        if let Some(project) = project {
            // A project narrows the page to the Macs with agents in it; this Mac stays
            // for its remote access block. With none anywhere, one block says so.
            let has_agents =
                |section: &EnvSection| !section.rows.is_empty() || !section.disconnected.is_empty();
            if !sections.iter().any(has_agents) {
                empty = Some(SectionEmpty::NoneInProject(project.to_owned()));
            }
            sections
                .retain(|section| has_agents(section) || (section.this_mac && access.is_some()));
        }
        Self {
            sections,
            count,
            access,
            empty,
        }
    }
}

/// The empty state of an environment with no agent in the scope.
fn section_empty(env: &Environment, project: Option<&str>, one: bool) -> Option<SectionEmpty> {
    if project.is_some() {
        // The page says it once (AgentsView::empty).
        return None;
    }
    if env.is_this_mac() {
        Some(SectionEmpty::ThisMac)
    } else if env.never_reported {
        Some(SectionEmpty::NeverReported)
    } else if env.note.is_some() {
        // Its note says why: "Update Apassy to see …".
        None
    } else {
        Some(SectionEmpty::OtherMac {
            name: env.name.clone(),
            link: one,
        })
    }
}

/// The detail of the header of an environment.
pub(crate) fn env_detail(
    env: &Environment,
    access: Option<&RemoteAccessWord>,
    now: u64,
    offset: i64,
) -> String {
    if env.is_this_mac() {
        return String::new();
    }
    if env.never_reported {
        return "Never reported".to_owned();
    }
    let age = env.reported_at.map(|at| {
        if env.stale(now) {
            format!("Last report {}", bouncer::day_month(at, offset))
        } else {
            bouncer::report_age(at, now, offset)
        }
    });
    let access = access
        .filter(|word| **word != RemoteAccessWord::On)
        .map(|word| word.text().to_owned());
    [access, age]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ")
}

/// What the owner chose on Agents or on an agent page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Open(AgentRef),
    Back,
    ConnectAgent,
    /// The remote access switch: on (Touch ID) or off.
    RemoteAccess(bool),
    CopyAddress(String),
    Problem(ProblemButton),
    ToggleDisconnected(DeviceScope),
    ShowAllEnvironments,
    ShowAllProjects,
    ChooseCredentials(u64),
    /// Remove a row of "Can see": a listed item (no check), or "Never" (the check).
    RemoveSee {
        agent: u64,
        item: u64,
        kind: SeeKind,
    },
    Disconnect(u64),
    ShowInLogs {
        env: DeviceScope,
        name: String,
    },
    EditNote(u64),
    Reconnect(u64),
}

/// The columns of a table of agents.
const COLUMNS: [Column; 5] = [
    Column {
        share: 2.3,
        right: false,
    },
    Column {
        share: 2.0,
        right: false,
    },
    Column {
        share: 1.5,
        right: false,
    },
    Column {
        share: 0.9,
        right: true,
    },
    Column {
        share: 0.9,
        right: true,
    },
];

/// Draw Agents. Returns what the owner chose.
pub(crate) fn draw_page(ui: &mut Ui, view: &AgentsView, state: &State) -> Option<Action> {
    let mut action = None;
    for (index, section) in view.sections.iter().enumerate() {
        if index > 0 {
            ui.add_space(10.0);
        }
        let chosen = ui
            .push_id(("agents-env", index), |ui| {
                draw_section(ui, section, view.access.as_ref(), state)
            })
            .inner;
        if chosen.is_some() {
            action = chosen;
        }
    }
    if let Some(empty) = &view.empty {
        if !view.sections.is_empty() {
            ui.add_space(10.0);
        }
        if let Some(chosen) = section_empty_block(ui, empty) {
            action = Some(chosen);
        }
    }
    action
}

fn draw_section(
    ui: &mut Ui,
    section: &EnvSection,
    access: Option<&AccessView>,
    state: &State,
) -> Option<Action> {
    let mut action = None;
    kit::dimmed(ui, section.dimmed, |ui| {
        let detail = (!section.detail.is_empty()).then_some(section.detail.as_str());
        kit::environment_header(ui, &section.name, section.this_mac, detail);
    });
    if section.this_mac
        && let Some(access) = access
        && let Some(chosen) = access_block(ui, access, section.rows.iter().any(|row| row.remote))
    {
        action = Some(chosen);
    }
    if let Some(note) = &section.note {
        kit::table_group(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(12, 10))
                .show(ui, |ui| {
                    ui.add(
                        Label::new(kit::text(note, Font::Callout).color(kit::palette().secondary))
                            .wrap(),
                    );
                });
        });
    }
    if let Some(empty) = &section.empty {
        if let Some(chosen) = section_empty_block(ui, empty) {
            action = Some(chosen);
        }
        return action;
    }
    if !section.rows.is_empty() {
        kit::dimmed(ui, section.dimmed, |ui| {
            if let Some(chosen) = agent_table(ui, &section.rows, "agents") {
                action = Some(chosen);
            }
        });
    }
    if !section.disconnected.is_empty() {
        let mut open = state.disconnected.contains(&section.scope);
        let before = open;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            kit::disclosure(
                ui,
                &mut open,
                &format!("Disconnected ({})", section.disconnected.len()),
            );
        });
        if open != before {
            action = Some(Action::ToggleDisconnected(section.scope.clone()));
        }
        if open && let Some(chosen) = agent_table(ui, &section.disconnected, "disconnected") {
            action = Some(chosen);
        }
    }
    action
}

/// A table of agents. A click opens the page of the agent.
fn agent_table(ui: &mut Ui, rows: &[AgentRow], salt: &str) -> Option<Action> {
    let mut action = None;
    kit::table_group(ui, |ui| {
        kit::table_header(
            ui,
            &COLUMNS,
            &["Agent", "Project", "Status", "Runs Today", "Asks You"],
        );
        for (index, row) in rows.iter().enumerate() {
            let asks = if row.asks_often {
                Cell::Text(kit::medium(&row.asks, Font::Body).color(Tone::Warning.text()))
            } else {
                Cell::plain(&row.asks)
            };
            let status = if row.tone == Tone::Neutral && !row.status.contains(" ago") {
                // A day before today, without a dot, as the mockup's dimmed Mac.
                Cell::secondary(&row.status)
            } else {
                Cell::Status {
                    text: row.status.clone(),
                    tone: row.tone,
                }
            };
            let runs = if row.runs_today == "—" {
                Cell::secondary(&row.runs_today)
            } else {
                Cell::plain(&row.runs_today)
            };
            let cells = [
                Cell::Agent {
                    name: row.name.clone(),
                    remote: row.remote,
                    label: row.name.clone(),
                },
                if row.projects == "—" {
                    Cell::Empty
                } else {
                    Cell::secondary(&row.projects)
                },
                status,
                runs,
                asks,
            ];
            let response = ui
                .push_id((salt, index), |ui| {
                    kit::table_row(ui, &COLUMNS, &cells, index == 0, false)
                })
                .inner;
            if response.clicked()
                && let Some(agent) = &row.agent
            {
                action = Some(Action::Open(agent.clone()));
            }
        }
    });
    action
}

/// The remote access block of this Mac: the switch, the address with Copy, and the
/// problem with its button.
fn access_block(ui: &mut Ui, access: &AccessView, has_remote: bool) -> Option<Action> {
    let mut action = None;
    kit::section(ui, None, None, |s| {
        s.row(|ui| {
            egui::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(
                                kit::medium("Remote Access", Font::Body)
                                    .color(kit::palette().label),
                            );
                            ui.label(
                                kit::text(
                                    concat!("Cloud agents can reach this ", crate::computer!()),
                                    Font::Callout,
                                )
                                .color(kit::palette().secondary),
                            );
                        });
                        kit::help_button(ui, "Remote Access", &ACCESS_HELP);
                    });
                },
                |ui| {
                    let shown = access.switch_on();
                    let mut on = shown;
                    let enabled = access.switch_enabled();
                    let response = ui
                        .add_enabled_ui(enabled, |ui| kit::toggle(ui, &mut on, "Remote Access"))
                        .inner;
                    if response.changed() && on != shown {
                        action = Some(Action::RemoteAccess(on));
                    }
                },
            );
        });
        if access.reading {
            s.row(|ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        kit::text("Checking Tailscale…", Font::Callout)
                            .color(kit::palette().secondary),
                    );
                });
            });
            return;
        }
        if let Some(problem) = &access.problem {
            s.row(|ui| {
                egui::Sides::new().shrink_left().show(
                    ui,
                    |ui| {
                        ui.horizontal(|ui| {
                            kit::paint_icon_in(ui, Icon::Warning, 14.0, problem.tone().mark());
                            ui.add(
                                Label::new(
                                    kit::text(problem.line(), Font::Body)
                                        .color(problem.tone().text()),
                                )
                                .wrap(),
                            );
                        });
                    },
                    |ui| {
                        if let Some((label, button)) = problem.button() {
                            let style = if matches!(button, ProblemButton::UsePort(_)) {
                                Style::Prominent
                            } else {
                                Style::Bordered
                            };
                            if kit::small_button(ui, &label, style).clicked() {
                                action = Some(Action::Problem(button));
                            }
                        }
                    },
                );
            });
            return;
        }
        if !access.on {
            return;
        }
        if let Some(address) = &access.address {
            s.row(|ui| {
                egui::Sides::new().shrink_left().show(
                    ui,
                    |ui| {
                        // The mockup's label of the row (frame 2): "MCP address".
                        ui.label(kit::text("MCP address", Font::Body).color(kit::palette().label));
                        ui.add_space(12.0);
                        ui.add(
                            Label::new(kit::text(address, Font::Mono).color(kit::palette().label))
                                .truncate(),
                        );
                    },
                    |ui| {
                        if kit::small_button(ui, "Copy", Style::Bordered).clicked() {
                            action = Some(Action::CopyAddress(address.clone()));
                        }
                    },
                );
            });
        }
        if access.no_remote_agents && !has_remote {
            s.row(|ui| {
                ui.horizontal(|ui| {
                    kit::paint_icon_in(ui, Icon::Info, 14.0, Tone::Accent.mark());
                    ui.label(
                        kit::text("No remote agents yet. Give one this address.", Font::Body)
                            .color(Tone::Accent.text()),
                    );
                });
            });
        }
    });
    action
}

/// Keep a line of an empty state within its 12 words, else say it without the name.
fn fit_line(line: String, short: &str) -> String {
    if kit::empty_text_fits("x", Some(line.as_str())) {
        line
    } else {
        short.to_owned()
    }
}

fn section_empty_block(ui: &mut Ui, empty: &SectionEmpty) -> Option<Action> {
    match empty {
        SectionEmpty::ThisMac => (kit::empty_block(
            ui,
            "No agents yet",
            Some("Connected agents and their runs show here."),
            Some("Connect an Agent…"),
            None,
        ) == EmptyChoice::Button)
            .then_some(Action::ConnectAgent),
        SectionEmpty::OtherMac { name, link } => {
            let line = fit_line(
                format!("Connect agents on {name}."),
                concat!("Connect agents on that ", crate::computer!(), "."),
            );
            (kit::empty_block(
                ui,
                "No agents yet",
                Some(line.as_str()),
                None,
                link.then_some("Show All Environments"),
            ) == EmptyChoice::Link)
                .then_some(Action::ShowAllEnvironments)
        }
        SectionEmpty::NeverReported => {
            kit::empty_block(
                ui,
                "No report yet",
                Some(concat!(
                    "Turn on Show agents on my other devices on that ",
                    crate::computer!(),
                    "."
                )),
                None,
                None,
            );
            ui.add_space(-12.0);
            ui.horizontal(|ui| {
                ui.add_space(2.0);
                kit::help_button(
                    ui,
                    "No report yet",
                    &[
                        concat!("On that ", crate::computer!(), ", open Apassy."),
                        "Unlock the vault.",
                        "Turn on Settings > Devices > Relay > \"Show agents on my other devices\".",
                    ],
                );
                ui.label(
                    kit::text("How to turn it on", Font::Footnote).color(kit::palette().tertiary),
                );
            });
            ui.add_space(12.0);
            None
        }
        SectionEmpty::NoneInProject(project) => {
            let title = format!("No agents in {}", bouncer::clip(project));
            let title = if kit::empty_text_fits(&title, None) {
                title
            } else {
                "No agents in this project".to_owned()
            };
            (kit::empty_block(ui, &title, None, Some("Show All Projects"), None)
                == EmptyChoice::Button)
                .then_some(Action::ShowAllProjects)
        }
    }
}

// ---- The page of one agent. ----

/// What a row of "Can see" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SeeKind {
    /// A listed item ("only these items").
    Only,
    /// "Never" for this agent.
    Never,
    /// "Always ask" for this agent.
    AlwaysAsk,
}

/// One row of "Can see".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeeRow {
    pub(crate) item: u64,
    pub(crate) name: String,
    pub(crate) kind: SeeKind,
}

/// What an agent of this Mac can see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CanSee {
    /// It sees the name of every credential (no "only these items").
    pub(crate) all: bool,
    /// Only rows first, then Never, then Always ask.
    pub(crate) rows: Vec<SeeRow>,
}

impl CanSee {
    /// It sees no credential: the empty state "Choose what it can see" (frame 13a).
    pub(crate) fn nothing(&self) -> bool {
        !self.all && !self.rows.iter().any(|row| row.kind == SeeKind::Only)
    }
}

/// The facts of an agent of this Mac that the cache does not have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LocalFacts {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) remote: bool,
    pub(crate) revoked: bool,
    pub(crate) created_at: u64,
    /// The end of its token (`bouncer::shown_token_end`); `None`: no end shown.
    pub(crate) token_end: Option<u64>,
    /// A remote agent connected with the MCP authorization flow (else a token of the
    /// command line).
    pub(crate) oauth: bool,
    pub(crate) can_see: CanSee,
    pub(crate) note: String,
}

/// One of the newest runs of the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunLine {
    pub(crate) at: u64,
    /// The command, or the credential when the source keeps no command.
    pub(crate) first: String,
    pub(crate) mono: bool,
    /// "httpbin test token · Waits for you", "synthetic-shop · Denied by you".
    pub(crate) second: String,
    pub(crate) outcome: LogOutcome,
}

impl RunLine {
    pub(crate) fn of(event: &LogEvent) -> Self {
        let credential = event.credential.clone().unwrap_or_default();
        let outcome = event.outcome.text();
        if event.command.is_empty() {
            let place = if event.project.is_empty() {
                outcome
            } else {
                format!("{} · {outcome}", event.project)
            };
            Self {
                at: event.at,
                first: if credential.is_empty() {
                    "A credential".to_owned()
                } else {
                    credential
                },
                mono: false,
                second: place,
                outcome: event.outcome.clone(),
            }
        } else {
            Self {
                at: event.at,
                first: event.command.clone(),
                mono: true,
                second: if credential.is_empty() {
                    outcome
                } else {
                    format!("{credential} · {outcome}")
                },
                outcome: event.outcome.clone(),
            }
        }
    }
}

/// One tile of the agent page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PageTile {
    pub(crate) label: &'static str,
    pub(crate) value: String,
    pub(crate) share: Option<String>,
}

/// The page of one agent (frames 4, 4b, 13a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentPage {
    pub(crate) agent: AgentRef,
    pub(crate) name: String,
    pub(crate) remote: bool,
    pub(crate) env_name: String,
    /// "Mac mini (office) · last seen now", "· connected 1 min ago", "· 1 h ago".
    pub(crate) line: String,
    /// The lines of the ⓘ of the header; empty: no ⓘ.
    pub(crate) help: Vec<String>,
    pub(crate) tiles: Vec<PageTile>,
    pub(crate) runs: Vec<RunLine>,
    /// What it can see, for an agent of this Mac; `None` for another Mac.
    pub(crate) can_see: Option<CanSee>,
    pub(crate) disconnected: bool,
    /// The token of a token agent ended: "Reconnect…".
    pub(crate) token_expired: bool,
    /// The note for the bouncer of an agent of another Mac, read-only.
    pub(crate) note: String,
}

impl AgentPage {
    /// The page of `agent`: the line of the cache, and for an agent of this Mac its facts.
    /// `None` when neither has it.
    pub(crate) fn of(
        data: &BouncerData,
        agent: &AgentRef,
        local: Option<&LocalFacts>,
        now: u64,
        offset: i64,
    ) -> Option<Self> {
        let line = data.agent(agent);
        if line.is_none() && local.is_none() {
            return None;
        }
        let env = data.environment(&agent.env());
        let env_name = env.map_or_else(
            || {
                line.map_or_else(
                    || concat!("This ", crate::computer!()).to_owned(),
                    |line| line.env_name.clone(),
                )
            },
            |env| env.name.clone(),
        );
        let name = local.map_or_else(
            || line.map(|line| line.name.clone()).unwrap_or_default(),
            |local| bouncer::clip(&local.name),
        );
        let remote = local.map_or_else(|| line.is_some_and(|line| line.remote), |l| l.remote);
        let disconnected = local.map_or_else(
            || {
                data.disconnected
                    .iter()
                    .any(|line| line.id.as_ref() == Some(agent))
            },
            |local| local.revoked,
        );
        let this_mac = matches!(agent, AgentRef::Local(_));
        let seen = line.and_then(|line| line.last_active);
        let connected = local
            .map(|local| local.created_at)
            .or_else(|| line.and_then(|line| line.connected_at));
        let when = match (seen, connected) {
            (Some(at), _) if now.saturating_sub(at) <= bouncer::ACTIVE_NOW => {
                "last seen now".to_owned()
            }
            (Some(at), _) if this_mac => format!("last seen {}", bouncer::ago(at, now, offset)),
            (Some(at), _) => bouncer::ago(at, now, offset),
            (None, Some(at)) => format!("connected {}", bouncer::ago(at, now, offset)),
            (None, None) => String::new(),
        };
        let line_text = if when.is_empty() {
            env_name.clone()
        } else {
            format!("{env_name} · {when}")
        };
        let mut help = Vec::new();
        if remote {
            help.push("An MCP client on the internet. Every run asks you.".to_owned());
        }
        if let Some(at) = connected {
            let how = match local {
                Some(local) if local.remote && local.oauth => {
                    concat!(" with ", crate::touch_id!())
                }
                _ => "",
            };
            help.push(format!(
                "Connected {}{how}.",
                bouncer::day_month_year(at, offset)
            ));
        }
        if let Some(local) = local {
            match local.token_end {
                Some(end) if now >= end => help.push(format!(
                    "Its token expired {}.",
                    bouncer::day_month_year(end, offset)
                )),
                Some(end) => help.push(format!(
                    "Access valid until {}.",
                    bouncer::day_month_year(end, offset)
                )),
                None if local.remote => {
                    help.push("Its access renews while it stays connected.".to_owned());
                }
                None => {}
            }
        }
        if line.is_some_and(|line| line.projects.is_empty()) {
            help.push("No project.".to_owned());
        }
        let asked = line.map_or(0, |line| line.asked);
        let denied = line.map_or(0, |line| line.not_allowed);
        // A feed of v1 has no runs of the agent: its tiles show "—".
        let total = line.and_then(|line| line.runs);
        let number = |value: u64| {
            if total.is_some() {
                value.to_string()
            } else {
                "—".to_owned()
            }
        };
        let mut tiles = vec![
            PageTile {
                label: "Runs",
                value: total.map_or_else(|| "—".to_owned(), |runs| runs.to_string()),
                share: None,
            },
            PageTile {
                label: "Asked you",
                value: number(asked),
                share: total.filter(|runs| *runs > 0).map(|runs| {
                    format!("{}%", (asked as f64 * 100.0 / runs as f64).round() as u64)
                }),
            },
            PageTile {
                label: "Denied",
                value: number(denied),
                share: None,
            },
        ];
        if this_mac {
            tiles.push(PageTile {
                label: "Median answer",
                value: data
                    .agent_answer_p50
                    .get(agent)
                    .map_or_else(|| "—".to_owned(), |secs| bouncer::duration_text(*secs)),
                share: None,
            });
        }
        let runs = line
            .map(|line| {
                data.runs_of(line, RECENT_RUNS, now)
                    .into_iter()
                    .map(RunLine::of)
                    .collect()
            })
            .unwrap_or_default();
        let token_expired = local
            .is_some_and(|local| !local.revoked && local.token_end.is_some_and(|end| now >= end));
        Some(Self {
            agent: agent.clone(),
            name,
            remote,
            env_name,
            line: line_text,
            help,
            tiles,
            runs,
            can_see: local.map(|local| local.can_see.clone()),
            disconnected,
            token_expired,
            note: String::new(),
        })
    }

    fn local_id(&self) -> Option<u64> {
        match self.agent {
            AgentRef::Local(id) => Some(id),
            AgentRef::Other { .. } => None,
        }
    }
}

/// Draw the page of one agent. "‹ Agents" is in the toolbar of the caller. Returns what
/// the owner chose.
pub(crate) fn draw_agent(ui: &mut Ui, page: &AgentPage, now: u64) -> Option<Action> {
    let mut action = None;
    // The header: the avatar with the cloud badge, the name, "Remote" or "Read-only", ⓘ.
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        kit::agent_avatar(ui, &page.name, 56.0, page.remote);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(
                    kit::text(&page.name, Font::Title)
                        .size(20.0)
                        .color(kit::palette().label),
                );
                if page.remote {
                    kit::remote_cap(ui);
                }
                if page.local_id().is_none() {
                    kit::cap(ui, "Read-only", false);
                }
                if !page.help.is_empty() {
                    let lines: Vec<&str> = page.help.iter().map(String::as_str).collect();
                    kit::help_button(ui, &page.name, &lines);
                }
            });
            ui.add(
                Label::new(kit::text(&page.line, Font::Body).color(kit::palette().secondary))
                    .wrap(),
            );
        });
    });
    ui.add_space(16.0);
    if page.disconnected {
        kit::notice(
            ui,
            Tone::Neutral,
            "Disconnected. It cannot reach this vault.",
            Some(if page.local_id().is_some() {
                "Connect it again to give it access."
            } else {
                concat!("Connect it again on its ", crate::computer!(), ".")
            }),
            |_| {},
        );
    }
    if page.token_expired
        && let Some(id) = page.local_id()
    {
        let mut reconnect = false;
        kit::notice(ui, Tone::Critical, "Its token expired.", None, |ui| {
            reconnect = kit::small_button(ui, "Reconnect…", Style::Prominent).clicked();
        });
        if reconnect {
            action = Some(Action::Reconnect(id));
        }
    }
    // Four tiles (three for another Mac: its feed has no median of the agent).
    let gap = 8.0;
    let count = page.tiles.len().max(1) as f32;
    let width = ((ui.available_width() - (count - 1.0) * gap) / count).floor();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        for tile in &page.tiles {
            kit::figure_tile(ui, width, tile.label, &tile.value, tile.share.as_deref());
        }
    });
    // A new remote agent sees nothing yet: that comes first (frame 13a).
    let nothing = page.can_see.as_ref().is_some_and(CanSee::nothing) && !page.disconnected;
    if nothing && let Some(id) = page.local_id() {
        ui.add_space(14.0);
        if kit::empty_block(
            ui,
            "Choose what it can see",
            Some("It sees no credentials yet."),
            Some("Choose Credentials…"),
            None,
        ) == EmptyChoice::Button
        {
            action = Some(Action::ChooseCredentials(id));
        }
    }
    kit::group_heading(ui, "Recent runs", None, "");
    kit::section(ui, None, None, |s| {
        if page.runs.is_empty() {
            s.row(|ui| {
                ui.label(kit::text("No runs yet", Font::Body).color(kit::palette().secondary));
            });
        }
        for run in &page.runs {
            s.row(|ui| run_row(ui, run, now));
        }
    });
    // "Can see": the listed items, and the stricter rows also before any is listed.
    if let (Some(see), Some(id)) = (&page.can_see, page.local_id())
        && (!nothing || !see.rows.is_empty())
        && let Some(chosen) = can_see(ui, id, see, page.disconnected)
    {
        action = Some(chosen);
    }
    if !page.note.trim().is_empty() {
        kit::group_heading(ui, "Note for the bouncer", None, "");
        kit::section(ui, None, None, |s| {
            s.row(|ui| {
                ui.add(
                    Label::new(kit::text(page.note.trim(), Font::Body).color(kit::palette().label))
                        .wrap(),
                );
            });
        });
    }
    match page.local_id() {
        Some(id) if !page.disconnected => {
            ui.add_space(14.0);
            kit::section(ui, None, None, |s| {
                let response = s.clickable_row(&format!("Disconnect {}…", page.name), |ui| {
                    ui.label(kit::text("Disconnect…", Font::Body).color(Tone::Critical.text()));
                });
                if response.clicked() {
                    action = Some(Action::Disconnect(id));
                }
            });
        }
        Some(_) => {}
        None => {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space(2.0);
                kit::note(ui, format!("Change on {}.", page.env_name));
            });
        }
    }
    action
}

/// The mark of a run: what its outcome was.
fn run_mark(outcome: &LogOutcome) -> (Icon, Tone) {
    match outcome {
        LogOutcome::WaitsForYou => (Icon::Clock, Tone::Warning),
        outcome if outcome.denied() => (Icon::Xmark, Tone::Critical),
        LogOutcome::AllowedByBouncer => (Icon::Check, Tone::Good),
        _ => (Icon::Check, Tone::Accent),
    }
}

fn run_row(ui: &mut Ui, run: &RunLine, now: u64) {
    let when = bouncer::ago(run.at, now, bouncer::local_offset(now));
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let (icon, tone) = run_mark(&run.outcome);
        ui.vertical(|ui| {
            ui.add_space(1.0);
            kit::paint_icon_in(ui, icon, 14.0, tone.mark());
        });
        let when_width = kit::galley(ui, kit::text(&when, Font::Callout)).size().x + 10.0;
        ui.vertical(|ui| {
            ui.set_width((ui.available_width() - when_width).max(80.0));
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.spacing_mut().interact_size.y = 0.0;
            let font = if run.mono { Font::Mono } else { Font::Body };
            ui.add(Label::new(kit::text(&run.first, font).color(kit::palette().label)).truncate());
            let second = if run.outcome.denied() {
                kit::text(&run.second, Font::Callout).color(Tone::Critical.text())
            } else {
                kit::text(&run.second, Font::Callout).color(kit::palette().secondary)
            };
            ui.add(Label::new(second).truncate());
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
            ui.label(kit::text(&when, Font::Callout).color(kit::palette().tertiary));
        });
    });
}

/// "Can see": the listed items, then Never and Always ask, each with Remove, and
/// "Choose Credentials…".
fn can_see(ui: &mut Ui, agent: u64, see: &CanSee, disconnected: bool) -> Option<Action> {
    let mut action = None;
    kit::group_heading(ui, "Can see", None, "");
    kit::section(ui, None, None, |s| {
        if see.all {
            s.row(|ui| {
                ui.label(
                    kit::text("All credential names, never values", Font::Body)
                        .color(kit::palette().secondary),
                );
            });
        }
        for row in &see.rows {
            s.row(|ui| {
                egui::Sides::new().shrink_left().show(
                    ui,
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            kit::tile(ui, &kit::Tile::icon(Tone::Neutral.mark(), Icon::Key), 20.0);
                            ui.add(
                                Label::new(
                                    kit::text(&row.name, Font::Body).color(kit::palette().label),
                                )
                                .truncate(),
                            );
                            match row.kind {
                                SeeKind::Never => {
                                    kit::cap(ui, "Never", true);
                                }
                                SeeKind::AlwaysAsk => {
                                    kit::cap(ui, "Always Ask", false);
                                }
                                SeeKind::Only => {}
                            }
                        });
                    },
                    |ui| {
                        if disconnected {
                            return;
                        }
                        let button = kit::small_button(ui, "Remove", Style::Bordered);
                        let label = format!("Remove {}", row.name);
                        ui.ctx()
                            .accesskit_node_builder(button.id, |node| node.set_label(label));
                        if button.clicked() {
                            action = Some(Action::RemoveSee {
                                agent,
                                item: row.item,
                                kind: row.kind,
                            });
                        }
                    },
                );
            });
        }
        if !disconnected {
            let response = s.clickable_row("Choose Credentials…", |ui| {
                ui.label(kit::text("Choose Credentials…", Font::Body).color(kit::palette().accent));
            });
            if response.clicked() {
                action = Some(Action::ChooseCredentials(agent));
            }
        }
    });
    action
}

#[cfg(test)]
#[path = "agents_page_tests.rs"]
mod tests;
