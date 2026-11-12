//! The in-memory demo build (`--features desktop` without `vault`). It uses the same
//! kit as the vault build. Values are synthetic, "Open vault" is not authentication,
//! and the rule interpreter is a fixture.

use eframe::egui::{self, Align, Label, Layout};

use super::columns;
use super::kit::{self, Font, Icon, Style, Tone};
use super::{Sheet, close_sheet, extra_label, kind_icon, kind_plural, meta_line};
use crate::contracts::{CredentialKind, Decision};
use crate::desktop::model::{
    AMBIGUOUS_SAMPLE_TEXT, CONFLICTING_SAMPLE_TEXT, DesktopModel, ExtraField, INTERPRETER_ID,
    ItemDetails, ItemDraft, ItemSummary, SAMPLE_RULE_TEXT, UNSUPPORTED_SAMPLE_TEXT,
};
use crate::desktop::{DemoScenario, DesktopApp, DraftStatus, RequestStatus};

fn locked_state(ui: &mut egui::Ui, title: &str) {
    kit::page_header(ui, title, None, |_| {});
    kit::empty_state(
        ui,
        Icon::Lock,
        "The demo vault is locked",
        "Select \"Open vault\" in the sidebar. This control is not owner authentication.",
        None,
    );
}

/// The list column of the demo credentials, grouped by kind.
pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let locked = app.model.is_locked();
    let count = if locked {
        0
    } else {
        app.model.list_items("").len()
    };
    let mut add = false;
    let title = columns::place_title(app);
    columns::list_toolbar(
        ui,
        &title,
        &columns::count_label(count, "item", "items"),
        |ui| {
            if !locked {
                add = kit::plain_icon_button(ui, Icon::Plus, "New credential").clicked();
            }
        },
    );
    if locked {
        columns::list_note(ui, "The demo vault is locked.");
        return;
    }
    columns::list_inset(ui, |ui| {
        kit::search_field(ui, &mut app.search, "demo-search", "Search");
    });
    let items = app.model.list_items(&app.search);
    let groups: Vec<columns::Group<ItemSummary>> = CredentialKind::ALL
        .into_iter()
        .filter_map(|kind| {
            let rows: Vec<ItemSummary> = items
                .iter()
                .filter(|item| item.kind == kind)
                .cloned()
                .collect();
            (!rows.is_empty()).then(|| columns::Group {
                title: kind_plural(kind).to_owned(),
                rows,
            })
        })
        .collect();
    let selected = app.selected_item_id.clone();
    let mut open = None;
    columns::grouped_rows(
        ui,
        "demo-list",
        &groups,
        true,
        |ui, item| {
            let meta = meta_line(&item.project, &item.service);
            let subtitle = if meta.is_empty() {
                item.kind.label().to_owned()
            } else {
                meta
            };
            let response = ui
                .push_id(("demo-row", &item.id), |ui| {
                    kit::list_row(
                        ui,
                        &kit::ListRow {
                            tile: super::credential_tile(item.kind, &item.service, &item.name),
                            title: &item.name,
                            subtitle: &subtitle,
                            meta: None,
                            production: false,
                            selected: selected.as_deref() == Some(item.id.as_str()),
                        },
                    )
                })
                .inner;
            if response.clicked() {
                open = Some(item.id.clone());
            }
        },
        |ui| {
            if items.is_empty() {
                columns::list_note(ui, "No item matches.");
            }
        },
    );
    if let Some(id) = open {
        app.select_item(id);
    }
    if add {
        app.add_form = ItemDraft::default();
        app.ui.sheet = Some(Sheet::AddItem { kind_chosen: false });
    }
}

/// The detail column of the demo credentials.
pub(super) fn detail_column(app: &mut DesktopApp, ui: &mut egui::Ui) {
    columns::detail_toolbar(ui, |_| {});
    let selected = app.selected_item_id.clone();
    columns::detail_body(ui, ("demo-detail", selected), |ui| {
        if app.model.is_locked() {
            locked_state(ui, "Credentials");
        } else if app.selected_item_id.is_some() {
            draw_detail(app, ui);
        } else {
            columns::nothing_selected(
                ui,
                Icon::Key,
                "No credential selected",
                "Select a credential in the list.",
            );
        }
    });
}

fn selected(app: &DesktopApp) -> Option<(String, ItemDetails)> {
    let id = app.selected_item_id.clone()?;
    let details = app.model.item_details(&id).ok()?;
    Some((id, details))
}

fn draw_detail(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some((id, details)) = selected(app) else {
        kit::note(ui, "Select an item in the vault.");
        return;
    };
    if details.hidden {
        kit::page_header(ui, &details.name, None, |_| {});
        kit::note(ui, &details.message);
        return;
    }
    let mut edit = false;
    ui.horizontal(|ui| {
        let (icon, color) = kind_icon(details.kind);
        kit::icon_tile_sized(ui, icon, color, 40.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(kit::text(&details.name, Font::Title).color(kit::palette().label));
            ui.label(
                kit::text(details.kind.label(), Font::Callout).color(kit::palette().secondary),
            );
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            edit = kit::button(ui, "Edit", Style::Bordered).clicked();
        });
    });
    ui.add_space(20.0);
    let mut toggle = false;
    let mut copy = false;
    let footer = if details.revealed {
        details.reveal_warning
    } else {
        details.copy_warning
    };
    kit::section(ui, Some("Synthetic value"), Some(footer), |s| {
        s.row(|ui| {
            egui::Sides::new().show(
                ui,
                |ui| {
                    let color = if details.revealed {
                        kit::palette().label
                    } else {
                        kit::palette().secondary
                    };
                    ui.label(kit::text(&details.display_value, Font::Mono).color(color));
                },
                |ui| {
                    ui.add_enabled_ui(details.revealed, |ui| {
                        copy = kit::small_button(ui, "Copy (demo)", Style::Link).clicked();
                    });
                    let label = if details.revealed {
                        "Hide demo value"
                    } else {
                        "Show demo value"
                    };
                    toggle = kit::small_button(ui, label, Style::Link).clicked();
                },
            );
        });
    });
    let rows: Vec<(&str, &str)> = [
        ("Project", details.project.as_str()),
        ("Service", details.service.as_str()),
        ("Username", details.username.as_str()),
        ("Host", details.host.as_str()),
        ("Database", details.database_name.as_str()),
        ("Field name", details.field_name.as_str()),
        ("Public key", details.public_label.as_str()),
        ("Notes", details.notes.as_str()),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .collect();
    kit::section(ui, Some("Details"), Some(details.agent_use_label), |s| {
        for (label, value) in rows {
            s.labeled(
                label,
                kit::text(value, Font::Body).color(kit::palette().secondary),
            );
        }
        s.labeled(
            "Revision",
            kit::text(details.revision.to_string(), Font::Body).color(kit::palette().secondary),
        );
    });
    let mut delete = false;
    kit::section(ui, None, None, |s| {
        delete = s
            .clickable_row("Delete item…", |ui| {
                ui.label(kit::text("Delete item…", Font::Body).color(Tone::Critical.text()));
            })
            .clicked();
    });
    if toggle {
        if details.revealed {
            let result = app.model.hide_item(&id);
            let _ = app.apply(result, "The demo value is hidden.");
        } else {
            match app.model.reveal_item(&id) {
                Ok(revealed) => app.set_ok(revealed.reveal_warning),
                Err(err) => app.set_err(err.message),
            }
        }
    }
    if copy {
        match app.model.demo_copy_item(&id) {
            Ok(copy) => app.set_ok(copy.warning),
            Err(err) => app.set_err(err.message),
        }
    }
    if edit {
        app.edit_form = ItemDraft {
            name: details.name.clone(),
            kind: details.kind,
            service: details.service.clone(),
            project: details.project.clone(),
            notes: details.notes.clone(),
            username: details.username.clone(),
            website: String::new(),
            host: details.host.clone(),
            database_name: details.database_name.clone(),
            field_name: details.field_name.clone(),
            public_label: details.public_label.clone(),
            details: Vec::new(),
        };
        app.ui.sheet = Some(Sheet::EditItem);
    }
    if delete {
        app.pending_delete = true;
    }
}

pub(super) fn draw_delete_alert(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some((id, details)) = selected(app) else {
        app.pending_delete = false;
        return;
    };
    let mut delete = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "delete-item", 380.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Delete “{}”?", details.name),
            Some("Delete removes the item from this demo memory."),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                delete = kit::button(ui, "Delete", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if cancel || response.escape {
        app.pending_delete = false;
        app.set_note("Delete is canceled.");
    }
    if delete {
        let result = app.model.delete_item(&id);
        app.pending_delete = false;
        if app.apply(result, "The item was deleted.").is_some() {
            app.selected_item_id = None;
            app.show_credentials();
        }
    }
}

/// Name, kind-specific labels, service, project, and notes. The demo has no secret
/// input: the model assigns the synthetic value.
fn item_form(ui: &mut egui::Ui, form: &mut ItemDraft, salt: &str) {
    let kind = form.kind;
    kit::section(ui, None, None, |s| {
        s.field("Name", |ui| {
            kit::text_input(ui, &mut form.name, &format!("{salt}-name"), "")
        });
        for field in DesktopModel::extra_fields(kind) {
            let value = match field {
                ExtraField::Username => &mut form.username,
                ExtraField::Website => &mut form.website,
                ExtraField::Host => &mut form.host,
                ExtraField::DatabaseName => &mut form.database_name,
                ExtraField::FieldName => &mut form.field_name,
                ExtraField::PublicLabel => &mut form.public_label,
            };
            s.field(extra_label(*field), |ui| {
                kit::text_input(ui, value, &format!("{salt}-{field:?}"), "")
            });
        }
        s.field("Service", |ui| {
            kit::text_input(ui, &mut form.service, &format!("{salt}-service"), "")
        });
        s.field("Project", |ui| {
            kit::text_input(ui, &mut form.project, &format!("{salt}-project"), "")
        });
    });
    kit::section(ui, Some("Notes"), None, |s| {
        s.row(|ui| {
            kit::text_area(ui, &mut form.notes, &format!("{salt}-notes"), "", 3);
        });
    });
}

pub(super) fn add_sheet(app: &mut DesktopApp, ctx: &egui::Context, kind_chosen: bool) -> bool {
    let mut pick = None;
    let mut add = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "add-item", 480.0, |ui| {
        if !kind_chosen {
            kit::sheet_title(
                ui,
                "Add an item",
                Some("The form stores labels only. The model creates the synthetic value."),
            );
            kit::section(ui, None, None, |s| {
                for kind in CredentialKind::ALL {
                    if s.nav(Some(kind_icon(kind)), kind.label(), None, None)
                        .clicked()
                    {
                        pick = Some(kind);
                    }
                }
            });
        } else {
            kit::sheet_title(ui, &format!("New {}", app.add_form.kind.label()), None);
            kit::sheet_body(ui, |ui| item_form(ui, &mut app.add_form, "add"));
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if kind_chosen {
                    add = kit::button(ui, "Add", Style::Prominent).clicked();
                }
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if let Some(kind) = pick {
        app.add_form.kind = kind;
        app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
    }
    if kind_chosen {
        add |= super::save_pressed(app, ctx);
    }
    if add {
        match app.model.create_item(app.add_form.clone()) {
            Ok(item) => {
                app.set_ok(format!("The desktop added {}.", item.name));
                app.add_form = ItemDraft::default();
                app.select_item(item.id);
            }
            Err(err) => app.set_err(err.message),
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

pub(super) fn edit_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(id) = app.selected_item_id.clone() else {
        app.ui.sheet = None;
        return false;
    };
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "edit-item", 480.0, |ui| {
        kit::sheet_title(ui, "Edit item", Some(app.edit_form.kind.label()));
        kit::sheet_body(ui, |ui| item_form(ui, &mut app.edit_form, "edit"));
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                save = kit::button(ui, "Save", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    save |= super::save_pressed(app, ctx);
    if save {
        let result = app.model.update_item(&id, app.edit_form.clone());
        if app.apply(result, "The item was updated.").is_some() {
            app.pending_delete = false;
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

pub(super) fn draw_rules(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::page_header(
        ui,
        "Rules",
        Some(
            "The editor accepts ordinary language. This desktop uses a deterministic fixture interpreter. It does not call a language model.",
        ),
        |_| {},
    );
    kit::notice(
        ui,
        Tone::Warning,
        &format!("Interpreter {INTERPRETER_ID}"),
        Some(
            "This is a fixture interpreter. It is not live natural-language support. It matches one exact sample and refuses other text.",
        ),
        |ui| {
            ui.horizontal_wrapped(|ui| {
                for (label, text) in [
                    ("Supported sample", SAMPLE_RULE_TEXT),
                    ("Ambiguous", AMBIGUOUS_SAMPLE_TEXT),
                    ("Conflicting", CONFLICTING_SAMPLE_TEXT),
                    ("Unsupported", UNSUPPORTED_SAMPLE_TEXT),
                ] {
                    if kit::small_button(ui, label, Style::Bordered).clicked() {
                        app.rule_text = text.to_owned();
                        app.set_note("The sample text is in the editor. Review the rule next.");
                    }
                }
            });
        },
    );
    kit::section(ui, Some("Rule text"), None, |s| {
        s.row(|ui| {
            kit::text_area(
                ui,
                &mut app.rule_text,
                "rule-text",
                "Describe what the agent may do.",
                5,
            );
        });
    });
    let draft = app.model.rule_draft().cloned();
    let can_confirm = draft
        .as_ref()
        .is_some_and(|draft| draft.status == DraftStatus::ReadyForReview && !draft.confirmed);
    let can_activate = draft
        .as_ref()
        .is_some_and(|draft| draft.status == DraftStatus::ReadyForReview && draft.confirmed);
    ui.horizontal(|ui| {
        if kit::button(ui, "Review rule", Style::Prominent).clicked() {
            match app.model.interpret_rule(&app.rule_text) {
                Ok(draft) if draft.status == DraftStatus::ReadyForReview => {
                    app.set_ok("The fixture interpreter produced a reviewable sample draft.");
                }
                Ok(_) => app.set_err(
                    "The fixture interpreter refused this text. See questions and issues.",
                ),
                Err(err) => app.set_err(err.message),
            }
        }
        if ui
            .add_enabled_ui(can_confirm, |ui| {
                kit::button(ui, "Confirm interpretation", Style::Bordered)
            })
            .inner
            .clicked()
        {
            let result = app.model.confirm_rule();
            let _ = app.apply(result, "The owner demo confirmation is recorded.");
        }
        if ui
            .add_enabled_ui(can_activate, |ui| {
                kit::button(ui, "Activate rule", Style::Bordered)
            })
            .inner
            .clicked()
        {
            let result = app.model.activate_rule();
            let _ = app.apply(result, "The sample rule is active in this desktop demo.");
        }
    });
    ui.add_space(20.0);
    if let Some(draft) = &draft {
        kit::section(
            ui,
            Some("Clause review"),
            Some(&format!(
                "{}. Interpreter: {}.",
                draft.status.label(),
                draft.interpreter
            )),
            |s| {
                if draft.clauses.is_empty() {
                    s.row(|ui| {
                        kit::note(ui, "No clauses. The interpreter did not invent a parse.")
                    });
                }
                for clause in &draft.clauses {
                    s.row(|ui| {
                        ui.horizontal(|ui| {
                            kit::tag(ui, clause.kind_label, Tone::Accent);
                            ui.label(
                                kit::text(&clause.text, Font::Body).color(kit::palette().label),
                            );
                        });
                        kit::note(ui, &clause.meaning);
                    });
                }
                for question in &draft.questions {
                    s.row(|ui| kit::tone_note(ui, question, Tone::Warning));
                }
                for issue in &draft.issues {
                    s.row(|ui| kit::tone_note(ui, &issue.message, Tone::Warning));
                }
                if let Some(examples) = &draft.examples {
                    s.labeled(
                        "Permit",
                        kit::text(&examples.allow, Font::Callout).color(kit::palette().secondary),
                    );
                    s.labeled(
                        "Wait",
                        kit::text(&examples.ask, Font::Callout).color(kit::palette().secondary),
                    );
                    s.labeled(
                        "Deny",
                        kit::text(&examples.deny, Font::Callout).color(kit::palette().secondary),
                    );
                }
            },
        );
    }
    if let Some(rule) = app.model.active_rule().cloned() {
        kit::section(ui, Some("Active rule"), Some(&rule.original_text), |s| {
            s.labeled(
                "Status",
                kit::text(rule.status, Font::Body).color(kit::palette().secondary),
            );
            s.labeled(
                "Agent",
                kit::text(&rule.agent_name, Font::Body).color(kit::palette().secondary),
            );
            s.labeled(
                "Item",
                kit::text(&rule.item_name, Font::Body).color(kit::palette().secondary),
            );
            s.labeled(
                "Destination",
                kit::text(rule.destination, Font::Body).color(kit::palette().secondary),
            );
            s.labeled(
                "Denied",
                kit::text(rule.denied_destinations.join(", "), Font::Body)
                    .color(kit::palette().secondary),
            );
            s.labeled(
                "Operation",
                kit::text(rule.operation, Font::Body).color(kit::palette().secondary),
            );
            s.labeled(
                "Expiry",
                kit::text(
                    format!("{} ({})", rule.expiry_iso, rule.time_zone),
                    Font::Body,
                )
                .color(kit::palette().secondary),
            );
            s.labeled(
                "Uses",
                kit::text(
                    format!("{} of {}", rule.use_count, rule.usage_limit),
                    Font::Body,
                )
                .color(kit::palette().secondary),
            );
        });
    }
}

fn decision_tone(decision: Decision) -> (&'static str, Tone) {
    match decision {
        Decision::Allow => ("Permit", Tone::Good),
        Decision::RequireApproval => ("Wait", Tone::Warning),
        Decision::Deny => ("Deny", Tone::Critical),
    }
}

pub(super) fn draw_activity(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::page_header(
        ui,
        "Activity",
        Some(
            "A normal grant is permitted. An unclear task waits. Production is denied and cannot be approved.",
        ),
        |_| {},
    );
    kit::notice(
        ui,
        Tone::Warning,
        "This is a fixture risk simulation. It is not a verified bouncer.",
        Some(
            "Demo requests and their alerts are in memory. This build has no notification channel: native notifications need the vault build of Apassy.app.",
        ),
        |ui| {
            ui.horizontal(|ui| {
                let options: Vec<(DemoScenario, String)> = DemoScenario::ALL
                    .into_iter()
                    .map(|scenario| (scenario, scenario.label().to_owned()))
                    .collect();
                let selected = app.scenario.label();
                kit::picker(
                    ui,
                    "demo_scenario",
                    &mut app.scenario,
                    &options,
                    selected,
                    200.0,
                );
                if kit::small_button(ui, "Send request", Style::Prominent).clicked() {
                    match app.model.simulate(app.scenario) {
                        Ok(request) if request.decision == Decision::Deny => {
                            app.set_err(request.message)
                        }
                        Ok(request) => app.set_ok(request.message),
                        Err(err) => app.set_err(err.message),
                    }
                }
            });
        },
    );
    let alerts: Vec<_> = app.model.list_alerts().into_iter().cloned().collect();
    kit::section(ui, Some("Inbox and alerts"), None, |s| {
        if alerts.is_empty() {
            s.row(|ui| kit::note(ui, "No alerts."));
        }
        for alert in &alerts {
            let request = app
                .model
                .list_requests()
                .iter()
                .find(|request| request.id == alert.request_id)
                .cloned();
            s.row(|ui| {
                let current = request.as_ref().map_or(alert.decision, |r| r.decision);
                let (label, tone) = decision_tone(current);
                ui.horizontal(|ui| {
                    kit::tag(ui, label, tone);
                    ui.label(kit::medium(&alert.title, Font::Body).color(kit::palette().label));
                });
                if let Some(request) = &request
                    && request.initial_decision != request.decision
                {
                    kit::note(
                        ui,
                        format!(
                            "First decision: {}",
                            decision_tone(request.initial_decision).0
                        ),
                    );
                }
                kit::paragraph(ui, &alert.message, Font::Callout, kit::palette().label);
                kit::note(
                    ui,
                    format!(
                        "{} · {} · {} · {} · delivery {}",
                        alert.agent_name,
                        alert.item_name,
                        alert.destination,
                        alert.operation,
                        alert.delivery_status
                    ),
                );
                ui.horizontal(|ui| {
                    if let Some(request) = &request
                        && request.status == RequestStatus::Pending
                        && request.approvable
                    {
                        if kit::small_button(ui, "Approve once", Style::Prominent).clicked() {
                            let result = app.model.approve_once(&request.id, None);
                            let _ = app.apply(result, "The request was approved once.");
                        }
                        if kit::small_button(ui, "Deny request", Style::Destructive).clicked() {
                            let result = app.model.deny_request(&request.id);
                            let _ = app.apply(result, "The request was denied.");
                        }
                    }
                    let connected = app
                        .model
                        .list_agents()
                        .iter()
                        .any(|agent| agent.id == alert.agent_id && agent.connected);
                    if connected
                        && kit::small_button(ui, "Revoke agent", Style::Destructive).clicked()
                    {
                        let message = format!("{} is revoked.", alert.agent_name);
                        let result = app.model.revoke_agent(&alert.agent_id);
                        let _ = app.apply(result, &message);
                    }
                });
            });
        }
    });
    let events: Vec<_> = app.model.list_activity().into_iter().cloned().collect();
    kit::section(ui, Some("History"), None, |s| {
        if events.is_empty() {
            s.row(|ui| kit::note(ui, "No history."));
        }
        for event in events {
            s.row(|ui| {
                ui.add(
                    Label::new(kit::text(&event.message, Font::Body).color(kit::palette().label))
                        .wrap(),
                );
                kit::note(ui, format!("{} · {}", event.at_iso, event.kind));
            });
        }
    });
}

// ---- The Bouncer pages (mockup docs/design/cloud-agents-mockup.html). ----

/// The frame of the mockup that the Bouncer pages show in the demo build. The toolbar
/// menu of each page picks it, and `APASSY_DEMO_FRAME` (1–6, 8a–8d, 9–11, 11a, 12, 12a,
/// 13a, 13b, 14) sets it at start, for screenshots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum BouncerFrame {
    /// 1 Overview, 2 and 3 Agents, 4 agent pages, 5 Decisions, 6 Logs: three Macs, a
    /// week of runs, Grok Bot waits.
    #[default]
    AllEnvironments,
    /// 8a: Tailscale is not installed.
    NotInstalled,
    /// 8b: Tailscale is not connected.
    NotConnected,
    /// 8c: the tailnet policy blocks Funnel.
    PolicyBlocks,
    /// 8d: another app uses port 8443.
    PortTaken,
    /// 9a–9d: one Mac, no agents, no runs.
    FirstRun,
    /// 10a and 10b: a quiet week; one Mac silent since 1 Nov.
    QuietDay,
    /// 11a: a new Mac without agents.
    NewMac,
    /// 11b: a project without runs this week.
    EmptyProject,
    /// 12a: a Mac of the vault that never reported.
    NeverReported,
    /// 12b: the only Mac; its environment menu says so.
    OneMac,
    /// 13a: Grok Bot just connected and sees nothing yet.
    NewRemoteAgent,
    /// 13b: remote access on, no remote agent yet.
    NoRemoteAgentYet,
    /// 14: Logs with filters that match nothing.
    FilteredLogs,
}

impl BouncerFrame {
    const ALL: [Self; 14] = [
        Self::AllEnvironments,
        Self::NotInstalled,
        Self::NotConnected,
        Self::PolicyBlocks,
        Self::PortTaken,
        Self::FirstRun,
        Self::QuietDay,
        Self::NewMac,
        Self::EmptyProject,
        Self::NeverReported,
        Self::OneMac,
        Self::NewRemoteAgent,
        Self::NoRemoteAgentYet,
        Self::FilteredLogs,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::AllEnvironments => "Frames 1–6: All Environments",
            Self::NotInstalled => "Frame 8a: Not Installed",
            Self::NotConnected => "Frame 8b: Not Connected",
            Self::PolicyBlocks => "Frame 8c: Funnel Not Allowed",
            Self::PortTaken => "Frame 8d: Port 8443 in Use",
            Self::FirstRun => "Frame 9: First Run",
            Self::QuietDay => "Frame 10: Quiet Day",
            Self::NewMac => "Frame 11a: New Mac",
            Self::EmptyProject => "Frame 11b: Empty Project",
            Self::NeverReported => "Frame 12a: Never Reported",
            Self::OneMac => "Frame 12b: One Mac",
            Self::NewRemoteAgent => "Frame 13a: New Remote Agent",
            Self::NoRemoteAgentYet => "Frame 13b: No Remote Agent Yet",
            Self::FilteredLogs => "Frame 14: Filtered Logs",
        }
    }

    /// The frame of `APASSY_DEMO_FRAME`.
    fn from_env() -> Option<Self> {
        match std::env::var("APASSY_DEMO_FRAME").ok()?.trim() {
            "1" | "2" | "3" | "4" | "5" | "6" => Some(Self::AllEnvironments),
            "8a" => Some(Self::NotInstalled),
            "8b" => Some(Self::NotConnected),
            "8c" => Some(Self::PolicyBlocks),
            "8d" => Some(Self::PortTaken),
            "9" => Some(Self::FirstRun),
            "10" => Some(Self::QuietDay),
            "11a" => Some(Self::NewMac),
            "11" | "11b" => Some(Self::EmptyProject),
            "12a" => Some(Self::NeverReported),
            "12" | "12b" => Some(Self::OneMac),
            "13a" => Some(Self::NewRemoteAgent),
            "13" | "13b" => Some(Self::NoRemoteAgentYet),
            "14" => Some(Self::FilteredLogs),
            _ => None,
        }
    }

    /// A frame of remote access problems (8a–8d).
    fn problem(self) -> bool {
        matches!(
            self,
            Self::NotInstalled | Self::NotConnected | Self::PolicyBlocks | Self::PortTaken
        )
    }
}

/// Make the Bouncer data of the demo frame when the frame or the project changes.
pub(super) fn bouncer_refresh(app: &mut DesktopApp, ctx: &egui::Context) {
    use std::sync::Once;
    static FROM_ENV: Once = Once::new();
    FROM_ENV.call_once(|| {
        if let Some(frame) = BouncerFrame::from_env() {
            select_frame_scope(app, frame);
        }
    });
    let frame = app.ui.demo_frame;
    let project = app.ui.activity_scope.project.clone();
    let time = ctx.input(|input| input.time);
    let stamp = super::bouncer::stamp(frame);
    app.ui
        .bouncer
        .refresh(time, stamp, project.as_deref(), |_| {
            bouncer_data(frame, demo_now())
        });
}

/// The toolbar menu that picks the demo frame.
pub(super) fn frame_picker(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut frame = app.ui.demo_frame;
    let options: Vec<(BouncerFrame, String)> = BouncerFrame::ALL
        .iter()
        .map(|frame| (*frame, frame.label().to_owned()))
        .collect();
    let shown = frame.label();
    kit::picker(ui, "demo-frame", &mut frame, &options, shown, 220.0);
    if frame != app.ui.demo_frame {
        select_frame_scope(app, frame);
    }
}

/// Pick a frame with the scope and the filters of its mockup frame.
pub(crate) fn select_frame_scope(app: &mut DesktopApp, frame: BouncerFrame) {
    use super::bouncer::{ActivityScope, AgentRef, DeviceScope, LogFilter, LogKindFilter};
    app.ui.demo_frame = frame;
    app.ui.activity_scope = ActivityScope::default();
    app.ui.logs = Default::default();
    app.ui.agent_page = Default::default();
    app.ui.decision_history = Default::default();
    app.ui.bouncer.invalidate();
    match frame {
        BouncerFrame::NewMac => {
            app.ui.activity_scope.device = DeviceScope::Other(DEMO_LAB.to_owned());
        }
        BouncerFrame::NeverReported => {
            app.ui.activity_scope.device = DeviceScope::Other(DEMO_HOME.to_owned());
        }
        BouncerFrame::NewRemoteAgent => {
            app.ui.activity_scope.device = DeviceScope::ThisMac;
            app.ui.agent_page.open = Some(AgentRef::Local(DEMO_GROK));
        }
        frame if frame.problem() => app.ui.activity_scope.device = DeviceScope::ThisMac,
        BouncerFrame::NoRemoteAgentYet => app.ui.activity_scope.device = DeviceScope::ThisMac,
        BouncerFrame::EmptyProject => {
            app.ui.activity_scope.project = Some("billing-v2".to_owned());
        }
        BouncerFrame::OneMac => app.ui.activity_scope.device = DeviceScope::ThisMac,
        BouncerFrame::FilteredLogs => {
            app.ui.activity_scope.device = DeviceScope::ThisMac;
            app.ui.activity_scope.project = Some("acme-billing".to_owned());
            // The mockup's filters of frame 14: Denied, Grok Bot, "delete".
            app.ui.logs.filter = LogFilter {
                kind: LogKindFilter::Denied,
                agent: Some("Grok Bot".to_owned()),
                text: "delete".to_owned(),
            };
        }
        _ => {}
    }
}

fn demo_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The relay run of the open Grok Bot run of frame 6.
const DEMO_RELAY_RUN: u64 = 41;

/// The proxied requests of a demo cloud run (frame 6).
pub(super) fn proxied_requests(relay_run: u64) -> Vec<super::bouncer::ProxyRow> {
    use super::bouncer::ProxyRow;
    if relay_run != DEMO_RELAY_RUN {
        return Vec::new();
    }
    let start = demo_now().saturating_sub(8 * 60);
    let row = |after: u64, host: &str, result: &str, refused: bool| ProxyRow {
        at: start + after,
        method: "GET".to_owned(),
        host: host.to_owned(),
        result: result.to_owned(),
        refused,
    };
    vec![
        row(8, "api.github.com", "200", false),
        row(9, "api.github.com", "200", false),
        row(11, "api.github.com", "200", false),
        row(100, "api.github.com", "404", false),
        row(122, "uploads.example.net", "Refused: wrong host", true),
    ]
}

/// The Bouncer data of a frame at `now`. Synthetic names and numbers of the mockup.
pub(crate) fn bouncer_data(frame: BouncerFrame, now: u64) -> super::bouncer::BouncerData {
    let mut data = frame_data(frame, now);
    agree_denials(&mut data, now);
    data
}

/// "Denied" of each agent counts at least the denied runs that its page lists: the
/// counts and the runs come from the same 7 days ([`super::bouncer::BouncerData::runs_of`]).
fn agree_denials(data: &mut super::bouncer::BouncerData, now: u64) {
    let denied: Vec<u64> = data
        .agents
        .iter()
        .map(|line| {
            data.runs_of(line, usize::MAX, now)
                .iter()
                .filter(|event| event.outcome.denied())
                .count() as u64
        })
        .collect();
    for (line, denied) in data.agents.iter_mut().zip(denied) {
        line.not_allowed = line.not_allowed.max(denied);
    }
}

fn frame_data(frame: BouncerFrame, now: u64) -> super::bouncer::BouncerData {
    use super::bouncer::{
        AgentLine, BouncerData, DayBar, DeviceScope, EnvStats, Environment, ProductionUse,
    };
    const STUDIO: &str = "6a1d3c5e-7b9f-4a2c-8e4d-1f3a5b7c9d0e";
    const LAPTOP: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
    let office = || Environment::this_mac("Mac mini (office)");
    let studio = || Environment {
        scope: DeviceScope::Other(STUDIO.to_owned()),
        name: "Mac mini (studio)".to_owned(),
        reported_at: Some(now.saturating_sub(120)),
        never_reported: false,
        note: None,
    };
    // Silent since about 43 hours: dimmed, and an attention item.
    let laptop = || Environment {
        scope: DeviceScope::Other(LAPTOP.to_owned()),
        name: "MacBook Pro".to_owned(),
        reported_at: Some(now.saturating_sub(43 * 3_600 + 40 * 60)),
        never_reported: false,
        note: None,
    };
    let days = |runs: [u64; 7], asked: [u64; 7]| -> Vec<DayBar> {
        runs.iter()
            .zip(asked)
            .map(|(runs, asked)| DayBar { runs: *runs, asked })
            .collect()
    };
    let stats = |runs, allowed, asked, denied, p50, bars: Vec<DayBar>| EnvStats {
        runs,
        allowed_by_bouncer: allowed,
        asked,
        denied,
        answer_p50_secs: Some(p50),
        answers: asked,
        days: bars,
    };
    let agent =
        |name: &str, env: &Environment, runs: u64, asked: u64, ago: Option<u64>, project: &str| {
            AgentLine {
                name: name.to_owned(),
                env: env.scope.clone(),
                env_name: env.name.clone(),
                remote: false,
                runs: Some(runs),
                asked,
                not_allowed: 0,
                last_active: ago.map(|ago| now.saturating_sub(ago)),
                waits: false,
                projects: if project.is_empty() {
                    Vec::new()
                } else {
                    vec![project.to_owned()]
                },
                id: Some(demo_agent_ref(&env.scope, name)),
                runs_today: Some(runs.div_ceil(7)),
                connected_at: None,
            }
        };
    let mut data = BouncerData::default();
    match frame {
        BouncerFrame::FirstRun => {
            let env = office();
            data.stats.insert(
                env.scope.clone(),
                EnvStats {
                    days: vec![DayBar::default(); 7],
                    ..EnvStats::default()
                },
            );
            data.environments = vec![env];
            return data;
        }
        BouncerFrame::OneMac
        | BouncerFrame::NewMac
        | BouncerFrame::NeverReported
        | BouncerFrame::NewRemoteAgent
        | BouncerFrame::NoRemoteAgentYet
        | BouncerFrame::NotInstalled
        | BouncerFrame::NotConnected
        | BouncerFrame::PolicyBlocks
        | BouncerFrame::PortTaken => {
            let env = office();
            data.stats.insert(
                env.scope.clone(),
                stats(
                    86,
                    74,
                    11,
                    1,
                    13,
                    days([14, 12, 13, 11, 13, 12, 11], [2, 1, 2, 1, 2, 2, 1]),
                ),
            );
            data.agents = vec![
                agent("Claude Code", &env, 52, 3, Some(120), "acme-billing"),
                agent("Codex", &env, 22, 2, Some(25 * 60), "acme-billing"),
                AgentLine {
                    remote: true,
                    ..agent("Grok Bot", &env, 12, 12, Some(2 * 3_600), "")
                },
            ];
            data.has_agents = true;
            data.projects = vec!["acme-billing".to_owned()];
            data.remote_access_on = !frame.problem() || frame == BouncerFrame::PortTaken;
            match frame {
                BouncerFrame::NewRemoteAgent => {
                    // Just connected: no run and no credential yet.
                    if let Some(grok) = data.agents.iter_mut().find(|a| a.name == "Grok Bot") {
                        grok.runs = Some(0);
                        grok.runs_today = Some(0);
                        grok.asked = 0;
                        grok.last_active = None;
                        grok.connected_at = Some(now.saturating_sub(60));
                    }
                }
                BouncerFrame::NoRemoteAgentYet => data.agents.retain(|a| !a.remote),
                _ => {
                    data.events = bouncer_events(now, false)
                        .into_iter()
                        .filter(|event| event.env == DeviceScope::ThisMac)
                        .collect();
                }
            }
            let mut envs = vec![env];
            if frame == BouncerFrame::NewMac {
                // Reported this morning at 08:12, with no agent yet.
                envs.push(Environment {
                    scope: DeviceScope::Other(DEMO_LAB.to_owned()),
                    name: "Mac mini (lab)".to_owned(),
                    reported_at: Some(now.saturating_sub(6 * 3_600)),
                    never_reported: false,
                    note: None,
                });
            }
            if frame == BouncerFrame::NeverReported {
                envs.push(Environment {
                    scope: DeviceScope::Other(DEMO_HOME.to_owned()),
                    name: "iMac (home)".to_owned(),
                    reported_at: None,
                    never_reported: true,
                    note: None,
                });
            }
            data.environments = envs;
            return data;
        }
        BouncerFrame::QuietDay => {
            let (o, s, l) = (office(), studio(), laptop());
            data.stats.insert(
                o.scope.clone(),
                stats(
                    160,
                    140,
                    19,
                    2,
                    15,
                    days([4, 26, 28, 27, 25, 26, 24], [0, 3, 4, 3, 3, 3, 3]),
                ),
            );
            data.stats.insert(
                s.scope.clone(),
                stats(
                    120,
                    104,
                    15,
                    3,
                    16,
                    days([2, 20, 19, 21, 19, 20, 19], [0, 3, 2, 3, 2, 3, 2]),
                ),
            );
            data.stats.insert(
                l.scope.clone(),
                stats(
                    40,
                    36,
                    3,
                    1,
                    14,
                    days([0, 0, 8, 8, 8, 8, 8], [0, 0, 1, 0, 1, 0, 1]),
                ),
            );
            data.agents = vec![
                agent("Claude Code", &o, 101, 8, Some(11 * 3_600), "acme-billing"),
                agent("Claude Code", &s, 69, 6, Some(12 * 3_600), "shop"),
                agent("Codex", &o, 47, 7, Some(13 * 3_600), "acme-billing"),
                agent("Codex", &s, 51, 9, Some(14 * 3_600), "shop"),
                agent("Claude Code", &l, 40, 3, Some(43 * 3_600), "side-project"),
                AgentLine {
                    remote: true,
                    ..agent("Grok Bot", &o, 12, 4, Some(16 * 3_600), "")
                },
            ];
            data.has_agents = true;
            data.environments = vec![o, s, l];
            data.projects = vec!["acme-billing".into(), "shop".into(), "side-project".into()];
            data.events = bouncer_events(now, false);
            return data;
        }
        BouncerFrame::EmptyProject => {
            let envs = vec![office(), studio(), laptop()];
            for env in &envs {
                data.stats.insert(
                    env.scope.clone(),
                    EnvStats {
                        days: vec![DayBar::default(); 7],
                        ..EnvStats::default()
                    },
                );
            }
            data.environments = envs;
            data.has_agents = true;
            data.projects = vec!["acme-billing".into(), "billing-v2".into(), "shop".into()];
            data.last_in_project = Some((now.saturating_sub(13 * 86_400), "Codex".to_owned()));
            return data;
        }
        BouncerFrame::AllEnvironments | BouncerFrame::FilteredLogs => {}
    }
    let (o, s, l) = (office(), studio(), laptop());
    // Today first. The days add up to the mockup's bars of frame 1 (Wed 48 … today
    // 104); the MacBook Pro has no runs after its last report on 1 Nov.
    data.stats.insert(
        o.scope.clone(),
        stats(
            215,
            190,
            22,
            3,
            12,
            days([60, 55, 6, 10, 32, 32, 20], [5, 4, 1, 1, 4, 4, 3]),
        ),
    );
    data.stats.insert(
        s.scope.clone(),
        stats(
            169,
            140,
            25,
            4,
            16,
            days([44, 40, 6, 8, 24, 27, 20], [6, 5, 1, 1, 4, 4, 4]),
        ),
    );
    data.stats.insert(
        l.scope.clone(),
        stats(
            40,
            40,
            4,
            0,
            14,
            days([0, 0, 6, 4, 10, 12, 8], [0, 0, 0, 0, 1, 2, 1]),
        ),
    );
    data.agents = vec![
        agent("Claude Code", &o, 142, 9, Some(120), "acme-billing"),
        agent("Claude Code", &s, 98, 4, Some(300), "shop"),
        agent("Codex", &o, 61, 7, Some(25 * 60), "acme-billing"),
        // Frame 4b: Denied 3.
        AgentLine {
            not_allowed: 3,
            ..agent("Codex", &s, 44, 13, Some(3_600), "shop")
        },
        agent(
            "Claude Code",
            &l,
            31,
            3,
            Some(43 * 3_600 + 40 * 60),
            "side-project",
        ),
        agent("T3 Code", &s, 27, 2, Some(3 * 3_600), "shop"),
        AgentLine {
            remote: true,
            waits: true,
            ..agent("Grok Bot", &o, 12, 12, Some(60), "acme-billing")
        },
        agent("Codex", &l, 9, 1, Some(3 * 86_400), "side-project"),
    ];
    data.has_agents = true;
    data.production = vec![ProductionUse {
        credential: "Stripe live".to_owned(),
        agent: "Claude Code".to_owned(),
        env: o.scope.clone(),
        env_name: o.name.clone(),
        times: 3,
    }];
    data.environments = vec![o, s, l];
    data.projects = vec![
        "acme-billing".into(),
        "billing-v2".into(),
        "shop".into(),
        "side-project".into(),
    ];
    data.events = bouncer_events(now, true);
    data.remote_access_on = true;
    // Frame 2: one disconnected agent on this Mac; frame 3: the studio's access is off.
    data.disconnected = vec![AgentLine {
        name: "Old agent".to_owned(),
        last_active: Some(now.saturating_sub(30 * 86_400)),
        ..agent("Old agent", &office(), 0, 0, None, "")
    }];
    data.remote_access_of.insert(
        DeviceScope::Other(STUDIO.to_owned()),
        super::bouncer::RemoteAccessWord::Off,
    );
    data.agent_answer_p50
        .insert(super::bouncer::AgentRef::Local(DEMO_GROK), 21);
    data.connects = vec![super::bouncer::ConnectLine {
        id: "demo-connect".to_owned(),
        name: "Grok Bot".to_owned(),
        code: "K7Q-4MD".to_owned(),
        at: now.saturating_sub(29),
        expires_at: now + 271,
        returns_to: DEMO_RETURNS_TO.to_owned(),
        local: false,
    }];
    for line in &mut data.agents {
        if line.remote {
            line.connected_at = Some(now.saturating_sub(6 * 86_400));
        }
    }
    data
}

/// The other Macs of frames 11a and 12a.
const DEMO_LAB: &str = "3e5f7a9b-1c2d-4e6f-8a0b-2c4d6e8f0a1b";
const DEMO_HOME: &str = "7c9e1a3b-5d7f-4b9d-8f1a-3b5d7f9b1d3f";
/// The vault id of Grok Bot in the demo.
const DEMO_GROK: u64 = 3;

/// The agent of a demo line: an agent of this Mac by a small id, else by its name.
fn demo_agent_ref(scope: &super::bouncer::DeviceScope, name: &str) -> super::bouncer::AgentRef {
    use super::bouncer::{AgentRef, DeviceScope};
    match scope {
        DeviceScope::Other(device) => AgentRef::Other {
            device: device.clone(),
            id: name.to_owned(),
        },
        _ => AgentRef::Local(match name {
            "Claude Code" => 1,
            "Codex" => 2,
            "Grok Bot" => DEMO_GROK,
            "T3 Code" => 4,
            _ => 9,
        }),
    }
}

/// The rows of frame 6, newest first.
fn bouncer_events(now: u64, waiting: bool) -> Vec<super::bouncer::LogEvent> {
    use super::bouncer::{DeviceScope, LogEvent, LogKind, LogOutcome, LogSource};
    const STUDIO: &str = "6a1d3c5e-7b9f-4a2c-8e4d-1f3a5b7c9d0e";
    const LAPTOP: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
    let mut next = 0;
    let mut row = |ago: u64,
                   env: &str,
                   agent: Option<&str>,
                   remote: bool,
                   kind: LogKind,
                   credential: Option<&str>,
                   outcome: LogOutcome| {
        next += 1;
        let (scope, env_name) = match env {
            "studio" => (DeviceScope::Other(STUDIO.to_owned()), "Mac mini (studio)"),
            "laptop" => (DeviceScope::Other(LAPTOP.to_owned()), "MacBook Pro"),
            _ => (DeviceScope::ThisMac, "Mac mini (office)"),
        };
        LogEvent {
            source: if scope == DeviceScope::ThisMac {
                LogSource::Decision(next)
            } else {
                LogSource::Feed(next)
            },
            at: now.saturating_sub(ago),
            env: scope,
            env_name: env_name.to_owned(),
            agent: agent.map(str::to_owned),
            remote_agent: remote,
            kind,
            credential: credential.map(str::to_owned),
            production: false,
            project: "acme-billing".to_owned(),
            outcome,
            relay_run: None,
            command: String::new(),
        }
    };
    let min = 60;
    let mut events = Vec::new();
    if waiting {
        let mut connect = row(
            min,
            "office",
            Some("Grok Bot (new)"),
            true,
            LogKind::Connect,
            None,
            LogOutcome::WaitsForYou,
        );
        connect.source = LogSource::Connect("demo-connect".to_owned());
        connect.project = String::new();
        events.push(connect);
        events.push(row(
            min,
            "office",
            Some("Grok Bot"),
            true,
            LogKind::Run,
            Some("httpbin test token"),
            LogOutcome::WaitsForYou,
        ));
    }
    events.push(row(
        6 * min,
        "studio",
        Some("Claude Code"),
        false,
        LogKind::Run,
        Some("Shop database"),
        LogOutcome::AllowedByBouncer,
    ));
    let mut cloud = row(
        8 * min,
        "office",
        Some("Grok Bot"),
        true,
        LogKind::Run,
        Some("GitHub token"),
        LogOutcome::AllowedOn("iPhone".to_owned()),
    );
    cloud.relay_run = Some(DEMO_RELAY_RUN);
    cloud.command = "gh api repos/acme/billing/issues --paginate".to_owned();
    events.push(cloud);
    let mut stripe = row(
        18 * min,
        "office",
        Some("Claude Code"),
        false,
        LogKind::Run,
        Some("Stripe live"),
        LogOutcome::AllowedByYou,
    );
    stripe.production = true;
    events.push(stripe);
    events.push(row(
        25 * min,
        "office",
        Some("Codex"),
        false,
        LogKind::Run,
        Some("OpenAI API"),
        LogOutcome::AllowedByBouncer,
    ));
    events.push(row(
        62 * min,
        "studio",
        Some("Codex"),
        false,
        LogKind::Run,
        Some("Deploy key"),
        LogOutcome::DeniedByYou,
    ));
    let mut access = row(
        75 * min,
        "office",
        None,
        false,
        LogKind::RemoteAccessOn,
        None,
        LogOutcome::ByYou,
    );
    access.source = LogSource::Activity(7);
    access.project = String::new();
    events.push(access);
    events.push(row(
        3 * 60 * min,
        "studio",
        Some("T3 Code"),
        false,
        LogKind::Run,
        Some("GitHub token"),
        LogOutcome::AllowedByBouncer,
    ));
    events.push(row(
        20 * 60 * min,
        "office",
        Some("Grok Bot"),
        true,
        LogKind::Run,
        Some("GitHub token"),
        LogOutcome::DeniedByYou,
    ));
    events.push(row(
        22 * 60 * min,
        "office",
        Some("Grok Bot"),
        true,
        LogKind::Run,
        Some("Stripe test"),
        LogOutcome::DeniedByYou,
    ));
    events.push(row(
        43 * 60 * min + 40 * min,
        "laptop",
        Some("Claude Code"),
        false,
        LogKind::Run,
        Some("Side project database"),
        LogOutcome::AllowedByBouncer,
    ));
    events
}

// ---- Settings > Devices (mockup docs/design/devices-settings-mockup.html). ----

/// The frame of the Devices mockup that Settings > Devices shows in the demo build. The
/// menu at the top of the section picks it, and `APASSY_DEMO_DEVICES` (1, 2a, 2b, 2c, 3a,
/// 3b, 3c, 3d, 3f, 3g, 3h, 4, 4b, 4c, 4d, 4d+, 5a, 5b, 5c, 6a, 6b, 6d, 7, 9a, 9b, 9c, 9d,
/// 9d+, 9e, R) sets it at
/// start and opens the section, for screenshots. 3e and 6c are frame 1 with the ⓘ of the switch or of Wi-Fi Pairing open.
/// Frames 2a–2c and 4b–4d are the steps of the add and move sheets, drawn by the same
/// functions as the vault build (`devices::link_step` and the others); "4d+" is frame 1
/// after "Later" of 4d, and "R" frame 1 with the Relay group (not in the mockup).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum DevicesFrame {
    /// 1: the route on, every kind of device, the Wi-Fi group.
    #[default]
    TailnetOn,
    /// 3a.
    NoTailscale,
    /// 3b.
    NotConnected,
    /// 3c.
    RouteOff,
    /// 3d.
    Starting,
    /// 3f.
    Locked,
    /// 3g.
    PortTaken,
    /// 3h.
    AddressChanged,
    /// 2a: the link of "Add an iPhone or a Mac…".
    AddLink,
    /// 2b: the safety words.
    AddWords,
    /// 2c: the device was added.
    Added,
    /// 4: the approvals go through Apassy relay.
    Move,
    /// 4b: the move sheet.
    MoveSheet,
    /// 4c: the approvals moved.
    Moved,
    /// 4d: the old entry is still on Apassy relay.
    OldEntry,
    /// After "Later" of 4d: the row in the This Mac group.
    OldEntryRow,
    /// 5a: Revoke an iPhone with a watch.
    RevokeIphone,
    /// 5b: Revoke another Mac.
    RevokeMac,
    /// 5c: after the revoke.
    AfterRevoke,
    /// 6a: the Wi-Fi notice with the route on.
    NoticeTailnet,
    /// 6b: the Wi-Fi notice without the route.
    NoticeRelay,
    /// 6d: the Wi-Fi group of the next release.
    NextVersion,
    /// 7: first run, no Tailscale.
    FirstRun,
    /// Frame 1 with the Relay group: the questions through the relay, the feed, the
    /// other Macs, and the end of the free approvals.
    Relay,
    /// 9a: the approvals through Apassy relay, both moves offered.
    ConnectBoth,
    /// 9b: the node on Apassy Connect without the tailnet route.
    ConnectOnly,
    /// 9c: the move to Apassy Connect waits for its first approval.
    ConnectPending,
    /// 9d: the hosted relay ended the free approvals (`410 free_connect_ended`).
    RelayEnded,
    /// 9d+: the hosted relay serves Apassy Connect only (`410 hosted_retired`).
    RelayRetired,
    /// 9e: a device that reaches this Mac through Apassy Connect.
    ViaConnect,
}

impl DevicesFrame {
    const ALL: [Self; 30] = [
        Self::TailnetOn,
        Self::AddLink,
        Self::AddWords,
        Self::Added,
        Self::NoTailscale,
        Self::NotConnected,
        Self::RouteOff,
        Self::Starting,
        Self::Locked,
        Self::PortTaken,
        Self::AddressChanged,
        Self::Move,
        Self::MoveSheet,
        Self::Moved,
        Self::OldEntry,
        Self::OldEntryRow,
        Self::RevokeIphone,
        Self::RevokeMac,
        Self::AfterRevoke,
        Self::NoticeTailnet,
        Self::NoticeRelay,
        Self::NextVersion,
        Self::FirstRun,
        Self::Relay,
        Self::ConnectBoth,
        Self::ConnectOnly,
        Self::ConnectPending,
        Self::RelayEnded,
        Self::RelayRetired,
        Self::ViaConnect,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::TailnetOn => "Frame 1: Tailnet On",
            Self::NoTailscale => "Frame 3a: No Tailscale",
            Self::NotConnected => "Frame 3b: Not Connected",
            Self::RouteOff => "Frame 3c: Route Off",
            Self::Starting => "Frame 3d: Starting",
            Self::Locked => "Frame 3f: Vault Locked",
            Self::PortTaken => "Frame 3g: Port in Use",
            Self::AddressChanged => "Frame 3h: Address Changed",
            Self::AddLink => "Frame 2a: Add, the Link",
            Self::AddWords => "Frame 2b: Add, the Words",
            Self::Added => "Frame 2c: Added",
            Self::Move => "Frame 4: Move Approvals",
            Self::MoveSheet => "Frame 4b: Move Sheet",
            Self::Moved => "Frame 4c: Approvals Moved",
            Self::OldEntry => "Frame 4d: Old Entry on Relay",
            Self::OldEntryRow => "Frame 4d+: After Later",
            Self::RevokeIphone => "Frame 5a: Revoke iPhone",
            Self::RevokeMac => "Frame 5b: Revoke Mac",
            Self::AfterRevoke => "Frame 5c: After Revoke",
            Self::NoticeTailnet => "Frame 6a: Notice, Tailnet",
            Self::NoticeRelay => "Frame 6b: Notice, Relay",
            Self::NextVersion => "Frame 6d: Next Version",
            Self::FirstRun => "Frame 7: First Run",
            Self::Relay => "Frame R: Relay Group",
            Self::ConnectBoth => "Frame 9a: Both Moves",
            Self::ConnectOnly => "Frame 9b: Connect Without Tailscale",
            Self::ConnectPending => "Frame 9c: Waits for the First Approval",
            Self::RelayEnded => "Frame 9d: Free Approvals Ended",
            Self::RelayRetired => "Frame 9d+: Hosted Relay Retired",
            Self::ViaConnect => "Frame 9e: A Device Through Connect",
        }
    }

    /// The frame of `APASSY_DEMO_DEVICES`.
    fn from_env() -> Option<Self> {
        let value = std::env::var("APASSY_DEMO_DEVICES").ok()?;
        let value = value.trim();
        Self::ALL.into_iter().find(|frame| {
            let number = frame.label().trim_start_matches("Frame ");
            number.split(':').next() == Some(value)
        })
    }
}

/// "Now" of the Devices fixtures: Tue 3 Nov 2026, 14:20 UTC, as the mockup.
const DEVICES_NOW: u64 = 1_793_715_600;
/// 12 Sep 2026: the Wi-Fi iPhone paired.
const WIFI_PAIRED: u64 = 1_789_203_600;

fn demo_device(
    name: &str,
    kind: super::devices::Kind,
    role: &str,
    route: Option<super::devices::Route>,
    ago: Option<u64>,
    target: super::devices::Target,
) -> super::devices::DeviceEntry {
    super::devices::DeviceEntry {
        name: name.to_owned(),
        kind,
        roles: vec![role.to_owned()],
        route,
        last_contact: ago.map(|ago| DEVICES_NOW - ago),
        target,
        failed: false,
    }
}

fn node_target(id: u64) -> super::devices::Target {
    super::devices::Target::Node {
        team_id: "t_demo".to_owned(),
        id,
        uuid: None,
    }
}

fn hosted_target(uuid: &str) -> super::devices::Target {
    super::devices::Target::Hosted {
        team_id: "t_demo".to_owned(),
        id: None,
        uuid: uuid.to_owned(),
    }
}

/// The view of a frame of the Devices mockup. Synthetic data only.
pub(crate) fn devices_view(frame: DevicesFrame) -> super::devices::DevicesView {
    use super::devices::{
        Address, DevicesView, Kind, NodeProblem, NodeState, OtherMacsRow, Questions, RelayView,
        Route, Target, WifiDevice, WifiEnd, WifiView,
    };
    let address = |ipv4: &str| Address {
        ipv4: ipv4.to_owned(),
        origin: format!("https://{ipv4}:8444"),
        port: 8444,
        words: Some("harbor lemon quartz otter cedar mango".to_owned()),
    };
    let moving = matches!(
        frame,
        DevicesFrame::Move
            | DevicesFrame::MoveSheet
            | DevicesFrame::ConnectBoth
            | DevicesFrame::ConnectOnly
            | DevicesFrame::ConnectPending
            | DevicesFrame::RelayEnded
            | DevicesFrame::RelayRetired
    );
    let first_run = frame == DevicesFrame::FirstRun;
    let (approvals, phone_route) = if moving {
        ("Asks for approvals", Route::Relay)
    } else if frame == DevicesFrame::ViaConnect {
        ("Hosts approvals", Route::Connect)
    } else {
        ("Hosts approvals", Route::Mac)
    };
    // This computer: a Mac mini on macOS, a Linux desktop on Linux (its kind reads
    // "Computer" there). The other Macs of the fixture are Macs on both.
    let this_name = if cfg!(target_os = "linux") {
        "Linux desktop"
    } else {
        "Mac mini (office)"
    };
    let this_mac = demo_device(
        this_name,
        Kind::Mac,
        if first_run {
            "Asks for approvals"
        } else {
            approvals
        },
        None,
        Some(0),
        Target::ThisMac,
    );
    let phone_target = |id, uuid| {
        if moving {
            hosted_target(uuid)
        } else {
            node_target(id)
        }
    };
    let mut devices = vec![this_mac];
    if !first_run {
        devices.extend([
            demo_device(
                "Alex's iPhone",
                Kind::Iphone,
                "Approves runs",
                Some(phone_route),
                Some(10),
                phone_target(2, "iphone"),
            ),
            demo_device(
                "Alex's Apple Watch",
                Kind::Watch,
                "Sees requests",
                Some(phone_route),
                Some(if moving { 9 * 60 } else { 4 * 60 }),
                phone_target(3, "watch"),
            ),
            demo_device(
                "MacBook Pro",
                Kind::Mac,
                "Syncs Personal",
                Some(Route::Relay),
                Some(2 * 60),
                hosted_target("macbook"),
            ),
            demo_device(
                "Mac mini (studio)",
                Kind::Mac,
                "Syncs Personal",
                Some(Route::Relay),
                Some(3_600),
                hosted_target("studio"),
            ),
        ]);
        if !moving {
            devices.push(demo_device(
                "build-box",
                Kind::LinuxNode,
                "Syncs Acme team",
                Some(Route::Tailnet),
                Some(5 * 60),
                Target::Linux {
                    vault: "acme".to_owned(),
                    team_id: "t_acme".to_owned(),
                    device_id: 7,
                    origin: "https://100.88.4.20:8444".to_owned(),
                },
            ));
        }
    }
    if frame == DevicesFrame::AfterRevoke {
        devices.retain(|device| device.kind != Kind::Iphone && device.kind != Kind::Watch);
        devices.retain(|device| device.name != "Mac mini (studio)");
        for device in &mut devices {
            device.last_contact = None;
        }
        if let Some(this_mac) = devices.first_mut() {
            this_mac.last_contact = Some(DEVICES_NOW);
        }
    }
    let (node, problem) = match frame {
        DevicesFrame::NoTailscale | DevicesFrame::FirstRun => (NodeState::Missing, None),
        DevicesFrame::NotConnected => (NodeState::NotConnected, None),
        DevicesFrame::RouteOff | DevicesFrame::NoticeRelay | DevicesFrame::ConnectOnly => {
            (NodeState::Off, None)
        }
        DevicesFrame::Starting => (NodeState::On { address: None }, None),
        DevicesFrame::Locked => (NodeState::Locked, None),
        DevicesFrame::PortTaken => (
            NodeState::On { address: None },
            Some(NodeProblem::PortTaken {
                port: 8444,
                before_pairing: true,
            }),
        ),
        DevicesFrame::AddressChanged => (
            NodeState::On {
                address: Some(address("100.77.20.5")),
            },
            Some(NodeProblem::AddressChanged),
        ),
        _ => (
            NodeState::On {
                address: Some(address("100.101.7.12")),
            },
            None,
        ),
    };
    let wifi = (!moving && !first_run).then(|| WifiView {
        listening: true,
        starting: false,
        failed: None,
        devices: vec![WifiDevice {
            id: "wifi-phone".to_owned(),
            name: "Alex's iPhone".to_owned(),
            paired_at: WIFI_PAIRED,
            last_seen_at: Some(DEVICES_NOW - 3 * 3_600),
        }],
        end: if frame == DevicesFrame::NextVersion {
            WifiEnd::NextVersion
        } else {
            WifiEnd::TwoVersions
        },
    });
    let ended = match frame {
        DevicesFrame::RelayEnded => Some((super::devices::Ended::Free, "0.5.20".to_owned())),
        DevicesFrame::RelayRetired => Some((super::devices::Ended::Retired, "0.5.20".to_owned())),
        _ => None,
    };
    let relay = (frame == DevicesFrame::Relay || ended.is_some()).then(|| RelayView {
        questions: if ended.is_some() {
            Questions::Ended
        } else {
            Questions::On
        },
        feed_shown: ended.is_none(),
        other_macs: Some(OtherMacsRow {
            relay: true,
            removed: false,
        }),
        free_end: ended.is_none().then(|| "0.5.20".to_owned()),
        can_move: ended.is_some(),
        can_move_connect: ended.is_some(),
        ended,
    });
    DevicesView {
        node,
        problem,
        locked: frame == DevicesFrame::Locked,
        // As the vault build: the same choices for this group and the Relay group.
        can_move: matches!(
            frame,
            DevicesFrame::Move
                | DevicesFrame::MoveSheet
                | DevicesFrame::ConnectBoth
                | DevicesFrame::RelayEnded
                | DevicesFrame::RelayRetired
        ),
        can_move_connect: matches!(
            frame,
            DevicesFrame::ConnectBoth
                | DevicesFrame::ConnectOnly
                | DevicesFrame::RelayEnded
                | DevicesFrame::RelayRetired
        ),
        connect_pending: frame == DevicesFrame::ConnectPending,
        devices,
        notes: Vec::new(),
        wifi,
        relay,
        old_relay_entry: frame == DevicesFrame::OldEntryRow,
        now: DEVICES_NOW,
    }
}

/// The link of frames 2a and 4b: the node origin of the mockup, 9:41 left.
fn demo_link_step() -> super::devices::LinkStep {
    super::devices::LinkStep {
        route: super::devices::Route::Mac,
        shown: Some(super::devices::shown_link(
            "https://100.101.7.12:8444/link#apassy_lnk_demo",
        )),
        seconds_left: Some(9 * 60 + 41),
    }
}

/// A synthetic QR code of 29 modules: the three finder patterns and a fixed scatter, in
/// the fixed QR colors. It encodes nothing.
fn demo_qr(ui: &mut egui::Ui, size: f32) {
    use super::kit::fixed;
    const WIDTH: usize = 29;
    const QUIET: usize = 2;
    let total = WIDTH + 2 * QUIET;
    let unit = (size / total as f32).floor().max(1.0);
    let side = unit * total as f32;
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(side), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 0, fixed::QR_LIGHT);
    let finder = |x: usize, y: usize| {
        [(0, 0), (WIDTH - 7, 0), (0, WIDTH - 7)]
            .iter()
            .find_map(|&(left, top)| {
                (x >= left && x < left + 7 && y >= top && y < top + 7).then(|| {
                    let (dx, dy) = (x - left, y - top);
                    let ring = dx == 0 || dy == 0 || dx == 6 || dy == 6;
                    let core = (2..=4).contains(&dx) && (2..=4).contains(&dy);
                    ring || core
                })
            })
    };
    for y in 0..WIDTH {
        for x in 0..WIDTH {
            let dark = finder(x, y).unwrap_or((x * 7 + y * 13 + x * y) % 5 < 2);
            if dark {
                let min =
                    rect.min + egui::vec2((x + QUIET) as f32 * unit, (y + QUIET) as f32 * unit);
                painter.rect_filled(
                    egui::Rect::from_min_size(min, egui::Vec2::splat(unit)),
                    0,
                    fixed::QR_DARK,
                );
            }
        }
    }
}

/// Frames 2a–2c and 4b–4d: the steps of the add and move sheets, from fixtures. Returns
/// the frame that the choice leads to.
fn demo_step_sheet(ctx: &egui::Context, frame: DevicesFrame) -> Option<DevicesFrame> {
    use super::devices::{self, Kind, MovePhase, Route, StepChoice};
    let mut choice = None;
    let response = kit::sheet(ctx, "demo-devices-step", 440.0, |ui| {
        choice = match frame {
            DevicesFrame::AddLink => {
                devices::link_step(ui, &demo_link_step(), |ui| demo_qr(ui, 180.0), |_| {})
            }
            DevicesFrame::AddWords => devices::join_step(
                ui,
                "Alex's iPhone",
                Kind::Iphone,
                "amber falcon",
                Route::Mac,
                true,
                |_| {},
            ),
            DevicesFrame::Added => devices::added_step(ui, "Alex's iPhone", false, true, |_| {}),
            DevicesFrame::MoveSheet => devices::move_step(
                ui,
                "Alex's iPhone",
                MovePhase::Scan,
                Some(&demo_link_step()),
                |ui| demo_qr(ui, 140.0),
                |_| {},
            ),
            DevicesFrame::Moved => devices::moved_step(
                ui,
                &["Alex's iPhone".to_owned()],
                true,
                &["Alex's Apple Watch".to_owned()],
            ),
            DevicesFrame::OldEntry => devices::old_entry_step(ui, false),
            _ => None,
        };
    });
    let choice = choice.or(response.escape.then_some(StepChoice::Cancel))?;
    Some(match (frame, choice) {
        (DevicesFrame::AddLink, StepChoice::Copy) => {
            ctx.copy_text("https://100.101.7.12:8444/link#apassy_lnk_demo".to_owned());
            return None;
        }
        (DevicesFrame::AddWords, StepChoice::Confirm) => DevicesFrame::Added,
        (DevicesFrame::MoveSheet, StepChoice::Cancel) => DevicesFrame::Move,
        (DevicesFrame::OldEntry, StepChoice::Later) => DevicesFrame::OldEntryRow,
        _ => DevicesFrame::TailnetOn,
    })
}

/// The status line of Settings > Devices in the demo build.
pub(super) fn devices_status(app: &DesktopApp) -> String {
    devices_view(app.ui.devices.demo).status_line()
}

/// Pick a frame of the Devices mockup, with its sheet.
fn select_devices_frame(app: &mut DesktopApp, frame: DevicesFrame) {
    use super::devices::{DevicesSheet, Kind, WatchChoice};
    app.ui.devices.demo = frame;
    let view = devices_view(frame);
    let find = |kind: Kind| view.devices.iter().position(|device| device.kind == kind);
    app.ui.devices.sheet = match frame {
        DevicesFrame::RevokeIphone => find(Kind::Iphone).map(|index| DevicesSheet::Revoke {
            device: view.devices[index].clone(),
            vault: None,
            watches: find(Kind::Watch)
                .map(|index| WatchChoice {
                    index,
                    name: view.devices[index].name.clone(),
                    revoke: true,
                })
                .into_iter()
                .collect(),
        }),
        DevicesFrame::RevokeMac => view
            .devices
            .iter()
            .find(|device| device.name == "MacBook Pro")
            .map(|device| DevicesSheet::Revoke {
                device: device.clone(),
                vault: Some("Personal".to_owned()),
                watches: Vec::new(),
            }),
        DevicesFrame::NoticeTailnet => Some(DevicesSheet::WifiNotice { tailnet: true }),
        DevicesFrame::NoticeRelay => Some(DevicesSheet::WifiNotice { tailnet: false }),
        _ => None,
    };
    if frame == DevicesFrame::AfterRevoke {
        app.set_ok("Alex's iPhone revoked");
    }
}

/// Settings > Devices in the demo build: the frame menu and the frame.
pub(super) fn devices_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::devices::{self, Action, Kind, rows};
    ui.add_space(8.0);
    let mut frame = app.ui.devices.demo;
    let options: Vec<(DevicesFrame, String)> = DevicesFrame::ALL
        .iter()
        .map(|frame| (*frame, frame.label().to_owned()))
        .collect();
    let shown = frame.label();
    kit::picker(ui, "demo-devices-frame", &mut frame, &options, shown, 240.0);
    if frame != app.ui.devices.demo {
        select_devices_frame(app, frame);
    }
    let view = devices_view(app.ui.devices.demo);
    let action = devices::draw(ui, &view, |g| {
        g.labeled("Notifications", rows::value("On"));
    });
    let next = match action {
        Some(Action::SetRoute(true)) => Some(DevicesFrame::TailnetOn),
        Some(Action::SetRoute(false)) => Some(DevicesFrame::RouteOff),
        Some(Action::CheckAgain) => Some(DevicesFrame::TailnetOn),
        Some(Action::Revoke(index)) => match view.devices.get(index).map(|device| device.kind) {
            Some(Kind::Iphone) => Some(DevicesFrame::RevokeIphone),
            Some(Kind::Mac) => Some(DevicesFrame::RevokeMac),
            _ => None,
        },
        Some(Action::Copy(origin)) => {
            ui.ctx().copy_text(origin);
            None
        }
        Some(Action::Add) => Some(DevicesFrame::AddLink),
        Some(Action::Move | Action::PairAgain) => Some(DevicesFrame::MoveSheet),
        _ => None,
    };
    if let Some(next) = next {
        select_devices_frame(app, next);
    }
}

/// The sheets of the Devices frames 2a–2c, 4b–4d, 5a, 5b, 6a, and 6b, and
/// `APASSY_DEMO_DEVICES`.
pub(super) fn devices_overlays(app: &mut DesktopApp, ctx: &egui::Context) {
    use super::devices::{Choice, DevicesSheet};
    use std::sync::Once;
    static FROM_ENV: Once = Once::new();
    FROM_ENV.call_once(|| {
        if let Some(frame) = DevicesFrame::from_env() {
            super::settings_view::open(app, super::settings_view::SettingsSection::Devices);
            select_devices_frame(app, frame);
        }
    });
    let frame = app.ui.devices.demo;
    if matches!(
        frame,
        DevicesFrame::AddLink
            | DevicesFrame::AddWords
            | DevicesFrame::Added
            | DevicesFrame::MoveSheet
            | DevicesFrame::Moved
            | DevicesFrame::OldEntry
    ) {
        if let Some(next) = demo_step_sheet(ctx, frame) {
            select_devices_frame(app, next);
        }
        return;
    }
    let Some(sheet) = app.ui.devices.sheet.clone() else {
        return;
    };
    let (choice, escape, sheet) = match sheet {
        DevicesSheet::Revoke {
            device,
            vault,
            mut watches,
        } => {
            let (choice, escape) =
                super::devices::revoke_sheet(ctx, &device, vault.as_deref(), &mut watches);
            (
                choice,
                escape,
                DevicesSheet::Revoke {
                    device,
                    vault,
                    watches,
                },
            )
        }
        DevicesSheet::WifiNotice { tailnet } => {
            let (choice, escape) = super::devices::wifi_notice(ctx, tailnet);
            (choice, escape, DevicesSheet::WifiNotice { tailnet })
        }
        DevicesSheet::Linux { .. } => (Some(Choice::Cancel), false, sheet),
    };
    match choice.or(escape.then_some(Choice::Cancel)) {
        Some(Choice::Confirm) => select_devices_frame(app, DevicesFrame::AfterRevoke),
        Some(_) => select_devices_frame(app, DevicesFrame::TailnetOn),
        None => app.ui.devices.sheet = Some(sheet),
    }
}

// ---- Agents and Decisions of the Bouncer section in the demo. ----

/// The MCP address of the demo (the mockup's).
const DEMO_ADDRESS: &str = "https://rafals-mac-mini.tail71fdd0.ts.net:8443/mcp";

/// The remote access block of a frame.
fn demo_access(frame: BouncerFrame) -> super::agents_page::AccessView {
    use super::agents_page::{AccessProblem, AccessView};
    let (on, problem) = match frame {
        BouncerFrame::FirstRun => (false, None),
        BouncerFrame::NotInstalled => (false, Some(AccessProblem::NotInstalled)),
        BouncerFrame::NotConnected => (false, Some(AccessProblem::NotConnected)),
        // The mockup's frames show the switch disabled: the owner tries to turn it on.
        BouncerFrame::PolicyBlocks => (false, Some(AccessProblem::Policy { link: None })),
        BouncerFrame::PortTaken => (
            false,
            Some(AccessProblem::PortTaken {
                port: 8443,
                alternative: Some(10000),
            }),
        ),
        _ => (true, None),
    };
    AccessView {
        on,
        address: on.then(|| DEMO_ADDRESS.to_owned()),
        problem,
        no_remote_agents: frame == BouncerFrame::NoRemoteAgentYet,
        reading: false,
        connect: None,
    }
}

/// What an agent of this Mac of the demo can see (frame 4: Grok Bot; 13a: nothing yet).
fn demo_facts(
    frame: BouncerFrame,
    agent: &super::bouncer::AgentRef,
    now: u64,
) -> Option<super::agents_page::LocalFacts> {
    use super::agents_page::{CanSee, LocalFacts, SeeKind, SeeRow};
    let super::bouncer::AgentRef::Local(id) = agent else {
        return None;
    };
    let name = match *id {
        1 => "Claude Code",
        2 => "Codex",
        DEMO_GROK => "Grok Bot",
        4 => "T3 Code",
        _ => "Old agent",
    };
    let remote = *id == DEMO_GROK;
    let row = |item, name: &str, kind| SeeRow {
        item,
        name: name.to_owned(),
        kind,
    };
    let can_see = match (remote, frame) {
        (true, BouncerFrame::NewRemoteAgent) => CanSee::default(),
        (true, _) => CanSee {
            all: false,
            rows: vec![
                row(11, "httpbin test token", SeeKind::Only),
                row(12, "GitHub token", SeeKind::Only),
                row(13, "Stripe test", SeeKind::Only),
                row(14, "Stripe live", SeeKind::Never),
            ],
        },
        (false, _) => CanSee {
            all: true,
            rows: vec![row(14, "Stripe live", SeeKind::Never)],
        },
    };
    Some(LocalFacts {
        id: *id,
        name: name.to_owned(),
        remote,
        revoked: *id == 9,
        created_at: if frame == BouncerFrame::NewRemoteAgent {
            now.saturating_sub(60)
        } else {
            now.saturating_sub(6 * 86_400)
        },
        token_end: (!remote).then_some(now + 60 * 86_400),
        oauth: remote,
        can_see,
        note: String::new(),
    })
}

/// Bouncer > Agents in the demo: the page of the frame, or the open agent page.
pub(super) fn agents_wide(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::agents_page::{self, Action, AgentPage, AgentsView};
    let now = demo_now();
    let offset = super::bouncer::local_offset(now);
    let frame = app.ui.demo_frame;
    let mut action = None;
    if let Some(agent) = app.ui.agent_page.open.clone() {
        let facts = demo_facts(frame, &agent, now);
        let Some(page) = AgentPage::of(&app.ui.bouncer.data, &agent, facts.as_ref(), now, offset)
        else {
            app.ui.agent_page.open = None;
            return;
        };
        columns::wide_toolbar(ui, "", "", |ui| frame_picker(app, ui));
        if columns::wide_inset(ui, |ui| kit::back_link(ui, "Agents")) {
            action = Some(Action::Back);
        }
        columns::wide_body(ui, ("demo-agent", &agent), |ui| {
            if let Some(chosen) = agents_page::draw_agent(ui, &page, now) {
                action = Some(chosen);
            }
        });
    } else {
        let view = AgentsView::of(
            &app.ui.bouncer.data,
            &app.ui.activity_scope,
            Some(demo_access(frame)),
            now,
            offset,
        );
        let subtitle = if view.count == 0 {
            String::new()
        } else {
            columns::count_label(view.count, "agent", "agents")
        };
        columns::wide_toolbar(ui, "Agents", &subtitle, |ui| frame_picker(app, ui));
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
        columns::wide_body(ui, "demo-agents", |ui| {
            if let Some(chosen) = agents_page::draw_page(ui, &view, &app.ui.agent_page) {
                action = Some(chosen);
            }
        });
    }
    let Some(action) = action else {
        return;
    };
    match action {
        Action::Open(agent) => app.ui.agent_page.open = Some(agent),
        Action::Back => app.ui.agent_page.open = None,
        Action::ToggleDisconnected(scope) => {
            if !app.ui.agent_page.disconnected.remove(&scope) {
                app.ui.agent_page.disconnected.insert(scope);
            }
        }
        Action::ShowAllEnvironments => {
            app.ui.activity_scope.device = super::bouncer::DeviceScope::All;
        }
        Action::ShowAllProjects => app.ui.activity_scope.project = None,
        Action::ShowInLogs { env, name } => {
            app.ui.activity_scope.device = env;
            super::logs::show_agent(app, Some(name));
            super::sidebar::navigate(app, crate::desktop::Place::Logs);
        }
        Action::CopyAddress(address) => {
            ui.ctx().copy_text(address);
            app.set_ok("The MCP address is copied.");
        }
        _ => app.set_note("The demo changes nothing. The vault build does this."),
    }
}

/// The keys of the two cards of the demo in Decisions.
const DEMO_CONNECT_KEY: u64 = 1;
/// The redirect line of the demo connect request (`crate::node::connect_returns_to`).
const DEMO_RETURNS_TO: &str = "Returns to grok.com";
const DEMO_CLOUD_KEY: u64 = 2;

/// The list column of Decisions in the demo: what waits (frame 5), then History.
pub(super) fn decisions_list(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::decisions_bouncer::{self as cards, HistoryAction, HistoryView};
    let ctx = ui.ctx().clone();
    bouncer_refresh(app, &ctx);
    let now = demo_now();
    let offset = super::bouncer::local_offset(now);
    let totals = app.ui.bouncer.data.totals(&app.ui.activity_scope.device);
    let subtitle = totals.runs.map_or_else(String::new, |_| {
        format!(
            "{} by you · {} automatic this week",
            totals.asked, totals.allowed_by_bouncer
        )
    });
    columns::list_toolbar(ui, "Decisions", &subtitle, |_| {});
    columns::list_inset(ui, |ui| {
        super::scope_bar::bouncer_bar(
            ui,
            &mut app.ui.activity_scope,
            &app.ui.bouncer.data.environments,
            &app.ui.bouncer.data.projects,
            now,
            offset,
        )
    });
    let waiting = app.ui.demo_frame == BouncerFrame::AllEnvironments;
    let view = HistoryView::of(
        &app.ui.bouncer.data,
        &app.ui.activity_scope,
        &app.ui.decision_history,
        now,
        offset,
    );
    let selected = app.ui.decision_history.selected;
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("demo-decisions")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if waiting {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(
                        kit::medium("Waiting  2", Font::Callout).color(kit::palette().secondary),
                    );
                });
                egui::Frame::NONE
                    .inner_margin(egui::Margin::symmetric(8, 2))
                    .show(ui, |ui| {
                        // Frame 5: the cloud badge of a remote agent and the time left at
                        // the right. The red dot marks production only: httpbin test
                        // token is Development.
                        let mark = cards::Mark::Agent("Grok Bot".to_owned());
                        for (key, title, subtitle, left, dot) in [
                            (
                                DEMO_CONNECT_KEY,
                                "Grok Bot wants to connect",
                                "Mac mini (office)",
                                "4:31",
                                false,
                            ),
                            (
                                DEMO_CLOUD_KEY,
                                "httpbin test token",
                                "Grok Bot · Mac mini (office)",
                                "4:02",
                                false,
                            ),
                        ] {
                            let row = cards::decision_row(
                                ui,
                                &cards::DecisionRow {
                                    mark: &mark,
                                    remote: true,
                                    title,
                                    subtitle,
                                    production: dot,
                                    left: Some(left),
                                    selected: selected == Some(key),
                                },
                            );
                            if row.clicked() {
                                action = Some(HistoryAction::Select(key));
                            }
                        }
                    });
            }
            if let Some(chosen) =
                cards::draw_history(ui, &view, &app.ui.decision_history, !waiting, &[])
            {
                action = Some(chosen);
            }
        });
    match action {
        Some(HistoryAction::Select(key)) => app.ui.decision_history.selected = Some(key),
        Some(HistoryAction::Filter(filter)) => {
            app.ui.decision_history.filter = filter;
            app.ui.decision_history.selected = None;
        }
        Some(HistoryAction::Agent(agent)) => {
            app.ui.decision_history.agent = agent;
            app.ui.decision_history.selected = None;
        }
        None => {}
    }
}

/// The detail of Decisions in the demo: the connect card, the cloud run card, a run of
/// History, or the week.
pub(super) fn decisions_detail(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::decisions_bouncer::{self as cards, CardAnswer};
    let now = demo_now();
    columns::detail_toolbar(ui, |ui| frame_picker(app, ui));
    let answer = match app.ui.decision_history.selected {
        Some(DEMO_CONNECT_KEY) => {
            let answer = cards::card_bar(ui, "demo-connect", "Allow", true);
            columns::detail_body(ui, "demo-connect", |ui| {
                cards::connect_card(
                    ui,
                    &cards::ConnectCard {
                        name: "Grok Bot".to_owned(),
                        mac: "Mac mini (office)".to_owned(),
                        left: "4:31".to_owned(),
                        code: "K7Q-4MD".to_owned(),
                        returns_to: DEMO_RETURNS_TO.to_owned(),
                        local: false,
                    },
                );
            });
            answer
        }
        Some(DEMO_CLOUD_KEY) => {
            let answer = cards::card_bar(ui, "demo-cloud", "Allow Once", true);
            columns::detail_body(ui, "demo-cloud", |ui| {
                cards::cloud_card(
                    ui,
                    &cards::CloudCard {
                        agent: "Grok Bot".to_owned(),
                        credential: "httpbin test token".to_owned(),
                        environment: Some(("Development".to_owned(), false)),
                        mac: "Mac mini (office)".to_owned(),
                        left: "4:02".to_owned(),
                        sends_to: "httpbin.org".to_owned(),
                        request: "Test my httpbin token with curl.".to_owned(),
                        command: "curl -H \"Authorization: Bearer $HTTPBIN_TOKEN\" $APASSY_BASE_HTTPBIN_TOKEN/bearer".to_owned(),
                    },
                );
            });
            answer
        }
        Some(key) => {
            let event = cards::find(&app.ui.bouncer.data, &app.ui.activity_scope, key).cloned();
            columns::detail_body(ui, ("demo-past", key), |ui| match &event {
                Some(event) => cards::history_detail(ui, event, None, now),
                None => demo_week(app, ui),
            });
            None
        }
        None => {
            columns::detail_body(ui, "demo-week", |ui| {
                demo_week(app, ui);
                if app.ui.demo_frame == BouncerFrame::AllEnvironments {
                    ui.add_space(12.0);
                    draw_activity(app, ui);
                }
            });
            None
        }
    };
    if let Some(answer) = answer {
        app.ui.decision_history.selected = None;
        app.set_note(match answer {
            CardAnswer::Allow => "The demo allows nothing. The vault build asks for Touch ID.",
            CardAnswer::Deny => "The demo denies nothing. The vault build does.",
        });
    }
}

/// The week of Decisions in the demo (frames 9c and 10a): "All clear" when nothing
/// waits, the totals, the environments, and the most active agents.
fn demo_week(app: &DesktopApp, ui: &mut egui::Ui) {
    let data = &app.ui.bouncer.data;
    let scope = &app.ui.activity_scope.device;
    let first_run = !data.has_agents;
    let now = demo_now();
    // Frames 1–6 have two requests waiting: no "All clear" over them.
    let waiting = app.ui.demo_frame == BouncerFrame::AllEnvironments;
    if !first_run && !waiting {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            kit::paint_icon_in(ui, Icon::CheckCircle, 16.0, Tone::Good.mark());
            ui.label(kit::medium("All clear", Font::Body).color(kit::palette().label));
        });
        ui.add_space(14.0);
    }
    ui.label(kit::text("This week", Font::Title3).color(kit::palette().label));
    ui.add_space(6.0);
    let totals = data.totals(scope);
    let width = ((ui.available_width() - 8.0) / 2.0).floor();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        kit::stat_tile(
            ui,
            width,
            "By you",
            &totals.asked.to_string(),
            "Questions you answered",
        );
        kit::stat_tile(
            ui,
            width,
            "Automatic",
            &totals.allowed_by_bouncer.to_string(),
            "Allowed without a question",
        );
    });
    ui.add_space(20.0);
    if first_run {
        return;
    }
    kit::section(ui, Some("Environments"), None, |s| {
        for env in data.environments_in(scope) {
            let value = data.stats.get(&env.scope).map_or_else(
                || "No counts".to_owned(),
                |stats| {
                    let counts = format!(
                        "{} by you · {} automatic",
                        stats.asked, stats.allowed_by_bouncer
                    );
                    match env.reported_at.filter(|_| env.stale(now)) {
                        Some(at) => format!("{counts} · {}", super::bouncer::day_month(at, 0)),
                        None => counts,
                    }
                },
            );
            s.labeled(&env.name, value);
        }
    });
    let mut agents = data.agents_in(&app.ui.activity_scope);
    agents.truncate(3);
    kit::section(ui, Some("Most active"), None, |s| {
        for agent in agents {
            s.labeled(
                &agent.name,
                format!("{} · {}", agent.runs.unwrap_or(0), agent.env_name),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame 4: "Denied" of each agent page counts at least the denied runs it lists
    /// (Grok Bot: 2, as the mockup), and frame 1 still lists the mockup's three items of
    /// "Needs attention".
    #[test]
    fn each_agent_page_counts_the_denied_runs_that_it_lists() {
        let now = 1_790_000_000;
        for frame in BouncerFrame::ALL {
            let data = bouncer_data(frame, now);
            for line in &data.agents {
                let listed = data
                    .runs_of(line, usize::MAX, now)
                    .iter()
                    .filter(|event| event.outcome.denied())
                    .count() as u64;
                assert!(
                    line.not_allowed >= listed,
                    "{frame:?} {}: Denied {} < {listed} listed",
                    line.name,
                    line.not_allowed
                );
            }
        }
        let data = bouncer_data(BouncerFrame::AllEnvironments, now);
        let grok = data
            .agents
            .iter()
            .find(|line| line.name == "Grok Bot")
            .expect("Grok Bot");
        assert_eq!(grok.not_allowed, 2);
        let titles: Vec<String> = data
            .attention(&super::super::bouncer::ActivityScope::default(), now)
            .iter()
            .map(super::super::bouncer::Attention::title)
            .collect();
        assert_eq!(
            titles,
            [
                "MacBook Pro not reporting",
                "Stripe live used 3 times",
                "Codex asks often",
            ]
        );
    }
}
