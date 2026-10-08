//! The in-memory demo build (`--features desktop` without `vault`). It uses the same
//! kit as the vault build. Values are synthetic, "Open vault" is not authentication,
//! and the rule interpreter is a fixture.

use eframe::egui::{self, Align, Label, Layout};

use super::kit::{self, Font, Icon, Size, Style, Tone};
use super::{Sheet, close_sheet, extra_label, kind_icon, kind_plural, meta_line};
use crate::contracts::{CredentialKind, Decision};
use crate::desktop::model::{
    AMBIGUOUS_SAMPLE_TEXT, CONFLICTING_SAMPLE_TEXT, DesktopModel, ExtraField, INTERPRETER_ID,
    ItemDetails, ItemDraft, SAMPLE_RULE_TEXT, UNSUPPORTED_SAMPLE_TEXT,
};
use crate::desktop::{DemoScenario, DesktopApp, DraftStatus, OwnerView, RequestStatus};

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

pub(super) fn draw_list(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if app.model.is_locked() {
        locked_state(ui, "Credentials");
        return;
    }
    let mut add = false;
    kit::page_header(
        ui,
        "Credentials",
        Some(
            "Five credential categories. This desktop assigns a fixed synthetic value. Real secrets are not valid input.",
        ),
        |ui| {
            add = kit::button_with(ui, Some(Icon::Plus), "Add", Style::Prominent, Size::Regular)
                .clicked();
        },
    );
    kit::text_input(
        ui,
        &mut app.search,
        "demo-search",
        "Search by name, project, service, or notes",
    );
    ui.add_space(18.0);
    let items = app.model.list_items(&app.search);
    if items.is_empty() {
        kit::note(ui, "No item matches.");
    }
    let mut open = None;
    for kind in CredentialKind::ALL {
        let group: Vec<_> = items.iter().filter(|item| item.kind == kind).collect();
        if group.is_empty() {
            continue;
        }
        kit::section(ui, Some(kind_plural(kind)), None, |s| {
            for item in group {
                let meta = meta_line(&item.project, &item.service);
                let subtitle = (!meta.is_empty()).then_some(meta.as_str());
                if s.nav(Some(kind_icon(kind)), &item.name, subtitle, None)
                    .clicked()
                {
                    open = Some(item.id.clone());
                }
            }
        });
    }
    if let Some(id) = open {
        app.select_item(id);
    }
    if add {
        app.add_form = ItemDraft::default();
        app.ui.sheet = Some(Sheet::AddItem { kind_chosen: false });
    }
}

fn selected(app: &DesktopApp) -> Option<(String, ItemDetails)> {
    let id = app.selected_item_id.clone()?;
    let details = app.model.item_details(&id).ok()?;
    Some((id, details))
}

pub(super) fn draw_detail(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::back_link(ui, "Credentials") {
        app.view = OwnerView::Vault;
        return;
    }
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
            ui.label(kit::text(&details.name, Font::Title).color(kit::LABEL));
            ui.label(kit::text(details.kind.label(), Font::Callout).color(kit::SECONDARY));
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
                        kit::LABEL
                    } else {
                        kit::SECONDARY
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
            s.labeled(label, kit::text(value, Font::Body).color(kit::SECONDARY));
        }
        s.labeled(
            "Revision",
            kit::text(details.revision.to_string(), Font::Body).color(kit::SECONDARY),
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
            app.view = OwnerView::Vault;
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
                            ui.label(kit::text(&clause.text, Font::Body).color(kit::LABEL));
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
                        kit::text(&examples.allow, Font::Callout).color(kit::SECONDARY),
                    );
                    s.labeled(
                        "Wait",
                        kit::text(&examples.ask, Font::Callout).color(kit::SECONDARY),
                    );
                    s.labeled(
                        "Deny",
                        kit::text(&examples.deny, Font::Callout).color(kit::SECONDARY),
                    );
                }
            },
        );
    }
    if let Some(rule) = app.model.active_rule().cloned() {
        kit::section(ui, Some("Active rule"), Some(&rule.original_text), |s| {
            s.labeled(
                "Status",
                kit::text(rule.status, Font::Body).color(kit::SECONDARY),
            );
            s.labeled(
                "Agent",
                kit::text(&rule.agent_name, Font::Body).color(kit::SECONDARY),
            );
            s.labeled(
                "Item",
                kit::text(&rule.item_name, Font::Body).color(kit::SECONDARY),
            );
            s.labeled(
                "Destination",
                kit::text(rule.destination, Font::Body).color(kit::SECONDARY),
            );
            s.labeled(
                "Denied",
                kit::text(rule.denied_destinations.join(", "), Font::Body).color(kit::SECONDARY),
            );
            s.labeled(
                "Operation",
                kit::text(rule.operation, Font::Body).color(kit::SECONDARY),
            );
            s.labeled(
                "Expiry",
                kit::text(
                    format!("{} ({})", rule.expiry_iso, rule.time_zone),
                    Font::Body,
                )
                .color(kit::SECONDARY),
            );
            s.labeled(
                "Uses",
                kit::text(
                    format!("{} of {}", rule.use_count, rule.usage_limit),
                    Font::Body,
                )
                .color(kit::SECONDARY),
            );
        });
    }
}

pub(super) fn draw_agents(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::page_header(
        ui,
        "Agents",
        Some(
            "You can connect a synthetic catalog agent. Revoke stops future sample use. This is not a verified isolation boundary.",
        ),
        |_| {},
    );
    let agents = app.model.catalog_agents();
    kit::section(ui, None, None, |s| {
        for agent in agents {
            s.row(|ui| {
                egui::Sides::new().shrink_left().wrap().show(
                    ui,
                    |ui| {
                        ui.vertical(|ui| {
                            ui.label(kit::medium(&agent.name, Font::Body).color(kit::LABEL));
                            kit::note(ui, &agent.summary);
                        });
                    },
                    |ui| {
                        if agent.connected {
                            if kit::small_button(ui, "Revoke agent", Style::Destructive).clicked() {
                                let message = format!("{} is revoked.", agent.name);
                                let result = app.model.revoke_agent(&agent.id);
                                let _ = app.apply(result, &message);
                            }
                            kit::tag(ui, agent.status_label, Tone::Good);
                        } else if kit::small_button(ui, "Connect agent", Style::Prominent).clicked()
                        {
                            let message = format!("{} is connected.", agent.name);
                            let result = app.model.connect_agent(&agent.id);
                            let _ = app.apply(result, &message);
                        }
                    },
                );
            });
        }
    });
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
                    ui.label(kit::medium(&alert.title, Font::Body).color(kit::LABEL));
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
                kit::paragraph(ui, &alert.message, Font::Callout, kit::LABEL);
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
                ui.add(Label::new(kit::text(&event.message, Font::Body).color(kit::LABEL)).wrap());
                kit::note(ui, format!("{} · {}", event.at_iso, event.kind));
            });
        }
    });
}
