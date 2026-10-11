//! Activity: runs that wait for the owner, access requests of agents (ADR 0012), the
//! inbox, and every agent request (goal items N1 to N4). A notification or "Mark as
//! seen" is never an approval.

use std::sync::Arc;

use eframe::egui::{self, CornerRadius, Frame, Label, Margin, Stroke};

use super::agents::{GrantForm, place_section};
use super::kit::{self, Font, Icon, Style, Tone};
use super::{Sheet, ask_owner_from_sheet, close_sheet};
use crate::broker::approvals::{
    ApprovalQueue, FirstUseDeclaration, FirstUseOffer, PendingRun, RememberOffer,
};
use crate::desktop::inbox::{self, InboxKind};
use crate::desktop::notify::Delivery;
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{BrokerState, DesktopApp, OwnerView};
use crate::vault::providers::{self, Suggestion};
use crate::vault::{
    AccessRequest, ActivityDecision, Declaration, EnvDelivery, Environment, ExecMode, GrantPlace,
};

/// How many inbox events the view shows.
const SHOWN_EVENTS: usize = 40;

/// The tab of the Activity view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Tab {
    #[default]
    Inbox,
    Requests,
}

fn approvals(app: &DesktopApp) -> Option<Arc<ApprovalQueue>> {
    match &app.broker {
        BrokerState::Running(handle) => Some(Arc::clone(handle.approvals())),
        _ => None,
    }
}

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    kit::page_header(
        ui,
        "Activity",
        Some("Runs that wait for you, requests that Apassy blocked, and every agent request."),
        |_| {},
    );
    // Each block can come or go when an agent asks. A scope keeps the IDs below it the
    // same, so the keyboard focus stays on its control.
    ui.scope(|ui| notifications_notice(app, ui));
    ui.scope(|ui| access_requests(app, ui));
    // A first-use form lives as long as its run waits.
    app.ui
        .first_use_forms
        .retain(|(run_id, _), _| pending.iter().any(|run| run.id == *run_id));
    ui.scope(|ui| {
        if !pending.is_empty() {
            ui.label(kit::text("Waiting for you", Font::Headline).color(kit::LABEL));
            ui.add_space(4.0);
            for run in pending {
                ui.push_id(("waiting-run", run.id), |ui| approval_card(app, ui, run));
                ui.add_space(14.0);
            }
            ui.add_space(6.0);
        }
    });
    let mut tab = app.ui.activity_tab;
    let picker = kit::segmented(
        ui,
        "activity-tab",
        &mut tab,
        &[(Tab::Inbox, "Inbox"), (Tab::Requests, "All requests")],
    );
    ui.ctx()
        .accesskit_node_builder(picker.id, |node| node.set_label("Activity list"));
    app.ui.activity_tab = tab;
    ui.add_space(12.0);
    match tab {
        Tab::Inbox => draw_inbox(app, ui, pending),
        Tab::Requests => draw_requests(app, ui),
    }
}

/// A short banner when macOS cannot show a notification. The controls are in Settings.
fn notifications_notice(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(center) = &app.owner.notifications else {
        return;
    };
    let view = center.view();
    if view.channel.can_deliver() {
        return;
    }
    let summary = view.channel.summary();
    let open = kit::notice(
        ui,
        Tone::Warning,
        "macOS notifications are off",
        Some(&summary),
        |ui| kit::small_button(ui, "Open Settings", Style::Link).clicked(),
    );
    if open {
        app.view = OwnerView::Settings;
        app.ui.settings_tab = super::settings::SettingsTab::Notifications;
    }
}

/// One run that waits for the owner, with its decision buttons.
/// Open access requests of agents (ADR 0012). "Give access…" opens a sheet with the
/// place and the decision; the owner check follows. "Deny" gives nothing.
fn access_requests(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let requests = app
        .owner_ui
        .session
        .access_requests(true)
        .unwrap_or_default();
    if requests.is_empty() {
        return;
    }
    let mut open = None;
    let mut deny = None;
    kit::section(
        ui,
        Some("Access requests"),
        Some(
            "The reason is the text of the agent. Give access only when it matches what you asked the agent to do.",
        ),
        |s| {
            for request in &requests {
                s.row(|ui| {
                    egui::Sides::new().shrink_left().wrap().show(
                        ui,
                        |ui| {
                            kit::dot(ui, Tone::Warning);
                            ui.label(
                                kit::medium(
                                    format!(
                                        "{} asks for {}",
                                        request.agent_name, request.item_name
                                    ),
                                    Font::Body,
                                )
                                .color(kit::LABEL),
                            );
                        },
                        |ui| {
                            if kit::small_button(ui, "Give access…", Style::Prominent).clicked() {
                                open = Some(request.clone());
                            }
                            if kit::small_button(ui, "Deny", Style::Bordered).clicked() {
                                deny = Some(request.id);
                            }
                        },
                    );
                    kit::indented(ui, kit::DOT_INDENT, |ui| {
                        ui.add(
                            Label::new(
                                kit::text(
                                    format!("\u{201c}{}\u{201d}", request.reason),
                                    Font::Callout,
                                )
                                .color(kit::SECONDARY),
                            )
                            .wrap(),
                        );
                        if !request.cwd.is_empty() {
                            ui.label(
                                kit::text(&request.cwd, Font::MonoSmall).color(kit::SECONDARY),
                            );
                        }
                    });
                });
            }
        },
    );
    ui.add_space(6.0);
    if let Some(request) = open {
        app.ui.grant = GrantForm {
            dir: request.cwd.clone(),
            any_folder: request.cwd.is_empty(),
            ..GrantForm::default()
        };
        app.ui.sheet = Some(Sheet::AccessRequest {
            request_id: request.id,
        });
    }
    if let Some(id) = deny {
        let result = app.owner_ui.session.deny_access_request(id);
        let _ = app.apply(result, "The request is denied. The agent can see that.");
    }
}

/// Decide one access request: where the agent can use the credential, and who decides.
pub(super) fn access_request_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    request_id: u64,
) -> bool {
    let Some(request) = app
        .owner_ui
        .session
        .access_requests(true)
        .ok()
        .and_then(|requests| {
            requests
                .into_iter()
                .find(|request| request.id == request_id)
        })
    else {
        app.ui.sheet = None;
        return false;
    };
    let real_value = app
        .owner_ui
        .session
        .process_binding(request.item_id)
        .ok()
        .flatten()
        .is_some_and(|binding| binding.delivery == EnvDelivery::Value);
    let mut mode = match app.ui.grant.mode {
        super::agents::Decision::Ask => ExecMode::Ask,
        super::agents::Decision::Bouncer => ExecMode::Bouncer,
    };
    let mut save = false;
    let mut deny = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "access-request", 540.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("{} asks for {}", request.agent_name, request.item_name),
            Some(&format!("\u{201c}{}\u{201d}", request.reason)),
        );
        kit::sheet_body(ui, |ui| {
            let form = &mut app.ui.grant;
            place_section(
                ui,
                ("request", request_id),
                &mut form.dir,
                &mut form.any_folder,
                &mut mode,
                usize::from(real_value),
            );
        });
        kit::sheet_buttons(
            ui,
            |ui| {
                deny = kit::button(ui, "Deny", Style::Destructive).clicked();
            },
            |ui| {
                save = kit::button(ui, "Give access", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    app.ui.grant.mode = match mode {
        ExecMode::Ask => super::agents::Decision::Ask,
        ExecMode::Bouncer => super::agents::Decision::Bouncer,
    };
    save |= super::save_pressed(app, ctx);
    if save {
        let place = app.ui.grant.place();
        let mode = if place == GrantPlace::AnyFolder && real_value {
            ExecMode::Ask
        } else {
            mode
        };
        grant_request(app, ctx, &request, place, mode);
    }
    if deny {
        let result = app.owner_ui.session.deny_access_request(request_id);
        if app
            .apply(result, "The request is denied. The agent can see that.")
            .is_some()
        {
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

fn grant_request(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    request: &AccessRequest,
    place: GrantPlace,
    mode: ExecMode,
) {
    // A grant needs an owner check (goal item A4).
    ask_owner_from_sheet(
        app,
        OwnerRequest::GrantRequest {
            request_id: request.id,
            agent_id: request.agent_id,
            item_id: request.item_id,
            agent_name: request.agent_name.clone(),
            item_name: request.item_name.clone(),
            place,
            mode,
        },
        ctx,
    );
}

pub(super) fn approval_card(app: &mut DesktopApp, ui: &mut egui::Ui, run: &PendingRun) {
    Frame::NONE
        .fill(kit::SURFACE)
        .stroke(Stroke::new(1.0, Tone::Warning.mark().gamma_multiply(0.45)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            approval_details(app, ui, run);
        });
}

fn approval_details(app: &mut DesktopApp, ui: &mut egui::Ui, run: &PendingRun) {
    // ADR 0024: a run with a first use has an offer in the queue.
    let offer = approvals(app).and_then(|queue| queue.first_use(run.id));
    let headline = match &offer {
        Some(offer) => format!(
            "{} wants to use {} for the first time",
            run.agent,
            item_names(offer)
        ),
        None => format!("{} asks to run a command with secrets", run.agent),
    };
    ui.spacing_mut().item_spacing.y = 6.0;
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            kit::dot(ui, Tone::Warning);
            ui.label(kit::text(headline, Font::Headline).color(kit::LABEL));
        },
        |ui| {
            kit::tag(ui, "Waiting", Tone::Warning);
        },
    );
    if run.user_request.is_empty() {
        kit::note(ui, "The agent did not send the user request.");
    } else {
        let source = if run.request_source.is_empty() {
            "from the agent"
        } else {
            run.request_source.as_str()
        };
        kit::paragraph(
            ui,
            format!("User request ({source}): \"{}\"", run.user_request),
            Font::Body,
            kit::LABEL,
        );
    }
    // Goal item B6: the hook request replaced a different text from the agent.
    if !run.agent_request.is_empty() {
        kit::tone_note(
            ui,
            format!(
                "The agent sent a different user request: \"{}\"",
                run.agent_request
            ),
            Tone::Warning,
        );
    }
    kit::code_block(ui, &shell_words(&run.command), 1);
    egui::Grid::new(("run", run.id))
        .num_columns(2)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            let rows = [
                ("Purpose", run.purpose.clone()),
                ("Folder", run.cwd.clone()),
                ("Secrets", run.env_names.join(", ")),
            ];
            for (term, value) in rows {
                ui.label(kit::text(term, Font::Callout).color(kit::SECONDARY));
                ui.add(Label::new(kit::text(value, Font::Callout).color(kit::LABEL)).wrap());
                ui.end_row();
            }
        });
    // A first use names its new items in the headline. Rule flags still show.
    if !run.risk.is_empty() && (offer.is_none() || run.risk.contains("Rule flags")) {
        kit::tone_note(ui, &run.risk, Tone::Warning);
    }
    if let Some(offer) = &run.remember {
        kit::note(ui, remember_text(offer));
    }
    let declarations = offer
        .as_ref()
        .map(|offer| first_use_section(app, ui, run.id, offer));
    kit::note(
        ui,
        "The process can read these secrets. Approve only a command that you trust. An approval needs Touch ID or the passphrase now. A notification is not an approval.",
    );
    ui.add_space(4.0);
    let mut deny = false;
    let mut approve = false;
    let mut remember = false;
    let mut grant = false;
    egui::Sides::new().show(
        ui,
        |ui| {
            deny = kit::button(ui, "Deny", Style::Destructive).clicked();
        },
        |ui| {
            if let Some(offer) = &offer {
                grant = kit::button(
                    ui,
                    &format!("Allow in {}", folder_name(&offer.folder)),
                    Style::Prominent,
                )
                .clicked();
                approve = kit::button(ui, "Allow once", Style::Bordered).clicked();
                return;
            }
            approve = kit::button(ui, "Approve once", Style::Prominent).clicked();
            // "Approve and remember" is an approval: the owner check and the queue path
            // of "Approve once" (ADR 0010, goal item A4).
            if run.remember.is_some() {
                remember = kit::button(ui, "Approve and remember", Style::Bordered).clicked();
            }
        },
    );
    let ctx = ui.ctx().clone();
    if grant && let (Some(offer), Some(declarations)) = (offer, declarations) {
        // One owner check for the run, the access, and the declarations (ADR 0024).
        app.ask_owner(
            OwnerRequest::ApproveAndGrant {
                run: run.clone(),
                offer,
                declarations,
            },
            Some(&ctx),
        );
    }
    if approve {
        // The proof names this run exactly as shown (goal items A4, N4).
        app.ask_owner(OwnerRequest::ApproveRun(run.clone()), Some(&ctx));
    }
    if remember {
        app.ask_owner(OwnerRequest::ApproveAndRemember(run.clone()), Some(&ctx));
    }
    if deny {
        match approvals(app) {
            Some(queue) if queue.deny(run.id) => app.set_ok("The run is denied."),
            _ => app.set_err("The run no longer waits."),
        }
    }
}

/// A waiting run in a sheet, from the banner of another view. The sheet closes when
/// the run no longer waits.
pub(super) fn approval_sheet(app: &mut DesktopApp, ctx: &egui::Context, run_id: u64) -> bool {
    let run = approvals(app)
        .map(|queue| queue.pending())
        .unwrap_or_default()
        .into_iter()
        .find(|run| run.id == run_id);
    let Some(run) = run else {
        if app.owner.check.is_none() {
            app.ui.sheet = None;
        }
        return false;
    };
    let mut later = false;
    let response = kit::sheet(ctx, "approval", 600.0, |ui| {
        kit::sheet_body(ui, |ui| approval_details(app, ui, &run));
        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            later = kit::small_button(ui, "Decide later", Style::Link).clicked();
        });
    });
    if later {
        app.ui.sheet = None;
    }
    response.escape
}

/// The access part of a first-use card (ADR 0024): where "Allow in FOLDER" gives
/// access, and the declaration of each new credential. An item without a declaration
/// gets the suggested form, and the owner can change its environment here. Returns the
/// declarations that "Allow in FOLDER" saves.
fn first_use_section(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    run_id: u64,
    offer: &FirstUseOffer,
) -> Vec<FirstUseDeclaration> {
    let mut chosen = Vec::new();
    kit::paragraph(
        ui,
        format!(
            "\"Allow in {}\" lets this agent use {} in {} and its subfolders. Later runs there that the bouncer finds clean start without a prompt. You can remove the access in Agents.",
            folder_name(&offer.folder),
            item_names(offer),
            offer.folder
        ),
        Font::Callout,
        kit::SECONDARY,
    );
    for item in &offer.items {
        let production = match &item.declaration {
            Some(declaration) => {
                kit::paragraph(
                    ui,
                    format!("{}: {}", item.name, declaration_text(declaration, None)),
                    Font::Callout,
                    kit::LABEL,
                );
                declaration.is_production()
            }
            None => {
                let key = (run_id, item.item_id);
                if !app.ui.first_use_forms.contains_key(&key) {
                    let mut form = app
                        .owner_ui
                        .session
                        .declaration_form(item.item_id)
                        .unwrap_or_default();
                    if form.project.trim().is_empty() {
                        form.project = folder_name(&offer.folder);
                    }
                    app.ui.first_use_forms.insert(key, form);
                }
                let Some(form) = app.ui.first_use_forms.get_mut(&key) else {
                    continue;
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(kit::text(format!("{}:", item.name), Font::Callout).color(kit::LABEL));
                    let options: Vec<(Environment, String)> = Environment::ALL
                        .iter()
                        .map(|environment| (*environment, environment.as_str().to_owned()))
                        .collect();
                    let selected = form.environment.as_str();
                    kit::picker(
                        ui,
                        ("first-use-environment", run_id, item.item_id),
                        &mut form.environment,
                        &options,
                        selected,
                        140.0,
                    );
                });
                kit::note(
                    ui,
                    format!(
                        "Declaration: {}. Apassy suggests it from the credential; a value that it does not find is the strictest one.",
                        declaration_text(&form.to_declaration(), form.provider.as_deref())
                    ),
                );
                chosen.push(FirstUseDeclaration {
                    item_id: item.item_id,
                    declaration: form.to_declaration(),
                    provider: form.provider.clone(),
                    suggested: form.suggestion.as_ref().map(Suggestion::prefilled),
                });
                form.to_declaration().is_production()
            }
        };
        if production {
            kit::tone_note(
                ui,
                format!(
                    "{} is a production credential. Each run with it waits for you, also after you allow access.",
                    item.name
                ),
                Tone::Warning,
            );
        }
    }
    chosen
}

/// The names of the new items of a first use, in quotes.
fn item_names(offer: &FirstUseOffer) -> String {
    offer
        .items
        .iter()
        .map(|item| format!("\"{}\"", item.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The last part of a folder path, for a button.
fn folder_name(folder: &str) -> String {
    std::path::Path::new(folder).file_name().map_or_else(
        || folder.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// A declaration in one line: the provider, the environment, the risk, the scope, and
/// the reversibility.
fn declaration_text(declaration: &Declaration, provider: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(provider) = provider.and_then(providers::find) {
        parts.push(provider.label.clone());
    }
    parts.push(declaration.environment.as_str().to_owned());
    parts.push(format!("{} risk", declaration.risk.as_str()));
    parts.push(declaration.scope.as_str().to_owned());
    parts.push(declaration.reversibility.as_str().to_owned());
    parts.join(", ")
}

/// The pattern that "Approve and remember" teaches, and its approvals.
fn remember_text(offer: &RememberOffer) -> String {
    format!(
        "Pattern: {} ({} of {} approvals). After {} approvals, this pattern runs without a prompt for this agent, project, and items.",
        offer.pattern, offer.approvals, offer.needed, offer.needed
    )
}

/// Arguments as one line. Arguments with spaces or quotes are in single quotes.
pub(super) fn shell_words(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| {
            let plain = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c));
            if plain {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn event_tone(kind: InboxKind) -> Tone {
    match kind {
        InboxKind::ApprovalWaiting => Tone::Warning,
        InboxKind::ApprovalEnded { approved: true } => Tone::Good,
        InboxKind::ApprovalEnded { approved: false } => Tone::Neutral,
        InboxKind::RequestBlocked => Tone::Critical,
    }
}

/// The inbox: waiting runs, ended approvals, and blocked requests. The events stay in
/// the encrypted vault after a restart.
fn draw_inbox(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    let events = match inbox::collect(&app.owner_ui.session, pending) {
        Ok(events) => events,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    if events.is_empty() {
        kit::empty_state(
            ui,
            Icon::Tray,
            "No events yet",
            "Apassy lists here each run that waited for you and each request that it blocked. A macOS notification shows the agent name and the event type only.",
            None,
        );
        return;
    }
    let mut seen = None;
    let now = kit::now();
    kit::section(
        ui,
        None,
        Some("\"Mark as seen\" only marks the event in this window. It changes no decision."),
        |s| {
            for event in events.into_iter().take(SHOWN_EVENTS) {
                let acknowledged = app.owner.acknowledged.contains(&event.key);
                let delivery = app
                    .owner
                    .notifications
                    .as_ref()
                    .and_then(|center| center.delivery(event.key));
                s.row(|ui| {
                    egui::Sides::new().shrink_left().wrap().show(
                        ui,
                        |ui| {
                            kit::dot(ui, event_tone(event.kind));
                            ui.label(kit::medium(event.kind.label(), Font::Body).color(kit::LABEL));
                            let when = event.at.map_or_else(
                                || event.when.clone(),
                                |at| kit::relative_time(at, now),
                            );
                            ui.label(
                                kit::text(format!("{when} · {}", event.agent), Font::Callout)
                                    .color(kit::SECONDARY),
                            )
                            .on_hover_text(&event.when);
                        },
                        |ui| {
                            if acknowledged {
                                kit::tag(ui, "Seen", Tone::Neutral);
                            } else if kit::small_button(ui, "Mark as seen", Style::Link).clicked() {
                                seen = Some(event.key);
                            }
                        },
                    );
                    kit::indented(ui, kit::DOT_INDENT, |ui| {
                        ui.add(
                            Label::new(
                                kit::text(&event.summary, Font::MonoSmall).color(kit::LABEL),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&event.summary);
                        kit::note(ui, &event.detail);
                        if let Some(delivery) = &delivery {
                            let tone = match delivery {
                                Delivery::Failed(_) => Tone::Critical,
                                _ => Tone::Neutral,
                            };
                            kit::tone_note(ui, delivery.label(), tone);
                        }
                    });
                });
            }
        },
    );
    if let Some(key) = seen {
        // Only a mark in memory. It changes no decision (goal item N4).
        app.owner.acknowledged.insert(key);
    }
}

/// Every agent request in the vault log, newest first.
fn draw_requests(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let rows = match app.owner_ui.session.activity(50) {
        Ok(rows) => rows,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    if rows.is_empty() {
        kit::empty_state(
            ui,
            Icon::Clock,
            "No agent request yet",
            "Each request of an agent shows here with the decision of Apassy.",
            None,
        );
        return;
    }
    let now = kit::now();
    kit::section(ui, None, None, |s| {
        for row in rows {
            s.row(|ui| {
                let (label, tone) = match row.decision {
                    ActivityDecision::Allow => ("Allowed", Tone::Good),
                    ActivityDecision::Deny => ("Denied", Tone::Critical),
                    ActivityDecision::Error => ("Failed", Tone::Warning),
                };
                egui::Sides::new().shrink_left().truncate().show(
                    ui,
                    |ui| {
                        ui.add(
                            Label::new(kit::text(&row.operation, Font::Mono).color(kit::LABEL))
                                .truncate(),
                        );
                    },
                    |ui| {
                        kit::tag(ui, label, tone);
                    },
                );
                ui.add(
                    Label::new(
                        kit::text(
                            format!(
                                "{} · {} · {}",
                                kit::relative_time(row.at, now),
                                row.agent,
                                row.item
                            ),
                            Font::Footnote,
                        )
                        .color(kit::SECONDARY),
                    )
                    .wrap(),
                )
                .on_hover_text(&row.when);
                if !row.reason.is_empty() {
                    kit::note(ui, &row.reason);
                }
            });
        }
    });
}
