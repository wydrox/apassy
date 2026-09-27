//! Activity: runs that wait for the owner, the inbox, and every agent request (goal
//! items N1 to N4). A notification or "Mark as seen" is never an approval.

use std::sync::Arc;

use eframe::egui::{self, CornerRadius, Frame, Label, Margin, Stroke};

use super::kit::{self, Font, Icon, Style, Tone};
use crate::broker::approvals::{ApprovalQueue, PendingRun, RememberOffer};
use crate::desktop::inbox::{self, InboxKind};
use crate::desktop::notify::Delivery;
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{BrokerState, DesktopApp, OwnerView};
use crate::vault::ActivityDecision;

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
    notifications_notice(app, ui);
    if !pending.is_empty() {
        ui.label(kit::text("Waiting for you", Font::Headline).color(kit::LABEL));
        ui.add_space(4.0);
        for run in pending {
            approval_card(app, ui, run);
            ui.add_space(14.0);
        }
        ui.add_space(6.0);
    }
    let mut tab = app.ui.activity_tab;
    kit::segmented(
        ui,
        "activity-tab",
        &mut tab,
        &[(Tab::Inbox, "Inbox"), (Tab::Requests, "All requests")],
    );
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
    }
}

/// One run that waits for the owner, with its decision buttons.
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
    ui.spacing_mut().item_spacing.y = 6.0;
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            kit::dot(ui, Tone::Warning);
            ui.label(
                kit::text(
                    format!("{} asks to run a command with secrets", run.agent),
                    Font::Headline,
                )
                .color(kit::LABEL),
            );
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
    if !run.risk.is_empty() {
        kit::tone_note(ui, &run.risk, Tone::Warning);
    }
    if let Some(offer) = &run.remember {
        kit::note(ui, remember_text(offer));
    }
    kit::note(
        ui,
        "The process can read these secrets. Approve only a command that you trust. An approval needs Touch ID or the passphrase now. A notification is not an approval.",
    );
    ui.add_space(4.0);
    let mut deny = false;
    let mut approve = false;
    let mut remember = false;
    egui::Sides::new().show(
        ui,
        |ui| {
            deny = kit::button(ui, "Deny", Style::Destructive).clicked();
        },
        |ui| {
            approve = kit::button(ui, "Approve once", Style::Prominent).clicked();
            // "Approve and remember" is an approval: the owner check and the queue path
            // of "Approve once" (ADR 0010, goal item A4).
            if run.remember.is_some() {
                remember = kit::button(ui, "Approve and remember", Style::Bordered).clicked();
            }
        },
    );
    let ctx = ui.ctx().clone();
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
                            ui.label(
                                kit::text(
                                    format!("{} · {}", event.when, event.agent),
                                    Font::Callout,
                                )
                                .color(kit::SECONDARY),
                            );
                        },
                        |ui| {
                            if acknowledged {
                                kit::tag(ui, "Seen", Tone::Neutral);
                            } else if kit::small_button(ui, "Mark as seen", Style::Link).clicked() {
                                seen = Some(event.key);
                            }
                        },
                    );
                    ui.add(
                        Label::new(kit::text(&event.summary, Font::MonoSmall).color(kit::LABEL))
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
                kit::note(ui, format!("{} · {} · {}", row.when, row.agent, row.item));
                if !row.reason.is_empty() {
                    kit::note(ui, &row.reason);
                }
            });
        }
    });
}
