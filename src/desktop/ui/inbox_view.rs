//! The inbox and the real notification channel (goal items N1 to N4). This card
//! replaces the demo notification switch.

use eframe::egui::{self, CornerRadius, Frame, Margin, RichText, Stroke};

use super::{ALLOW, ASK, DENY, INK, INK_MUTED, LINE, card_frame};
use crate::desktop::inbox::{self, InboxKind};
use crate::desktop::notify::{self, Delivery};
use crate::desktop::{BrokerState, DesktopApp};

/// How many inbox events the card shows.
const SHOWN_EVENTS: usize = 40;

pub(super) fn draw_inbox(app: &mut DesktopApp, ui: &mut egui::Ui) {
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Inbox").size(16.0).strong().color(INK));
        ui.label(
            RichText::new(
                "A waiting approval or a blocked request causes a macOS notification. The notification shows only the agent name and the event type. You decide in this app. The events stay in the encrypted vault after a restart.",
            )
            .color(INK_MUTED),
        );
        draw_channel(app, ui);
        ui.add_space(6.0);
        if app.owner_ui.session.is_locked() {
            ui.label(
                RichText::new(
                    "Unlock the vault to see the inbox. The events are in the encrypted activity log.",
                )
                .color(INK_MUTED),
            );
            return;
        }
        let pending = match &app.broker {
            BrokerState::Running(handle) => handle.approvals().pending(),
            _ => Vec::new(),
        };
        let events = match inbox::collect(&app.owner_ui.session, &pending) {
            Ok(events) => events,
            Err(err) => {
                ui.label(RichText::new(err.message).color(DENY));
                return;
            }
        };
        if events.is_empty() {
            ui.label(RichText::new("No event yet.").color(INK_MUTED));
            return;
        }
        let mut seen = None;
        for event in events.into_iter().take(SHOWN_EVENTS) {
            let acknowledged = app.owner.acknowledged.contains(&event.key);
            let color = match event.kind {
                InboxKind::ApprovalWaiting => ASK,
                InboxKind::ApprovalEnded { approved: true } => ALLOW,
                InboxKind::ApprovalEnded { approved: false } => INK_MUTED,
                InboxKind::RequestBlocked => DENY,
            };
            let delivery = app
                .owner
                .notifications
                .as_ref()
                .and_then(|center| center.delivery(event.key));
            Frame::NONE
                .stroke(Stroke::new(1.0, LINE))
                .inner_margin(Margin::symmetric(10, 8))
                .corner_radius(CornerRadius::same(6))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(event.kind.label()).strong().color(color));
                        ui.label(
                            RichText::new(format!("{} · {}", event.when, event.agent))
                                .color(INK_MUTED),
                        );
                        if acknowledged {
                            ui.label(RichText::new("Seen").color(INK_MUTED));
                        }
                    });
                    ui.label(RichText::new(&event.summary).monospace().color(INK));
                    ui.label(RichText::new(&event.detail).color(INK_MUTED));
                    if let Some(delivery) = &delivery {
                        let tint = match delivery {
                            Delivery::Failed(_) => DENY,
                            _ => INK_MUTED,
                        };
                        ui.label(RichText::new(delivery.label()).color(tint));
                    }
                    if event.kind == InboxKind::ApprovalWaiting {
                        ui.label(
                            RichText::new(
                                "Review it in the approval card at the top. \"Mark as seen\" does not approve it.",
                            )
                            .color(ASK),
                        );
                    }
                    if !acknowledged && ui.button("Mark as seen").clicked() {
                        seen = Some(event.key);
                    }
                });
            ui.add_space(4.0);
        }
        if let Some(key) = seen {
            // Only a mark in memory. It changes no decision (goal item N4).
            app.owner.acknowledged.insert(key);
        }
    });
}

fn draw_channel(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(center) = &app.owner.notifications else {
        ui.label(
            RichText::new(
                "Notifications: not running. The notification center starts with the Apassy window and the broker. Events stay in the inbox.",
            )
            .color(ASK),
        );
        return;
    };
    let view = center.view();
    let color = if view.channel.can_deliver() {
        ALLOW
    } else {
        ASK
    };
    ui.label(RichText::new(format!("Notifications: {}", view.channel.summary())).color(color));
    let failed = view
        .deliveries
        .values()
        .filter(|delivery| matches!(delivery, Delivery::Failed(_)))
        .count();
    if failed > 0 {
        ui.label(
            RichText::new(format!(
                "{failed} notification(s) failed. The events stay in this inbox."
            ))
            .color(DENY),
        );
    }
    ui.horizontal_wrapped(|ui| {
        if ui.button("Check notification settings").clicked() {
            center.refresh_status();
        }
        // The notifier (Contents/Helpers/ApassyNotify.app, display name "Apassy")
        // asks macOS. The button hides while the macOS prompt is on the screen.
        if view.channel.needs_permission()
            && ui
                .button("Allow notifications")
                .on_hover_text(
                    "macOS shows a prompt for \"Apassy\" at the top right of the screen. Select \"Allow\".",
                )
                .clicked()
        {
            center.request_permission();
        }
        // After a denial, macOS shows no new prompt. Only System Settings helps.
        if view.channel.needs_settings()
            && ui
                .button("Open notification settings")
                .on_hover_text("System Settings > Notifications > Apassy. Turn on \"Allow notifications\" and select \"Banners\".")
                .clicked()
        {
            match notify::open_notification_settings() {
                Ok(()) => center.refresh_status(),
                Err(err) => center.report_problem(format!(
                    "Apassy cannot open System Settings ({err}). Open System Settings > Notifications > Apassy."
                )),
            }
        }
    });
}
