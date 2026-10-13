//! The plan in the window: Settings > Plan (flow spec M5), the Upgrade sheet at a paid
//! pick (M4), and the sheet when a paid plan ended (E). The plan comes from
//! `DesktopApp::plan`; with no offer ([`crate::plan::NoPlanProvider`]) none of this
//! shows.
//!
//! Not built yet: stream S2 fills this file. The sheets close as soon as they open,
//! and the section has no group, so nothing shows.

use eframe::egui;

use super::close_sheet;
use crate::desktop::DesktopApp;
use crate::plan::UpgradeFrom;

/// The status line of Settings > Plan in the list: the name of the plan.
pub(super) fn status_line(app: &DesktopApp) -> String {
    // S2: the plan with its state ("Personal · renews DATE", "Plan checked DATE").
    app.plan.current().plan.label().to_owned()
}

/// The groups of Settings > Plan.
pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    // S2: Free (Compare plans) or paid (renews, Manage subscription, Sign out).
    let _ = (app, ui);
}

/// The Upgrade sheet for a paid feature picked at `from`. Returns whether Escape
/// closes it.
pub(super) fn upgrade_sheet(app: &mut DesktopApp, ctx: &egui::Context, from: UpgradeFrom) -> bool {
    // S2: the headline for `from`, what you get, the price of `offer(from)`,
    // "Continue to checkout", "Not now".
    let _ = from;
    close_sheet(app, ctx);
    false
}

/// "Personal ended": move sync to iCloud Drive or turn it off. Returns whether Escape
/// closes it.
pub(super) fn ended_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    // S2: "Move sync to iCloud Drive" (primary), "Turn sync off", "Manage subscription".
    close_sheet(app, ctx);
    false
}
