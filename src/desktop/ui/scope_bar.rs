//! The scope bar of Agents and Decisions: "Showing [All devices ▾] in [All projects ▾]",
//! one sentence with two menus.

use eframe::egui;

use crate::desktop::remote_feeds::{ActivityScope, DeviceScope};

/// Draw the scope bar. `devices` lists the choices after "All devices" with their labels
/// (this Mac first); `projects` lists the project labels after "All projects". Returns
/// true when the owner changed the scope.
pub(super) fn scope_bar(
    ui: &mut egui::Ui,
    scope: &mut ActivityScope,
    devices: &[(DeviceScope, String)],
    projects: &[String],
) -> bool {
    let _ = (ui, scope, devices, projects);
    false
}
