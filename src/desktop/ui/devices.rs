//! Settings > Devices, the hub (flow spec M1), and its sheets: "Add a device…" (M2).
//!
//! Not built yet: stream S1 fills this file. The sheets close as soon as they open,
//! so nothing shows.

use eframe::egui;

use super::close_sheet;
use crate::desktop::DesktopApp;

/// A sheet of the Devices hub (`Sheet::Devices`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DevicesSheet {
    /// "Add a device": one QR code and one link for an iPhone or a Mac (M2).
    // S1 opens it; until then only the tests do.
    #[cfg_attr(not(test), allow(dead_code))]
    AddDevice,
}

/// Draw `sheet`. Returns whether Escape closes it, as each sheet.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &DevicesSheet) -> bool {
    // S1: draw the sheets of the hub (M2 "Add a device").
    let _ = sheet;
    close_sheet(app, ctx);
    false
}
