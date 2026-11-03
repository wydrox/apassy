//! The scope bar of Agents and Decisions: "Showing [All devices ▾] in [All projects ▾]",
//! one sentence with two menus.

use eframe::egui;

use super::detail_rows as rows;
use super::kit::{self, Font};
use crate::desktop::remote_feeds::{ActivityScope, DeviceScope};

/// The text size of the sentence, the size of the menus.
const SIZE: f32 = 12.5;
/// The space between the words and the menus.
const GAP: f32 = 6.0;
/// The width that a menu adds to its text: the padding and the chevron
/// (`detail_rows::bordered_pop_menu`).
const MENU_EXTRA: f32 = 31.0;

/// Draw the scope bar. `devices` lists the choices after "All devices" with their labels
/// (this Mac first); `projects` lists the project labels after "All projects". Returns
/// true when the owner changed the scope.
///
/// The device menu shows only with more than one device, and the project menu only with
/// a project. With neither, the bar draws nothing. A menu whose scope is not "All" stays,
/// so the owner can always go back to "All". VoiceOver reads each menu with its value:
/// "Devices, All devices", "Projects, acme-billing".
///
/// Use it under the title of a list column, for example in `columns::list_inset`.
pub(super) fn scope_bar(
    ui: &mut egui::Ui,
    scope: &mut ActivityScope,
    devices: &[(DeviceScope, String)],
    projects: &[String],
) -> bool {
    let show_devices = devices.len() > 1 || scope.device != DeviceScope::All;
    let show_projects = !projects.is_empty() || scope.project.is_some();
    if !show_devices && !show_projects {
        return false;
    }
    let before = scope.clone();
    let mut device_options = vec![(DeviceScope::All, "All devices".to_owned())];
    device_options.extend(devices.iter().cloned());
    let device_shown = device_label(&scope.device, devices);
    let mut project_options = vec![(None, "All projects".to_owned())];
    project_options.extend(
        projects
            .iter()
            .map(|project| (Some(project.clone()), project.clone())),
    );
    // A chosen project that is no longer in the list stays a choice.
    if let Some(project) = scope.project.as_ref().filter(|p| !projects.contains(*p)) {
        project_options.push((Some(project.clone()), project.clone()));
    }
    let project_shown = scope
        .project
        .clone()
        .unwrap_or_else(|| "All projects".to_owned());
    let device_menu = |ui: &mut egui::Ui, scope: &mut ActivityScope| {
        ui.push_id("scope-devices", |ui| {
            rows::bordered_pop_menu(
                ui,
                &mut scope.device,
                &device_options,
                &device_shown,
                &format!("Devices, {device_shown}"),
            );
        });
    };
    let project_menu = |ui: &mut egui::Ui, scope: &mut ActivityScope| {
        ui.push_id("scope-projects", |ui| {
            rows::bordered_pop_menu(
                ui,
                &mut scope.project,
                &project_options,
                &project_shown,
                &format!("Projects, {project_shown}"),
            );
        });
    };
    // Each menu sits in its own `push_id` part, which a wrapping row cannot break. So
    // the bar measures the sentence: when it does not fit, "in" and the project menu go
    // on a second line.
    let mut width = text_width(ui, "Showing");
    if show_devices {
        width += GAP + text_width(ui, &device_shown) + MENU_EXTRA;
    }
    if show_devices && show_projects {
        width += GAP + text_width(ui, "in");
    }
    if show_projects {
        width += GAP + text_width(ui, &project_shown) + MENU_EXTRA;
    }
    let split = show_devices && show_projects && width > ui.available_width();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        words(ui, "Showing");
        if show_devices {
            device_menu(ui, scope);
        }
        if show_devices && show_projects && !split {
            words(ui, "in");
        }
        if show_projects && !split {
            project_menu(ui, scope);
        }
    });
    if split {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            words(ui, "in");
            project_menu(ui, scope);
        });
    }
    *scope != before
}

/// The label of the chosen device: "All devices", or the label from `devices`. A device
/// that is gone shows as "All devices", as the lists treat it.
fn device_label(device: &DeviceScope, devices: &[(DeviceScope, String)]) -> String {
    devices
        .iter()
        .find(|(choice, _)| choice == device)
        .map_or_else(|| "All devices".to_owned(), |(_, label)| label.clone())
}

/// The gray words of the sentence around the menus.
fn words(ui: &mut egui::Ui, text: &str) {
    ui.label(
        kit::text(text, Font::Callout)
            .size(SIZE)
            .color(kit::SECONDARY),
    );
}

/// The width of `text` in the size of the sentence and of the menus.
fn text_width(ui: &egui::Ui, text: &str) -> f32 {
    kit::galley(ui, kit::text(text, Font::Callout).size(SIZE))
        .size()
        .x
}
