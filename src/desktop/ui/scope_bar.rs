//! The scope bar of the Bouncer pages: "Showing [All Environments ▾] in [All Projects ▾]",
//! one sentence with two menus (implementation-plan-bouncer-section §1).
//!
//! [`bouncer_bar`] is the bar of all four pages: the environment menu lists this Mac
//! first, then each other Mac of the vault with the age of its report, the Macs that
//! never reported last and dimmed. It always shows, also with one Mac.
// The demo build draws the pages from fixtures and uses part of this module.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::{self, Pos2, Rect, Sense, Stroke, Vec2, WidgetInfo, WidgetType};

use super::bouncer::{ActivityScope, DeviceScope, Environment};
use super::kit::{self, Font};

/// The text size of the sentence, the size of the menus.
const SIZE: f32 = 12.5;
/// The space between the words and the menus.
const GAP: f32 = 6.0;
/// The width that a menu adds to its text: the padding and the chevron ([`menu_button`]).
const MENU_EXTRA: f32 = 31.0;

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

// ---- The bar of the Bouncer pages. ----

/// "Other Macs appear when they use this vault." under the menu of a vault with one Mac.
pub(super) const ONE_MAC: &str = "Other Macs appear when they use this vault.";

/// The label of the environment scope: "All Environments", or the name of the Mac. A Mac
/// that is gone shows as "All Environments", as the pages treat it.
pub(super) fn environment_label(device: &DeviceScope, envs: &[Environment]) -> String {
    match device {
        DeviceScope::All => "All Environments".to_owned(),
        scope => envs
            .iter()
            .find(|env| env.scope == *scope)
            .map_or_else(|| "All Environments".to_owned(), |env| env.name.clone()),
    }
}

/// A scope of a Mac that is no longer an environment shows all environments again.
pub(super) fn fit_scope(scope: &mut ActivityScope, envs: &[Environment]) {
    if scope.device != DeviceScope::All && !envs.iter().any(|env| env.scope == scope.device) {
        scope.device = DeviceScope::All;
    }
}

/// One item of the environment menu: the scope, the name, the text at the right, and
/// whether it is dimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MenuItem {
    pub(super) scope: DeviceScope,
    pub(super) name: String,
    pub(super) detail: String,
    pub(super) dimmed: bool,
}

/// The items of the environment menu. With one Mac, the menu has that Mac alone and
/// [`ONE_MAC`] under it; else "All Environments" first.
pub(super) fn menu_items(envs: &[Environment], now: u64, offset: i64) -> Vec<MenuItem> {
    let mut items = Vec::new();
    if envs.len() > 1 {
        items.push(MenuItem {
            scope: DeviceScope::All,
            name: "All Environments".to_owned(),
            detail: String::new(),
            dimmed: false,
        });
    }
    items.extend(envs.iter().map(|env| MenuItem {
        scope: env.scope.clone(),
        name: env.name.clone(),
        detail: env.menu_detail(now, offset),
        dimmed: env.dimmed(now),
    }));
    items
}

/// The scope bar of a Bouncer page. Returns true when the owner changed the scope.
/// VoiceOver reads each menu with its value: "Environments, All Environments",
/// "Projects, acme-billing".
pub(super) fn bouncer_bar(
    ui: &mut egui::Ui,
    scope: &mut ActivityScope,
    envs: &[Environment],
    projects: &[String],
    now: u64,
    offset: i64,
) -> bool {
    fit_scope(scope, envs);
    let before = scope.clone();
    let env_shown = environment_label(&scope.device, envs);
    let project_shown = scope
        .project
        .clone()
        .unwrap_or_else(|| "All Projects".to_owned());
    let items = menu_items(envs, now, offset);
    let mut project_options: Vec<Option<String>> = vec![None];
    project_options.extend(projects.iter().cloned().map(Some));
    if let Some(project) = scope.project.as_ref().filter(|p| !projects.contains(*p)) {
        project_options.push(Some(project.clone()));
    }
    let width = text_width(ui, "Showing")
        + GAP
        + text_width(ui, &env_shown)
        + MENU_EXTRA
        + GAP
        + text_width(ui, "in")
        + GAP
        + text_width(ui, &project_shown)
        + MENU_EXTRA;
    let split = width > ui.available_width();
    let env_menu = |ui: &mut egui::Ui, scope: &mut ActivityScope| {
        ui.push_id("bouncer-environments", |ui| {
            let button = menu_button(ui, &env_shown, &format!("Environments, {env_shown}"));
            egui::Popup::menu(&button).show(|ui| {
                ui.set_min_width(290.0);
                // One Mac: "All" and the Mac are the same choice.
                let one = envs.len() == 1;
                for item in &items {
                    let selected =
                        item.scope == scope.device || (one && scope.device == DeviceScope::All);
                    if menu_row(ui, item, selected).clicked() {
                        scope.device = item.scope.clone();
                        ui.close();
                    }
                }
                if one {
                    ui.add_space(2.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.add_space(8.0);
                        ui.label(kit::text(ONE_MAC, Font::Callout).color(kit::SECONDARY));
                    });
                }
            });
        });
    };
    let project_menu = |ui: &mut egui::Ui, scope: &mut ActivityScope| {
        ui.push_id("bouncer-projects", |ui| {
            let button = menu_button(ui, &project_shown, &format!("Projects, {project_shown}"));
            egui::Popup::menu(&button).show(|ui| {
                ui.set_min_width(200.0);
                for option in &project_options {
                    let item = MenuItem {
                        scope: DeviceScope::All,
                        name: option.clone().unwrap_or_else(|| "All Projects".to_owned()),
                        detail: String::new(),
                        dimmed: false,
                    };
                    if menu_row(ui, &item, scope.project == *option).clicked() {
                        scope.project = option.clone();
                        ui.close();
                    }
                }
            });
        });
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        words(ui, "Showing");
        env_menu(ui, scope);
        if !split {
            words(ui, "in");
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

/// The bordered button of a menu: its value and a chevron.
fn menu_button(ui: &mut egui::Ui, shown: &str, name: &str) -> egui::Response {
    let galley = kit::galley(ui, kit::text(shown, Font::Callout).size(SIZE));
    let size = Vec2::new(galley.size().x + MENU_EXTRA, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::ComboBox, enabled, name));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            kit::FILL_PRESSED
        } else if response.hovered() {
            kit::FILL
        } else {
            kit::SURFACE
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 6, fill);
        painter.rect_stroke(
            rect,
            6,
            Stroke::new(1.0, kit::BORDER),
            egui::StrokeKind::Inside,
        );
        if response.has_focus() {
            kit::focus_ring(painter, rect, 6);
        }
        painter.galley(
            Pos2::new(rect.left() + 8.0, rect.center().y - galley.size().y / 2.0),
            galley,
            kit::LABEL,
        );
        let center = Pos2::new(rect.right() - 12.0, rect.center().y - 0.5);
        painter.line(
            vec![
                center + Vec2::new(-3.5, -1.8),
                center + Vec2::new(0.0, 1.8),
                center + Vec2::new(3.5, -1.8),
            ],
            Stroke::new(1.4, kit::SECONDARY),
        );
    }
    response
}

/// One row of a menu: a check for the chosen one, the name, and its detail at the right.
/// A dimmed row is a Mac silent for 24 hours or one that never reported.
fn menu_row(ui: &mut egui::Ui, item: &MenuItem, selected: bool) -> egui::Response {
    let width = ui.available_width().max(200.0);
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 24.0), Sense::click());
    let name = if item.detail.is_empty() {
        item.name.clone()
    } else {
        format!("{}, {}", item.name, item.detail)
    };
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, &name));
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let highlight = response.hovered() || response.has_focus();
    let painter = ui.painter();
    if highlight {
        painter.rect_filled(rect, 5, kit::SELECTION);
    }
    let alpha = if item.dimmed { kit::DIMMED } else { 1.0 };
    let (label, secondary) = if highlight {
        (egui::Color32::WHITE, egui::Color32::from_white_alpha(217))
    } else {
        (
            kit::LABEL.gamma_multiply(alpha),
            kit::SECONDARY.gamma_multiply(alpha),
        )
    };
    if selected {
        let check = kit::galley(ui, kit::text("✓", Font::Callout));
        painter.galley(
            Pos2::new(rect.left() + 6.0, rect.center().y - check.size().y / 2.0),
            check,
            label,
        );
    }
    let text = kit::galley(ui, kit::text(&item.name, Font::Body));
    let text_pos = Pos2::new(rect.left() + 22.0, rect.center().y - text.size().y / 2.0);
    painter.galley(text_pos, text, label);
    if !item.detail.is_empty() {
        let detail = kit::galley(ui, kit::text(&item.detail, Font::Callout));
        let at = Rect::from_min_size(
            Pos2::new(
                rect.right() - 10.0 - detail.size().x,
                rect.center().y - detail.size().y / 2.0,
            ),
            detail.size(),
        );
        painter.galley(at.min, detail, secondary);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_715_600;

    fn other(name: &str, reported_at: Option<u64>) -> Environment {
        Environment {
            scope: DeviceScope::Other(name.to_lowercase()),
            name: name.to_owned(),
            reported_at,
            never_reported: reported_at.is_none(),
            note: None,
        }
    }

    /// With one Mac the menu still shows: that Mac alone, checked, and the line that
    /// other Macs appear when they use this vault (frame 12b).
    #[test]
    fn one_mac_has_a_menu_with_itself_and_the_one_mac_line() {
        let envs = vec![Environment::this_mac("Mac mini (office)")];
        let items = menu_items(&envs, NOW, 0);
        assert_eq!(
            items,
            [MenuItem {
                scope: DeviceScope::ThisMac,
                name: "Mac mini (office)".to_owned(),
                detail: "This Mac".to_owned(),
                dimmed: false,
            }]
        );
        assert_eq!(
            environment_label(&DeviceScope::All, &envs),
            "All Environments"
        );
        assert_eq!(
            environment_label(&DeviceScope::ThisMac, &envs),
            "Mac mini (office)"
        );
        assert_eq!(ONE_MAC, "Other Macs appear when they use this vault.");
        assert!(ONE_MAC.split_whitespace().count() <= 12);
    }

    /// A Mac that never reported is listed last and dimmed; a Mac silent for 24 hours
    /// is dimmed with the day of its last report.
    #[test]
    fn a_never_reported_mac_is_last_and_dimmed() {
        let mut envs = vec![
            other("iMac (home)", None),
            Environment::this_mac("Mac mini (office)"),
            other("Mac mini (studio)", Some(NOW - 120)),
            other("MacBook Pro", Some(NOW - 2 * 86_400)),
        ];
        crate::desktop::ui::bouncer::sort_environments(&mut envs);
        let items = menu_items(&envs, NOW, 0);
        let rows: Vec<(&str, &str, bool)> = items
            .iter()
            .map(|item| (item.name.as_str(), item.detail.as_str(), item.dimmed))
            .collect();
        assert_eq!(
            rows,
            [
                ("All Environments", "", false),
                ("Mac mini (office)", "This Mac", false),
                ("Mac mini (studio)", "2 min ago", false),
                ("MacBook Pro", "1 Nov", true),
                ("iMac (home)", "Never reported", true),
            ]
        );
    }

    /// A Mac that left the vault leaves the scope: all environments show again.
    #[test]
    fn a_gone_mac_falls_back_to_all_environments() {
        let envs = vec![Environment::this_mac("Here")];
        let mut scope = ActivityScope {
            device: DeviceScope::Other("gone".to_owned()),
            project: Some("shop".to_owned()),
        };
        assert_eq!(environment_label(&scope.device, &envs), "All Environments");
        fit_scope(&mut scope, &envs);
        assert_eq!(scope.device, DeviceScope::All);
        assert_eq!(scope.project.as_deref(), Some("shop"), "the project stays");
        let mut here = ActivityScope {
            device: DeviceScope::ThisMac,
            project: None,
        };
        fit_scope(&mut here, &envs);
        assert_eq!(here.device, DeviceScope::ThisMac);
    }
}
