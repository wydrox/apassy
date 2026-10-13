//! Settings as a view of the window (ADR 0026 §3), as each other place: the gear at the
//! bottom of the sidebar and ⌘, open it. The list column lists the sections, each with
//! its tile, its name, and one short status line, as macOS System Settings does. The
//! detail column shows the selected section as groups of rows. A click on any sidebar
//! row leaves Settings.
//!
//! Sheets and owner checks that a section opens show over the window, as all others.

use eframe::egui;

use super::columns;
#[cfg(feature = "vault")]
use super::kit::Font;
use super::kit::{self, Icon};
use crate::desktop::{DesktopApp, Place};

/// A section of Settings, in the order of the list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum SettingsSection {
    /// The open vault, its sync, its backups, and import.
    #[cfg(feature = "vault")]
    #[default]
    Vault,
    /// Touch ID and the passphrase.
    #[cfg(feature = "vault")]
    Security,
    /// This Mac, the iPhones, the other Macs, and the relay for the questions.
    #[cfg(feature = "vault")]
    Devices,
    /// The model of the bouncer, and calibration and learning.
    #[cfg(feature = "vault")]
    Bouncer,
    /// The command line and the browser extension.
    #[cfg(feature = "vault")]
    Tools,
    /// Free, Personal, or Team, and the subscription. Listed only when the plan
    /// provider has an offer ([`SettingsSection::listed`]).
    #[cfg(feature = "vault")]
    Plan,
    /// Updates, the version, and the keyboard shortcuts.
    #[cfg(feature = "vault")]
    Updates,
    /// The demo build: the fixture rule interpreter (ADR 0026 §2).
    #[cfg(not(feature = "vault"))]
    #[default]
    Rules,
}

impl SettingsSection {
    /// The sections in the order of the list. The list shows the [`Self::listed`] ones.
    #[cfg(feature = "vault")]
    pub(crate) const ALL: [Self; 7] = [
        Self::Vault,
        Self::Security,
        Self::Devices,
        Self::Bouncer,
        Self::Tools,
        Self::Plan,
        Self::Updates,
    ];
    #[cfg(not(feature = "vault"))]
    pub(crate) const ALL: [Self; 1] = [Self::Rules];

    pub(crate) fn label(self) -> &'static str {
        match self {
            #[cfg(feature = "vault")]
            Self::Vault => "Vault",
            #[cfg(feature = "vault")]
            Self::Security => "Security",
            #[cfg(feature = "vault")]
            Self::Devices => "Devices",
            #[cfg(feature = "vault")]
            Self::Bouncer => "Bouncer",
            #[cfg(feature = "vault")]
            Self::Tools => "Tools",
            #[cfg(feature = "vault")]
            Self::Plan => "Plan",
            #[cfg(feature = "vault")]
            Self::Updates => "Updates",
            #[cfg(not(feature = "vault"))]
            Self::Rules => "Rules",
        }
    }

    /// The tile of the section: its icon on a color, as in System Settings.
    fn tile(self) -> kit::Tile {
        let (red, green, blue, icon) = match self {
            #[cfg(feature = "vault")]
            Self::Vault => (0, 122, 255, Icon::Database),
            #[cfg(feature = "vault")]
            Self::Security => (88, 86, 214, Icon::Lock),
            #[cfg(feature = "vault")]
            Self::Devices => (48, 160, 200, Icon::Laptop),
            #[cfg(feature = "vault")]
            Self::Bouncer => (175, 82, 222, Icon::Shield),
            #[cfg(feature = "vault")]
            Self::Tools => (99, 99, 102, Icon::Terminal),
            #[cfg(feature = "vault")]
            // Gray for every plan: a paid plan is not a reward color.
            Self::Plan => (120, 120, 128, Icon::Check),
            #[cfg(feature = "vault")]
            Self::Updates => (142, 142, 147, Icon::Download),
            #[cfg(not(feature = "vault"))]
            Self::Rules => (255, 149, 0, Icon::List),
        };
        kit::Tile::icon(egui::Color32::from_rgb(red, green, blue), icon)
    }

    /// Whether the list shows the section. Plan shows only when there is a plan to
    /// buy, so a build with no account service shows nothing about plans.
    pub(crate) fn listed(self, app: &DesktopApp) -> bool {
        #[cfg(feature = "vault")]
        if self == Self::Plan {
            return app.plans_offered();
        }
        let _ = app;
        true
    }

    /// The listed sections in the order of the list.
    pub(crate) fn listed_all(app: &DesktopApp) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|section| section.listed(app))
            .collect()
    }
}

/// Show Settings with the given section.
#[cfg(feature = "vault")]
pub(crate) fn open(app: &mut DesktopApp, section: SettingsSection) {
    show(app);
    app.ui.settings_section = section;
}

/// Show Settings with the section that was open last. In a narrow window the floating
/// sidebar closes.
pub(super) fn show(app: &mut DesktopApp) {
    app.place = Place::Settings;
    app.ui.sidebar_float = false;
}

/// The status line of a section in the list.
fn status(app: &DesktopApp, section: SettingsSection) -> String {
    #[cfg(feature = "vault")]
    return super::settings::status_line(app, section);
    #[cfg(not(feature = "vault"))]
    {
        let _ = (app, section);
        "Fixture rule interpreter".to_owned()
    }
}

/// The list column: "Settings" with the name of the open vault, and one row for each
/// section.
pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui) {
    #[cfg(feature = "vault")]
    let subtitle = app
        .current_vault()
        .map(|entry| entry.name.clone())
        .unwrap_or_default();
    #[cfg(not(feature = "vault"))]
    let subtitle = "Demo".to_owned();
    columns::list_toolbar(ui, "Settings", &subtitle, |_| {});
    let rows: Vec<(SettingsSection, String)> = SettingsSection::listed_all(app)
        .into_iter()
        .map(|section| (section, status(app, section)))
        .collect();
    let groups = [columns::Group {
        title: String::new(),
        rows,
    }];
    let selected = app.ui.settings_section;
    let mut chosen = None;
    columns::grouped_rows(
        ui,
        "settings-list",
        &groups,
        false,
        |ui, (section, status)| {
            let response = ui
                .push_id(("settings-section", section), |ui| {
                    kit::list_row(
                        ui,
                        &kit::ListRow {
                            tile: section.tile(),
                            title: section.label(),
                            subtitle: status,
                            meta: None,
                            production: false,
                            selected: selected == *section,
                        },
                    )
                })
                .inner;
            if response.clicked() {
                chosen = Some(*section);
            }
        },
        |_| {},
    );
    if let Some(section) = chosen {
        app.ui.settings_section = section;
    }
}

/// The detail column: the selected section under its header.
pub(super) fn detail_column(app: &mut DesktopApp, ui: &mut egui::Ui) {
    // A section that is no longer listed (the offer went away) shows the first one.
    if !app.ui.settings_section.listed(app) {
        app.ui.settings_section = SettingsSection::default();
    }
    let section = app.ui.settings_section;
    columns::detail_toolbar(ui, |_| {});
    // Each section keeps its own scroll position and its own IDs, so the focus of one
    // section never moves to another.
    columns::detail_body(ui, ("settings", section), |ui| {
        #[cfg(feature = "vault")]
        {
            ui.scope(|ui| super::updates::banner(app, ui));
            // The Vault section has the sync notes in its Sync group.
            if section != SettingsSection::Vault {
                ui.scope(|ui| super::sync::banner(app, ui));
            }
            header(app, ui, section);
            ui.push_id(section, |ui| super::settings::draw(app, ui, section));
        }
        #[cfg(not(feature = "vault"))]
        {
            ui.add_space(12.0);
            match section {
                SettingsSection::Rules => super::demo::draw_rules(app, ui),
            }
        }
        // Room for the shadow of the last group.
        ui.add_space(2.0);
    });
}

/// The header of a section, as the header of an agent: its tile, its name, and its
/// status line.
#[cfg(feature = "vault")]
fn header(app: &DesktopApp, ui: &mut egui::Ui, section: SettingsSection) {
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        kit::tile(ui, &section.tile(), 44.0);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(kit::text(section.label(), Font::Title).color(kit::LABEL));
            let line = status(app, section);
            if !line.is_empty() {
                ui.add(
                    egui::Label::new(kit::text(line, Font::Body).color(kit::SECONDARY)).truncate(),
                );
            }
        });
    });
    ui.add_space(2.0);
}
