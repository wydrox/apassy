//! Settings > About > Updates, and the banner of a ready update (ADR 0015).

use eframe::egui;

use super::kit::{self, Font, Style, Tone};
use super::timeline;
use crate::desktop::update::{
    CHANGELOG_URL, DOWNLOAD_PAGE_URL, Phase, StagedKind, UpdateView, open,
};
use crate::desktop::{DesktopApp, OwnerView};

/// What the owner clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    CheckNow,
    Download,
    Restart,
    OpenImage,
    OpenDownloadPage,
    OpenChangelog,
    HideBanner,
}

const FOOTER: &str = "Apassy downloads a new version from apassy.wyderka.cc. It installs it only when Apple notarized it and it is signed by the same Developer ID team as this copy. It never installs an older version.";
const LINUX_NOTE: &str = "Updates are available only for the macOS app. On Linux, build the new version from the source.";

/// The Updates section of Settings.
pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let view = app.updates.view();
    let build = app.updates.build().label();
    if !view.supported {
        kit::section(ui, Some("Updates"), Some(LINUX_NOTE), |s| {
            s.labeled(
                "Version",
                kit::text(build, Font::Body).color(kit::SECONDARY),
            );
        });
        return;
    }
    let mut auto_check = view.auto_check;
    let mut auto_install = view.auto_install;
    let mut action = None;
    kit::section(ui, Some("Updates"), Some(FOOTER), |s| {
        s.labeled(
            "Version",
            kit::text(build, Font::Body).color(kit::SECONDARY),
        );
        s.toggle(
            "Check for updates automatically",
            Some("At the start of Apassy and every 6 hours."),
            &mut auto_check,
        );
        s.toggle(
            "Download and install automatically",
            Some("A new version installs when you quit Apassy."),
            &mut auto_install,
        );
        s.row(|ui| status(&view, ui, &mut action));
        if let Some(report) = &view.last_install {
            s.row(|ui| {
                let tone = if report.ok {
                    Tone::Good
                } else {
                    Tone::Critical
                };
                let when = timeline::relative_time(report.at, timeline::now());
                kit::tone_note(
                    ui,
                    format!("Last install, {when}: {}", report.message),
                    tone,
                );
            });
        }
        // A whole-row link, as "New vault…" in Settings > General: its text lines up
        // with the other rows.
        let changelog = s
            .clickable_row("What's new in Apassy", |ui| {
                ui.label(kit::text("What's new in Apassy", Font::Body).color(kit::ACCENT_TEXT));
            })
            .on_hover_text(CHANGELOG_URL);
        if changelog.clicked() {
            action = Some(Action::OpenChangelog);
        }
    });
    if auto_check != view.auto_check {
        app.updates.set_auto_check(auto_check);
    }
    if auto_install != view.auto_install {
        app.updates.set_auto_install(auto_install);
    }
    if let Some(action) = action {
        act(app, ui.ctx(), action);
    }
}

/// The state line, its buttons, and "Check now".
fn status(view: &UpdateView, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let busy = matches!(
        view.phase,
        Phase::Checking | Phase::Downloading { .. } | Phase::Verifying { .. }
    );
    let (line, tone) = match &view.phase {
        Phase::Idle => (
            view.last_result
                .clone()
                .unwrap_or_else(|| "Apassy has not checked for updates yet.".to_owned()),
            Tone::Neutral,
        ),
        Phase::Checking => ("Checking for updates…".to_owned(), Tone::Accent),
        Phase::Available { version, .. } => {
            (format!("Apassy {version} is available."), Tone::Accent)
        }
        Phase::Downloading {
            version,
            received,
            total,
        } => {
            let percent = if *total == 0 {
                0
            } else {
                received.saturating_mul(100) / total
            };
            (
                format!("Downloading Apassy {version}… {percent}%"),
                Tone::Accent,
            )
        }
        Phase::Verifying { version } => (
            format!("Checking the signature of Apassy {version}…"),
            Tone::Accent,
        ),
        Phase::Ready(staged) => match staged.kind {
            StagedKind::App => (format!("Apassy {} is ready.", staged.version), Tone::Good),
            StagedKind::Image => (
                format!("Apassy {} is downloaded.", staged.version),
                Tone::Good,
            ),
        },
        Phase::Error(_) => ("The last check failed.".to_owned(), Tone::Critical),
    };
    egui::Sides::new().show(
        ui,
        |ui| {
            ui.vertical(|ui| {
                ui.label(kit::text(line, Font::Body).color(tone.text()));
                let checked = view.last_check.map_or_else(
                    || "Last check: never".to_owned(),
                    |at| {
                        format!(
                            "Last check: {}",
                            timeline::relative_time(at, timeline::now())
                        )
                    },
                );
                kit::note(ui, checked);
            });
        },
        |ui| {
            ui.add_enabled_ui(!busy && view.running, |ui| {
                if kit::small_button(ui, "Check now", Style::Bordered).clicked() {
                    *action = Some(Action::CheckNow);
                }
            });
        },
    );
    match &view.phase {
        Phase::Downloading {
            received, total, ..
        } if *total > 0 => {
            ui.add(egui::ProgressBar::new(*received as f32 / *total as f32).desired_height(4.0));
        }
        Phase::Available {
            blocked: Some(reason),
            ..
        } => {
            kit::tone_note(ui, reason, Tone::Warning);
            if kit::small_button(ui, "Open the download page", Style::Bordered).clicked() {
                *action = Some(Action::OpenDownloadPage);
            }
        }
        Phase::Available { blocked: None, .. } => {
            if kit::small_button(ui, "Download now", Style::Prominent)
                .on_hover_text(
                    "Apassy downloads and checks the new version. Then you restart to install it.",
                )
                .clicked()
            {
                *action = Some(Action::Download);
            }
        }
        Phase::Ready(staged) if staged.kind == StagedKind::App => {
            if view.auto_install {
                kit::note(ui, "It installs when you quit Apassy.");
            }
            if kit::small_button(ui, "Restart now", Style::Prominent)
                .on_hover_text("Apassy locks the vault, ends runs that wait for you, installs the new version, and opens it.")
                .clicked()
            {
                *action = Some(Action::Restart);
            }
        }
        Phase::Ready(_) => {
            kit::note(ui, IMAGE_NOTE);
            if kit::small_button(ui, "Open the disk image", Style::Prominent).clicked() {
                *action = Some(Action::OpenImage);
            }
        }
        Phase::Error(err) => kit::tone_note(ui, err, Tone::Critical),
        _ => {}
    }
}

const IMAGE_NOTE: &str = "Apassy cannot replace itself in its folder. Open the disk image, quit Apassy, and drag Apassy to Applications.";

/// "Apassy X is ready" on top of each page but Settings > About, which has the same
/// buttons.
pub(super) fn banner(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if app.view == OwnerView::Settings && app.ui.settings_tab == super::SettingsTab::About {
        return;
    }
    let view = app.updates.view();
    let Phase::Ready(staged) = &view.phase else {
        return;
    };
    if app.updates.banner_hidden.as_ref() == Some(&staged.commit) {
        return;
    }
    let (title, message) = match staged.kind {
        StagedKind::App => (
            format!("Apassy {} is ready.", staged.version),
            if view.auto_install {
                "It installs when you quit Apassy. Restart now to install it at once."
            } else {
                "Restart Apassy to install it."
            },
        ),
        StagedKind::Image => (
            format!("Apassy {} is downloaded.", staged.version),
            IMAGE_NOTE,
        ),
    };
    let mut action = None;
    kit::notice(ui, Tone::Accent, &title, Some(message), |ui| {
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            let main = match staged.kind {
                StagedKind::App => ("Restart now", Action::Restart),
                StagedKind::Image => ("Open the disk image", Action::OpenImage),
            };
            if kit::small_button(ui, main.0, Style::Prominent).clicked() {
                action = Some(main.1);
            }
            if kit::small_button(ui, "Later", Style::Link).clicked() {
                action = Some(Action::HideBanner);
            }
        });
    });
    if let Some(action) = action {
        act(app, ui.ctx(), action);
    }
}

fn act(app: &mut DesktopApp, ctx: &egui::Context, action: Action) {
    let result = match action {
        Action::CheckNow => {
            app.updates.check_now();
            Ok(())
        }
        Action::Download => {
            app.updates.download_now();
            Ok(())
        }
        Action::Restart => {
            app.restart_to_update(ctx);
            Ok(())
        }
        Action::OpenImage => app.updates.open_image(),
        Action::OpenDownloadPage => open(DOWNLOAD_PAGE_URL.as_ref()),
        Action::OpenChangelog => open(CHANGELOG_URL.as_ref()),
        Action::HideBanner => {
            if let Phase::Ready(staged) = app.updates.view().phase {
                app.updates.banner_hidden = Some(staged.commit);
            }
            Ok(())
        }
    };
    if let Err(err) = result {
        app.set_err(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::update::{SUPPORTED, Staged};
    use eframe::egui::{Pos2, RawInput, Rect, Shape, Vec2};

    const PASS: &str = "ui-update-pass-ok";

    fn text_of(shape: &Shape, out: &mut String) {
        match shape {
            Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            Shape::Vec(nested) => nested.iter().for_each(|inner| text_of(inner, out)),
            _ => {}
        }
    }

    /// The text of the third frame.
    fn draw(app: &mut DesktopApp, size: Vec2) -> String {
        let ctx = egui::Context::default();
        let mut text = String::new();
        for _ in 0..3 {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| super::super::draw(app, ui));
            text.clear();
            for clipped in &output.shapes {
                text_of(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        text
    }

    fn unlocked(dir: &tempfile::TempDir) -> DesktopApp {
        let mut app = DesktopApp::new();
        let path = dir.path().join("ui.db");
        app.owner_ui
            .session
            .create_file(&path, PASS)
            .expect("create");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app
    }

    fn staged(kind: StagedKind) -> Staged {
        Staged {
            version: "0.3.1".to_owned(),
            build: "e710914".to_owned(),
            commit: "e710914de97c988f775bf180ab1f9f43c2ee20ee".to_owned(),
            kind,
            team: "ABCDE12345".to_owned(),
        }
    }

    const TALL: Vec2 = Vec2::new(1280.0, 6000.0);

    #[test]
    fn settings_show_the_updates_section() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = unlocked(&dir);
        crate::desktop::ui::open_settings(&mut app, crate::desktop::ui::SettingsTab::About);
        let text = draw(&mut app, TALL);
        assert!(text.contains("Updates"), "{text}");
        let version = app.updates.build().label();
        assert!(version.starts_with(env!("CARGO_PKG_VERSION")), "{version}");
        assert!(text.contains(&version), "{text}");
        if !SUPPORTED {
            assert!(text.contains(LINUX_NOTE), "{text}");
            assert!(!text.contains("Check now"), "{text}");
            return;
        }
        for expected in [
            "Check for updates automatically",
            "Download and install automatically",
            "Apassy has not checked for updates yet.",
            "Last check: never",
            "Check now",
            "What's new in Apassy",
            FOOTER,
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }

        // The last check and the last install.
        let now = timeline::now();
        app.updates.set_results_for_test(
            now,
            "Apassy 0.3.0 is up to date.",
            Some(crate::desktop::update::InstallReport {
                at: now,
                ok: true,
                message: "Apassy is updated to 0.3.0.".to_owned(),
            }),
        );
        let text = draw(&mut app, TALL);
        for expected in [
            "Apassy 0.3.0 is up to date.",
            "Last check: just now",
            "Last install, just now: Apassy is updated to 0.3.0.",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }

        // Each phase has its line.
        let cases = [
            (Phase::Checking, "Checking for updates…"),
            (
                Phase::Downloading {
                    version: "0.3.1".to_owned(),
                    received: 50,
                    total: 200,
                },
                "Downloading Apassy 0.3.1… 25%",
            ),
            (
                Phase::Verifying {
                    version: "0.3.1".to_owned(),
                },
                "Checking the signature of Apassy 0.3.1…",
            ),
            (
                Phase::Available {
                    version: "0.3.1".to_owned(),
                    blocked: None,
                },
                "Download now",
            ),
            (
                Phase::Available {
                    version: "0.3.1".to_owned(),
                    blocked: Some("Synthetic reason.".to_owned()),
                },
                "Open the download page",
            ),
            (Phase::Ready(staged(StagedKind::App)), "Restart now"),
            (
                Phase::Ready(staged(StagedKind::Image)),
                "Open the disk image",
            ),
            (
                Phase::Error("Synthetic check error.".to_owned()),
                "Synthetic check error.",
            ),
        ];
        for (phase, expected) in cases {
            app.updates.set_phase_for_test(phase.clone());
            let text = draw(&mut app, TALL);
            assert!(
                text.contains(expected),
                "{phase:?}: missing {expected}: {text}"
            );
        }
        // Settings has the buttons, so it shows no banner.
        app.updates
            .set_phase_for_test(Phase::Ready(staged(StagedKind::App)));
        let text = draw(&mut app, TALL);
        assert_eq!(text.matches("Apassy 0.3.1 is ready.").count(), 1, "{text}");
    }

    #[test]
    fn a_ready_update_shows_a_banner_in_the_main_window() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = unlocked(&dir);
        let size = Vec2::new(1180.0, 800.0);
        let text = draw(&mut app, size);
        assert!(
            !text.contains("is ready"),
            "no banner without an update: {text}"
        );

        app.updates
            .set_phase_for_test(Phase::Ready(staged(StagedKind::App)));
        for view in [OwnerView::Vault, OwnerView::Agents, OwnerView::Activity] {
            app.view = view;
            let text = draw(&mut app, size);
            assert!(text.contains("Apassy 0.3.1 is ready."), "{view:?}: {text}");
            assert!(text.contains("Restart now"), "{text}");
            assert!(text.contains("It installs when you quit Apassy."), "{text}");
            assert!(text.contains("Later"), "{text}");
        }
        app.updates.set_auto_install(false);
        let text = draw(&mut app, size);
        assert!(text.contains("Restart Apassy to install it."), "{text}");

        app.updates
            .set_phase_for_test(Phase::Ready(staged(StagedKind::Image)));
        let text = draw(&mut app, size);
        assert!(text.contains("Apassy 0.3.1 is downloaded."), "{text}");
        assert!(text.contains("Open the disk image"), "{text}");

        app.updates.banner_hidden = Some(staged(StagedKind::Image).commit);
        let text = draw(&mut app, size);
        assert!(
            !text.contains("Apassy 0.3.1"),
            "Later hides the banner: {text}"
        );
        // A newer version shows it again.
        let mut newer = staged(StagedKind::App);
        newer.version = "0.3.2".to_owned();
        newer.commit = "0123456789abcdef0123456789abcdef01234567".to_owned();
        app.updates.set_phase_for_test(Phase::Ready(newer));
        let text = draw(&mut app, size);
        assert!(text.contains("Apassy 0.3.2 is ready."), "{text}");
    }

    /// Without a ready app, "Restart now" changes nothing: the vault stays open.
    #[test]
    fn restart_without_a_ready_version_keeps_the_vault_open() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let mut app = unlocked(&dir);
        let ctx = egui::Context::default();
        app.restart_to_update(&ctx);
        assert!(!app.owner_ui.session.is_locked());
        assert_eq!(app.status_kind, crate::desktop::StatusKind::Error);
        assert!(
            app.status_text.contains("not running"),
            "{}",
            app.status_text
        );

        app.updates
            .set_phase_for_test(Phase::Ready(staged(StagedKind::App)));
        app.restart_to_update(&ctx);
        assert!(
            !app.owner_ui.session.is_locked(),
            "the idle updater has no files"
        );
    }
}
