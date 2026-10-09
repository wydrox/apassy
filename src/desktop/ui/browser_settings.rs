//! Settings > General > Browser extension (ADR 0021): connect a browser with one click.
//!
//! "Connect" writes the host manifest of the browser ([`crate::browser::install`]) and
//! opens the page of the extension in the Chrome Web Store in that browser, where the
//! owner clicks "Add to Chrome" (ADR 0021, D5). The folder in Apassy.app stays for a
//! load with Developer mode.

use std::time::{Duration, Instant};

use eframe::egui;

use super::kit::{self, Font, Style, Tone};
use crate::browser::install::{self, BROWSERS, Browser, Install, State};
use crate::desktop::DesktopApp;

/// The note of a source build. Tests read it.
pub(super) const SOURCE_BUILD_NOTE: &str = "The browser extension works with Apassy.app. A source build is not protected from agents, so it does not connect a browser.";

#[derive(Clone, Copy)]
enum Action {
    Connect,
    Disconnect,
    OpenStore,
}

/// When the extension last talked to the app.
fn last_seen_text(seen: Option<Instant>) -> String {
    let Some(seen) = seen else {
        return "No request yet".to_owned();
    };
    let ago = seen.elapsed();
    if ago < Duration::from_secs(60) {
        "Last request just now".to_owned()
    } else if ago < Duration::from_secs(3600) {
        format!("Last request {} min ago", ago.as_secs() / 60)
    } else {
        format!("Last request {} h ago", ago.as_secs() / 3600)
    }
}

pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let bundle = Install::current();
    let home = install::home();
    let mut action: Option<(Action, &'static Browser)> = None;
    let mut show_folder = false;
    kit::section(
        ui,
        Some("Browser extension"),
        Some(
            "Fill logins in Helium, Chrome, and other Chromium browsers. Each fill asks for Touch ID or your passphrase. Agents never get the password.",
        ),
        |s| {
            let (Some(bundle), Some(home)) = (&bundle, &home) else {
                s.row(|ui| kit::tone_note(ui, SOURCE_BUILD_NOTE, Tone::Warning));
                return;
            };
            let host = bundle.host();
            let mut found = 0;
            for browser in BROWSERS {
                let state = install::state(home, browser, &host);
                if state == State::Missing {
                    continue;
                }
                found += 1;
                let (status, tone) = match &state {
                    State::Connected => ("Connected", kit::ACCENT),
                    State::Other(_) => ("Connected to another Apassy", Tone::Warning.text()),
                    _ => ("Not connected", kit::SECONDARY),
                };
                s.row(|ui| {
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.vertical(|ui| {
                                ui.label(kit::text(browser.name, Font::Body).color(kit::LABEL));
                                ui.label(kit::text(status, Font::Callout).color(tone));
                            });
                        },
                        |ui| {
                            if state == State::Connected {
                                if kit::small_button(ui, "Disconnect", Style::Bordered).clicked() {
                                    action = Some((Action::Disconnect, browser));
                                }
                                if kit::small_button(ui, "Get the extension", Style::Bordered)
                                    .clicked()
                                {
                                    action = Some((Action::OpenStore, browser));
                                }
                            } else if kit::button(ui, "Connect", Style::Prominent).clicked() {
                                action = Some((Action::Connect, browser));
                            }
                        },
                    );
                });
            }
            if found == 0 {
                s.row(|ui| kit::note(ui, "No Chromium browser is on this Mac."));
            }
            s.row(|ui| {
                kit::note(
                    ui,
                    "Connect opens the Apassy page of the Chrome Web Store in the browser. Click Add to Chrome there. Do it once for each browser.",
                );
                kit::note(
                    ui,
                    "To load the extension from Apassy.app instead, turn on Developer mode on the extensions page of the browser and drag the folder browser-extension onto it.",
                );
                show_folder =
                    kit::small_button(ui, "Show the extension folder", Style::Bordered).clicked();
            });
            s.labeled(
                "Extension",
                kit::text(last_seen_text(app.browser.last_seen), Font::Callout)
                    .color(kit::SECONDARY),
            );
            if !bundle.is_installed_app() {
                s.row(|ui| {
                    kit::tone_note(
                        ui,
                        "This Apassy.app is not /Applications/Apassy.app. The agent profile protects it only when agents start with the apassy-sandbox of this app.",
                        Tone::Warning,
                    );
                });
            }
            if let Some(problem) = &app.browser.problem {
                s.row(|ui| kit::tone_note(ui, problem, Tone::Critical));
            }
        },
    );
    let (Some(bundle), Some(home)) = (bundle, home) else {
        return;
    };
    if show_folder {
        reveal_folder(app, &bundle);
    }
    match action {
        Some((Action::Connect, browser)) => {
            if let Err(err) = install::connect(&home, browser, &bundle.host()) {
                app.set_err(format!("{} is not connected: {err}", browser.name));
                return;
            }
            let opened = install::open_store_page(browser).is_ok();
            app.set_ok(if opened {
                format!(
                    "{} is connected. Click Add to Chrome on the page that opened in it.",
                    browser.name
                )
            } else {
                format!(
                    "{} is connected. Open {} in it and click Add to Chrome.",
                    browser.name,
                    install::STORE_URL
                )
            });
        }
        Some((Action::Disconnect, browser)) => match install::disconnect(&home, browser) {
            Ok(_) => app.set_ok(format!(
                "{} is disconnected. Remove the Apassy extension on its extensions page too.",
                browser.name
            )),
            Err(err) => app.set_err(format!("{} is still connected: {err}", browser.name)),
        },
        Some((Action::OpenStore, browser)) if install::open_store_page(browser).is_err() => {
            app.set_err(format!(
                "{} did not open. Open {} in it.",
                browser.name,
                install::STORE_URL
            ));
        }
        Some((Action::OpenStore, _)) | None => {}
    }
}

fn reveal_folder(app: &mut DesktopApp, bundle: &Install) {
    let folder = bundle.extension_dir();
    if !folder.join("manifest.json").is_file() {
        app.set_err(
            "The extension folder is missing in this Apassy.app. Install the current Apassy.app.",
        );
        return;
    }
    if let Err(err) = install::reveal(&folder) {
        app.set_err(format!(
            "The Finder did not show the extension folder ({err}). It is {}.",
            folder.display()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_request_reads_as_a_time() {
        assert_eq!(last_seen_text(None), "No request yet");
        assert_eq!(
            last_seen_text(Some(Instant::now())),
            "Last request just now"
        );
        let earlier = Instant::now().checked_sub(Duration::from_secs(5 * 60));
        if let Some(earlier) = earlier {
            assert_eq!(last_seen_text(Some(earlier)), "Last request 5 min ago");
        }
    }
}
