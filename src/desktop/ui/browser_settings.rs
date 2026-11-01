//! Settings > Tools > Browser extension (ADR 0021): connect a browser with one click.
//!
//! "Connect" writes the host manifest of the browser ([`crate::browser::install`]) and
//! opens the page of the extension in the Chrome Web Store in that browser, where the
//! owner clicks "Add to Chrome" (ADR 0021, D5).

use std::time::{Duration, Instant};

use eframe::egui;

use super::kit::{self, Font, Style, Tone};
use crate::browser::install::{self, BROWSERS, Browser, Install, State};
use crate::desktop::DesktopApp;

/// The note of a source build. Tests read it.
pub(super) const SOURCE_BUILD_NOTE: &str =
    "A source build is not protected from agents, so it connects no browser.";

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

/// Settings > Tools > Browser extension: a row for each Chromium browser on this Mac
/// with its state and "Connect", and when the extension last asked.
pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::settings::rows;

    let bundle = Install::current();
    let home = install::home();
    let mut action: Option<(Action, &'static Browser)> = None;
    rows::section(
        ui,
        Some("Browser extension"),
        Some(
            "Fills ask for Touch ID as set in Security › How often to ask. Agents never get the password.",
        ),
        |g| {
            let (Some(bundle), Some(home)) = (&bundle, &home) else {
                g.line_note(
                    "Chrome extension",
                    Some(kit::text("Needs Apassy.app", Font::Body).color(Tone::Warning.text())),
                    Some(rows::note(SOURCE_BUILD_NOTE)),
                    |_| {},
                );
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
                    State::Connected => ("Connected", kit::ACCENT_TEXT),
                    State::Other(_) => ("Connected to another Apassy", Tone::Warning.text()),
                    _ => ("Not connected", kit::SECONDARY),
                };
                g.line(
                    browser.name,
                    Some(kit::text(status, Font::Body).color(tone)),
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
                        } else if kit::small_button(ui, "Connect", Style::Prominent)
                            .on_hover_text(
                                "Connect opens the Apassy page of the Chrome Web Store in the browser. Click Add to Chrome there. Do it once for each browser.",
                            )
                            .clicked()
                        {
                            action = Some((Action::Connect, browser));
                        }
                    },
                );
            }
            if found == 0 {
                g.note_row("No Chromium browser is on this Mac.");
            }
            g.line(
                "Extension",
                Some(rows::value(last_seen_text(app.browser.last_seen))),
                |_| {},
            );
            if !bundle.is_installed_app() {
                g.tone_row(
                    "This Apassy.app is not /Applications/Apassy.app. The agent profile protects it only when agents start with the apassy-sandbox of this app.",
                    Tone::Warning.text(),
                );
            }
            if let Some(problem) = &app.browser.problem {
                g.tone_row(problem, Tone::Critical.text());
            }
        },
    );
    let (Some(bundle), Some(home)) = (bundle, home) else {
        return;
    };
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
