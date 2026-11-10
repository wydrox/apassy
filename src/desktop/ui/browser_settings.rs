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
/// The status of a browser that cannot reach the host (Linux snap, Flatpak, unknown
/// build). Its row gives the reason and the alternative, and offers no Connect.
pub(super) const UNSUPPORTED_STATUS: &str = "Not supported";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Connect,
    Disconnect,
    OpenStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowTone {
    Accent,
    Warning,
    Secondary,
}

/// What the row of one browser shows: its status, a note under it, and its buttons.
#[derive(Debug, PartialEq, Eq)]
struct RowView {
    status: &'static str,
    tone: RowTone,
    note: Option<String>,
    buttons: Vec<Action>,
}

/// The row of `browser` in `state`, or `None` when the browser is not here. `stale`
/// says that a manifest file exists. A browser that cannot reach the host (a Linux
/// snap, Flatpak or unknown build) is never shown as connected and offers no Connect:
/// its note gives the reason and the alternative, and a stale manifest can go.
fn row_view(browser: &Browser, state: &State, stale: bool) -> Option<RowView> {
    let (status, tone, note, buttons) = match state {
        State::Missing => return None,
        State::Unsupported(kind) => (
            UNSUPPORTED_STATUS,
            RowTone::Warning,
            Some(kind.explain(browser)),
            if stale {
                vec![Action::Disconnect]
            } else {
                vec![]
            },
        ),
        State::Connected => (
            "Connected",
            RowTone::Accent,
            None,
            vec![Action::Disconnect, Action::OpenStore],
        ),
        State::Other(_) => (
            "Connected to another Apassy",
            RowTone::Warning,
            None,
            vec![Action::Connect],
        ),
        State::NotConnected => (
            "Not connected",
            RowTone::Secondary,
            None,
            vec![Action::Connect],
        ),
    };
    Some(RowView {
        status,
        tone,
        note,
        buttons,
    })
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
    ui.label("Browser instances agents may fill in with remote debugging (all profiles)");
    if let Some(identity) = app.browser.unsafe_instance.clone() {
        ui.horizontal(|ui| {
            ui.label(identity.description());
            if ui.button("Trust this instance…").clicked() {
                app.prepare_owner(
                    crate::desktop::owner_check::OwnerRequest::BrowserDebugging {
                        request_label: "Agent fills in all profiles of this instance".into(),
                        identity,
                        scope: None,
                        binding: None,
                    },
                    Some(ui.ctx()),
                    false,
                );
            }
        });
    }
    let profiles = app
        .browser
        .trusted_instances
        .get_or_insert_with(crate::browser::trust::profiles)
        .clone();
    match profiles {
        Ok(profiles) => {
            for identity in profiles {
                ui.horizontal(|ui| {
                    ui.label(identity.description());
                    if ui.button("Remove").clicked() {
                        if let Err(e) = crate::browser::trust::remove(&identity) {
                            app.set_err(e);
                        }
                        app.browser.trusted_instances = None;
                    }
                });
            }
        }
        Err(_) => {
            ui.label("Protected device setting unavailable. Agent fills are refused.");
        }
    }
    let home = install::home();
    let mut action: Option<(Action, &'static Browser)> = None;
    rows::section(
        ui,
        Some("Browser extension"),
        Some(concat!(
            "Fills ask for ",
            crate::touch_id!(),
            " as set in Security › How often to ask. Agents never get the password."
        )),
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
                let stale = install::manifest_path(home, browser).is_file();
                let Some(row) = row_view(browser, &state, stale) else {
                    continue;
                };
                found += 1;
                let tone = match row.tone {
                    RowTone::Accent => kit::palette().accent_text,
                    RowTone::Warning => Tone::Warning.text(),
                    RowTone::Secondary => kit::palette().secondary,
                };
                g.line_note(
                    browser.name,
                    Some(kit::text(row.status, Font::Body).color(tone)),
                    row.note.as_deref().map(rows::note),
                    |ui| {
                        for button in &row.buttons {
                            let (label, style, hover) = match button {
                                Action::Connect => (
                                    "Connect",
                                    Style::Prominent,
                                    Some("Connect opens the Apassy page of the Chrome Web Store in the browser. Click Add to Chrome there. Do it once for each browser."),
                                ),
                                Action::Disconnect if row.status == UNSUPPORTED_STATUS => (
                                    "Remove manifest",
                                    Style::Bordered,
                                    Some("This browser cannot use the manifest. Remove it."),
                                ),
                                Action::Disconnect => ("Disconnect", Style::Bordered, None),
                                Action::OpenStore => ("Get the extension", Style::Bordered, None),
                            };
                            let mut response = kit::small_button(ui, label, style);
                            if let Some(hover) = hover {
                                response = response.on_hover_text(hover);
                            }
                            if response.clicked() {
                                action = Some((*button, browser));
                            }
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
    fn browsers_that_cannot_reach_the_host_are_never_connected_or_offered_connect() {
        use crate::browser::install::Unsupported;
        let browser = &BROWSERS[BROWSERS.len() - 1];
        for kind in [
            Unsupported::Snap,
            Unsupported::Flatpak,
            Unsupported::UnknownBuild,
        ] {
            for stale in [false, true] {
                let row = row_view(browser, &State::Unsupported(kind), stale).unwrap();
                assert_eq!(row.status, UNSUPPORTED_STATUS);
                assert_eq!(row.tone, RowTone::Warning);
                assert!(!row.buttons.contains(&Action::Connect));
                assert!(!row.buttons.contains(&Action::OpenStore));
                assert_eq!(row.buttons.contains(&Action::Disconnect), stale);
                let note = row.note.unwrap();
                assert!(note.starts_with(&kind.reason(browser)), "{note}");
                assert!(
                    note.ends_with("Use Google Chrome, or Chromium from a .deb."),
                    "{note}"
                );
            }
        }
        assert_eq!(row_view(browser, &State::Missing, true), None);
        let connected = row_view(browser, &State::Connected, true).unwrap();
        assert_eq!(connected.status, "Connected");
        assert_eq!(
            connected.buttons,
            vec![Action::Disconnect, Action::OpenStore]
        );
        assert_eq!(
            row_view(browser, &State::NotConnected, false)
                .unwrap()
                .buttons,
            vec![Action::Connect]
        );
    }

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
