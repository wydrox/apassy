//! The words of the window by platform (ADR 0041, unit L7). On Linux, every main view
//! and every Settings section, rendered with the fixture vault, names nothing that
//! exists only on a Mac: no Touch ID, Keychain, Finder, Dock, iCloud, Apassy.app,
//! System Settings, macOS, no ⌘ ⌥ ⌃ shortcut signs, and no "Mac" for this computer.
//! On macOS the same views keep their Mac words: [`mac_views_keep_their_mac_words`]
//! names them literally, without the macros of `src/wording.rs`.
//!
//! The text of a view is what it paints and the AccessKit names of its controls (where
//! the hover hints of the sidebar live).

use std::collections::HashMap;

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2, accesskit};
use tempfile::TempDir;

use super::owner_tests::{collect, locked_app, unlocked_app_with_item};
use super::settings_view::SettingsSection;
use super::{Sheet, draw};
use crate::desktop::{DesktopApp, Place};

/// A tall window, so that each group of a section is on the screen.
const SIZE: Vec2 = Vec2::new(1180.0, 6000.0);

/// Words for a Mac-only thing. Any of them on a Linux screen fails the test.
#[cfg(target_os = "linux")]
const MAC_ONLY: [&str; 13] = [
    "Touch ID",
    "Keychain",
    "keychain",
    "Finder",
    "Dock",
    "iCloud",
    "Apassy.app",
    "System Settings",
    "macOS",
    "⌘",
    "⌥",
    "⌃",
    "Notification Center",
];

/// Where "Mac" may stay on a Linux screen: a device that really is a Mac or an Apple
/// device, never this computer (class c of the L7 inventory). Each entry is the whole
/// phrase around the word.
#[cfg(target_os = "linux")]
const MAC_ALLOWED: [&str; 0] = [];

/// Whole lines of Settings > Tools > Browser extension (`browser_settings.rs`) that
/// unit L5 owns and changes in parallel; L7 does not edit that file. Remove each line
/// here when L5 makes it platform-aware: the guard then covers it too.
#[cfg(target_os = "linux")]
const PENDING_L5: [&str; 3] = [
    "Needs Apassy.app",
    "No Chromium browser is on this Mac.",
    "This Apassy.app is not /Applications/Apassy.app. The agent profile protects it only when agents start with the apassy-sandbox of this app.",
];

/// The painted texts and the AccessKit names of one screen after a few frames.
struct Screen {
    // Only the Linux guard names the screen, in its failure message.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    name: String,
    text: String,
}

/// Draw `app` for a few frames, so that a new layout and its lazy loads settle.
fn render(name: &str, app: &mut DesktopApp, prepare: impl Fn(&egui::Context)) -> Screen {
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    prepare(&ctx);
    let mut names: HashMap<accesskit::NodeId, String> = HashMap::new();
    let mut text = String::new();
    for frame in 0..4 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(f64::from(frame) * 0.1),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        if let Some(update) = &output.platform_output.accesskit_update {
            for (id, node) in &update.nodes {
                if let Some(label) = node.label() {
                    names.insert(*id, label.to_owned());
                }
            }
        }
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    let mut labels: Vec<_> = names.into_values().collect();
    labels.sort();
    text.push_str(&labels.join("\n"));
    Screen {
        name: name.to_owned(),
        text,
    }
}

/// Open the hidden rows of Settings > Updates (the keyboard shortcuts).
fn show_all_rows(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        data.insert_temp(egui::Id::new(("apassy-settings-more", "shortcuts")), true);
    });
}

/// Every screen of the guard: the welcome screen, the open screen of a synced vault,
/// the locked vault, each place of the sidebar with the sidebar full and as a rail, a
/// credential, the new-credential sheet, and each Settings section with its hidden rows
/// shown.
fn screens() -> Vec<Screen> {
    let dir = TempDir::new().expect("temp dir");
    let mut screens = Vec::new();

    let mut welcome = DesktopApp::new();
    welcome.sync.offered = true;
    screens.push(render("welcome", &mut welcome, |_| {}));
    super::sync::begin_open(&mut welcome);
    screens.push(render("open a synced vault", &mut welcome, |_| {}));

    let locked_dir = TempDir::new().expect("temp dir");
    let mut locked = locked_app(&locked_dir, "locked.db");
    screens.push(render("locked", &mut locked, |_| {}));

    let (mut app, item) = unlocked_app_with_item(&dir);
    app.sync.offered = true;
    for (name, place) in [
        ("credentials", Place::CREDENTIALS),
        ("overview", Place::Overview),
        ("decisions", Place::Decisions),
        ("agents", Place::Agents),
        ("logs", Place::Logs),
    ] {
        app.place = place.clone();
        app.ui.sidebar_hidden = false;
        screens.push(render(name, &mut app, |_| {}));
        app.ui.sidebar_hidden = true;
        screens.push(render(&format!("{name}, sidebar rail"), &mut app, |_| {}));
    }
    app.ui.sidebar_hidden = false;
    app.place = Place::CREDENTIALS;
    app.select_item(item.to_string());
    screens.push(render("a credential", &mut app, |_| {}));
    app.ui.sheet = Some(Sheet::NewCredential);
    screens.push(render("new credential", &mut app, |_| {}));
    app.ui.sheet = None;
    app.selected_item_id = None;
    for section in SettingsSection::ALL {
        super::open_settings(&mut app, section);
        screens.push(render(
            &format!("Settings > {}", section.label()),
            &mut app,
            show_all_rows,
        ));
    }
    screens
}

/// The words of `text` that name a Mac-only thing, and each "Mac" that is not in the
/// allow-list.
#[cfg(target_os = "linux")]
fn mac_words(text: &str) -> Vec<String> {
    let text = text
        .lines()
        .filter(|line| !PENDING_L5.contains(line))
        .collect::<Vec<_>>()
        .join("\n");
    let text = text.as_str();
    let mut found: Vec<String> = MAC_ONLY
        .iter()
        .filter(|word| text.contains(*word))
        .map(|word| (*word).to_owned())
        .collect();
    for line in text.lines() {
        let mut rest = line;
        while let Some(at) = rest.find("Mac") {
            let before = rest[..at].chars().next_back();
            let after = rest[at + 3..].chars().next();
            let word_start = before.is_none_or(|c| !c.is_alphanumeric());
            let word_end = after.is_none_or(|c| !c.is_alphanumeric() || c == 's');
            let allowed = MAC_ALLOWED.iter().any(|phrase| line.contains(phrase));
            if word_start && word_end && !allowed {
                found.push(line.to_owned());
                break;
            }
            rest = &rest[at + 3..];
        }
    }
    found
}

/// The guard of L7: no Linux screen names a Mac-only thing or calls this computer a
/// Mac. It runs in the ubuntu `tests` job.
#[cfg(target_os = "linux")]
#[test]
fn linux_screens_name_nothing_of_the_mac() {
    let screens = screens();
    assert!(screens.len() > 15, "{} screens", screens.len());
    let mut failures = Vec::new();
    for screen in &screens {
        assert!(
            !screen.text.trim().is_empty(),
            "{} painted nothing",
            screen.name
        );
        let words = mac_words(&screen.text);
        if !words.is_empty() {
            failures.push(format!("{}: {words:?}", screen.name));
        }
    }
    assert!(
        failures.is_empty(),
        "Mac words on Linux:\n{}",
        failures.join("\n")
    );
}

/// The guard sees what it guards: the Linux words are on the screens, among them the
/// Linux shortcuts in Settings > Updates and in the sidebar names.
#[cfg(target_os = "linux")]
#[test]
fn linux_screens_use_the_linux_words() {
    let screens = screens();
    let all = screens
        .iter()
        .map(|screen| screen.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Each vault is one encrypted file on this computer.",
        "Use a vault from another computer",
        "Hide sidebar  F9",
        "Show sidebar  F9",
        "Settings  Ctrl+,",
        "Lock the vault  Ctrl+L",
        "Ctrl+1 to Ctrl+5",
        "Alt+Left",
        "Ctrl+Shift+H",
        "Tab, Shift+Tab",
        "Quit Apassy",
        "Apassy does not update itself on Linux",
    ] {
        assert!(all.contains(expected), "no screen shows {expected:?}");
    }
}

/// The sibling of the guard on macOS: the same screens keep their Mac words, written
/// here literally, so a change of a macro in `src/wording.rs` cannot change them
/// unnoticed. It runs in the macOS `tests` job of a ready pull request.
#[cfg(not(target_os = "linux"))]
#[test]
fn mac_views_keep_their_mac_words() {
    let screens = screens();
    let all = screens
        .iter()
        .map(|screen| screen.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Credentials for you and your agents. Each vault is one encrypted file on this Mac. Agents use the secrets through Apassy and never see the values.",
        "Use a vault from another Mac",
        "macOS can ask for permission to use iCloud Drive before Apassy can read the file.",
        "Help with iCloud",
        "Hide sidebar  ⌃⌘S",
        "Show sidebar  ⌃⌘S",
        "Settings  ⌘,",
        "Lock the vault  ⌘L",
        "⌘1 to ⌘5",
        "⌘[",
        "⌘⇧H",
        "Tab, ⇧Tab",
        "⌘H stays the macOS shortcut for \"Hide Apassy\", so showing values uses ⌘⇧H.",
        "This Mac",
    ] {
        assert!(all.contains(expected), "no screen shows {expected:?}");
    }
    for linux_only in ["Quit Apassy", "F9", "Ctrl+", "Alt+Left", "this computer"] {
        assert!(
            !all.contains(linux_only),
            "a Mac screen shows {linux_only:?}"
        );
    }
}
