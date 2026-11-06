//! Tests of the Bouncer pages in the window: Overview and Logs draw the cached data, each
//! empty state of the mockup, the notification deep link, and no vault read per frame.
//! Synthetic names only.

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::bouncer::tests::{NOW, STUDIO, fixture};
use super::bouncer::{
    ActivityScope, BouncerData, DayBar, DeviceScope, EnvStats, LogFilter, LogKindFilter, ProxyRow,
};
use super::owner_tests::unlocked_app_with_item;
use super::{draw, kit, logs};
use crate::desktop::{DesktopApp, Place};

const SIZE: Vec2 = Vec2::new(1280.0, 1600.0);

/// Draw `frames` frames from `start`, a tenth of a second apart, and return the text of
/// the last one.
fn frames_from(app: &mut DesktopApp, start: f64, frames: usize) -> String {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for frame in 0..frames {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(start + frame as f64 * 0.1),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            super::owner_tests::collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn frames(app: &mut DesktopApp, count: usize) -> String {
    frames_from(app, 0.1, count)
}

/// The fixture of frame 1 at the real time, so the ages read as in the mockup.
fn data_now() -> BouncerData {
    fixture(kit::now().saturating_sub(NOW))
}

/// The app on `place` with `data` in the cache: the frames after it within 2 seconds
/// read no vault.
fn app_with(dir: &TempDir, place: Place, scope: ActivityScope, data: BouncerData) -> DesktopApp {
    let (mut app, _) = unlocked_app_with_item(dir);
    app.place = place;
    let project = scope.project.clone();
    app.ui.activity_scope = scope;
    app.ui.bouncer.store(0.0, 0, project.as_deref(), data);
    app
}

#[test]
fn overview_logs_and_agents_are_wide_and_decisions_keeps_its_columns() {
    assert!(Place::Overview.is_wide());
    assert!(Place::Agents.is_wide());
    assert!(Place::Logs.is_wide());
    assert!(!Place::Decisions.is_wide());
    assert!(!Place::CREDENTIALS.is_wide());
    assert!(!Place::Settings.is_wide());
    for place in [
        Place::Overview,
        Place::Decisions,
        Place::Agents,
        Place::Logs,
    ] {
        assert!(place.is_bouncer(), "{place:?}");
    }
    assert_eq!(Place::Overview.label(), "Overview");
    assert_eq!(Place::Logs.label(), "Logs");
    // Agents is one wide page: with no agent, frame 9b.
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.place = Place::Agents;
    let text = frames(&mut app, 3);
    assert!(text.contains("No agents yet"), "{text}");
    // The sidebar section is Bouncer, with its four rows.
    for row in ["Bouncer", "Overview", "Decisions", "Agents", "Logs"] {
        assert!(text.contains(row), "{row}: {text}");
    }
}

/// Frame 1: the Overview shows the numbers of the fixture.
#[test]
fn the_overview_shows_the_numbers_of_the_stats_fixture() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_with(&dir, Place::Overview, ActivityScope::default(), data_now());
    let text = frames(&mut app, 4);
    for expected in [
        "Last 7 days",
        "Showing",
        "All Environments",
        "All Projects",
        "424",
        "370",
        "87%",
        "51",
        "12%",
        "14 s",
        "Runs per day",
        "Allowed by bouncer",
        "Asked you",
        "Needs attention",
        "MacBook Pro not reporting",
        "Stripe live used 3 times",
        "Codex asks often",
        "30%",
        "Asks You",
        "Last Active",
        "Waits for you",
        "Active now",
        "Environments",
        "215 runs",
        "169 runs",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(text.find("MacBook Pro not reporting") < text.find("Codex asks often"));
    assert_eq!(app.ui.bouncer.computations, 1, "the data of the test only");
}

/// One environment in the scope: only its numbers.
#[test]
fn the_scope_of_one_mac_shows_its_numbers() {
    let dir = TempDir::new().expect("temp dir");
    let scope = ActivityScope {
        device: DeviceScope::Other(STUDIO.to_owned()),
        project: None,
    };
    let mut app = app_with(&dir, Place::Overview, scope, data_now());
    let text = frames(&mut app, 4);
    assert!(text.contains("169"), "{text}");
    assert!(text.contains("Mac mini (studio)"), "{text}");
    assert!(!text.contains("424"), "{text}");
    assert!(!text.contains("Stripe live used"), "{text}");
}

/// Frame 9a: one Mac, no agents, no runs. Frame 9d: Logs with nothing yet. Both read the
/// real (empty) vault.
#[test]
fn a_first_run_shows_the_empty_states_of_overview_and_logs() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.place = Place::Overview;
    let text = frames(&mut app, 3);
    for expected in [
        "No runs yet",
        "Connect an agent to see its runs here.",
        "Connect an Agent…",
        "Turn On Remote Access",
        "Median answer",
        "—",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Runs per day"), "no empty chart: {text}");
    app.place = Place::Logs;
    let text = frames(&mut app, 3);
    assert!(text.contains("No activity yet"), "{text}");
    assert!(text.contains("Outcome"), "the table header stays: {text}");
    assert!(!text.contains("Clear Filters"), "{text}");
}

/// Frame 10b: a quiet week; only the silent Mac needs attention.
#[test]
fn a_quiet_day_lists_only_the_silent_mac() {
    let dir = TempDir::new().expect("temp dir");
    let mut data = data_now();
    data.production.clear();
    for agent in &mut data.agents {
        agent.asked = agent.asked.min(2);
        agent.not_allowed = 0;
        agent.waits = false;
    }
    let mut app = app_with(&dir, Place::Overview, ActivityScope::default(), data);
    let text = frames(&mut app, 4);
    assert!(text.contains("MacBook Pro not reporting"), "{text}");
    assert!(!text.contains("asks often"), "{text}");
    assert!(!text.contains("Nothing needs you"), "{text}");
}

/// Frame 11b: a project without runs this week names its last run.
#[test]
fn a_project_without_runs_names_its_last_run() {
    let dir = TempDir::new().expect("temp dir");
    let mut data = data_now();
    for stats in data.stats.values_mut() {
        *stats = EnvStats {
            days: vec![DayBar::default(); 7],
            ..EnvStats::default()
        };
    }
    data.last_in_project = Some((NOW - 13 * 86_400, "Codex".to_owned()));
    let scope = ActivityScope {
        device: DeviceScope::All,
        project: Some("billing-v2".to_owned()),
    };
    let mut app = app_with(&dir, Place::Overview, scope, data);
    let text = frames(&mut app, 4);
    for expected in [
        "billing-v2",
        "No runs in billing-v2",
        "Last run 21 Oct, by Codex.",
        "Show All Projects",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Runs per day"), "{text}");
}

/// Frame 6: Logs lists the rows of every Mac; the filters narrow them; a cloud run of
/// this Mac opens with its proxied requests, never a path.
#[test]
fn logs_filter_the_rows_and_open_a_cloud_run() {
    let dir = TempDir::new().expect("temp dir");
    let data = data_now();
    let cloud = data.events[1].key();
    let mut app = app_with(&dir, Place::Logs, ActivityScope::default(), data);
    let text = frames(&mut app, 4);
    // Recent fixture rows can be yesterday's when this runs just after local midnight.
    assert!(
        text.lines()
            .any(|line| matches!(line, "Today" | "Yesterday")),
        "the recent fixture has a relative day heading: {text}"
    );
    for expected in [
        "Time",
        "Environment",
        "Event",
        "Credential",
        "Outcome",
        "Mac mini (studio)",
        "Allowed by bouncer",
        "Allowed on iPhone",
        "Denied by you",
        "Remote access on",
        "Connect",
        "Remote",
        "All Agents",
        "Runs",
        "Connections",
        "Denied",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    app.ui.logs.filter = LogFilter {
        kind: LogKindFilter::Denied,
        ..LogFilter::default()
    };
    let text = frames(&mut app, 3);
    assert!(text.contains("Denied by you"), "{text}");
    assert!(!text.contains("Allowed on iPhone"), "{text}");
    assert!(!text.contains("Remote access on"), "{text}");

    app.ui.logs.filter = LogFilter::default();
    logs::open_row_for_test(
        &mut app,
        cloud,
        vec![
            ProxyRow::from_audit(
                r#"{"at":1793715128,"method":"GET","host":"api.github.com",
                    "path":"/repos/acme/SECRET-PATH","status":200,"outcome":"forwarded"}"#,
            )
            .expect("a row"),
            ProxyRow::from_audit(
                r#"{"at":1793715242,"method":"GET","host":"uploads.example.net",
                    "path":null,"status":403,"outcome":"refused","code":"wrong_host"}"#,
            )
            .expect("a row"),
        ],
    );
    let text = frames(&mut app, 3);
    for expected in [
        "gh api repos/acme/billing/issues --paginate",
        "Proxied requests",
        "Method",
        "Host",
        "Status",
        "api.github.com",
        "200",
        "Refused: wrong host",
        "114 s",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("SECRET-PATH"), "{text}");
    // The chevrons of the rows are drawn: SF Pro has no "⌄", which showed as a box.
    assert!(!text.contains('⌄') && !text.contains('›'), "{text}");
}

/// Headers belong to the first displayed group even when every row is older than today.
#[test]
fn older_logs_show_column_headers_once_above_the_first_day() {
    let mut data = fixture(0);
    // Keep a second day visible so repeating the headers for every group also fails.
    data.events.last_mut().expect("fixture event").at -= 86_400;
    let scope = ActivityScope::default();
    let filter = LogFilter::default();
    let state = logs::State::default();
    let offset = 0;
    for (now, first_day) in [(NOW + 86_400, "Yesterday"), (NOW + 2 * 86_400, "3 Nov")] {
        let view = logs::LogsView::of(&data, &scope, &filter, now, offset);
        assert_eq!(view.groups.len(), 2);
        assert_eq!(view.groups[0].0, first_day);
        assert_eq!(view.groups[1].0, "2 Nov");
        assert_eq!(
            view.groups
                .iter()
                .map(|(_, rows)| rows.len())
                .sum::<usize>(),
            data.events.len()
        );
        let ctx = egui::Context::default();
        let mut text = String::new();
        for frame in 0..3 {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
                time: Some(0.1 + frame as f64 * 0.1),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| {
                let _ = logs::draw(ui, &view, &state, &data, now, offset);
            });
            text.clear();
            for clipped in &output.shapes {
                super::owner_tests::collect(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        for title in [
            first_day,
            "2 Nov",
            "Time",
            "Environment",
            "Agent",
            "Event",
            "Credential",
            "Outcome",
        ] {
            assert_eq!(
                text.lines().filter(|line| *line == title).count(),
                1,
                "{title}: {text}"
            );
        }
        assert!(!text.lines().any(|line| line == "Today"), "{text}");
        assert!(text.find(first_day) < text.find("Time"), "{text}");
        assert!(
            text.find("Time").expect("header")
                < text.find("Allowed by bouncer").expect("first day's row"),
            "{text}"
        );
        assert!(
            text.contains("Connect"),
            "the second day's row stays: {text}"
        );
    }
}

/// Frame 14: filters that match nothing; Clear Filters is the way back.
#[test]
fn filtered_logs_without_a_match_offer_clear_filters() {
    let dir = TempDir::new().expect("temp dir");
    let scope = ActivityScope {
        device: DeviceScope::ThisMac,
        project: Some("acme-billing".to_owned()),
    };
    let mut app = app_with(&dir, Place::Logs, scope, data_now());
    app.ui.logs.filter = LogFilter {
        agent: Some("Grok Bot".to_owned()),
        text: "delete".to_owned(),
        ..LogFilter::default()
    };
    let text = frames(&mut app, 4);
    for expected in [
        "No matches",
        "Clear Filters",
        "Mac mini (office)",
        "acme-billing",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("No activity yet"), "{text}");
}

/// A notification of a blocked request opens Logs, not Decisions, with its row asked for.
#[test]
fn a_notification_of_an_activity_line_opens_logs() {
    use crate::desktop::inbox::EventKey;
    use crate::desktop::notify::NotificationDestination;
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.ui.activity_scope.device = DeviceScope::Other(STUDIO.to_owned());
    app.ui.activity_scope.project = Some("shop".to_owned());
    let destination = NotificationDestination::Event {
        key: EventKey::Activity(7),
        vault_path: app.owner_ui.session.vault_path().unwrap(),
        session_epoch: app.owner_ui.session.epoch().unwrap(),
    };
    super::decisions::route_notification(&mut app, destination);
    assert_eq!(app.place, Place::Logs);
    assert_eq!(app.ui.logs.activity_id(), Some(7));
    assert_eq!(
        app.ui.activity_scope,
        ActivityScope::default(),
        "the row is of this Mac"
    );
    // ⌘[ in Logs leaves the selection.
    app.ui.logs.clear_selection();
    assert!(!app.ui.logs.has_selection());
}

/// No vault read per frame: many frames within 2 seconds compute once; a change reads
/// again after 2 seconds, and only then.
#[test]
fn the_pages_read_the_vault_at_most_every_two_seconds() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.place = Place::Overview;
    frames_from(&mut app, 0.1, 15);
    assert_eq!(app.ui.bouncer.computations, 1, "15 frames in 1.5 seconds");
    app.place = Place::Logs;
    frames_from(&mut app, 1.6, 3);
    assert_eq!(app.ui.bouncer.computations, 1, "Logs shares the cache");
    // An owner action sets a status message: the stamp moves.
    app.set_note("synthetic change");
    frames_from(&mut app, 1.9, 1);
    assert_eq!(app.ui.bouncer.computations, 1, "not within 2 seconds");
    frames_from(&mut app, 2.2, 5);
    assert_eq!(app.ui.bouncer.computations, 2, "once after 2 seconds");
    // A lock forgets the data.
    app.lock_vault(None);
    frames_from(&mut app, 3.0, 2);
    assert_eq!(app.ui.bouncer.computations, 0);
}
