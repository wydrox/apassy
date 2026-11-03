//! Tests of Decisions for the whole vault: the line of the week adds the feeds of the
//! other Macs in the device scope, the recent list mixes this Mac and the other Macs by
//! day and follows the scope, the detail shows the week by device and the most active
//! agents, a feed that left out uses says so, a past decision of another Mac shows
//! read-only, and Activity adds the uses of the feeds. Without another Mac the page
//! shows this Mac only. The feed is the example of relay-feed-v1 section 17.1, with
//! synthetic times. Synthetic values only.

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::decisions;
use super::decisions_activity::{self, Day, Source, day_of};
use super::draw;
use super::owner_tests::{collect, unlocked_app_with_item};
use crate::broker::action_kind::ActionKind;
use crate::desktop::remote_feeds::{
    ActivityScope, DeviceScope, FeedProblem, RemoteFeedState, RemoteMac,
};
use crate::desktop::{DesktopApp, Place};
use crate::questions::feed::{Feed, FeedUse};
use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};

const DEFAULT: Vec2 = Vec2::new(1180.0, 800.0);
const SMALLEST: Vec2 = Vec2::new(900.0, 600.0);
const WIDE: Vec2 = Vec2::new(1800.0, 1400.0);

/// The feed of relay-feed-v1 section 17.1.
const EXAMPLE_FEED: &str = r#"{"v":1,"mac":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"seq":1790000040,"generated_at":1790000040,"truncated":false,"week":{"by_you":3,"automatic":128},"agents":[{"id":"4","name":"Claude Code","host":"claude","where":"mac","revoked":false,"token_expires_at":1797776000,"last_use_at":1790000010,"uses_this_week":12,"projects":["synthetic-shop"],"note":"Deploys only from the main branch.","restricted":false,"actions":[{"action":"deploy","allowed":2,"not_allowed":1,"projects":["synthetic-shop"]}],"exceptions":[{"item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","item_title":"Shop database","kind":"never","created_at":1789990000}],"recent":[{"at":1790000010,"item":"8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e","item_title":"API token","action":"deploy","project":"synthetic-shop","command":"npm run deploy -- --token [apassy:secret]","outcome":"allowed","decided_by":"owner","answered_on":"Test iPhone"}]}]}"#;

const REMOTE_DEVICE: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";

fn now() -> u64 {
    super::kit::now()
}

/// The example feed with its use just now and a second use, not allowed, 10 days ago.
fn example_feed() -> Feed {
    let mut feed: Feed = serde_json::from_str(EXAMPLE_FEED).expect("the example feed");
    let now = now();
    let agent = &mut feed.agents[0];
    agent.recent[0].at = now;
    agent.recent.push(FeedUse {
        at: now - 10 * 86_400,
        item: None,
        item_title: "Shop database".to_owned(),
        action: "read".to_owned(),
        project: "synthetic-shop".to_owned(),
        command: String::new(),
        outcome: "denied".to_owned(),
        decided_by: "bouncer".to_owned(),
        answered_on: String::new(),
    });
    feed
}

fn ready_mac(feed: Feed) -> RemoteMac {
    RemoteMac {
        device: REMOTE_DEVICE.to_owned(),
        name: "MacBook Pro".to_owned(),
        state: RemoteFeedState::Ready(feed),
        received_at: now(),
        problem: None,
    }
}

/// An agent of this Mac with one use, allowed by the owner, in project `local-proj`.
fn local_use(app: &mut DesktopApp, item_id: u64) {
    let (agent, _) = app
        .owner_ui
        .session
        .register_agent("Local Agent")
        .expect("agent");
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault
                .record_item_use(&NewItemUse {
                    item_id,
                    agent_id: Some(agent.id),
                    agent_name: "Local Agent".to_owned(),
                    project_key: "/synthetic/local-proj".to_owned(),
                    project_label: "local-proj".to_owned(),
                    action: ActionKind::Read,
                    command_summary: "synthetic read".to_owned(),
                    hosts: Vec::new(),
                    outcome: UseOutcome::Allowed,
                    decided_by: UseDecidedBy::Owner,
                    answered_on: String::new(),
                    decision_log_id: None,
                })
                .expect("use");
        })
        .expect("open");
}

/// The app at Decisions with a local use and the feed of one other Mac.
fn vault_app(dir: &TempDir, feed: Feed) -> DesktopApp {
    let (mut app, item_id) = unlocked_app_with_item(dir);
    local_use(&mut app, item_id);
    app.remote_macs_pinned = true;
    app.remote_macs = vec![ready_mac(feed)];
    app.place = Place::Decisions;
    app
}

/// `frames` frames of the whole app at `size`. Returns the painted text of the last one,
/// and each text that runs past the right edge of its clip.
fn frames(app: &mut DesktopApp, size: Vec2, frames: usize) -> (String, Vec<String>) {
    let ctx = egui::Context::default();
    let mut text = String::new();
    let mut past = Vec::new();
    for _ in 0..frames {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        text.clear();
        past.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
            past_edge(&clipped.shape, clipped.clip_rect, size, &mut past);
        }
        output.drop_without_applying_deltas();
    }
    (text, past)
}

fn past_edge(shape: &egui::Shape, clip: Rect, size: Vec2, out: &mut Vec<String>) {
    match shape {
        egui::Shape::Text(text) => {
            let rect = text.galley.rect.translate(text.pos.to_vec2());
            let edge = clip.right().min(size.x) + 1.0;
            if rect.intersects(clip) && !text.galley.text().is_empty() && rect.right() > edge {
                out.push(text.galley.text().to_owned());
            }
        }
        egui::Shape::Vec(nested) => nested
            .iter()
            .for_each(|inner| past_edge(inner, clip, size, out)),
        _ => {}
    }
}

fn scope(device: DeviceScope, project: Option<&str>) -> ActivityScope {
    ActivityScope {
        device,
        project: project.map(str::to_owned),
    }
}

fn line(by_you: u64, automatic: u64) -> String {
    format!("{by_you} by you · {automatic} automatic this week")
}

#[test]
fn the_week_line_adds_the_feeds_in_the_device_scope() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    let local = app.owner_ui.session.week_counts().expect("counts");

    let (text, _) = frames(&mut app, WIDE, 3);
    let all = line(local.by_you + 3, local.automatic + 128);
    assert!(text.contains(&all), "{all}: {text}");

    app.ui.activity_scope = scope(DeviceScope::ThisMac, None);
    let (text, _) = frames(&mut app, WIDE, 3);
    let this_mac = line(local.by_you, local.automatic);
    assert!(text.contains(&this_mac), "{this_mac}: {text}");

    app.ui.activity_scope = scope(DeviceScope::Other(REMOTE_DEVICE.to_owned()), None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains(&line(3, 128)), "{text}");

    // The project does not change the totals.
    app.ui.activity_scope = scope(DeviceScope::All, Some("synthetic-shop"));
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains(&all), "{all}: {text}");

    // A Mac that has no feed now leaves the scope.
    app.ui.activity_scope = scope(DeviceScope::Other("gone".to_owned()), None);
    frames(&mut app, WIDE, 2);
    assert_eq!(app.ui.activity_scope.device, DeviceScope::All);
}

#[test]
fn the_scope_bar_gets_this_mac_the_ready_macs_and_the_projects() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    app.remote_macs.push(RemoteMac {
        device: "1a2b3c4d-0000-4000-8000-000000000001".to_owned(),
        name: "Mac mini".to_owned(),
        state: RemoteFeedState::NeedsSync,
        received_at: now(),
        problem: None,
    });
    let activity = decisions_activity::load(&app);
    assert_eq!(
        activity.devices,
        [
            (DeviceScope::ThisMac, "This Mac".to_owned()),
            (
                DeviceScope::Other(REMOTE_DEVICE.to_owned()),
                "MacBook Pro".to_owned()
            ),
        ],
        "only the Macs with a feed that opened"
    );
    assert_eq!(activity.projects, ["local-proj", "synthetic-shop"]);
}

#[test]
fn the_recent_list_mixes_this_mac_and_the_other_macs_by_day() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    let activity = decisions_activity::load(&app);
    let recent = activity.recent_in(&ActivityScope::default());
    assert_eq!(recent.len(), 3, "{recent:?}");
    assert!(
        recent.windows(2).all(|pair| pair[0].at >= pair[1].at),
        "newest first"
    );
    let remote = recent
        .iter()
        .find(|decision| decision.item == "API token")
        .expect("the use of the feed");
    assert_eq!(
        remote.source,
        Source::Other {
            device: REMOTE_DEVICE.to_owned(),
            name: "MacBook Pro".to_owned()
        }
    );
    assert_eq!(remote.title(), "Claude Code · API token");
    assert_eq!(remote.outcome_text(), "Allowed");
    assert_eq!(remote.decided_text(), "Answered on Test iPhone");
    let denied = recent
        .iter()
        .find(|decision| decision.item == "Shop database")
        .expect("the older use of the feed");
    assert_eq!(denied.outcome_text(), "Not allowed");
    assert_eq!(denied.decided_text(), "Automatic");
    let local = recent
        .iter()
        .find(|decision| decision.source == Source::ThisMac)
        .expect("the use of this Mac");
    assert_eq!(local.title(), "Local Agent · Guarded key");
    assert_eq!(local.decided_text(), "By you");

    let (text, past) = frames(&mut app, WIDE, 3);
    for expected in [
        "Nothing waits for you.",
        "A new question also shows as a macOS notification.",
        "Recent decisions",
        "Today",
        "Earlier",
        "Claude Code · API token",
        "Deploy · synthetic-shop · on MacBook Pro",
        "Allowed · Answered on Test iPhone",
        "Claude Code · Shop database",
        "Not allowed · Automatic",
        "Local Agent · Guarded key",
        "Read · local-proj · on This Mac",
        "Allowed · By you",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Nothing needs you"), "{text}");
    assert!(
        text.find("Today") < text.find("Earlier"),
        "Today comes first: {text}"
    );
    assert!(past.is_empty(), "{past:?}");
}

#[test]
fn the_recent_list_follows_the_device_and_the_project() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());

    app.ui.activity_scope = scope(DeviceScope::ThisMac, None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("Local Agent · Guarded key"), "{text}");
    assert!(!text.contains("Claude Code · API token"), "{text}");
    assert!(!text.contains("on MacBook Pro"), "{text}");

    app.ui.activity_scope = scope(DeviceScope::Other(REMOTE_DEVICE.to_owned()), None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("Claude Code · API token"), "{text}");
    assert!(!text.contains("Local Agent · Guarded key"), "{text}");

    app.ui.activity_scope = scope(DeviceScope::All, Some("synthetic-shop"));
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("Claude Code · API token"), "{text}");
    assert!(!text.contains("Local Agent · Guarded key"), "{text}");

    app.ui.activity_scope = scope(DeviceScope::ThisMac, Some("synthetic-shop"));
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("No decisions yet."), "{text}");
}

#[test]
fn the_days_follow_the_local_calendar() {
    // 14:13:20 UTC.
    let now = 1_790_000_000;
    let since_midnight = 51_200;
    assert_eq!(day_of(now - 3_600, now, 0), Day::Today);
    assert_eq!(day_of(now - since_midnight, now, 0), Day::Today);
    assert_eq!(day_of(now - since_midnight - 1, now, 0), Day::Yesterday);
    assert_eq!(
        day_of(now - since_midnight - 86_400, now, 0),
        Day::Yesterday
    );
    assert_eq!(
        day_of(now - since_midnight - 86_400 - 1, now, 0),
        Day::Earlier
    );
    // At UTC+10 it is 00:13:20 of the next day: 20 minutes ago is yesterday.
    assert_eq!(day_of(now - 1_200, now, 36_000), Day::Yesterday);
    assert_eq!(day_of(now - 600, now, 36_000), Day::Today);
    // The clock of another Mac runs ahead: today.
    assert_eq!(day_of(now + 600, now, 0), Day::Today);
}

#[test]
fn the_week_shows_each_device_and_the_most_active_agents() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    app.remote_macs.push(RemoteMac {
        device: "1a2b3c4d-0000-4000-8000-000000000001".to_owned(),
        name: "Mac mini".to_owned(),
        state: RemoteFeedState::NeedsUpdate,
        received_at: now(),
        problem: None,
    });
    let local = app.owner_ui.session.week_counts().expect("counts");
    let local_row = format!("{} by you · {} automatic", local.by_you, local.automatic);
    let (text, past) = frames(&mut app, WIDE, 3);
    for expected in [
        "All clear",
        "This week",
        "By you",
        "Automatic",
        "Devices",
        "This Mac",
        local_row.as_str(),
        "MacBook Pro",
        "3 by you · 128 automatic",
        "Mac mini",
        "Update Apassy to see the activity of Mac mini.",
        "Most active agents",
        "Claude Code",
        "12 uses · MacBook Pro",
        "Local Agent",
        "1 use · This Mac",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(
        text.find("12 uses · MacBook Pro") < text.find("1 use · This Mac"),
        "the most uses first: {text}"
    );
    assert!(past.is_empty(), "{past:?}");

    // One device: only its row, and no Mac without a feed.
    app.ui.activity_scope = scope(DeviceScope::ThisMac, None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(!text.contains("3 by you · 128 automatic"), "{text}");
    assert!(!text.contains("12 uses · MacBook Pro"), "{text}");
    assert!(!text.contains("Mac mini"), "{text}");
    assert!(text.contains("1 use · This Mac"), "{text}");
}

#[test]
fn a_truncated_feed_says_that_older_uses_stay_on_its_mac() {
    let dir = TempDir::new().expect("temp dir");
    let mut feed = example_feed();
    feed.truncated = true;
    let mut app = vault_app(&dir, feed);
    let note = "Some older uses are on MacBook Pro only.";
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains(note), "{text}");

    app.ui.activity_scope = scope(DeviceScope::ThisMac, None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(!text.contains(note), "{text}");
}

/// A Mac whose later feed no longer opens keeps the counts and the decisions of its last
/// good feed, and the list says why they are old (relay-feed-v1 section 7.4); in the
/// scope of this Mac only, the note goes.
#[test]
fn a_kept_feed_keeps_its_activity_and_says_why_it_is_old() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    app.remote_macs[0].problem = Some(FeedProblem::NeedsSync);
    let note = "Sync this vault to see the activity of MacBook Pro.";
    let activity = decisions_activity::gather(None, &[], &app.remote_macs);
    assert_eq!(
        activity.feed_notes(&DeviceScope::All),
        vec![note.to_owned()]
    );
    assert!(activity.unavailable.is_empty(), "its counts stay");
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains(note), "{text}");
    assert!(text.contains("API token"), "the old decisions stay: {text}");

    app.remote_macs[0].problem = Some(FeedProblem::NeedsUpdate);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(
        text.contains("Update Apassy to see the activity of MacBook Pro."),
        "{text}"
    );

    app.ui.activity_scope = scope(DeviceScope::ThisMac, None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(!text.contains("to see the activity of"), "{text}");
}

#[test]
fn a_decision_of_another_mac_shows_its_facts_read_only() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    let id = decisions_activity::load(&app)
        .recent
        .iter()
        .find(|decision| decision.item == "API token")
        .expect("the use of the feed")
        .id;
    decisions::select_past(&mut app, id);
    let (text, past) = frames(&mut app, WIDE, 3);
    assert_eq!(
        decisions::selected_past(&app),
        Some(id),
        "the key holds in each frame"
    );
    for expected in [
        "Decision",
        "Mac",
        "MacBook Pro",
        "Agent",
        "Claude Code",
        "Credential",
        "API token",
        "Action",
        "Deploy",
        "Project",
        "synthetic-shop",
        "Command",
        "npm run deploy -- --token [apassy:secret]",
        "Outcome",
        "Allowed",
        "Decided",
        "Answered on Test iPhone",
        "Time",
        "This decision was made on MacBook Pro. A change to the agent is made there.",
        "This Week",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(
        !text.contains("All clear"),
        "the detail shows the decision: {text}"
    );
    assert!(past.is_empty(), "{past:?}");

    // A scope without it: the detail shows the week again.
    decisions::select_past(&mut app, id);
    app.ui.activity_scope = scope(DeviceScope::ThisMac, None);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(!text.contains("npm run deploy"), "{text}");
    assert!(text.contains("All clear"), "{text}");
}

#[test]
fn without_other_macs_decisions_shows_this_mac() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.place = Place::Decisions;
    assert!(app.remote_macs.is_empty());
    let local = line(
        app.owner_ui.session.week_counts().expect("counts").by_you,
        app.owner_ui
            .session
            .week_counts()
            .expect("counts")
            .automatic,
    );
    for size in [DEFAULT, SMALLEST] {
        let (text, past) = frames(&mut app, size, 3);
        for expected in [
            "Decisions",
            local.as_str(),
            "Nothing waits for you.",
            "Recent decisions",
            "No decisions yet.",
            "All clear",
            "This week",
            "This Mac",
            "No agent used a credential this week.",
        ] {
            assert!(text.contains(expected), "{expected} at {size:?}: {text}");
        }
        assert!(!text.contains("on This Mac"), "one device: {text}");
        assert!(past.is_empty(), "past the edge at {size:?}: {past:?}");
    }
    let activity = decisions_activity::load(&app);
    assert_eq!(
        activity.devices,
        [(DeviceScope::ThisMac, "This Mac".to_owned())]
    );
    assert!(activity.recent.is_empty());
}

#[test]
fn the_recent_list_draws_at_the_smallest_size() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = vault_app(&dir, example_feed());
    for size in [DEFAULT, SMALLEST] {
        let (text, past) = frames(&mut app, size, 3);
        assert!(text.contains("Claude Code · API token"), "{size:?}: {text}");
        assert!(past.is_empty(), "past the edge at {size:?}: {past:?}");
    }
}
