//! Tests of Agents with the agents of the other Macs of the vault (relay-feed-v1, with a
//! Mac as the reader): a section for each Mac, the notes of a feed that does not open or
//! that this version does not read, the scope bar and its filters, the read-only page of
//! an agent of another Mac, and the compact page of an agent with no use. The feed is the
//! example of the contract (section 7.1). Synthetic values only.

use eframe::egui::{self, Event, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::owner_tests::{collect, unlocked_app_with_item};
use super::{agents, draw, kit};
use crate::desktop::remote_feeds::{ActivityScope, DeviceScope, RemoteFeedState, RemoteMac};
use crate::desktop::{DesktopApp, Place};
use crate::questions::feed::{Feed, FeedException};

const SIZE: Vec2 = Vec2::new(1400.0, 1600.0);
/// The device of the Mac of the contract's feed.
const DEVICE: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
const SYNC_DEVICE: &str = "5d0c1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f";
const UPDATE_DEVICE: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

/// The feed of the contract (section 17.1).
const FEED: &str = r#"{"v":1,"mac":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"seq":1790000040,"generated_at":1790000040,"truncated":false,"week":{"by_you":3,"automatic":128},"agents":[{"id":"4","name":"Claude Code","host":"claude","where":"mac","revoked":false,"token_expires_at":1797776000,"last_use_at":1790000010,"uses_this_week":12,"projects":["synthetic-shop"],"note":"Deploys only from the main branch.","restricted":false,"actions":[{"action":"deploy","allowed":2,"not_allowed":1,"projects":["synthetic-shop"]}],"exceptions":[{"item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","item_title":"Shop database","kind":"never","created_at":1789990000}],"recent":[{"at":1790000010,"item":"8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e","item_title":"API token","action":"deploy","project":"synthetic-shop","command":"npm run deploy -- --token [apassy:secret]","outcome":"allowed","decided_by":"owner","answered_on":"Test iPhone"}]}]}"#;

const DAY: u64 = 86_400;

/// The feed of the contract with a token that is valid for 30 more days, changed by
/// `edit`.
fn feed(edit: impl FnOnce(&mut Feed)) -> Feed {
    let mut feed: Feed = serde_json::from_str(FEED).expect("the feed of the contract");
    feed.agents[0].token_expires_at = kit::now() + 30 * DAY;
    edit(&mut feed);
    feed
}

/// A Mac of the vault whose feed came 5 minutes ago.
fn mac(device: &str, name: &str, state: RemoteFeedState) -> RemoteMac {
    RemoteMac {
        device: device.to_owned(),
        name: name.to_owned(),
        state,
        received_at: kit::now().saturating_sub(300),
    }
}

/// An unlocked vault with the agent "Codex" on this Mac, on Agents.
fn app_with_codex(dir: &TempDir) -> (DesktopApp, u64) {
    let (mut app, _) = unlocked_app_with_item(dir);
    let (agent, _) = app.owner_ui.session.register_agent("Codex").expect("agent");
    app.place = Place::Agents;
    (app, agent.id)
}

/// The MacBook Pro of the contract, a Mac whose feed does not open, and a Mac whose
/// feed has a newer form.
fn three_macs(feed: Feed) -> Vec<RemoteMac> {
    vec![
        mac(DEVICE, "MacBook Pro", RemoteFeedState::Ready(feed)),
        mac(SYNC_DEVICE, "Mac mini", RemoteFeedState::NeedsSync),
        mac(UPDATE_DEVICE, "Mac Studio", RemoteFeedState::NeedsUpdate),
    ]
}

/// One window that keeps its egui state between frames, with the painted texts and the
/// AccessKit names of the last frame.
struct Window {
    ctx: egui::Context,
    time: f64,
    text: String,
    texts: Vec<(String, Pos2)>,
    names: Vec<String>,
}

impl Window {
    fn new() -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        Self {
            ctx,
            time: 0.0,
            text: String::new(),
            texts: Vec::new(),
            names: Vec::new(),
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) {
        self.time += 0.1;
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(self.time),
            events,
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        self.names.clear();
        if let Some(update) = &output.platform_output.accesskit_update {
            for (_, node) in &update.nodes {
                if let Some(label) = node.label() {
                    self.names.push(label.to_owned());
                }
            }
        }
        self.text.clear();
        self.texts.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut self.text);
            positions(&clipped.shape, &mut self.texts);
        }
        output.drop_without_applying_deltas();
    }

    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..4 {
            self.frame(app, Vec::new());
        }
    }

    fn has(&self, needle: &str) -> bool {
        self.text.contains(needle)
    }

    fn named(&self, name: &str) -> bool {
        self.names.iter().any(|named| named == name)
    }

    /// The first painted text that is `needle`, a little inside it.
    fn first(&self, needle: &str) -> Pos2 {
        self.texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text))
    }

    /// The last painted text that is `needle`: in an open menu, its choice.
    fn last(&self, needle: &str) -> Pos2 {
        self.texts
            .iter()
            .rev()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text))
    }

    fn click_at(&mut self, app: &mut DesktopApp, at: Pos2) {
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        self.frame(app, vec![Event::PointerMoved(at)]);
        self.frame(app, vec![button(true)]);
        self.frame(app, vec![button(false)]);
        self.idle(app);
    }
}

fn positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| positions(inner, out)),
        _ => {}
    }
}

/// This Mac first, then each other Mac: its connected agents before its disconnected
/// ones, or the note of its feed. The count and a click select by device and agent.
#[test]
fn the_list_has_a_section_for_each_mac_with_its_agents_or_its_note() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, codex) = app_with_codex(&dir);
    app.remote_macs = three_macs(feed(|feed| {
        let mut old = feed.agents[0].clone();
        old.id = "5".to_owned();
        old.name = "Old agent".to_owned();
        old.revoked = true;
        old.uses_this_week = 0;
        // The feed lists it first: the list shows it after the connected agent.
        feed.agents.insert(0, old);
    }));
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "This Mac · 0 uses this week",
        "MacBook Pro · 12 uses this week",
        // The meta of "Old agent", whose subtitle it shortens.
        "Disconnected",
        "Sync this vault to see the agents of Mac mini",
        "Update Apassy to see the agents of Mac Studio",
        // Codex here and Claude Code on the MacBook Pro; "Old agent" is disconnected.
        "2 connected",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    assert!(window.first("This Mac").y < window.first("MacBook Pro").y);
    assert!(window.first("Claude Code").y < window.first("Old agent").y);
    assert!(window.first("MacBook Pro").y < window.first("Mac mini").y);
    // The sidebar counts the connected agents of every Mac.
    assert_eq!(agents::remote_connected(&app.remote_macs), 1);

    let at = window.first("Claude Code");
    window.click_at(&mut app, at);
    assert_eq!(
        app.ui.agents.remote,
        Some((DEVICE.to_owned(), "4".to_owned()))
    );
    assert_eq!(app.owner_ui.selected_agent, None);
    let at = window.first("Codex");
    window.click_at(&mut app, at);
    assert_eq!(app.owner_ui.selected_agent, Some(codex));
    assert_eq!(app.ui.agents.remote, None);
}

/// The scope narrows the list to one Mac or to the agents of one project, and the count
/// follows it.
#[test]
fn the_scope_filters_by_device_and_by_project() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_codex(&dir);
    app.remote_macs = three_macs(feed(|_| {}));
    let mut window = Window::new();

    app.ui.activity_scope = ActivityScope {
        device: DeviceScope::ThisMac,
        project: None,
    };
    window.idle(&mut app);
    assert!(window.has("Codex"), "{}", window.text);
    assert!(window.has("1 connected"), "{}", window.text);
    for absent in ["Claude Code", "Sync this vault", "Update Apassy to see"] {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }

    app.ui.activity_scope.device = DeviceScope::Other(DEVICE.to_owned());
    window.idle(&mut app);
    assert!(window.has("Claude Code"), "{}", window.text);
    assert!(window.has("1 connected"), "{}", window.text);
    for absent in ["Codex", "Sync this vault", "Update Apassy to see"] {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }

    app.ui.activity_scope = ActivityScope {
        device: DeviceScope::All,
        project: Some("synthetic-shop".to_owned()),
    };
    window.idle(&mut app);
    // Codex has no use in the project; the notes of the other Macs stay.
    assert!(window.has("Claude Code"), "{}", window.text);
    assert!(window.has("1 connected"), "{}", window.text);
    assert!(!window.has("Codex"), "{}", window.text);
    assert!(
        window.has("Sync this vault to see the agents of Mac mini"),
        "{}",
        window.text
    );

    app.ui.activity_scope.project = Some("another-project".to_owned());
    window.idle(&mut app);
    assert!(window.has("0 connected"), "{}", window.text);
    assert!(!window.has("Claude Code"), "{}", window.text);
}

/// The page of an agent of another Mac has the facts of its feed, and no action: a
/// change is made on that Mac.
#[test]
fn the_page_of_an_agent_of_another_mac_only_shows() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_codex(&dir);
    app.remote_macs = three_macs(feed(|_| {}));
    app.ui.agents.remote = Some((DEVICE.to_owned(), "4".to_owned()));
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "MacBook Pro · updated 5 min ago",
        "Uses this week",
        "12",
        "Projects",
        "synthetic-shop",
        "Credential names, never values",
        "Actions this week",
        "Deploy",
        "2 · synthetic-shop · 1 not allowed",
        "Recent",
        "API token",
        "Deploy in synthetic-shop · You allowed once, on Test iPhone",
        "Note for the bouncer",
        "Deploys only from the main branch.",
        "Exceptions",
        "Never: Shop database",
        "Change this agent on MacBook Pro.",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    for absent in [
        "Disconnect",
        "Remove",
        "Save Note",
        "Reconnect",
        "Some older uses",
        "No use this week",
    ] {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }
}

/// A feed that left uses out says where they are. A restricted agent sees its listed
/// items, a gone item is "A deleted credential", and an expired token is reconnected on
/// its Mac.
#[test]
fn a_cut_feed_a_restricted_agent_and_an_expired_token_say_so() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_codex(&dir);
    app.remote_macs = three_macs(feed(|feed| {
        feed.truncated = true;
        let agent = &mut feed.agents[0];
        agent.restricted = true;
        agent.token_expires_at = kit::now().saturating_sub(3 * DAY + 60);
        agent.exceptions.push(FeedException {
            item: None,
            item_title: String::new(),
            kind: "only".to_owned(),
            created_at: 1_789_990_000,
        });
    }));
    app.ui.agents.remote = Some((DEVICE.to_owned(), "4".to_owned()));
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "Some older uses are on MacBook Pro only.",
        "Only 1 credential, never values",
        "Only: A deleted credential",
        "Expired 3 days ago. Reconnect on MacBook Pro.",
        "Token expired",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    assert!(!window.has("Reconnect…"), "{}", window.text);
}

/// With no use this week, one row says so instead of a count and an empty group; with
/// no exception, one gray line instead of a group. On both Macs.
#[test]
fn an_agent_with_no_use_and_no_exception_has_a_compact_page() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, codex) = app_with_codex(&dir);
    app.remote_macs = three_macs(feed(|feed| {
        let agent = &mut feed.agents[0];
        agent.uses_this_week = 0;
        agent.actions.clear();
        agent.exceptions.clear();
        agent.recent.clear();
        agent.note.clear();
    }));
    let mut window = Window::new();
    let absent = [
        "Uses this week",
        "Actions this week",
        "No actions yet",
        "Exceptions",
        "None. Exceptions",
        "Recent",
    ];

    app.ui.agents.remote = Some((DEVICE.to_owned(), "4".to_owned()));
    window.idle(&mut app);
    for expected in [
        "No use this week",
        "No exceptions. They come from your answers in Decisions.",
        "Change this agent on MacBook Pro.",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    for absent in absent.iter().chain(&["Note for the bouncer"]) {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }

    app.owner_ui.selected_agent = Some(codex);
    window.idle(&mut app);
    for expected in [
        "This Mac · connected just now",
        "No use this week",
        "No exceptions. They come from your answers in Decisions.",
        "Disconnect Codex…",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    for absent in absent {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }
}

/// One device and no project: no bar. With another Mac, "Showing [All devices] in [All
/// projects]", each menu named with its value; a choice changes the scope.
#[test]
fn the_scope_bar_shows_with_a_choice_and_its_menus_change_the_scope() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_codex(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    for absent in ["Showing", "All devices", "All projects"] {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }

    app.remote_macs = vec![mac(
        DEVICE,
        "MacBook Pro",
        RemoteFeedState::Ready(feed(|_| {})),
    )];
    window.idle(&mut app);
    for expected in ["Showing", "All devices", "All projects"] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    assert!(window.named("Devices, All devices"), "{:?}", window.names);
    assert!(window.named("Projects, All projects"), "{:?}", window.names);

    let at = window.first("All devices");
    window.click_at(&mut app, at);
    let at = window.last("MacBook Pro");
    window.click_at(&mut app, at);
    assert_eq!(
        app.ui.activity_scope.device,
        DeviceScope::Other(DEVICE.to_owned())
    );
    assert!(window.named("Devices, MacBook Pro"), "{:?}", window.names);
    assert!(!window.has("Codex"), "{}", window.text);

    let at = window.first("All projects");
    window.click_at(&mut app, at);
    let at = window.last("synthetic-shop");
    window.click_at(&mut app, at);
    assert_eq!(
        app.ui.activity_scope.project,
        Some("synthetic-shop".to_owned())
    );
    assert!(
        window.named("Projects, synthetic-shop"),
        "{:?}",
        window.names
    );
}
