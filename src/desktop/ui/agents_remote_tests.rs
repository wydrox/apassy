//! Window tests of Bouncer > Agents (implementation-plan-bouncer-section §5, U3b-2): a
//! table for each environment with its header, the read-only page of an agent of another
//! Mac, the remote access block (read on a worker thread: no Tailscale command line in a
//! frame), its problems 8a and 8d with their buttons, "Choose Credentials…" through the
//! owner check to the items of the relay agent, "Disconnect…" of both kinds, and the
//! connect card of Decisions through the owner check. The feed is the example of the
//! contract (section 7.1); the node and Tailscale are fakes. Synthetic values only.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use eframe::egui::{self, Event, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::bouncer::AgentRef;
use super::node_tests::{Fixture, fixture, offered, offered_to, until};
use super::owner_tests::{PASS, collect, socket_dir, unlocked_app_with_item};
use super::{agents, agents_page, decisions, draw, kit};
use crate::broker::approvals::OwnerCheck;
use crate::desktop::node::NodeFlows;
use crate::desktop::remote_feeds::{DeviceScope, RemoteFeedState, RemoteMac};
use crate::desktop::{DesktopApp, Place};
use crate::node::funnel::tests::{FakeCli, serve_443_only, serve_with_8443};
use crate::node::funnel::{CliOutput, TailscaleCli};
use crate::node::master_key::tests::FakeKeys;
use crate::node::tests::FakeBackend;
use crate::node::{Node, NodeOptions};
use crate::questions::feed::Feed;

const SIZE: Vec2 = Vec2::new(1400.0, 1600.0);
/// The device of the Mac of the contract's feed.
const DEVICE: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
const SYNC_DEVICE: &str = "5d0c1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f";
const UPDATE_DEVICE: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

/// The feed of the contract (section 17.1).
const FEED: &str = r#"{"v":1,"mac":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"seq":1790000040,"generated_at":1790000040,"truncated":false,"week":{"by_you":3,"automatic":128},"agents":[{"id":"4","name":"Claude Code","host":"claude","where":"mac","revoked":false,"token_expires_at":1797776000,"last_use_at":1790000010,"uses_this_week":12,"projects":["synthetic-shop"],"note":"Deploys only from the main branch.","restricted":false,"actions":[{"action":"deploy","allowed":2,"not_allowed":1,"projects":["synthetic-shop"]}],"exceptions":[{"item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","item_title":"Shop database","kind":"never","created_at":1789990000}],"recent":[{"at":1790000010,"item":"8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e","item_title":"API token","action":"deploy","project":"synthetic-shop","command":"npm run deploy -- --token [apassy:secret]","outcome":"allowed","decided_by":"owner","answered_on":"Test iPhone"}]}]}"#;

fn feed() -> Feed {
    serde_json::from_str(FEED).expect("the feed of the contract")
}

/// A Mac of the vault whose feed came 5 minutes ago.
fn mac(device: &str, name: &str, state: RemoteFeedState) -> RemoteMac {
    RemoteMac {
        device: device.to_owned(),
        name: name.to_owned(),
        state,
        received_at: kit::now().saturating_sub(300),
        problem: None,
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
fn three_macs() -> Vec<RemoteMac> {
    vec![
        mac(DEVICE, "MacBook Pro", RemoteFeedState::Ready(feed())),
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

    /// Frames until `needle` shows (a worker thread answers), at most 20 seconds.
    fn until_shows(&mut self, app: &mut DesktopApp, needle: &str) {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            self.frame(app, Vec::new());
            if self.has(needle) {
                return;
            }
            assert!(
                Instant::now() < end,
                "\"{needle}\" never showed: {}",
                self.text
            );
            std::thread::sleep(Duration::from_millis(20));
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

    /// The last painted text that is `needle`.
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

    fn key(&mut self, app: &mut DesktopApp, key: egui::Key, modifiers: Modifiers) {
        let press = |pressed| Event::Key {
            key,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers,
        };
        self.frame(app, vec![press(true)]);
        self.frame(app, vec![press(false)]);
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

/// This Mac first, then each other Mac with its header and its own table, or the note of
/// a feed that this Mac cannot show.
#[test]
fn each_environment_has_its_own_table_and_header() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_codex(&dir);
    app.remote_macs_pinned = true;
    app.remote_macs = three_macs();
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "Agents",
        "2 agents",
        "This Mac",
        "Codex",
        "MacBook Pro",
        "Read-only",
        "Claude Code",
        "synthetic-shop",
        "Agent",
        "Project",
        "Status",
        "Runs Today",
        "Asks You",
        "Sync this vault to see the agents of Mac mini.",
        "Update Apassy to see the agents of Mac Studio.",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    assert!(window.first("Codex").y < window.first("Claude Code").y);
    assert!(
        window.named("Environments, All Environments"),
        "{:?}",
        window.names
    );
    assert!(window.named("Projects, All Projects"), "{:?}", window.names);
    // No vault read for the table in a frame: the cache computes once per step.
    let before = app.ui.bouncer.computations;
    window.frame(&mut app, Vec::new());
    assert!(app.ui.bouncer.computations <= before + 1);

    // One Mac in the scope: its table only.
    app.ui.activity_scope.device = DeviceScope::Other(DEVICE.to_owned());
    window.idle(&mut app);
    assert!(window.has("Claude Code"), "{}", window.text);
    assert!(!window.has("Codex"), "{}", window.text);
}

/// A row opens the page of the agent; an agent of another Mac only shows, and "‹ Agents"
/// (⌘[) goes back.
#[test]
fn a_row_opens_the_read_only_page_of_an_agent_of_another_mac() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_codex(&dir);
    app.remote_macs_pinned = true;
    app.remote_macs = three_macs();
    let mut window = Window::new();
    window.idle(&mut app);
    let at = window.first("Claude Code");
    window.click_at(&mut app, at);
    assert_eq!(
        app.ui.agent_page.open,
        Some(AgentRef::Other {
            device: DEVICE.to_owned(),
            id: "4".to_owned()
        })
    );
    for expected in [
        "Claude Code",
        "Read-only",
        "Runs",
        "Asked you",
        "Denied",
        "Recent runs",
        "npm run deploy -- --token [apassy:secret]",
        "API token · Allowed on Test iPhone",
        "Note for the bouncer",
        "Deploys only from the main branch.",
        "Change on MacBook Pro.",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    for absent in [
        "Disconnect…",
        "Choose Credentials…",
        "Median answer",
        "Remove",
        "9999",
    ] {
        assert!(!window.has(absent), "{absent}: {}", window.text);
    }
    window.key(&mut app, egui::Key::OpenBracket, Modifiers::COMMAND);
    assert_eq!(app.ui.agent_page.open, None);
    assert!(window.has("Runs Today"), "{}", window.text);

    // A local agent opens its own page, with what it can see and Disconnect.
    let at = window.first("Codex");
    window.click_at(&mut app, at);
    assert!(matches!(app.ui.agent_page.open, Some(AgentRef::Local(_))));
    for expected in [
        "Codex",
        "Choose what it can see",
        "No runs yet",
        "Disconnect…",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
}

/// A Tailscale command line that notes the thread of each call.
struct ThreadCli {
    inner: FakeCli,
    threads: Mutex<Vec<ThreadId>>,
}

impl TailscaleCli for ThreadCli {
    fn run(&self, args: &[&str]) -> Option<CliOutput> {
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        self.inner.run(args)
    }
}

/// An app on Agents with a node of fakes and the Tailscale command line `cli`.
fn app_with_node(dir: &TempDir, cli: Arc<dyn TailscaleCli>) -> (DesktopApp, Arc<Node>) {
    let (mut app, _) = unlocked_app_with_item(dir);
    app.start_broker(&socket_dir(dir));
    let node = Arc::new(Node::new(NodeOptions {
        backend: Arc::new(FakeBackend::default()),
        keys: Arc::new(FakeKeys::empty()),
        cli,
        data_dir: dir.path().join("node"),
    }));
    app.node = NodeFlows::with_node(Arc::clone(&node));
    app.place = Place::Agents;
    (app, node)
}

/// The block reads Tailscale on a worker thread: a frame never runs its command line.
#[test]
fn the_remote_access_block_runs_no_tailscale_command_on_the_ui_thread() {
    let dir = TempDir::new().expect("temp dir");
    let cli = Arc::new(ThreadCli {
        inner: FakeCli::connected(serve_443_only()),
        threads: Mutex::new(Vec::new()),
    });
    let (mut app, _) = app_with_node(&dir, cli.clone());
    let mut window = Window::new();
    window.frame(&mut app, Vec::new());
    assert!(window.has("Checking Tailscale…"), "{}", window.text);
    window.until_shows(&mut app, "Cloud agents can reach this Mac");
    while window.has("Checking Tailscale…") {
        window.frame(&mut app, Vec::new());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(window.has("Remote Access"), "{}", window.text);
    assert!(window.named("Remote Access"), "{:?}", window.names);
    for _ in 0..10 {
        window.frame(&mut app, Vec::new());
    }
    let threads = cli.threads.lock().unwrap().clone();
    assert!(!threads.is_empty(), "the block read Tailscale");
    let ui_thread = std::thread::current().id();
    assert!(
        threads.iter().all(|thread| *thread != ui_thread),
        "a Tailscale command ran on the UI thread"
    );
    // Ten frames within the interval read nothing again.
    assert_eq!(app.node.access.reads, 1);
}

/// 8a: no Tailscale. The switch cannot go on; "Get Tailscale…" opens its page.
#[test]
fn without_tailscale_the_block_offers_get_tailscale() {
    let dir = TempDir::new().expect("temp dir");
    let cli = Arc::new(FakeCli {
        installed: false,
        ..FakeCli::connected(serve_443_only())
    });
    let (mut app, _) = app_with_node(&dir, cli);
    let mut window = Window::new();
    window.until_shows(&mut app, "Tailscale is not installed.");
    assert!(window.has("Get Tailscale…"), "{}", window.text);
    agents::OPENED.with(|opened| opened.borrow_mut().clear());
    let at = window.last("Get Tailscale…");
    window.click_at(&mut app, at);
    let opened = agents::OPENED.with(|opened| opened.borrow().clone());
    assert_eq!(opened, [agents_page::TAILSCALE_DOWNLOAD]);
}

/// 8d: another program has port 8443. "Use Port 10000" moves the route there.
#[test]
fn a_taken_port_offers_port_10000() {
    let dir = TempDir::new().expect("temp dir");
    let cli = Arc::new(FakeCli::connected(serve_with_8443(
        "http://127.0.0.1:8080",
        true,
    )));
    let (mut app, node) = app_with_node(&dir, cli);
    app.owner_ui
        .session
        .with_vault(|vault| vault.set_cloud_route_on(true).expect("route"))
        .expect("open vault");
    let mut window = Window::new();
    let end = Instant::now() + Duration::from_secs(20);
    while !window.has("Another app uses port 8443.") {
        assert!(Instant::now() < end, "no port problem: {}", window.text);
        app.sync_node(&window.ctx);
        app.check_remote_access_again();
        window.frame(&mut app, Vec::new());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(window.has("Use Port 10000"), "{}", window.text);
    let at = window.last("Use Port 10000");
    window.click_at(&mut app, at);
    assert_eq!(node.funnel_port(), 10000);
    assert!(
        app.status_text.contains("port 10000"),
        "{}",
        app.status_text
    );
}

/// The fixture of `node_tests` with Grok Bot connected through an allowed connect request.
fn connected() -> (Fixture, egui::Context, u64, u64) {
    let mut fx = fixture();
    let ctx = egui::Context::default();
    until(&ctx, &mut fx.app, "the node runs", |app| {
        app.node.running_for.is_some()
    });
    let connect = offered(&fx, "cr_grok", "client_grok");
    fx.app.ask_allow_connect(&connect, Some(&ctx));
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let agent = fx.app.remote_agents()[0].agent_id;
    let item = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.search("httpbin").expect("search")[0].id)
        .expect("open vault");
    (fx, ctx, agent, item)
}

fn relay_items(fx: &Fixture) -> Vec<String> {
    fx.backend
        .state
        .lock()
        .unwrap()
        .agents
        .values()
        .find(|(name, _, _)| name == "Grok Bot")
        .map(|(_, items, _)| items.clone())
        .unwrap_or_default()
}

/// "Choose Credentials…": an added credential asks the owner first, then the relay
/// agent gets it; a removed one goes at once.
#[test]
fn choose_credentials_changes_the_items_of_the_relay_agent_after_the_owner_check() {
    let (mut fx, ctx, agent, item) = connected();
    assert!(
        relay_items(&fx).is_empty(),
        "a new remote agent sees nothing"
    );
    fx.app.ui.agents.choosing = Some(agents::Choosing {
        agent_id: agent,
        before: BTreeSet::new(),
        chosen: [item].into_iter().collect(),
        search: String::new(),
    });
    agents::save_choice(&mut fx.app, &ctx, agent, "Grok Bot");
    let text = fx
        .app
        .owner
        .check
        .as_ref()
        .map(|dialog| dialog.request.describe())
        .expect("the owner check");
    assert!(
        text.contains("Grok Bot") && text.contains("1 more credential"),
        "{text}"
    );
    assert!(relay_items(&fx).is_empty(), "nothing before the check");
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(relay_items(&fx).len(), 1, "{}", fx.app.status_text);
    let listed = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.visible_items_for_agent(agent).expect("view"))
        .expect("open vault");
    assert_eq!(listed, Some([item].into_iter().collect()));

    // Removing takes access away: no check, and the relay agent loses it.
    fx.app.ui.agents.choosing = Some(agents::Choosing {
        agent_id: agent,
        before: [item].into_iter().collect(),
        chosen: BTreeSet::new(),
        search: String::new(),
    });
    agents::save_choice(&mut fx.app, &ctx, agent, "Grok Bot");
    assert!(fx.app.owner.check.is_none());
    assert!(relay_items(&fx).is_empty());
}

/// "Disconnect…" of a remote agent revokes it on the node too; of a local agent, in the
/// vault. Neither asks the owner: it takes authority away.
#[test]
fn disconnect_works_for_a_remote_and_a_local_agent() {
    let (mut fx, _ctx, agent, _) = connected();
    assert!(agents::disconnect_agent(
        &mut fx.app,
        agent,
        "Grok Bot",
        true
    ));
    assert!(fx.app.owner.check.is_none());
    let revoked = fx
        .backend
        .state
        .lock()
        .unwrap()
        .agents
        .values()
        .any(|(name, _, revoked)| name == "Grok Bot" && *revoked);
    assert!(revoked, "the relay agent is revoked");
    assert!(fx.app.remote_agents().is_empty());

    let (local, _) = fx
        .app
        .owner_ui
        .session
        .register_agent("Codex")
        .expect("agent");
    assert!(agents::disconnect_agent(
        &mut fx.app,
        local.id,
        "Codex",
        false
    ));
    let agents = fx.app.owner_ui.session.agents().expect("agents");
    assert!(agents.iter().any(|a| a.id == local.id && a.revoked));
}

/// The connect card of Decisions: the code, where the code goes back, and one warning
/// line; Allow opens the owner check for exactly that request, Deny needs none.
#[test]
fn the_connect_card_goes_through_the_owner_check() {
    let mut fx = fixture();
    let ctx = egui::Context::default();
    until(&ctx, &mut fx.app, "the node runs", |app| {
        app.node.running_for.is_some()
    });
    let connect = offered(&fx, "cr_card", "client_card");
    fx.app.place = Place::Decisions;
    let mut window = Window::new();
    window.idle(&mut fx.app);
    assert!(window.has("Grok Bot wants to connect"), "{}", window.text);
    decisions::select_key(
        &mut fx.app,
        decisions::Key::Connect(decisions::connect_key(&connect.id)),
    );
    window.idle(&mut fx.app);
    for expected in [
        "Grok Bot wants to connect",
        "Code",
        "K7Q-4MD",
        "Returns to grok.example",
        "Deny unless you just added Apassy to Grok Bot.",
        "Deny",
        "Allow",
        "left",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
    assert!(
        !window.has(crate::questions::envelope::LOCAL_CONNECT_WARNING),
        "{}",
        window.text
    );
    let at = window.last("Allow");
    window.click_at(&mut fx.app, at);
    let text = fx
        .app
        .owner
        .check
        .as_ref()
        .map(|dialog| dialog.request.describe())
        .expect("Allow asks the owner");
    assert!(text.contains("K7Q-4MD"), "{text}");
    assert!(
        fx.backend.state.lock().unwrap().decided.is_empty(),
        "nothing before the check"
    );
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(
        fx.backend
            .state
            .lock()
            .unwrap()
            .decided
            .iter()
            .any(|(id, _)| id == "cr_card")
    );
}

/// A connect request whose code goes back to a program on a computer: the card says so
/// and warns that a program on this Mac can start it.
#[test]
fn the_connect_card_warns_about_a_local_redirect() {
    let mut fx = fixture();
    let ctx = egui::Context::default();
    until(&ctx, &mut fx.app, "the node runs", |app| {
        app.node.running_for.is_some()
    });
    let connect = offered_to(&fx, "cr_local", "client_local", "127.0.0.1");
    assert!(crate::node::connect_is_local(&connect));
    fx.app.place = Place::Decisions;
    let mut window = Window::new();
    window.idle(&mut fx.app);
    decisions::select_key(
        &mut fx.app,
        decisions::Key::Connect(decisions::connect_key(&connect.id)),
    );
    window.idle(&mut fx.app);
    for expected in [
        crate::node::connect_returns_to(&connect).as_str(),
        "Returns to a program on a computer (localhost)",
        crate::questions::envelope::LOCAL_CONNECT_WARNING,
        "Deny unless you just added Apassy to Grok Bot.",
    ] {
        assert!(window.has(expected), "{expected}: {}", window.text);
    }
}

/// Frame 9a: "Turn On Remote Access" of the Overview asks for Touch ID and turns the route
/// on at once, with no detour through Agents.
#[test]
fn turn_on_remote_access_of_the_overview_asks_the_owner_and_turns_the_route_on() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_node(&dir, Arc::new(FakeCli::connected(serve_443_only())));
    app.place = Place::Overview;
    let mut window = Window::new();
    window.idle(&mut app);
    let at = window.last("Turn On Remote Access");
    window.click_at(&mut app, at);
    assert_eq!(app.place, Place::Overview, "it stays on the Overview");
    let text = app
        .owner
        .check
        .as_ref()
        .map(|dialog| dialog.request.describe())
        .expect("the owner check");
    assert!(text.contains("Turn on remote access"), "{text}");
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let on = app
        .owner_ui
        .session
        .with_vault(|vault| vault.cloud_node_setting().expect("setting").route_on)
        .expect("open vault");
    assert!(on, "{}", app.status_text);
}
