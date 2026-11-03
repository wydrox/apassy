//! Headless tests of the node in the window (ADR 0037, cloud slice): it starts for an
//! unlocked vault with the route on and a cloud agent, a close of the window keeps the
//! app open while it runs, and a lock and a quit stop it and turn the Funnel route off.
//! The node and the Tailscale command line are fakes; all values are synthetic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, RawInput, ViewportCommand, ViewportEvent, ViewportId, ViewportInfo};
use tempfile::TempDir;

use super::owner_tests::{PASS, socket_dir, unlocked_app_with_item};
use crate::contracts::CredentialKind;
use crate::desktop::node::{KEPT_OPEN, NodeFlows};
use crate::desktop::{BrokerState, DesktopApp};
use crate::node::funnel::tests::{FakeCli, serve_443_only};
use crate::node::master_key::tests::FakeKeys;
use crate::node::tests::FakeBackend;
use crate::node::{Node, NodeOptions};
use crate::vault::{EnvDelivery, Field, ItemDraft, SecretValue};

struct Fixture {
    _dir: TempDir,
    app: DesktopApp,
    node: Arc<Node>,
    backend: FakeBackend,
    cli: Arc<FakeCli>,
}

/// An unlocked app with a running broker, a node of fakes, a placeholder item, the
/// route on, and one cloud agent. Adding the agent starts the node.
fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.start_broker(&socket_dir(&dir));
    let backend = FakeBackend::default();
    let cli = Arc::new(FakeCli::connected(serve_443_only()));
    let node = Arc::new(Node::new(NodeOptions {
        backend: Arc::new(backend.clone()),
        keys: Arc::new(FakeKeys::empty()),
        cli: cli.clone(),
        data_dir: dir.path().join("node"),
    }));
    app.node = NodeFlows::with_node(Arc::clone(&node));
    let item = app
        .owner_ui
        .session
        .with_vault(|vault| {
            let item = vault
                .add(ItemDraft {
                    title: "httpbin".to_owned(),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".to_owned(),
                        value: SecretValue::new("SYNTH-window-httpbin-0123456789".to_owned()),
                        secret: true,
                    }],
                })
                .expect("add")
                .id;
            vault
                .set_env_binding_with(
                    item,
                    "SYNTH_HTTPBIN_TOKEN",
                    "token",
                    &EnvDelivery::Placeholder(vec!["httpbingo.org".to_owned()]),
                )
                .expect("binding");
            vault.set_cloud_route_on(true).expect("route");
            item
        })
        .expect("open vault");
    let BrokerState::Running(broker) = &app.broker else {
        panic!("the broker runs");
    };
    let context = broker.context();
    node.add_agent(
        &app.owner_ui.session.shared_vault(),
        context,
        "Grok Bot",
        &[item],
        90,
    )
    .expect("a cloud agent");
    Fixture {
        _dir: dir,
        app,
        node,
        backend,
        cli,
    }
}

/// One frame of `logic` with a close request of the window when `close` is true.
/// Returns the commands of the root viewport.
fn frame(ctx: &egui::Context, app: &mut DesktopApp, close: bool) -> Vec<ViewportCommand> {
    let mut input = RawInput::default();
    input.viewports.insert(
        ViewportId::ROOT,
        ViewportInfo {
            events: if close {
                vec![ViewportEvent::Close]
            } else {
                Vec::new()
            },
            ..ViewportInfo::default()
        },
    );
    let output = ctx.run_ui(input, |ui| {
        app.sync_node(ui.ctx());
        app.keep_open_for_node(ui.ctx());
    });
    let commands = output.viewport_output[&ViewportId::ROOT].commands.clone();
    output.drop_without_applying_deltas();
    commands
}

/// The route went off, and the Serve state of the fake is the owner's 443 handler only.
fn route_turned_off(cli: &FakeCli) -> bool {
    cli.calls()
        .iter()
        .any(|call| call == "funnel --https=8443 off")
        && *cli.serve.lock().unwrap() == serve_443_only()
}

/// Run frames until `done` holds.
fn until(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    what: &str,
    done: impl Fn(&DesktopApp) -> bool,
) {
    let end = Instant::now() + Duration::from_secs(20);
    while !done(app) {
        assert!(Instant::now() < end, "timed out: {what}");
        // Each comparison waits for its interval: force the next one.
        app.node_changed();
        frame(ctx, app, false);
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_node_follows_the_vault_and_a_close_keeps_the_app_open_while_it_runs() {
    let mut fx = fixture();
    let ctx = egui::Context::default();
    let epoch = fx.app.owner_ui.session.epoch().expect("unlocked");
    until(
        &ctx,
        &mut fx.app,
        "the window takes the running node",
        |app| app.node.running_for == Some(epoch),
    );
    assert!(fx.app.node_running());

    // A close while it runs: cancelled, and the window is minimized.
    let commands = frame(&ctx, &mut fx.app, true);
    assert!(
        commands.contains(&ViewportCommand::CancelClose),
        "{commands:?}"
    );
    assert!(
        commands.contains(&ViewportCommand::Minimized(true)),
        "{commands:?}"
    );
    assert_eq!(fx.app.status_text, KEPT_OPEN);

    // A lock stops it at once, and the route goes off. (A route check of the window may
    // run beside it, so the calls are not compared in order.)
    fx.cli.calls.lock().unwrap().clear();
    fx.app.lock_vault(Some(&ctx));
    assert!(!fx.node.is_running());
    assert!(fx.backend.state.lock().unwrap().stopped);
    assert!(route_turned_off(&fx.cli));
    assert_eq!(fx.app.node.running_for, None);
    // Now a close quits: nothing cancels it.
    let commands = frame(&ctx, &mut fx.app, true);
    assert!(
        !commands.contains(&ViewportCommand::CancelClose),
        "{commands:?}"
    );

    // An unlock starts it again for the new session.
    fx.app.owner_ui.session.unlock(PASS).expect("unlock");
    let epoch = fx.app.owner_ui.session.epoch().expect("unlocked");
    until(&ctx, &mut fx.app, "the node starts again", |app| {
        app.node.running_for == Some(epoch)
    });
    assert!(fx.node.is_running());
    assert_eq!(fx.backend.state.lock().unwrap().starts, 2);

    // The route off: the node stops at the next comparison.
    let vault = fx.app.owner_ui.session.shared_vault();
    fx.node.set_route(&vault, false).expect("route off");
    until(&ctx, &mut fx.app, "the window sees the stop", |app| {
        app.node.running_for.is_none()
    });
    assert!(!fx.node.is_running());

    // The route on again, then a quit: it stops, and the route goes off.
    fx.node.set_route(&vault, true).expect("route on");
    until(&ctx, &mut fx.app, "the node starts for the route", |app| {
        app.node.running_for.is_some()
    });
    fx.cli.calls.lock().unwrap().clear();
    fx.app.shut_down();
    assert!(!fx.node.is_running());
    assert!(route_turned_off(&fx.cli));
}

#[test]
fn without_a_backend_there_is_no_node_and_a_close_quits() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    assert!(app.cloud_node().is_none());
    let ctx = egui::Context::default();
    let commands = frame(&ctx, &mut app, true);
    assert!(!commands.contains(&ViewportCommand::CancelClose));
    assert!(!app.node_running());
}

/// The delay of the next frame that one comparison of the node asks for, after two
/// empty frames that settle egui. `Duration::MAX`: no frame.
fn asked_repaint(ctx: &egui::Context, app: &mut DesktopApp) -> Duration {
    for _ in 0..2 {
        ctx.run_ui(RawInput::default(), |_| {})
            .drop_without_applying_deltas();
    }
    let output = ctx.run_ui(RawInput::default(), |ui| app.sync_node(ui.ctx()));
    let delay = output.viewport_output[&ViewportId::ROOT].repaint_delay;
    output.drop_without_applying_deltas();
    delay
}

/// The node woke the window each second to compare it with the vault, also while the
/// window was minimized. A frame between two comparisons now asks for no frame of its
/// own; with no frame the window looks again after `IDLE_SYNC_INTERVAL` while the vault
/// is unlocked, and not at all while it is locked. A new vault session is compared at
/// once, and `node_changed` wakes the window.
#[test]
fn the_node_wakes_an_idle_window_only_rarely() {
    use crate::desktop::node::IDLE_SYNC_INTERVAL;
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    // A node of fakes, with the route off: it does not start.
    app.node = NodeFlows::with_node(Arc::new(Node::new(NodeOptions {
        backend: Arc::new(FakeBackend::default()),
        keys: Arc::new(FakeKeys::empty()),
        cli: Arc::new(FakeCli::connected(serve_443_only())),
        data_dir: dir.path().join("node"),
    })));
    let ctx = egui::Context::default();
    let idle = |delay: Duration| {
        delay > IDLE_SYNC_INTERVAL - Duration::from_secs(1) && delay <= IDLE_SYNC_INTERVAL
    };
    let delay = asked_repaint(&ctx, &mut app);
    assert!(idle(delay), "the first comparison: {delay:?}");
    assert_eq!(
        asked_repaint(&ctx, &mut app),
        Duration::MAX,
        "a frame between two comparisons"
    );

    // A lock is a new session: compared at once, and nothing is asked while locked.
    app.lock_vault(Some(&ctx));
    assert_eq!(asked_repaint(&ctx, &mut app), Duration::MAX, "locked");
    assert_eq!(asked_repaint(&ctx, &mut app), Duration::MAX, "still locked");

    // An unlock is compared at once, also within a second of the last comparison.
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let delay = asked_repaint(&ctx, &mut app);
    assert!(idle(delay), "after the unlock: {delay:?}");

    // A change of the owner wakes the window at once.
    app.node_changed();
    let output = ctx.run_ui(RawInput::default(), |_| {});
    assert_eq!(
        output.viewport_output[&ViewportId::ROOT].repaint_delay,
        Duration::ZERO
    );
    output.drop_without_applying_deltas();
    assert!(!app.node_running());
}
