//! Headless tests of the node in the window (ADR 0037, cloud slice): it starts for an
//! unlocked vault with the route (remote access) on, a close of the window keeps the
//! app open while it runs, and a lock and a quit stop it and turn the Funnel route off.
//! Remote agents connect through it: Allow on a connect card asks for the owner check,
//! and `apassy agent add-remote` prints its token once after the check. The node and the
//! Tailscale command line are fakes; all values are synthetic.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui::{self, RawInput, ViewportCommand, ViewportEvent, ViewportId, ViewportInfo};
use tempfile::TempDir;

use super::owner_tests::{PASS, socket_dir, unlocked_app_with_item};
use crate::broker::approvals::OwnerCheck;
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::node::{KEPT_OPEN, NodeFlows};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_socket::Envelope;
use crate::node::backend::{ConnectDecision, PendingConnect, TokenIssue};
use crate::node::funnel::tests::{FakeCli, serve_443_only};
use crate::node::master_key::tests::FakeKeys;
use crate::node::tests::FakeBackend;
use crate::node::{ACTIVITY_CONNECTED, Node, NodeOptions};
use crate::owner::wire::{Command, Data, OWNER_WIRE_VERSION, Request, Response, SecretText};
use crate::vault::{ConnectedWith, EnvDelivery, Field, ItemDraft, SecretValue};

pub(super) struct Fixture {
    pub(super) _dir: TempDir,
    pub(super) app: DesktopApp,
    pub(super) node: Arc<Node>,
    pub(super) backend: FakeBackend,
    pub(super) cli: Arc<FakeCli>,
}

/// An unlocked app with a running broker, a node of fakes, a placeholder item, and the
/// route on: the window starts the node with no remote agent yet.
pub(super) fn fixture() -> Fixture {
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
    app.owner_ui
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
        })
        .expect("open vault");
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
pub(super) fn frame(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    close: bool,
) -> Vec<ViewportCommand> {
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
pub(super) fn until(
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Wait until the node (its host thread) lists the connect request `id`.
pub(super) fn offered(fx: &Fixture, id: &str, client: &str) -> PendingConnect {
    offered_to(fx, id, client, "grok.example")
}

/// [`offered`] for a request whose code goes back to `redirect_host`.
pub(super) fn offered_to(
    fx: &Fixture,
    id: &str,
    client: &str,
    redirect_host: &str,
) -> PendingConnect {
    fx.backend
        .state
        .lock()
        .unwrap()
        .connects
        .push(PendingConnect {
            id: id.to_owned(),
            client_id: client.to_owned(),
            client_name: Some("Grok Bot".to_owned()),
            code: "K7Q-4MD".to_owned(),
            created_at: unix_now(),
            expires_at: unix_now() + 300,
            redirect_host: redirect_host.to_owned(),
        });
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(connect) = fx
            .app
            .pending_connects()
            .into_iter()
            .find(|connect| connect.id == id)
        {
            return connect;
        }
        assert!(Instant::now() < end, "timed out: the connect request");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn allow_on_a_connect_card_asks_the_owner_then_connects_and_deny_needs_no_check() {
    let mut fx = fixture();
    let ctx = egui::Context::default();
    until(
        &ctx,
        &mut fx.app,
        "the node runs for the route alone",
        |app| app.node.running_for.is_some(),
    );
    let connect = offered(&fx, "cr_1", "client_grok");
    fx.app.ask_allow_connect(&connect, Some(&ctx));
    let text = fx
        .app
        .owner
        .check
        .as_ref()
        .map(|dialog| dialog.request.describe())
        .expect("the owner check");
    assert!(
        text.contains("Grok Bot") && text.contains("K7Q-4MD"),
        "{text}"
    );
    assert!(
        fx.backend.state.lock().unwrap().decided.is_empty(),
        "nothing before the check"
    );
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(
        fx.app.status_text.contains("is connected"),
        "{}",
        fx.app.status_text
    );
    {
        let state = fx.backend.state.lock().unwrap();
        assert!(matches!(
            state.decided.as_slice(),
            [(id, ConnectDecision::Allow { .. })] if id == "cr_1"
        ));
        assert_eq!(state.tokens.values().next(), Some(&TokenIssue::Later));
    }
    let agents = fx.app.remote_agents();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name, "Grok Bot");
    assert_eq!(agents[0].connected_with, ConnectedWith::OAuth);
    assert!(agents[0].items.is_empty());
    let rows = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.recent_activity(20).expect("activity"))
        .expect("open vault");
    assert!(rows.iter().any(|row| row.operation == ACTIVITY_CONNECTED));

    // A second request: Deny goes at once, with no owner check.
    let other = offered(&fx, "cr_2", "client_other");
    fx.app.deny_connect(&other.id);
    assert!(fx.app.owner.check.is_none());
    assert!(
        fx.backend
            .state
            .lock()
            .unwrap()
            .decided
            .contains(&("cr_2".to_owned(), ConnectDecision::Deny))
    );
    assert_eq!(fx.app.remote_agents().len(), 1);

    // A request that ended before the check passed connects nothing.
    let late = offered(&fx, "cr_3", "client_late");
    fx.app.ask_allow_connect(&late, Some(&ctx));
    fx.backend
        .state
        .lock()
        .unwrap()
        .connects
        .retain(|connect| connect.id != "cr_3");
    let end = Instant::now() + Duration::from_secs(20);
    while fx
        .app
        .pending_connects()
        .iter()
        .any(|connect| connect.id == "cr_3")
    {
        assert!(Instant::now() < end, "timed out: the request ends");
        std::thread::sleep(Duration::from_millis(20));
    }
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(
        fx.app.status_text.contains("does not wait any more"),
        "{}",
        fx.app.status_text
    );
    assert_eq!(fx.app.remote_agents().len(), 1);
}

/// One command-line request; the answer comes on the receiver.
fn ask_cli(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    session: Option<&str>,
    command: Command,
) -> mpsc::Receiver<Response> {
    let (reply, answer) = mpsc::channel();
    app.handle_cli(
        Envelope {
            request: Request {
                v: OWNER_WIRE_VERSION,
                session: session.map(|token| SecretText::new(token.to_owned())),
                command,
            },
            reply,
        },
        ctx,
    );
    answer
}

#[test]
fn agent_add_remote_asks_the_owner_and_answers_the_token_once_with_the_address() {
    let mut fx = fixture();
    let ctx = egui::Context::default();
    // A session of the command line.
    let login = ask_cli(&mut fx.app, &ctx, None, Command::Login);
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let Data::Session { token: session, .. } = login.try_recv().expect("login").data else {
        panic!("no session");
    };
    let session = session.expose().to_owned();

    // Remote access does not run yet: refused before any check.
    let stopped = ask_cli(
        &mut fx.app,
        &ctx,
        Some(&session),
        Command::AgentAddRemote {
            name: "Grok Bot".to_owned(),
            days: None,
        },
    )
    .try_recv()
    .expect("an answer at once");
    assert_eq!(stopped.code, "remote_access_off", "{stopped:?}");
    assert!(fx.app.owner.check.is_none());

    until(&ctx, &mut fx.app, "the node runs", |app| {
        app.node.running_for.is_some()
    });
    let bad = ask_cli(
        &mut fx.app,
        &ctx,
        Some(&session),
        Command::AgentAddRemote {
            name: "Grok Bot".to_owned(),
            days: Some(0),
        },
    )
    .try_recv()
    .expect("an answer at once");
    assert_eq!(bad.code, "invalid_input");

    let answer = ask_cli(
        &mut fx.app,
        &ctx,
        Some(&session),
        Command::AgentAddRemote {
            name: "Grok Bot".to_owned(),
            days: Some(30),
        },
    );
    assert!(answer.try_recv().is_err(), "it waits for the owner check");
    assert!(matches!(
        fx.app.owner.check.as_ref().map(|dialog| &dialog.request),
        Some(OwnerRequest::AddRemoteAgent { days: 30, .. })
    ));
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("the answer");
    assert!(response.ok, "{response:?}");
    let Data::RemoteToken {
        agent,
        token,
        mcp_url,
    } = &response.data
    else {
        panic!("no remote token: {response:?}");
    };
    assert!(token.expose().starts_with("apassy_tagt_"));
    assert_eq!(mcp_url, "https://mac.example-tailnet.ts.net:8443/mcp");
    assert_eq!(agent.name, "Grok Bot");
    assert!(!agent.sees_all);
    // The window keeps no copy, and the token is in no other answer.
    assert!(!fx.app.status_text.contains(token.expose()));
    assert!(fx.app.cli.fresh_remote_is_empty());
    {
        let state = fx.backend.state.lock().unwrap();
        assert_eq!(
            state.tokens.values().next(),
            Some(&TokenIssue::Now { lifetime_days: 30 })
        );
        assert!(state.agents.values().all(|(_, items, _)| items.is_empty()));
    }
    let agents = fx.app.remote_agents();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].connected_with, ConnectedWith::Token);
    assert!(agents[0].token_expires_at.is_some());
    assert!(agents[0].items.is_empty());
    // A second agent with the same name gets a number.
    let again = ask_cli(
        &mut fx.app,
        &ctx,
        Some(&session),
        Command::AgentAddRemote {
            name: "Grok Bot".to_owned(),
            days: None,
        },
    );
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let Data::RemoteToken { agent, .. } = again.try_recv().expect("the answer").data else {
        panic!("no remote token");
    };
    assert_eq!(agent.name, "Grok Bot 2");
}

/// Review 0.5.16: an open owner-check window (ADR 0030) covers other command-line
/// requests, but `apassy agent add-remote` still asks the owner: its token works from
/// the internet, and a session of the command line proves no owner at the Mac.
#[test]
fn agent_add_remote_asks_the_owner_inside_an_open_window() {
    use crate::broker::approvals::{CheckMethod, OwnerFrequency};
    let mut fx = fixture();
    let ctx = egui::Context::default();
    let login = ask_cli(&mut fx.app, &ctx, None, Command::Login);
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let Data::Session { token: session, .. } = login.try_recv().expect("login").data else {
        panic!("no session");
    };
    let session = session.expose().to_owned();
    until(&ctx, &mut fx.app, "the node runs", |app| {
        app.node.running_for.is_some()
    });
    let window = fx.app.owner_ui.session.owner_window.clone();
    window.configure(OwnerFrequency::UntilLock);
    window.observe(true);
    window.seed(
        fx.app.owner_ui.session.epoch().expect("epoch"),
        CheckMethod::TouchId,
        window.generation(),
    );
    let answer = ask_cli(
        &mut fx.app,
        &ctx,
        Some(&session),
        Command::AgentAddRemote {
            name: "Grok Bot".to_owned(),
            days: Some(30),
        },
    );
    assert!(answer.try_recv().is_err(), "it waits for the owner check");
    assert!(matches!(
        fx.app.owner.check.as_ref().map(|dialog| &dialog.request),
        Some(OwnerRequest::AddRemoteAgent { days: 30, .. })
    ));
    assert!(
        fx.app.remote_agents().is_empty(),
        "nothing before the check"
    );
    assert!(fx.backend.state.lock().unwrap().tokens.is_empty());
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("the answer");
    assert!(response.ok, "{response:?}");
    assert!(matches!(response.data, Data::RemoteToken { .. }));
    assert_eq!(fx.app.remote_agents().len(), 1);
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
