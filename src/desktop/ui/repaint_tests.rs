//! An idle window asks for no frame soon. The window of 0.5.15 drew about ten frames a
//! second with nothing to show: the open wait of the browser extension asked for a frame
//! every 100 ms, the approvals every 500 ms, and the node every second, also while the
//! window was minimized. Each frame searched the vault twice for the sidebar. Now a
//! worker wakes the window when its state changes, and a timer asks only for what the
//! window shows. Synthetic values only.

use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{self, RawInput, ViewportId};
use tempfile::TempDir;

use super::draw;
use super::owner_tests::{
    input, not_available_helper, socket_dir, unlocked_app_with_item, waiting_run,
};
use crate::desktop::node::NodeFlows;
use crate::desktop::notify::NotificationCenter;
use crate::desktop::{DesktopApp, Place};
use crate::node::funnel::tests::{FakeCli, serve_443_only};
use crate::node::master_key::tests::FakeKeys;
use crate::node::tests::FakeBackend;
use crate::node::{Node, NodeOptions};

/// The shortest wait for a frame that an idle window may ask for. It asks only to see
/// what nothing reports: the node (every 10 s), the auto-lock and the time of "Synced …
/// ago" (every 30 s).
const IDLE_AT_LEAST: Duration = Duration::from_secs(5);

/// One whole frame at `time`: the logic of eframe, which also runs while the window is
/// minimized, then the window. Returns the delay of the next frame that it asks for
/// (`Duration::MAX`: none).
fn frame(ctx: &egui::Context, app: &mut DesktopApp, time: f64) -> Duration {
    let mut frame = eframe::Frame::_new_kittest();
    let output = ctx.run_ui(input(time, Vec::new()), |ui| {
        eframe::App::logic(app, ui.ctx(), &mut frame);
        draw(app, ui);
    });
    let delay = output.viewport_output[&ViewportId::ROOT].repaint_delay;
    output.drop_without_applying_deltas();
    delay
}

/// Where the calls that asked for the last frame are, for a failed check.
fn asked_by(ctx: &egui::Context) -> String {
    let mut causes = String::new();
    let output = ctx.run_ui(RawInput::default(), |ui| {
        causes = format!("{:?}", ui.ctx().repaint_causes());
    });
    output.drop_without_applying_deltas();
    causes
}

/// An unlocked app as the Mac app runs it: the broker, the notification center (its
/// notifier wakes the window for a new run), and a node with the route off.
fn idle_app(dir: &TempDir) -> DesktopApp {
    let (mut app, _) = unlocked_app_with_item(dir);
    app.start_broker(&socket_dir(dir));
    let approvals = app.approvals().expect("the broker runs");
    app.owner.notifications = Some(NotificationCenter::start(
        approvals,
        app.owner_ui.session.shared_vault(),
        not_available_helper(dir.path()),
        || {},
    ));
    app.node = NodeFlows::with_node(Arc::new(Node::new(NodeOptions {
        backend: Arc::new(FakeBackend::default()),
        keys: Arc::new(FakeKeys::empty()),
        cli: Arc::new(FakeCli::connected(serve_443_only())),
        data_dir: dir.path().join("node"),
    })));
    app
}

/// Frames of `place` until the window settles (a new view lays out over a few frames,
/// and an animation ends), then the wait that its idle frame asks for.
fn settled(ctx: &egui::Context, app: &mut DesktopApp, place: &Place, time: &mut f64) -> Duration {
    app.place = place.clone();
    let mut delay = Duration::ZERO;
    for _ in 0..12 {
        *time += 0.5;
        delay = frame(ctx, app, *time);
    }
    delay
}

#[test]
fn an_idle_window_asks_for_no_frame_soon() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = idle_app(&dir);
    let ctx = egui::Context::default();
    let mut time = 0.0;
    for place in [Place::CREDENTIALS, Place::Decisions, Place::Agents] {
        let delay = settled(&ctx, &mut app, &place, &mut time);
        assert!(
            delay >= IDLE_AT_LEAST,
            "{place:?} asks for a frame in {delay:?}, by {}",
            asked_by(&ctx)
        );
    }
}

/// A run that waits can end on its own (a timeout, the agent stops), so the window looks
/// each second while one waits, and stops when none waits.
#[test]
fn a_waiting_run_is_watched_each_second_until_it_ends() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = idle_app(&dir);
    let approvals = app.approvals().expect("the broker runs");
    let waiter = {
        let approvals = Arc::clone(&approvals);
        std::thread::spawn(move || {
            approvals.wait_for(waiting_run("UI agent"), Duration::from_secs(20), || true)
        })
    };
    let run = loop {
        if let Some(run) = approvals.pending().into_iter().next() {
            break run;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let ctx = egui::Context::default();
    let mut time = 0.0;
    let delay = settled(&ctx, &mut app, &Place::Decisions, &mut time);
    assert!(
        delay <= Duration::from_secs(1),
        "a waiting run: {delay:?}, by {}",
        asked_by(&ctx)
    );
    assert!(approvals.deny(run.id));
    let _ = waiter.join().expect("the waiter ends");
    let delay = settled(&ctx, &mut app, &Place::Decisions, &mut time);
    assert!(
        delay >= IDLE_AT_LEAST,
        "no run waits: {delay:?}, by {}",
        asked_by(&ctx)
    );
}
