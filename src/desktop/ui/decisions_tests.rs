//! Tests of the Decisions view and the read-only Agents view (ADR 0025 §3, §3f; ADR 0026
//! §2): the sections and their order, the facts of a question, the main answer from the
//! answers that can take effect, the owner check for each answer that gives authority and
//! none for a stricter one, the next question after an answer, the timers, the agent page,
//! and each place at the default and the smallest window. Synthetic values only.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::decisions::{
    self, Answer, Primary, action_label, clock, next_selection, primary, primary_label, time_left,
};
use super::owner_tests::{PASS, WRONG, collect, socket_dir, unlocked_app_with_item};
use super::{agents, draw};
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::{
    AnswerKind, ApprovalOutcome, ApprovalQueue, OwnerCheck, PendingRun, QuestionInfo, QuestionItem,
    QuestionRefusal, Settled,
};
use crate::broker::project::Project;
use crate::desktop::{BrokerState, DesktopApp, Place};
use crate::vault::exceptions::ExceptionKind;

const DEFAULT: Vec2 = Vec2::new(1180.0, 800.0);
const SMALLEST: Vec2 = Vec2::new(900.0, 600.0);
const WIDE: Vec2 = Vec2::new(1800.0, 1400.0);

type Waiter = JoinHandle<Result<Settled, QuestionRefusal>>;

fn project(label: &str) -> Project {
    Project {
        key: format!("/synthetic/{label}"),
        label: label.to_owned(),
        root: PathBuf::from(format!("/synthetic/{label}")),
    }
}

/// The answers of a question without a remembered answer.
fn base_answers() -> Vec<AnswerKind> {
    vec![
        AnswerKind::Once,
        AnswerKind::NeverForAgent,
        AnswerKind::AlwaysAskForAgent,
        AnswerKind::Disconnect,
    ]
}

fn question(items: Vec<QuestionItem>, extra: &[AnswerKind]) -> QuestionInfo {
    let mut valid_answers = base_answers();
    valid_answers.extend_from_slice(extra);
    QuestionInfo {
        id: 0,
        item_ids: items.iter().map(|item| item.item_id).collect(),
        project: Some(project("acme-billing")),
        action: ActionKind::Read,
        production: items.iter().any(|item| item.production),
        why: "This is a production key, and there is no production rule for reading in acme-billing yet.".to_owned(),
        items,
        valid_answers,
    }
}

fn item(item_id: u64, name: &str) -> QuestionItem {
    QuestionItem {
        item_id,
        name: name.to_owned(),
        ..QuestionItem::default()
    }
}

fn run(agent: &str, question: QuestionInfo) -> PendingRun {
    PendingRun {
        id: 0,
        agent: agent.to_owned(),
        command: vec![
            "curl".to_owned(),
            "https://api.stripe.com/v1/payouts".to_owned(),
        ],
        cwd: "/synthetic/acme-billing".to_owned(),
        env_names: vec!["STRIPE_SECRET_KEY".to_owned()],
        purpose: "List the payouts.".to_owned(),
        risk: String::new(),
        user_request: "Show the last payouts.".to_owned(),
        request_source: String::new(),
        agent_request: String::new(),
        remember: None,
        question,
    }
}

/// The queue of a running broker for the app.
fn queue_of(app: &mut DesktopApp, dir: &TempDir) -> Arc<ApprovalQueue> {
    app.start_broker(&socket_dir(dir));
    let BrokerState::Running(handle) = &app.broker else {
        panic!("the broker did not start");
    };
    Arc::clone(handle.approvals())
}

/// Put the question of `agent_id` in the queue and wait until it shows.
fn ask(
    app: &DesktopApp,
    queue: &Arc<ApprovalQueue>,
    agent_id: u64,
    pending: PendingRun,
) -> (Waiter, PendingRun) {
    let before: Vec<u64> = queue.pending().iter().map(|run| run.id).collect();
    let epoch = app.owner_ui.session.epoch().expect("unlocked");
    let waiter = {
        let queue = Arc::clone(queue);
        std::thread::spawn(move || {
            queue.wait_for_question(pending, agent_id, epoch, Duration::from_secs(30), || true)
        })
    };
    let run = loop {
        if let Some(run) = queue
            .pending()
            .into_iter()
            .find(|run| !before.contains(&run.id))
        {
            break run;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    (waiter, run)
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

/// Texts that show in their clip and run past its right edge or past the window.
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

#[test]
fn timers_count_down_the_five_minute_wait() {
    let wait = Duration::from_secs(300);
    assert_eq!(
        time_left(wait, Duration::from_secs(8)),
        Duration::from_secs(292)
    );
    assert_eq!(time_left(wait, Duration::from_secs(400)), Duration::ZERO);
    assert_eq!(clock(Duration::from_secs(292)), "4:52");
    assert_eq!(clock(Duration::from_millis(299_400)), "5:00");
    assert_eq!(clock(Duration::from_millis(59_001)), "1:00");
    assert_eq!(clock(Duration::from_secs(9)), "0:09");
    assert_eq!(clock(Duration::ZERO), "0:00");
    assert_eq!(crate::broker::server::QUESTION_WAIT, wait);
}

/// The main button follows the answers that can take effect
/// ([`QuestionInfo::valid_answers`]): production first, then the project answer, then the
/// correction of a default production value. Without one, Allow Once is the main button.
#[test]
fn the_main_answer_follows_the_valid_answers() {
    let plain = question(vec![item(1, "Stripe test")], &[]);
    assert_eq!(primary(&plain), None);
    assert_eq!(primary_label(&plain), None);

    let in_project = question(
        vec![item(1, "Stripe test")],
        &[AnswerKind::InProject(ActionKind::Change)],
    );
    assert_eq!(
        primary(&in_project),
        Some(Primary::InProject(ActionKind::Change))
    );
    assert_eq!(
        primary_label(&in_project).as_deref(),
        Some("Allow Change in acme-billing")
    );

    let mut live = item(2, "Stripe live");
    live.production = true;
    let production = question(vec![live], &[AnswerKind::Production(ActionKind::Deploy)]);
    assert_eq!(
        primary_label(&production).as_deref(),
        Some("Allow production: Deploy in acme-billing")
    );

    let mut unknown = item(3, "OpenAI API");
    unknown.unconfirmed = true;
    let correct = question(vec![unknown.clone()], &[AnswerKind::CorrectEnvironment]);
    assert_eq!(primary(&correct), Some(Primary::Correct));
    assert_eq!(primary_label(&correct).as_deref(), Some("Development"));
    // A project answer comes before the correction; the correction stays on the card.
    let both = question(
        vec![unknown],
        &[
            AnswerKind::CorrectEnvironment,
            AnswerKind::InProject(ActionKind::Read),
        ],
    );
    assert_eq!(primary(&both), Some(Primary::InProject(ActionKind::Read)));

    // Without a project nothing is remembered.
    let mut nowhere = in_project.clone();
    nowhere.project = None;
    assert_eq!(primary_label(&nowhere), None);

    // A long project name is cut in the button.
    let mut long = in_project;
    long.project = Some(project("a-very-long-project-name-for-the-narrow-window"));
    let label = primary_label(&long).expect("a label");
    assert!(label.ends_with('…'), "{label}");
    assert!(
        label.chars().count() <= "Allow Change in ".len() + 28,
        "{label}"
    );
    assert_eq!(action_label(ActionKind::Delete), "Delete");
}

#[test]
fn the_next_question_takes_the_place_of_the_answered_one() {
    assert_eq!(next_selection(&[], Some(4), 0), None);
    assert_eq!(next_selection(&[4, 5, 6], None, 0), Some(4));
    assert_eq!(next_selection(&[4, 5, 6], Some(5), 1), Some(5));
    // 5 was answered at place 1: 6 takes its place.
    assert_eq!(next_selection(&[4, 6], Some(5), 1), Some(6));
    // The last one was answered: the one before it.
    assert_eq!(next_selection(&[4, 5], Some(6), 2), Some(5));
}

/// The list has "Waiting" with the questions, the least time left first. Requests and
/// Suggestions have no section until the vault keeps them. The badge counts what blocks
/// an agent.
#[test]
fn the_list_has_waiting_questions_in_order_and_no_empty_sections() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, DEFAULT, 3);
    assert!(text.contains("Nothing needs you"), "{text}");
    assert!(text.contains("All clear"), "{text}");
    assert!(text.contains("by you · 0 automatic this week"), "{text}");

    let queue = queue_of(&mut app, &dir);
    let (first_waiter, first) = ask(
        &app,
        &queue,
        1,
        run(
            "Claude Code",
            question(vec![item(item_id, "Guarded key")], &[]),
        ),
    );
    std::thread::sleep(Duration::from_millis(20));
    let (second_waiter, second) = ask(
        &app,
        &queue,
        2,
        run("Codex", question(vec![item(item_id, "Guarded key")], &[])),
    );
    let pending = queue.pending();
    let waiting = decisions::waiting(&app, &pending);
    assert_eq!(
        waiting.iter().map(|w| w.run.id).collect::<Vec<_>>(),
        [first.id, second.id],
        "the least time left first"
    );
    assert!(waiting[0].left <= waiting[1].left);
    assert_eq!(decisions::badge_count(&app, &pending), 2);

    let (text, _) = frames(&mut app, DEFAULT, 3);
    for expected in [
        "Waiting",
        "Guarded key",
        "Claude Code · acme-billing",
        "Codex · acme-billing",
        "left to answer",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for absent in ["Requests", "Suggestions", "Nothing needs you"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    assert!(text.find("Claude Code · acme-billing") < text.find("Codex · acme-billing"));
    // The first question is selected.
    assert_eq!(decisions::selected(&app), Some(first.id));

    assert!(queue.deny(first.id));
    assert!(queue.deny(second.id));
    for waiter in [first_waiter, second_waiter] {
        let settled = waiter.join().expect("waiter").expect("an answer");
        assert_eq!(settled.outcome, ApprovalOutcome::Denied);
    }
}

/// The card says who wants what: the credential with its production cap, the action, the
/// project, the hosts, the command, and why the owner is asked. The bar has Deny, Allow
/// Once, and the answer that the question offers. No value shows.
#[test]
fn the_detail_shows_the_facts_the_command_and_why() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let queue = queue_of(&mut app, &dir);
    let mut live = item(item_id, "Live key");
    live.production = true;
    let (waiter, pending) = ask(
        &app,
        &queue,
        1,
        run(
            "Claude Code",
            question(vec![live], &[AnswerKind::Production(ActionKind::Read)]),
        ),
    );
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "Claude Code wants to use Live key",
        "left to answer",
        "Credential",
        "Production",
        "Action",
        "Read",
        "Project",
        "acme-billing",
        "Sends to",
        "api.stripe.com",
        "Request",
        "\"Show the last payouts.\" (from the agent)",
        "Command",
        "curl https://api.stripe.com/v1/payouts",
        "Why you are asked",
        "This is a production key, and there is no production rule for reading in acme-billing yet.",
        "Deny",
        "Allow Once",
        "Allow production: Read in acme-billing",
        "Production stays allowed for reading in acme-billing for all agents.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("ui-owner-token-canary"), "{text}");
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");
}

/// "Allow ACTION in PROJECT" opens the owner check. A wrong passphrase approves nothing.
/// After the check the question ends with the answer that the broker remembers for every
/// agent in the project. The next question is selected.
#[test]
fn allow_in_project_needs_the_owner_check_and_selects_the_next_question() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let queue = queue_of(&mut app, &dir);
    let offered = question(
        vec![item(item_id, "Guarded key")],
        &[AnswerKind::InProject(ActionKind::Read)],
    );
    let (waiter, first) = ask(&app, &queue, 1, run("Claude Code", offered.clone()));
    std::thread::sleep(Duration::from_millis(20));
    let (other_waiter, second) = ask(&app, &queue, 2, run("Codex", offered));
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, DEFAULT, 3);
    assert!(text.contains("Allow Read in acme-billing"), "{text}");
    assert!(
        text.contains("Allow is remembered for all agents in acme-billing."),
        "{text}"
    );
    assert_eq!(decisions::selected(&app), Some(first.id));

    let ctx = egui::Context::default();
    decisions::apply(&mut app, &ctx, &first, Answer::InProject(ActionKind::Read));
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        check
            .request
            .describe()
            .contains("Allow reading in \"acme-billing\" for every agent"),
        "{}",
        check.request.describe()
    );
    assert!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    assert_eq!(
        queue.pending().len(),
        2,
        "a wrong passphrase approves nothing"
    );

    decisions::apply(&mut app, &ctx, &first, Answer::InProject(ActionKind::Read));
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let settled = waiter.join().expect("waiter").expect("an answer");
    assert_eq!(settled.outcome, ApprovalOutcome::Approved);
    let answer = settled.answer.expect("the answer to remember");
    assert_eq!(answer.project.label, "acme-billing");
    assert_eq!(answer.action, ActionKind::Read);
    assert!(!answer.production);
    assert!(
        app.status_text
            .contains("Apassy remembers reading in acme-billing for all agents"),
        "{}",
        app.status_text
    );

    frames(&mut app, DEFAULT, 1);
    assert_eq!(
        decisions::selected(&app),
        Some(second.id),
        "the next question"
    );
    assert!(queue.deny(second.id));
    other_waiter.join().expect("waiter").expect("an answer");
}

/// "Never for AGENT" denies the question and saves the exception without an owner check:
/// it only takes authority away (ADR 0025 §3f). So do "Always Ask" and "Disconnect".
#[test]
fn stricter_answers_need_no_owner_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let queue = queue_of(&mut app, &dir);
    let (agent, _) = app
        .owner_ui
        .session
        .register_agent("UI agent")
        .expect("agent");
    let ctx = egui::Context::default();

    let (waiter, pending) = ask(
        &app,
        &queue,
        agent.id,
        run(
            "UI agent",
            question(vec![item(item_id, "Guarded key")], &[]),
        ),
    );
    decisions::apply(&mut app, &ctx, &pending, Answer::Never);
    assert!(app.owner.check.is_none(), "no owner check");
    let settled = waiter.join().expect("waiter").expect("an answer");
    assert_eq!(settled.outcome, ApprovalOutcome::Denied);
    let exceptions = app
        .owner_ui
        .session
        .with_vault(|vault| vault.agent_exceptions(agent.id))
        .expect("open")
        .expect("read");
    assert!(
        exceptions
            .iter()
            .any(|e| e.item_id == item_id && e.kind == ExceptionKind::Never),
        "{exceptions:?}"
    );
    assert!(
        app.status_text.contains("UI agent never gets Guarded key"),
        "{}",
        app.status_text
    );

    let (waiter, pending) = ask(
        &app,
        &queue,
        agent.id,
        run(
            "UI agent",
            question(vec![item(item_id, "Guarded key")], &[]),
        ),
    );
    decisions::apply(&mut app, &ctx, &pending, Answer::AlwaysAsk);
    assert!(app.owner.check.is_none());
    waiter.join().expect("waiter").expect("an answer");
    let standing = app
        .owner_ui
        .session
        .with_vault(|vault| vault.agent_exceptions(agent.id))
        .expect("open")
        .expect("read");
    assert!(standing.iter().any(|e| e.kind == ExceptionKind::AlwaysAsk));

    // "Disconnect…" asks once in a sheet, then revokes the agent: no owner check.
    let (waiter, pending) = ask(
        &app,
        &queue,
        agent.id,
        run(
            "UI agent",
            question(vec![item(item_id, "Guarded key")], &[]),
        ),
    );
    decisions::apply(&mut app, &ctx, &pending, Answer::Disconnect);
    assert!(decisions::disconnecting(&app));
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, DEFAULT, 3);
    assert!(text.contains("Disconnect UI agent?"), "{text}");
    assert!(app.owner.check.is_none());
    assert_eq!(queue.pending().len(), 1, "nothing before the confirmation");
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");
    frames(&mut app, DEFAULT, 1);
    assert!(
        !decisions::disconnecting(&app),
        "the sheet goes with its question"
    );
}

/// "Development" on a credential that is production only by default needs the owner
/// check: the bouncer is then less careful. "Production" is stricter and needs none.
/// The question still waits after either.
#[test]
fn a_correction_toward_development_needs_the_owner_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let queue = queue_of(&mut app, &dir);
    let mut unknown = item(item_id, "Guarded key");
    unknown.unconfirmed = true;
    let (waiter, pending) = ask(
        &app,
        &queue,
        1,
        run(
            "Codex",
            question(vec![unknown], &[AnswerKind::CorrectEnvironment]),
        ),
    );
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, DEFAULT, 3);
    for expected in [
        "Development",
        "Production",
        "Allow Once",
        "Production by default",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    let environment = |app: &DesktopApp| {
        app.owner_ui
            .session
            .declaration(item_id)
            .expect("read")
            .map(|declaration| declaration.environment)
    };
    let before = environment(&app);
    let ctx = egui::Context::default();
    decisions::apply(
        &mut app,
        &ctx,
        &pending,
        Answer::Development {
            item_id,
            name: "Guarded key".to_owned(),
        },
    );
    assert!(app.owner.check.is_some(), "the owner check opens");
    assert!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    assert_eq!(environment(&app), before);
    decisions::apply(
        &mut app,
        &ctx,
        &pending,
        Answer::Development {
            item_id,
            name: "Guarded key".to_owned(),
        },
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(
        environment(&app),
        Some(crate::vault::Environment::Development)
    );
    assert_eq!(queue.pending().len(), 1, "the question still waits");

    decisions::apply(
        &mut app,
        &ctx,
        &pending,
        Answer::MarkProduction {
            item_id,
            name: "Guarded key".to_owned(),
        },
    );
    assert!(app.owner.check.is_none(), "stricter: no owner check");
    assert_eq!(
        environment(&app),
        Some(crate::vault::Environment::Production)
    );
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");
}

/// The agent page shows, it does not configure: the note saves without a check, and the
/// removal of an exception that gives authority back waits for the owner check. A listed
/// item ("Only") goes at once.
#[test]
fn the_agent_page_saves_the_note_and_removes_an_exception_after_the_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let (agent, _) = app
        .owner_ui
        .session
        .register_agent("CI on GitHub")
        .expect("agent");
    app.owner_ui
        .session
        .with_vault(|vault| vault.add_agent_exception(agent.id, item_id, ExceptionKind::Never))
        .expect("open")
        .expect("exception");
    app.place = Place::Agents;
    app.owner_ui.selected_agent = Some(agent.id);
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "CI on GitHub",
        "This Mac · connected",
        "Uses this week",
        "Projects",
        "None yet",
        "Note for the bouncer",
        "Exceptions",
        "Never: Guarded key",
        "Remove",
        "Recent uses",
        "Disconnect CI on GitHub…",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for absent in [
        "Process access",
        "What it can see",
        "API operations",
        "Give access",
    ] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }

    // The note: no owner check.
    app.ui.agents.note = Some((
        agent.id,
        "CI agent for Acme, only the Stripe test key.".to_owned(),
    ));
    agents::save_note(&mut app, agent.id);
    assert!(app.owner.check.is_none());
    let note = app
        .owner_ui
        .session
        .with_vault(|vault| vault.agent_note(agent.id))
        .expect("open")
        .expect("read");
    assert_eq!(note, "CI agent for Acme, only the Stripe test key.");

    // Removing "Never" gives authority back: the owner check first.
    let exceptions = |app: &DesktopApp| {
        app.owner_ui
            .session
            .with_vault(|vault| vault.agent_exceptions(agent.id))
            .expect("open")
            .expect("read")
    };
    let never = exceptions(&app)[0].clone();
    let ctx = egui::Context::default();
    agents::remove_exception(&mut app, &ctx, &agent, &never);
    assert!(app.owner.check.is_some());
    assert!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    assert_eq!(
        exceptions(&app).len(),
        1,
        "a wrong passphrase removes nothing"
    );
    agents::remove_exception(&mut app, &ctx, &agent, &never);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(exceptions(&app).is_empty());

    // A listed item goes without a check: the agent sees less.
    app.owner_ui
        .session
        .with_vault(|vault| vault.add_agent_exception(agent.id, item_id, ExceptionKind::Only))
        .expect("open")
        .expect("listed");
    let only = exceptions(&app)
        .into_iter()
        .find(|e| e.kind == ExceptionKind::Only)
        .expect("listed");
    agents::remove_exception(&mut app, &ctx, &agent, &only);
    assert!(app.owner.check.is_none());
    assert!(
        exceptions(&app)
            .iter()
            .all(|e| e.kind != ExceptionKind::Only)
    );
}

/// Decisions and Agents draw at the default and the smallest window, with the sidebar
/// full, collapsed, and floating: with a question, with an agent, and empty. No text runs
/// past the edge.
#[test]
fn decisions_and_agents_draw_at_every_size_with_and_without_content() {
    #[derive(Debug, Clone, Copy)]
    enum Sidebar {
        Full,
        Collapsed,
        Float,
    }
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let check = |app: &mut DesktopApp, place: Place, expected: &[&str]| {
        for size in [DEFAULT, SMALLEST] {
            for sidebar in [Sidebar::Full, Sidebar::Collapsed, Sidebar::Float] {
                app.place = place.clone();
                app.ui.sidebar_hidden = matches!(sidebar, Sidebar::Collapsed);
                app.ui.sidebar_float = matches!(sidebar, Sidebar::Float);
                let (text, past) = frames(app, size, 3);
                let at = format!("{place:?} at {size:?}, {sidebar:?}");
                for needle in expected {
                    assert!(text.contains(needle), "{needle} in {at}: {text}");
                }
                assert!(past.is_empty(), "past the edge in {at}: {past:?}");
            }
        }
    };
    // Empty states.
    check(
        &mut app,
        Place::Decisions,
        &["Decisions", "Nothing needs you", "All clear"],
    );
    check(
        &mut app,
        Place::Agents,
        &["Agents", "No agents yet", "Connect an Agent"],
    );

    // With content: a long production question and an agent with an exception.
    let queue = queue_of(&mut app, &dir);
    let mut live = item(
        item_id,
        "A production key with a rather long name for the card",
    );
    live.production = true;
    let mut long = question(vec![live], &[AnswerKind::Production(ActionKind::Delete)]);
    long.project = Some(project("a-very-long-project-name-for-the-narrow-window"));
    let (waiter, pending) = ask(&app, &queue, 1, run("Claude Code", long));
    check(
        &mut app,
        Place::Decisions,
        &[
            "Waiting",
            "Deny",
            "Allow Once",
            "Allow production: Delete in",
            "left to answer",
        ],
    );
    let (agent, _) = app.owner_ui.session.register_agent("Codex").expect("agent");
    app.owner_ui
        .session
        .with_vault(|vault| vault.add_agent_exception(agent.id, item_id, ExceptionKind::AlwaysAsk))
        .expect("open")
        .expect("exception");
    app.owner_ui.selected_agent = Some(agent.id);
    check(
        &mut app,
        Place::Agents,
        &["Codex", "Always ask: Guarded key", "Note for the bouncer"],
    );
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");
}

/// "Connect an Agent" offers the four hosts and says that a question waits 5 minutes.
#[test]
fn connect_an_agent_lists_the_hosts() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.place = Place::Agents;
    app.ui.sheet = Some(super::Sheet::RegisterAgent);
    let (text, past) = frames(&mut app, SMALLEST, 3);
    for expected in [
        "Connect an Agent",
        "Claude Code",
        "Codex",
        "T3 Code",
        "Through Claude Code or Codex",
        "Other",
        "Token and command line, also remote",
        "a question waits up to 5 minutes for you",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(past.is_empty(), "{past:?}");
}
