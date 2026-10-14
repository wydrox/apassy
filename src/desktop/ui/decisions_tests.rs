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
    self, Answer, Key, Primary, RequestAnswer, SuggestionAnswer, action_label, clock,
    next_selection, primary, primary_label, time_left,
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
use crate::vault::OriginTool;
use crate::vault::agent_items::{
    Correction, CorrectionAnswer, CorrectionKind, CorrectionState, CredentialRequest,
    CredentialRequestState, NewCredentialRequest, RAISED_FROM_FACT,
};
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
            queue.wait_for_question(
                pending,
                agent_id,
                epoch,
                [0; 32],
                Duration::from_secs(30),
                || true,
            )
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
    // As in the mockup: the list says so, and the detail says "All clear".
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
        "Command",
        "curl https://api.stripe.com/v1/payouts",
        "Why you are asked",
        "This is a production key, and there is no production rule for reading in acme-billing yet.",
        "Deny",
        "Allow Once",
        "Allow production: Read in acme-billing",
        "Production stays allowed for all agents in acme-billing.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // As in the mockup, the request of the user has no group of its own.
    assert!(!text.contains("Show the last payouts."), "{text}");
    assert!(!text.contains("ui-owner-token-canary"), "{text}");
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");

    // Goal item B6: when the agent sent a different request, both show.
    let mut changed = run(
        "Claude Code",
        question(vec![item(item_id, "Live key")], &[]),
    );
    changed.agent_request = "Delete the old payouts.".to_owned();
    let (waiter, pending) = ask(&app, &queue, 1, changed);
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "Request",
        "\"Show the last payouts.\" (from the agent)",
        "The agent sent a different request: \"Delete the old payouts.\"",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");
}

/// The command of a command line tool names no host: the card has no "Sends to" row, as
/// in the mockup.
#[test]
fn a_command_without_a_host_has_no_sends_to_row() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let queue = queue_of(&mut app, &dir);
    let mut cli = run("Codex", question(vec![item(item_id, "Live key")], &[]));
    cli.command = ["stripe", "payouts", "list"].map(str::to_owned).to_vec();
    let (waiter, pending) = ask(&app, &queue, 1, cli);
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("stripe payouts list"), "{text}");
    assert!(!text.contains("Sends to"), "{text}");
    assert!(!text.contains("No host in the command"), "{text}");
    assert!(queue.deny(pending.id));
    waiter.join().expect("waiter").expect("an answer");
}

/// Agent avatars: Claude Code orange and Codex green as in the mockup, also for an ID or
/// a member's agent; another agent gets a steady color of its own.
#[test]
fn agent_avatars_have_the_colors_of_the_mockup() {
    use super::kit::agent_color;
    let orange = egui::Color32::from_rgb(217, 119, 87);
    let green = egui::Color32::from_rgb(16, 163, 127);
    for name in ["Claude Code", "claude-code", "Ola's Claude Code"] {
        assert_eq!(agent_color(name), orange, "{name}");
    }
    for name in ["Codex", "codex-cli"] {
        assert_eq!(agent_color(name), green, "{name}");
    }
    assert_eq!(agent_color("Aider"), agent_color("Aider"));
    assert_ne!(agent_color("Aider"), orange);
    assert_ne!(agent_color("Aider"), green);
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
        // A new agent sees no credential until it is connected.
        "No credentials yet",
        "Disconnect CI on GitHub…",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // As in the mockup: no uses list and no token row; "⋯" has Reconnect.
    for absent in [
        "Process access",
        "What it can see",
        "API operations",
        "Give access",
        "Recent uses",
        "Reconnect",
        "Only 0",
    ] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    // A connected agent without "only these items" sees each credential name.
    app.owner_ui
        .session
        .with_vault(|vault| vault.set_agent_sees_all(agent.id, true))
        .expect("open")
        .expect("sees all");
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("Credential names, never values"), "{text}");

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
    check(&mut app, Place::Decisions, &["Decisions", "All clear"]);
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

// ---- Requests and Suggestions (ADR 0025 §5, §6). ----

/// A synthetic key of a provider with a known prefix.
fn fake(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

/// The open request of `agent` for a credential. The agent is registered at its first
/// request. Returns the agent ID and the request ID.
fn ask_for_key(app: &mut DesktopApp, agent: &str, name: &str, where_to_get: &str) -> (u64, u64) {
    let known = app
        .owner_ui
        .session
        .with_vault(|vault| vault.credential_requests(false))
        .expect("open")
        .expect("read")
        .into_iter()
        .find(|request| request.agent_name == agent)
        .map(|request| request.agent_id);
    let agent_id = match known {
        Some(id) => id,
        None => {
            app.owner_ui
                .session
                .register_agent(agent)
                .expect("agent")
                .0
                .id
        }
    };
    let request = app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault.open_credential_request(&NewCredentialRequest {
                agent_id,
                agent_name: agent.to_owned(),
                project_key: "/synthetic/acme-billing".to_owned(),
                project_label: "acme-billing".to_owned(),
                name: name.to_owned(),
                purpose: "Run the payout tests against the Stripe test mode.".to_owned(),
                where_to_get: where_to_get.to_owned(),
                folder: None,
            })
        })
        .expect("open")
        .expect("request");
    (agent_id, request)
}

fn request_of(app: &DesktopApp, id: u64) -> CredentialRequest {
    app.owner_ui
        .session
        .with_vault(|vault| vault.credential_request(id))
        .expect("open")
        .expect("request")
}

fn propose(
    app: &DesktopApp,
    item_id: u64,
    kind: CorrectionKind,
    proposed: &str,
    facts: serde_json::Value,
) -> u64 {
    app.owner_ui
        .session
        .with_vault(|vault| vault.propose_correction(item_id, kind, proposed, &facts))
        .expect("open")
        .expect("propose")
        .expect("a new correction")
}

fn correction_of(app: &DesktopApp, item_id: u64, id: u64) -> Correction {
    app.owner_ui
        .session
        .with_vault(|vault| vault.item_corrections(item_id))
        .expect("open")
        .expect("read")
        .into_iter()
        .find(|correction| correction.id == id)
        .expect("the correction")
}

fn environment_of(app: &DesktopApp, item_id: u64) -> Option<crate::vault::Environment> {
    app.owner_ui
        .session
        .declaration(item_id)
        .expect("read")
        .map(|declaration| declaration.environment)
}

/// The domain of "where to get it" is the host that a browser would open: user info
/// does not fool it, a bare host counts, and a look-alike name that is not plain ASCII
/// shows as no domain.
#[test]
fn the_domain_of_where_to_get_it_is_the_real_host() {
    assert_eq!(
        decisions::where_domains("Create one at https://dashboard.stripe.com/test/apikeys"),
        ["dashboard.stripe.com"]
    );
    assert_eq!(
        decisions::where_domains("https://dashboard.stripe.com@keys.evil-example.net/login"),
        ["keys.evil-example.net"]
    );
    assert_eq!(
        decisions::where_domains("dashboard.stripe.com/apikeys, then Reveal"),
        ["dashboard.stripe.com"]
    );
    assert!(
        decisions::where_domains("The Stripe dashboard, e.g. Developers > API keys.").is_empty()
    );
    assert!(decisions::where_domains("https://str\u{0456}pe.com/keys").is_empty());
    assert!(decisions::where_domains("").is_empty());
}

/// A request shows in "Requests" with the agent and the project, and its detail says
/// what the agent asks for, why, the domain as plain text, and the folder. It counts in
/// the badge; a suggestion does not.
#[test]
fn a_request_shows_its_facts_and_counts_in_the_badge() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let where_to_get = "Create one at https://dashboard.stripe.com@keys.evil-example.net/apikeys";
    let (_, request) = ask_for_key(&mut app, "Codex", "Stripe test key", where_to_get);
    propose(
        &app,
        item_id,
        CorrectionKind::Environment,
        "development",
        serde_json::json!({ "signal": "every use went to a development or test host", "uses": 3 }),
    );
    assert_eq!(
        decisions::badge_count(&app, &[]),
        1,
        "requests count, suggestions do not"
    );
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "Requests",
        "Suggestions",
        "Stripe test key",
        "Codex · acme-billing",
        "Codex asks for a Stripe test key",
        "For",
        "Run the payout tests against the Stripe test mode.",
        "Get it at",
        "keys.evil-example.net",
        where_to_get,
        "Apassy opens no link. Check the domain before you sign in.",
        "Saves to",
        "Personal",
        "Key",
        "Not Now",
        "Save",
        "Codex never sees the value.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert_eq!(decisions::selected_key(&app), Some(Key::Request(request)));
    // The domain is the host that a browser opens, not the user info before "@".
    assert!(!text.contains("\ndashboard.stripe.com\n"), "{text}");
}

/// Save adds the pasted credential with the origin of the request (the agent asked, the
/// owner pasted: not an own item of the agent), settles the request with it, erases the
/// paste, and selects the next decision. No owner check, and no value shows.
#[test]
fn save_adds_the_item_with_the_request_origin_and_settles_the_request() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let (agent_id, first) = ask_for_key(
        &mut app,
        "Codex",
        "Stripe test key",
        "https://dashboard.stripe.com/test/apikeys",
    );
    let (_, second) = ask_for_key(
        &mut app,
        "Codex",
        "OpenAI key",
        "platform.openai.com/api-keys",
    );
    app.place = Place::Decisions;
    frames(&mut app, DEFAULT, 2);
    assert_eq!(decisions::selected_key(&app), Some(Key::Request(first)));
    let key = fake("sk_test_", 24);
    decisions::set_paste(&mut app, &key);
    let (text, _) = frames(&mut app, WIDE, 3);
    assert!(text.contains("Stripe"), "the provider: {text}");
    assert!(!text.contains(&key), "the paste is masked: {text}");

    let ctx = egui::Context::default();
    let request = request_of(&app, first);
    decisions::apply_request(&mut app, &ctx, &request, RequestAnswer::Save);
    assert!(app.owner.check.is_none(), "a new item needs no owner check");
    assert!(decisions::paste_is_empty(&app), "the paste is erased");
    let saved = request_of(&app, first);
    assert_eq!(saved.state, CredentialRequestState::Saved);
    let item_id = saved.item_id.expect("the saved item");
    let origin = app
        .owner_ui
        .session
        .with_vault(|vault| vault.item_origin(item_id))
        .expect("open")
        .expect("read")
        .expect("an origin");
    assert_eq!(origin.origin.tool, OriginTool::AskOwner);
    assert_eq!(origin.origin.agent_id, agent_id);
    assert_eq!(origin.origin.project_label, "acme-billing");
    let own = app
        .owner_ui
        .session
        .with_vault(|vault| vault.agent_owns_item(agent_id, item_id))
        .expect("open")
        .expect("read");
    assert!(!own, "the owner pasted the value: not the agent's own item");
    let details = app.owner_ui.session.details(item_id).expect("details");
    assert_eq!(details.name, "Stripe test key");
    assert!(
        app.status_text
            .contains("Saved Stripe test key in Personal for Codex"),
        "{}",
        app.status_text
    );
    assert!(!app.status_text.contains(&key));

    let (text, _) = frames(&mut app, WIDE, 3);
    assert_eq!(
        decisions::selected_key(&app),
        Some(Key::Request(second)),
        "the next request"
    );
    assert!(text.contains("Codex asks for a OpenAI key"), "{text}");
    assert!(!text.contains(&key), "{text}");
    assert_eq!(decisions::badge_count(&app, &[]), 1);
}

/// Not Now dismisses the request without a check and adds nothing. A paste of another
/// request is erased when the selection moves.
#[test]
fn not_now_dismisses_the_request() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let (_, first) = ask_for_key(&mut app, "Codex", "Stripe test key", "");
    let (_, second) = ask_for_key(
        &mut app,
        "Codex",
        "GitHub token",
        "github.com/settings/tokens",
    );
    app.place = Place::Decisions;
    frames(&mut app, DEFAULT, 2);
    decisions::set_paste(&mut app, &fake("ghp_", 36));
    decisions::select_key(&mut app, Key::Request(second));
    let (text, _) = frames(&mut app, DEFAULT, 2);
    assert!(
        decisions::paste_is_empty(&app),
        "another selection erases the paste"
    );
    assert!(text.contains("github.com"), "{text}");
    decisions::select_key(&mut app, Key::Request(first));
    let (text, _) = frames(&mut app, DEFAULT, 2);
    assert!(text.contains("The agent did not say"), "{text}");

    let items_before = app.owner_ui.session.search("").expect("search").len();
    let ctx = egui::Context::default();
    let request = request_of(&app, first);
    decisions::apply_request(&mut app, &ctx, &request, RequestAnswer::NotNow);
    assert!(app.owner.check.is_none());
    assert_eq!(
        request_of(&app, first).state,
        CredentialRequestState::Dismissed
    );
    assert_eq!(
        app.owner_ui.session.search("").expect("search").len(),
        items_before
    );
    assert!(
        app.status_text
            .contains("Not now. Codex gets no Stripe test key."),
        "{}",
        app.status_text
    );
    frames(&mut app, DEFAULT, 1);
    assert_eq!(decisions::selected_key(&app), Some(Key::Request(second)));
    // Save without a paste saves nothing.
    let request = request_of(&app, second);
    decisions::apply_request(&mut app, &ctx, &request, RequestAnswer::Save);
    assert_eq!(request_of(&app, second).state, CredentialRequestState::Open);
}

/// The matrix of the owner check for suggestions: a stricter answer (production, a
/// project, ignoring a development proposal) acts at once; an answer that leaves the
/// credential at development waits for the check, and a wrong passphrase changes nothing.
#[test]
fn suggestions_accept_a_stricter_value_at_once_and_a_looser_one_after_the_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let development = propose(
        &app,
        item_id,
        CorrectionKind::Environment,
        "development",
        serde_json::json!({
            "signal": "every use went to a development or test host",
            "hosts": ["api.sandbox.example", "files.test"],
            "uses": 3,
        }),
    );
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "Suggestions",
        "Development or production?",
        "Is Guarded key a development key?",
        "Apassy noticed this from how agents use it.",
        "Seen",
        "every use went to a development or test host",
        "Sends to",
        "only api.sandbox.example, files.test",
        "Uses",
        "Ignore",
        "Development",
        "Production",
        "Development needs Touch ID or the passphrase.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert_eq!(
        decisions::selected_key(&app),
        Some(Key::Suggestion(development))
    );
    let correction = correction_of(&app, item_id, development);
    assert!(decisions::suggestion_needs_check(
        &app,
        &correction,
        SuggestionAnswer::Environment(crate::vault::Environment::Development)
    ));
    assert!(!decisions::suggestion_needs_check(
        &app,
        &correction,
        SuggestionAnswer::Environment(crate::vault::Environment::Production)
    ));
    assert!(!decisions::suggestion_needs_check(
        &app,
        &correction,
        SuggestionAnswer::Ignore
    ));

    let ctx = egui::Context::default();
    let before = environment_of(&app, item_id);
    let looser = SuggestionAnswer::Environment(crate::vault::Environment::Development);
    decisions::apply_suggestion(&mut app, &ctx, &correction, "Guarded key", looser);
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        check
            .request
            .describe()
            .contains("Mark \"Guarded key\" as development"),
        "{}",
        check.request.describe()
    );
    assert!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    assert_eq!(environment_of(&app, item_id), before);
    assert_eq!(
        correction_of(&app, item_id, development).state,
        CorrectionState::Open
    );
    // The session refuses a looser answer without a proof, also when called directly.
    let refused = app.owner_ui.session.answer_correction(
        development,
        item_id,
        CorrectionAnswer::Accepted,
        None,
        None,
    );
    assert_eq!(refused.expect_err("refused").code, "owner_check_required");
    decisions::apply_suggestion(&mut app, &ctx, &correction, "Guarded key", looser);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(
        environment_of(&app, item_id),
        Some(crate::vault::Environment::Development)
    );
    assert_eq!(
        correction_of(&app, item_id, development).state,
        CorrectionState::Accepted
    );
    let sources = app
        .owner_ui
        .session
        .with_vault(|vault| vault.declaration_sources(item_id))
        .expect("open")
        .expect("read");
    assert_eq!(sources.environment, crate::vault::DeclarationSource::Owner);

    // Production is stricter: no check.
    let production = propose(
        &app,
        item_id,
        CorrectionKind::Environment,
        "production",
        serde_json::json!({ "signal": "the value has a production prefix of its provider", "provider": "stripe" }),
    );
    let correction = correction_of(&app, item_id, production);
    decisions::apply_suggestion(
        &mut app,
        &ctx,
        &correction,
        "Guarded key",
        SuggestionAnswer::Environment(crate::vault::Environment::Production),
    );
    assert!(app.owner.check.is_none(), "stricter: no owner check");
    assert_eq!(
        environment_of(&app, item_id),
        Some(crate::vault::Environment::Production)
    );
    assert_eq!(
        correction_of(&app, item_id, production).state,
        CorrectionState::Accepted
    );

    // A project is stricter: no check.
    let project = propose(
        &app,
        item_id,
        CorrectionKind::Project,
        "acme-billing",
        serde_json::json!({ "project_label": "acme-billing", "project_key": "/synthetic/acme-billing", "uses": 5, "agents": ["Codex"] }),
    );
    frames(&mut app, WIDE, 2);
    decisions::select_key(&mut app, Key::Suggestion(project));
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "Limit Guarded key to acme-billing?",
        "Only in acme-billing",
        "Agents",
        "Codex",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    let correction = correction_of(&app, item_id, project);
    decisions::apply_suggestion(
        &mut app,
        &ctx,
        &correction,
        "Guarded key",
        SuggestionAnswer::Accept,
    );
    assert!(app.owner.check.is_none());
    let declaration = app
        .owner_ui
        .session
        .declaration(item_id)
        .expect("read")
        .expect("declared");
    assert_eq!(declaration.project, "acme-billing");
}

/// Ignore needs no check when it changes nothing. Ignoring a raise to production gives
/// the credential its looser environment back, so that Ignore waits for the check.
#[test]
fn ignore_needs_the_check_only_when_it_restores_a_looser_environment() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let development = propose(
        &app,
        item_id,
        CorrectionKind::Environment,
        "development",
        serde_json::json!({ "uses": 3 }),
    );
    let correction = correction_of(&app, item_id, development);
    decisions::apply_suggestion(
        &mut app,
        &ctx,
        &correction,
        "Guarded key",
        SuggestionAnswer::Ignore,
    );
    assert!(app.owner.check.is_none());
    assert_eq!(
        correction_of(&app, item_id, development).state,
        CorrectionState::Ignored
    );
    assert!(app.status_text.contains("Ignored."), "{}", app.status_text);

    // The use log raised the item from development to production until the answer.
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.set_declaration_environment(item_id, crate::vault::Environment::Production)
        })
        .expect("open")
        .expect("raise");
    let raised = propose(
        &app,
        item_id,
        CorrectionKind::Environment,
        "production",
        serde_json::json!({ "signal": "the value has a production prefix of its provider", RAISED_FROM_FACT: "development" }),
    );
    let correction = correction_of(&app, item_id, raised);
    assert!(decisions::suggestion_needs_check(
        &app,
        &correction,
        SuggestionAnswer::Ignore
    ));
    let choices = decisions::suggestion_choices(&correction);
    assert_eq!(choices[0].0, "Production");
    assert_eq!(choices[1].0, "Development");
    app.place = Place::Decisions;
    let (text, _) = frames(&mut app, WIDE, 3);
    for expected in [
        "Is Guarded key a production key?",
        "Before",
        "Ignore makes it development again.",
        "Development and Ignore need Touch ID or the passphrase.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    decisions::apply_suggestion(
        &mut app,
        &ctx,
        &correction,
        "Guarded key",
        SuggestionAnswer::Ignore,
    );
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        check
            .request
            .describe()
            .contains("Ignore the suggestion for \"Guarded key\": it is development again."),
        "{}",
        check.request.describe()
    );
    assert!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    assert_eq!(
        environment_of(&app, item_id),
        Some(crate::vault::Environment::Production)
    );
    decisions::apply_suggestion(
        &mut app,
        &ctx,
        &correction,
        "Guarded key",
        SuggestionAnswer::Ignore,
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(
        environment_of(&app, item_id),
        Some(crate::vault::Environment::Development)
    );
    assert_eq!(
        correction_of(&app, item_id, raised).state,
        CorrectionState::Ignored
    );
    frames(&mut app, WIDE, 1);
    assert_eq!(decisions::selected_key(&app), None, "nothing waits");
}

/// The facts of a correction read as rows in the order of the mockup (the uses, where it
/// sends, the provider, then the signal); a provider shows its name, and the
/// bookkeeping of the correction shows no row.
#[test]
fn the_facts_of_a_suggestion_read_as_rows() {
    let rows = decisions::fact_rows(&serde_json::json!({
        "uses": 4,
        "hosts": ["api.sandbox.example"],
        "signal": "every use went to a development or test host",
        "provider": "stripe",
        "extra_note": true,
        "nothing": null,
        "applied": false,
        "previous_environment": "production",
    }));
    let labels: Vec<&str> = rows.iter().map(|(label, _)| label.as_str()).collect();
    assert_eq!(
        labels,
        ["Uses", "Sends to", "Provider", "Seen", "Extra note"]
    );
    assert_eq!(rows[0].1, "4");
    assert_eq!(rows[1].1, "only api.sandbox.example");
    assert_eq!(rows[2].1, "Stripe");
    assert_eq!(rows[4].1, "Yes");
    assert!(decisions::fact_rows(&serde_json::Value::Null).is_empty());
}

/// A request (with a detected paste) and a suggestion draw at the default and the
/// smallest window, with the sidebar full, collapsed, and floating. No text runs past
/// the edge, and the paste never shows.
#[test]
fn requests_and_suggestions_draw_at_every_size() {
    #[derive(Debug, Clone, Copy)]
    enum Sidebar {
        Full,
        Collapsed,
        Float,
    }
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let (_, request) = ask_for_key(
        &mut app,
        "A coding agent with a rather long name",
        "A Stripe test key with a rather long name for the narrow card",
        "Open https://dashboard.stripe.com/test/apikeys and create a restricted key with write access to payouts",
    );
    let suggestion = propose(
        &app,
        item_id,
        CorrectionKind::Environment,
        "development",
        serde_json::json!({
            "signal": "every use went to a development or test host",
            "hosts": ["api.sandbox.example", "uploads.sandbox.example", "files.test"],
            "uses": 12,
        }),
    );
    let key = fake("sk_test_", 24);
    for (selected, expected) in [
        (Key::Request(request), ["Get it at", "Not Now", "Save"]),
        (
            Key::Suggestion(suggestion),
            ["Seen", "Ignore", "Development"],
        ),
    ] {
        for size in [DEFAULT, SMALLEST] {
            for sidebar in [Sidebar::Full, Sidebar::Collapsed, Sidebar::Float] {
                app.place = Place::Decisions;
                app.ui.sidebar_hidden = matches!(sidebar, Sidebar::Collapsed);
                app.ui.sidebar_float = matches!(sidebar, Sidebar::Float);
                decisions::select_key(&mut app, selected);
                frames(&mut app, size, 1);
                if matches!(selected, Key::Request(_)) {
                    decisions::set_paste(&mut app, &key);
                }
                let (text, past) = frames(&mut app, size, 3);
                let at = format!("{selected:?} at {size:?}, {sidebar:?}");
                for needle in expected {
                    assert!(text.contains(needle), "{needle} in {at}: {text}");
                }
                assert!(!text.contains(&key), "the paste shows in {at}");
                assert!(past.is_empty(), "past the edge in {at}: {past:?}");
            }
        }
    }
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

/// The unlock erases a previous value that is no longer valid (an allowed use came after
/// the new value), so no stale secret waits in the file.
#[test]
fn unlock_prunes_the_previous_values_that_are_no_longer_valid() {
    use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
    use crate::vault::{ItemOrigin, OriginTool};

    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let (agent, _) = app
        .owner_ui
        .session
        .register_agent("Prune agent")
        .expect("agent");
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault
                .set_item_origin(
                    item_id,
                    &ItemOrigin {
                        agent_id: agent.id,
                        agent_name: "Prune agent".to_owned(),
                        project_key: String::new(),
                        project_label: String::new(),
                        tool: OriginTool::Generate,
                    },
                )
                .expect("origin");
            vault
                .replace_own_item_value(agent.id, item_id, "FAKE-new-value-0002")
                .expect("replace");
            assert!(vault.previous_value(item_id).expect("read").is_some());
            vault
                .record_item_use(&NewItemUse {
                    item_id,
                    agent_id: Some(agent.id),
                    agent_name: "Prune agent".to_owned(),
                    project_key: String::new(),
                    project_label: String::new(),
                    action: ActionKind::Read,
                    command_summary: "synthetic".to_owned(),
                    hosts: Vec::new(),
                    outcome: UseOutcome::Allowed,
                    decided_by: UseDecidedBy::Bouncer,
                    answered_on: String::new(),
                    decision_log_id: None,
                })
                .expect("use");
        })
        .expect("open");
    app.owner_ui.session.lock().expect("lock");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let left = app
        .owner_ui
        .session
        .with_vault(|vault| vault.prune_previous_values())
        .expect("open")
        .expect("prune");
    assert_eq!(left, 0, "the unlock pruned it already");
}

// ---- Questions of other Macs (relay-questions-v1 section 13). ----

/// A question of the Mac "Synthetic Mac mini" for `run`, as the lister opens it.
fn remote_opened(pending: &PendingRun) -> crate::questions::OpenedQuestion {
    use crate::questions::{Card, OpenedQuestion, QuestionRecord};
    use crate::vault::{TrustedDevice, TrustedDeviceKind};
    let qid = "oKGio6SlpqeoqaqrrK2urw";
    let asker = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let card = Card::from_run(qid, asker, "Synthetic Mac mini", now, pending);
    let run = card.to_run().expect("the card names a run");
    OpenedQuestion {
        team_id: "t_7k2m5q4x3c".to_owned(),
        record: QuestionRecord {
            qid: qid.to_owned(),
            seq: 1,
            to: "member".to_owned(),
            from_device_id: 2,
            from_device_name: "Synthetic Mac mini".to_owned(),
            key_id: "630dcd2966c43366".to_owned(),
            nonce: String::new(),
            ciphertext: String::new(),
            created_at: now,
            expires_at: now + 240,
            state: "open".to_owned(),
            settled_at: None,
            settle: None,
        },
        card,
        run,
        asker: TrustedDevice {
            uuid: asker.to_owned(),
            name: "Synthetic Mac mini".to_owned(),
            kind: TrustedDeviceKind::Mac,
            relay_devices: Default::default(),
            sign_key: vec![4; 65],
            answer_key: None,
            created_at: 0,
            updated_at: 0,
            updated_by: String::new(),
        },
    }
}

/// A question of another Mac waits in Waiting after the questions of this Mac, "from
/// MAC", with the same detail and bar, and counts in the badge. "Allow Once" opens the
/// owner check for `OwnerAction::AnswerRemoteQuestion` of exactly this question and
/// answer; a stricter answer opens none, and "Disconnect" asks once. (The relay round
/// trip is in `tests/relay_questions.rs`.)
#[test]
fn a_question_of_another_mac_waits_from_that_mac_and_allow_needs_the_owner_check() {
    use crate::broker::approvals::OwnerAction;
    use crate::desktop::owner_check::OwnerRequest;
    use crate::questions::{QuestionsConfig, QuestionsWorker};
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let queue = queue_of(&mut app, &dir);
    // The questions waiter of the app, without a relay membership: it calls no relay.
    let worker = QuestionsWorker::start(
        Arc::clone(&queue),
        app.owner_ui.session.shared_vault(),
        app.owner_gate(),
        QuestionsConfig {
            question_wait: Duration::from_secs(300),
            tick: Duration::from_millis(50),
            device_name: "Synthetic MacBook".to_owned(),
            ..QuestionsConfig::default()
        },
    );
    let mut pending = run(
        "claude-code",
        question(vec![item(item_id, "Guarded key")], &[]),
    );
    pending.id = 41;
    let opened = remote_opened(&pending);
    let remote_id = worker.insert_remote_for_test(opened.clone());
    app.owner.questions = Some(worker);
    app.place = Place::Decisions;
    let ctx = egui::Context::default();

    let (text, past) = frames(&mut app, DEFAULT, 3);
    assert!(text.contains("Waiting"), "{text}");
    assert!(
        text.contains("claude-code · acme-billing · from Synthetic Mac mini"),
        "{text}"
    );
    assert!(past.is_empty(), "{past:?}");
    assert_eq!(decisions::badge_count(&app, &[]), 1);
    assert_eq!(decisions::selected_key(&app), Some(Key::Remote(remote_id)));
    for expected in [
        "claude-code wants to use Guarded key",
        "Asked on Synthetic Mac mini.",
        "Allow Once",
        "Deny",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    let (_, past) = frames(&mut app, SMALLEST, 3);
    assert!(past.is_empty(), "{past:?}");

    // "Allow Once": the owner check of this Mac for exactly this answer.
    let remote = app.owner.questions.as_ref().expect("worker").view().remote[0].clone();
    decisions::apply_remote(&mut app, &ctx, &remote, Answer::Once);
    let request = app
        .owner
        .check
        .as_ref()
        .expect("owner check")
        .request
        .clone();
    assert!(matches!(
        request,
        OwnerRequest::AnswerRemoteQuestion { remote_id: id, .. } if id == remote_id
    ));
    let action = request.action();
    assert_eq!(
        action,
        OwnerAction::AnswerRemoteQuestion {
            qid: opened.record.qid.clone(),
            asker: "Synthetic Mac mini".to_owned(),
            answer: Box::new(OwnerAction::ApproveRun(opened.run.clone())),
        }
    );
    assert!(
        action.reason().ends_with(" on Synthetic Mac mini"),
        "{}",
        action.reason()
    );
    assert!(
        request.describe().starts_with(
            "Answer \"Allow Once\" to the question of claude-code on Synthetic Mac mini."
        ),
        "{}",
        request.describe()
    );
    // A wrong passphrase sends nothing.
    assert!(
        app.confirm_owner_now(crate::broker::approvals::OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    app.settle_remote_answers_for_test();
    assert!(app.owner.check.is_none());

    // A stricter answer: no owner check. Without a relay session it goes nowhere, and
    // says so.
    decisions::apply_remote(&mut app, &ctx, &remote, Answer::Never);
    assert!(app.owner.check.is_none(), "no owner check");
    app.settle_remote_answers_for_test();
    assert_eq!(
        app.status_text, "This question no longer waits on this Mac.",
        "{}",
        app.status_text
    );
    decisions::apply_remote(&mut app, &ctx, &remote, Answer::Disconnect);
    assert!(decisions::disconnecting(&app), "Disconnect asks once");
    assert!(app.owner.check.is_none());
    let (text, _) = frames(&mut app, DEFAULT, 3);
    assert!(text.contains("Disconnect claude-code?"), "{text}");
    assert_eq!(queue.pending().len(), 0, "the local queue is untouched");
}

/// Each answer on the bar is the answer kind of the card (section 9.1).
#[test]
fn the_answers_of_the_bar_map_to_the_answer_kinds() {
    use crate::questions::{Choice, RemoteEnvironment};
    let pending = run(
        "claude-code",
        question(
            vec![item(7, "Guarded key")],
            &[AnswerKind::InProject(ActionKind::Read)],
        ),
    );
    let key = "/synthetic/acme-billing".to_owned();
    let cases = [
        (Answer::Deny, Choice::Deny),
        (Answer::Once, Choice::ApproveOnce),
        (
            Answer::InProject(ActionKind::Read),
            Choice::ApproveInProject {
                action: ActionKind::Read,
                project_key: key.clone(),
            },
        ),
        (
            Answer::Production(ActionKind::Read),
            Choice::AllowProduction {
                action: ActionKind::Read,
                project_key: key,
            },
        ),
        (
            Answer::Development {
                item_id: 7,
                name: "Guarded key".to_owned(),
            },
            Choice::CorrectEnvironment {
                item_id: 7,
                environment: RemoteEnvironment::Development,
            },
        ),
        (
            Answer::MarkProduction {
                item_id: 7,
                name: "Guarded key".to_owned(),
            },
            Choice::CorrectEnvironment {
                item_id: 7,
                environment: RemoteEnvironment::Production,
            },
        ),
        (Answer::Never, Choice::NeverForAgent),
        (Answer::AlwaysAsk, Choice::AlwaysAskForAgent),
        (Answer::Disconnect, Choice::Disconnect),
    ];
    for (answer, choice) in cases {
        let mapped = decisions::remote_choice(&pending, &answer).expect("an answer kind");
        assert_eq!(mapped, choice, "{answer:?}");
        let approving = matches!(
            answer,
            Answer::Once
                | Answer::InProject(_)
                | Answer::Production(_)
                | Answer::Development { .. }
        );
        assert_eq!(mapped.needs_owner_check(), approving, "{answer:?}");
    }
    let mut no_project = pending.clone();
    no_project.question.project = None;
    assert!(decisions::remote_choice(&no_project, &Answer::InProject(ActionKind::Read)).is_none());
}
