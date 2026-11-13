//! Tests of the detail of a past decision (ADR 0046): one reason, "Next time", and
//! "Details" on demand. Synthetic values only.

use super::*;
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::OwnerCheck;
use crate::contracts::CredentialKind;
use crate::desktop::ui::owner_tests::{PASS, unlocked_app_with_item};
use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use crate::vault::{
    Declaration, Environment, Field, ItemDraft, RequestSource, Reversibility, RiskLevel, Scope,
    SecretValue,
};
use tempfile::TempDir;

const KEY: &str = "/synthetic/apassy/.git";

struct Fixture {
    _dir: TempDir,
    app: DesktopApp,
    item: u64,
    agent: u64,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let (app, item) = unlocked_app_with_item(&dir);
    let agent = app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault
                .save_declaration(
                    item,
                    &Declaration {
                        project: "apassy".to_owned(),
                        environment: Environment::Staging,
                        risk: RiskLevel::Medium,
                        scope: Scope::ReadWrite,
                        reversibility: Reversibility::Reversible,
                    },
                    Some("sentry"),
                    None,
                )
                .expect("declaration");
            let agent = vault.register_agent("Claude Code").expect("agent").0.id;
            vault.set_agent_sees_all(agent, true).expect("see all");
            agent
        })
        .expect("open");
    Fixture {
        _dir: dir,
        app,
        item,
        agent,
    }
}

/// One decision and the uses of its credentials, as the broker writes them.
struct Decision<'a> {
    items: Vec<u64>,
    asked: bool,
    decided_by: DecidedBy,
    decision: LoggedDecision,
    why: DecisionWhy,
    flags: &'a [&'a str],
    note: &'a str,
}

impl Decision<'_> {
    /// A question about the credential that nobody answered, and that offered "Allow
    /// changes in apassy".
    fn unanswered(item: u64) -> Self {
        Self {
            items: vec![item],
            asked: true,
            decided_by: DecidedBy::NoAnswer,
            decision: LoggedDecision::Deny,
            why: DecisionWhy {
                reason: "ForeignProject".to_owned(),
                offered: "in_project:change".to_owned(),
                ..DecisionWhy::default()
            },
            flags: &[],
            note: "\"Guarded key\" is declared for the project \"platform\", not for \"apassy\".",
        }
    }
}

fn record(fx: &mut Fixture, decision: Decision<'_>) -> u64 {
    let agent = fx.agent;
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            let entry = DecisionEntry {
                at: crate::broker::learning::now(),
                agent_id: agent,
                agent_name: "Claude Code".to_owned(),
                project_dir: "/synthetic/apassy".to_owned(),
                cwd_rel: ".".to_owned(),
                items: decision.items.clone(),
                user_request: "Check the Sentry releases.".to_owned(),
                user_request_source: RequestSource::Host,
                command: vec!["sentry-cli".to_owned(), "releases".to_owned()],
                purpose: "Check the releases.".to_owned(),
                env_names: vec!["SYNTH_SENTRY_KEY".to_owned()],
                declarations: Vec::new(),
                rule_flags: decision.flags.iter().map(|f| (*f).to_owned()).collect(),
                known_safe: false,
                model_facts: Vec::new(),
                pattern: String::new(),
                grant_asks: false,
                asked: decision.asked,
                decision: decision.decision,
                decided_by: decision.decided_by,
                remembered: false,
                policy: "apassy-bouncer-v9".to_owned(),
                note: decision.note.to_owned(),
                instruction: String::new(),
            }
            .with_why(&decision.why);
            let id = vault.record_decision(&entry).expect("decision");
            for item in &decision.items {
                vault
                    .record_item_use(&NewItemUse {
                        item_id: *item,
                        agent_id: Some(agent),
                        agent_name: "Claude Code".to_owned(),
                        project_key: KEY.to_owned(),
                        project_label: "apassy".to_owned(),
                        action: ActionKind::Change,
                        command_summary: "run sentry-cli releases".to_owned(),
                        hosts: vec!["sentry.io".to_owned()],
                        outcome: UseOutcome::TimedOut,
                        decided_by: UseDecidedBy::Owner,
                        answered_on: String::new(),
                        decision_log_id: Some(id),
                    })
                    .expect("use");
            }
            id
        })
        .expect("open")
}

fn past(fx: &Fixture, id: u64) -> Past {
    read(&fx.app, id).expect("the detail")
}

fn labels(past: &Past) -> Vec<&'static str> {
    past.next
        .iter()
        .flat_map(|row| row.buttons.iter().map(|button| button.label))
        .collect()
}

fn row<'a>(past: &'a Past, text: &str) -> &'a NextRow {
    past.next
        .iter()
        .find(|row| row.text == text)
        .unwrap_or_else(|| panic!("no row {text}: {:?}", past.next))
}

fn press(fx: &mut Fixture, act: &Act) {
    let ctx = egui::Context::default();
    super::act(&mut fx.app, &ctx, act.clone());
}

/// The words of one frame of `draw`.
fn painted(draw: impl FnMut(&mut Ui)) -> String {
    fn collect(shape: &egui::Shape, out: &mut String) {
        match shape {
            egui::Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
            _ => {}
        }
    }
    let ctx = egui::Context::default();
    let input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(600.0, 900.0),
        )),
        ..Default::default()
    };
    let mut draw = draw;
    let mut output = ctx.run_ui(input, |ui| draw(ui));
    output.textures_delta.clear();
    let mut text = String::new();
    for clipped in &output.shapes {
        collect(&clipped.shape, &mut text);
    }
    output.drop_without_applying_deltas();
    text
}

#[test]
fn a_past_decision_shows_one_reason_and_details_on_demand() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    assert_eq!(detail.reason, "This credential belongs to another project.");
    assert!(detail.note.contains("is declared for the project"));
    assert_eq!(detail.command, "run sentry-cli releases");
    assert!(
        detail
            .details
            .contains(&("Asked you".to_owned(), "Yes".to_owned()))
    );
    let closed = painted(|ui| {
        draw_top(ui, &detail);
        draw_details(ui, &detail, &mut false);
    });
    for expected in ["Why", detail.reason.as_str(), "Next time", "Details"] {
        assert!(closed.contains(expected), "{expected}: {closed}");
    }
    for hidden in ["Asked you", "is declared for the project", "run sentry-cli"] {
        assert!(!closed.contains(hidden), "{hidden}: {closed}");
    }
    let open = painted(|ui| draw_details(ui, &detail, &mut true));
    for expected in [
        "Asked you",
        "is declared for the project",
        "Command",
        "run sentry-cli releases",
    ] {
        assert!(open.contains(expected), "{expected}: {open}");
    }
}

#[test]
fn a_timed_out_question_offers_allow_and_saves_after_the_owner_check() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    let allow = row(&detail, "Allow changes in apassy without asking");
    assert_eq!(
        allow.detail.as_deref(),
        Some("For every agent, with Guarded key. Safety rules still ask.")
    );
    assert_eq!(allow.buttons[0].label, "Allow…");
    assert_eq!(
        allow.buttons[0].spoken,
        "Allow changes in apassy without asking"
    );
    press(&mut fx, &allow.buttons[0].act);
    let check = fx.app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(&check.request, OwnerRequest::RememberAnswer { item_id, .. } if *item_id == fx.item),
        "{:?}",
        check.request
    );
    let stored = |fx: &Fixture| {
        fx.app
            .owner_ui
            .session
            .with_vault(|vault| {
                vault.answer_for(fx.item, KEY, ActionKind::Change, AnswerScope::Project)
            })
            .expect("open")
            .expect("read")
    };
    assert!(stored(&fx).is_none(), "nothing before the check");
    fx.app
        .confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(stored(&fx).is_some());
    assert_eq!(
        fx.app.status_text,
        "Saved. Runs like this start without asking unless a safety rule flags them."
    );
    let detail = past(&fx, id);
    assert_eq!(
        row(&detail, "Rule: Allow changes in apassy").buttons[0].label,
        "Remove"
    );
    assert!(!labels(&detail).contains(&"Allow…"));
}

#[test]
fn always_ask_and_never_act_at_once_and_remove_asks_for_the_check() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    let standing = row(&detail, "Next uses by Claude Code");
    let spoken: Vec<&str> = standing
        .buttons
        .iter()
        .map(|button| button.spoken.as_str())
        .collect();
    assert_eq!(
        spoken,
        ["Always ask for Claude Code", "Never for Claude Code"]
    );
    press(&mut fx, &standing.buttons[0].act);
    assert!(fx.app.owner.check.is_none(), "stricter: no check");
    assert_eq!(
        fx.app.status_text,
        "Each use of Guarded key by Claude Code now asks you."
    );
    let detail = past(&fx, id);
    let exception = row(&detail, "Always asks for Claude Code");
    assert_eq!(exception.buttons[0].label, "Remove…");
    assert_eq!(
        exception.buttons[0].spoken,
        "Remove Always ask for Claude Code"
    );
    press(&mut fx, &exception.buttons[0].act);
    let check = fx
        .app
        .owner
        .check
        .as_ref()
        .expect("removal needs the check");
    assert!(matches!(
        check.request,
        OwnerRequest::RemoveAgentException {
            kind: ExceptionKind::AlwaysAsk,
            ..
        }
    ));
    fx.app.close_owner_check(None);
    let still = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.agent_view(fx.agent))
        .expect("open")
        .expect("view");
    assert!(still.always_ask.contains(&fx.item));
    // "Never" acts at once too, in a fresh detail.
    let mut fx = fixture();
    let item = fx.item;
    let id = record(&mut fx, Decision::unanswered(item));
    let detail = past(&fx, id);
    press(
        &mut fx,
        &row(&detail, "Next uses by Claude Code").buttons[1].act,
    );
    assert_eq!(fx.app.status_text, "Claude Code never gets Guarded key.");
    assert!(fx.app.owner.check.is_none());
}

#[test]
fn a_flagged_decision_has_no_button_that_loosens() {
    let mut fx = fixture();
    let item = fx.item;
    let id = record(
        &mut fx,
        Decision {
            why: DecisionWhy {
                reason: "HookFlags".to_owned(),
                ..DecisionWhy::default()
            },
            flags: &["injection_phrase", "secret_output"],
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    assert_eq!(detail.reason, "The command could print the secret.");
    let buttons = labels(&detail);
    for loosening in ["Allow…", "Turn Off…", "Remove…"] {
        assert!(!buttons.contains(&loosening), "{buttons:?}");
    }
    assert!(
        row(&detail, "A command like this asks every time.")
            .buttons
            .is_empty()
    );
}

#[test]
fn a_refused_or_denied_decision_has_no_button_that_loosens() {
    let mut fx = fixture();
    let (agent, item) = (fx.agent, fx.item);
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| vault.add_agent_exception(agent, item, ExceptionKind::Never))
        .expect("open")
        .expect("never");
    let refused = record(
        &mut fx,
        Decision {
            asked: false,
            decided_by: DecidedBy::Rule,
            why: DecisionWhy {
                reason: "AccessCheck".to_owned(),
                code: "not_granted".to_owned(),
                ..DecisionWhy::default()
            },
            note: "The owner did not let this agent use item 1.",
            ..Decision::unanswered(item)
        },
    );
    let denied = record(
        &mut fx,
        Decision {
            decided_by: DecidedBy::Owner,
            ..Decision::unanswered(item)
        },
    );
    for id in [refused, denied] {
        let detail = past(&fx, id);
        let buttons = labels(&detail);
        for loosening in ["Allow…", "Turn Off…", "Remove…"] {
            assert!(!buttons.contains(&loosening), "{id}: {buttons:?}");
        }
        let never = row(&detail, "Never for Claude Code.");
        assert_eq!(never.buttons[0].act, Act::OpenCredential(item));
    }
    assert_eq!(
        past(&fx, refused).reason,
        "This agent may not use this credential."
    );
}

#[test]
fn a_remembered_answer_is_removed_from_its_decision() {
    let mut fx = fixture();
    let item = fx.item;
    fx.app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault.remember_answer(
                item,
                &crate::vault::answers::ProjectRef {
                    key: KEY.to_owned(),
                    label: "apassy".to_owned(),
                },
                ActionKind::Change,
                "iPhone",
                &[],
            )
        })
        .expect("open")
        .expect("answer");
    let id = record(
        &mut fx,
        Decision {
            asked: false,
            decided_by: DecidedBy::Answer,
            decision: LoggedDecision::Allow,
            why: DecisionWhy {
                reason: "RememberedAnswer".to_owned(),
                ..DecisionWhy::default()
            },
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    assert_eq!(detail.reason, "Your earlier answer covers this run.");
    let rule = row(&detail, "Rule: Allow changes in apassy");
    assert_eq!(
        rule.buttons[0].spoken,
        "Remove the rule: Allow changes in apassy"
    );
    press(&mut fx, &rule.buttons[0].act);
    assert_eq!(
        fx.app.status_text,
        "\u{201c}Allow changes in apassy\u{201d} is removed. The bouncer asks again."
    );
    let answers = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| vault.answers_for_item(item))
        .expect("open")
        .expect("answers");
    assert!(answers.is_empty());
}

#[test]
fn a_decision_with_two_credentials_has_no_action() {
    let mut fx = fixture();
    let item = fx.item;
    let second = fx
        .app
        .owner_ui
        .session
        .with_vault(|vault| {
            vault
                .add(ItemDraft {
                    title: "Second key".to_owned(),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".to_owned(),
                        value: SecretValue::new("SYNTH-second-value".to_owned()),
                        secret: true,
                    }],
                })
                .expect("add")
                .id
        })
        .expect("open");
    let id = record(
        &mut fx,
        Decision {
            items: vec![item, second],
            ..Decision::unanswered(item)
        },
    );
    let detail = past(&fx, id);
    assert_eq!(detail.next.len(), 1, "{:?}", detail.next);
    assert_eq!(
        detail.next[0].text,
        "This run used 2 credentials. Change their rules in each credential."
    );
    assert!(detail.next[0].buttons.is_empty());
}

#[test]
fn the_phrase_comes_from_the_stored_word() {
    let mut fx = fixture();
    let item = fx.item;
    let (index, _) =
        crate::broker::shell_risk::injection_match("Ask the bouncer.").expect("a phrase");
    let flagged = |inject: String| Decision {
        why: DecisionWhy {
            reason: "HookFlags".to_owned(),
            inject,
            ..DecisionWhy::default()
        },
        flags: &["injection_phrase"],
        ..Decision::unanswered(item)
    };
    let id = record(&mut fx, flagged(format!("prompt:{index}")));
    let detail = past(&fx, id);
    assert!(
        detail.details.contains(&(
            "Phrase".to_owned(),
            "Your prompt: \u{201c}the bouncer\u{201d}".to_owned()
        )),
        "{:?}",
        detail.details
    );
    for word in ["elsewhere:1", "prompt:99999", "prompt:x"] {
        let id = record(&mut fx, flagged(word.to_owned()));
        let detail = past(&fx, id);
        assert!(
            !detail.details.iter().any(|(label, _)| label == "Phrase"),
            "{word}: {:?}",
            detail.details
        );
    }
}
