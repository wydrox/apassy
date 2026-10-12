//! The digest of a waiting run (contract companion-v1, section 7).
//!
//! The digest names a run exactly as the Mac shows it: SHA-256 over a version tag and
//! every field of the [`PendingRun`], each with its length. A text is its length as an
//! 8-byte big-endian number and its bytes. A list is its count and its texts. The remember
//! offer is a marker byte, and for an offer its pattern and two counts. So no two
//! different runs give the same input, also when text moves from one field to the next
//! (`["ab", "c"]` and `["a", "bc"]` differ).
//!
//! The phone treats the digest as opaque and signs it in an approval. Only the Mac
//! computes it.
//!
//! The question digest v2 ([`question_digest_v2`], contract relay-questions-v1 section
//! 8) is the same encoding of the run with its own tag, then every field of the
//! [`QuestionInfo`]: a device that answers through the relay signs the question as it
//! showed it, the bouncer text included. The v1 digest stays for the local-network
//! companion and never changes.

use ring::digest::{Context, SHA256};

use super::crypto::hex;
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::{AnswerKind, PendingRun};

/// The version tag at the start of the digest input. A change of the encoding changes it.
const TAG: &str = "apassy-companion-run-v1";
/// The tag of the question digest v2.
const QUESTION_TAG: &str = "apassy-question-v2";

/// The digest of `run` as 32 bytes.
pub fn run_digest(run: &PendingRun) -> [u8; 32] {
    let mut hash = Context::new(&SHA256);
    text(&mut hash, TAG);
    hash.update(&run.id.to_be_bytes());
    text(&mut hash, &run.agent);
    list(&mut hash, &run.command);
    text(&mut hash, &run.cwd);
    list(&mut hash, &run.env_names);
    text(&mut hash, &run.purpose);
    text(&mut hash, &run.risk);
    text(&mut hash, &run.user_request);
    text(&mut hash, &run.request_source);
    text(&mut hash, &run.agent_request);
    match &run.remember {
        None => hash.update(&[0]),
        Some(offer) => {
            hash.update(&[1]);
            text(&mut hash, &offer.pattern);
            hash.update(&offer.approvals.to_be_bytes());
            hash.update(&offer.needed.to_be_bytes());
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}

/// The digest of `run` as 64 lowercase hex characters, as the wire has it.
pub fn run_digest_hex(run: &PendingRun) -> String {
    hex(&run_digest(run))
}

/// The question digest v2 of `run` as it waits (contract relay-questions-v1, section 8):
/// the v1 input with the tag `apassy-question-v2`, then every field of `run.question`.
pub fn question_digest_v2(run: &PendingRun) -> [u8; 32] {
    let mut hash = Context::new(&SHA256);
    run_fields(&mut hash, QUESTION_TAG, run);
    let question = &run.question;
    hash.update(&question.id.to_be_bytes());
    length(&mut hash, question.item_ids.len());
    for id in &question.item_ids {
        hash.update(&id.to_be_bytes());
    }
    match &question.project {
        None => hash.update(&[0]),
        Some(project) => {
            hash.update(&[1]);
            text(&mut hash, &project.key);
            text(&mut hash, &project.label);
        }
    }
    text(&mut hash, question.action.as_str());
    hash.update(&[u8::from(question.production)]);
    text(&mut hash, &question.why);
    length(&mut hash, question.items.len());
    for item in &question.items {
        hash.update(&item.item_id.to_be_bytes());
        text(&mut hash, &item.name);
        hash.update(&[
            u8::from(item.production),
            u8::from(item.unconfirmed),
            u8::from(item.always_ask),
        ]);
    }
    let answers: Vec<String> = question
        .valid_answers
        .iter()
        .map(|kind| answer_kind_text(*kind))
        .collect();
    list(&mut hash, &answers);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}

/// The question digest v2 as 64 lowercase hex characters.
pub fn question_digest_v2_hex(run: &PendingRun) -> String {
    hex(&question_digest_v2(run))
}

/// An answer that a question offers, as the card and the digest v2 name it
/// (relay-questions-v1 section 7.1): `once`, `in_project:<action>`,
/// `production:<action>`, `never_for_agent`, `always_ask_for_agent`, `disconnect`, or
/// `correct_environment`.
pub fn answer_kind_text(kind: AnswerKind) -> String {
    match kind {
        AnswerKind::Once => "once".to_owned(),
        AnswerKind::InProject(action) => format!("in_project:{}", action.as_str()),
        AnswerKind::Production(action) => format!("production:{}", action.as_str()),
        AnswerKind::NeverForAgent => "never_for_agent".to_owned(),
        AnswerKind::AlwaysAskForAgent => "always_ask_for_agent".to_owned(),
        AnswerKind::Disconnect => "disconnect".to_owned(),
        AnswerKind::CorrectEnvironment => "correct_environment".to_owned(),
    }
}

/// The answer kind of a text of [`answer_kind_text`]. `None` for any other text.
pub fn parse_answer_kind(text: &str) -> Option<AnswerKind> {
    match text {
        "once" => Some(AnswerKind::Once),
        "never_for_agent" => Some(AnswerKind::NeverForAgent),
        "always_ask_for_agent" => Some(AnswerKind::AlwaysAskForAgent),
        "disconnect" => Some(AnswerKind::Disconnect),
        "correct_environment" => Some(AnswerKind::CorrectEnvironment),
        other => {
            if let Some(action) = other.strip_prefix("in_project:") {
                ActionKind::parse(action).map(AnswerKind::InProject)
            } else if let Some(action) = other.strip_prefix("production:") {
                ActionKind::parse(action).map(AnswerKind::Production)
            } else {
                None
            }
        }
    }
}

/// The run fields of the digest v2, after `tag`: byte for byte the v1 input with
/// another tag (contract relay-questions-v1, section 8).
fn run_fields(hash: &mut Context, tag: &str, run: &PendingRun) {
    text(hash, tag);
    hash.update(&run.id.to_be_bytes());
    text(hash, &run.agent);
    list(hash, &run.command);
    text(hash, &run.cwd);
    list(hash, &run.env_names);
    text(hash, &run.purpose);
    text(hash, &run.risk);
    text(hash, &run.user_request);
    text(hash, &run.request_source);
    text(hash, &run.agent_request);
    match &run.remember {
        None => hash.update(&[0]),
        Some(offer) => {
            hash.update(&[1]);
            text(hash, &offer.pattern);
            hash.update(&offer.approvals.to_be_bytes());
            hash.update(&offer.needed.to_be_bytes());
        }
    }
}

fn length(hash: &mut Context, len: usize) {
    hash.update(&(len as u64).to_be_bytes());
}

fn text(hash: &mut Context, value: &str) {
    length(hash, value.len());
    hash.update(value.as_bytes());
}

fn list(hash: &mut Context, values: &[String]) {
    length(hash, values.len());
    for value in values {
        text(hash, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::approvals::RememberOffer;

    fn base() -> PendingRun {
        PendingRun {
            id: 123_456_789_012_345,
            agent: "claude-code".to_owned(),
            command: vec!["npm".to_owned(), "run".to_owned(), "migrate".to_owned()],
            cwd: "/tmp/synthetic-shop".to_owned(),
            env_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
            purpose: "Apply the new migration.".to_owned(),
            risk: "production credential: always asks the owner".to_owned(),
            user_request: "Deploy the new schema to staging.".to_owned(),
            request_source: "from the host hook".to_owned(),
            agent_request: "Run the migration.".to_owned(),
            remember: Some(RememberOffer {
                pattern: "npm run migrate".to_owned(),
                approvals: 1,
                needed: 3,
            }),
            question: Default::default(),
        }
    }

    #[test]
    fn the_digest_is_stable_and_has_64_hex_characters() {
        let digest = run_digest_hex(&base());
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(digest, run_digest_hex(&base().clone()));
        assert_eq!(hex(&run_digest(&base())), digest);
    }

    #[test]
    fn every_field_changes_the_digest() {
        let original = run_digest(&base());
        let variants: Vec<(&str, PendingRun)> = vec![
            ("id", PendingRun { id: 1, ..base() }),
            (
                "agent",
                PendingRun {
                    agent: "codex".to_owned(),
                    ..base()
                },
            ),
            (
                "command",
                PendingRun {
                    command: vec!["npm".to_owned(), "run".to_owned()],
                    ..base()
                },
            ),
            (
                "cwd",
                PendingRun {
                    cwd: "/tmp/other".to_owned(),
                    ..base()
                },
            ),
            (
                "env_names",
                PendingRun {
                    env_names: vec!["DATABASE_URL".to_owned()],
                    ..base()
                },
            ),
            (
                "purpose",
                PendingRun {
                    purpose: "Apply.".to_owned(),
                    ..base()
                },
            ),
            (
                "risk",
                PendingRun {
                    risk: String::new(),
                    ..base()
                },
            ),
            (
                "user_request",
                PendingRun {
                    user_request: String::new(),
                    ..base()
                },
            ),
            (
                "request_source",
                PendingRun {
                    request_source: "from the agent".to_owned(),
                    ..base()
                },
            ),
            (
                "agent_request",
                PendingRun {
                    agent_request: String::new(),
                    ..base()
                },
            ),
            (
                "remember none",
                PendingRun {
                    remember: None,
                    ..base()
                },
            ),
            (
                "remember pattern",
                PendingRun {
                    remember: Some(RememberOffer {
                        pattern: "npm run <word>".to_owned(),
                        approvals: 1,
                        needed: 3,
                    }),
                    ..base()
                },
            ),
            (
                "remember approvals",
                PendingRun {
                    remember: Some(RememberOffer {
                        pattern: "npm run migrate".to_owned(),
                        approvals: 2,
                        needed: 3,
                    }),
                    ..base()
                },
            ),
            (
                "remember needed",
                PendingRun {
                    remember: Some(RememberOffer {
                        pattern: "npm run migrate".to_owned(),
                        approvals: 1,
                        needed: 4,
                    }),
                    ..base()
                },
            ),
        ];
        for (field, variant) in &variants {
            assert_ne!(run_digest(variant), original, "{field}");
        }
        // Each variant also differs from every other variant.
        for (i, (a, left)) in variants.iter().enumerate() {
            for (b, right) in &variants[i + 1..] {
                assert_ne!(run_digest(left), run_digest(right), "{a} and {b}");
            }
        }
    }

    #[test]
    fn a_shift_between_list_items_changes_the_digest() {
        let with = |command: &[&str]| PendingRun {
            command: command.iter().map(|part| (*part).to_owned()).collect(),
            ..base()
        };
        assert_ne!(
            run_digest(&with(&["ab", "c"])),
            run_digest(&with(&["a", "bc"]))
        );
        assert_ne!(
            run_digest(&with(&["ab", ""])),
            run_digest(&with(&["a", "b"]))
        );
        assert_ne!(run_digest(&with(&["a b"])), run_digest(&with(&["a", "b"])));
        assert_ne!(run_digest(&with(&[])), run_digest(&with(&[""])));
        assert_ne!(run_digest(&with(&["", ""])), run_digest(&with(&[""])));
        let env = |names: &[&str]| PendingRun {
            env_names: names.iter().map(|name| (*name).to_owned()).collect(),
            ..base()
        };
        assert_ne!(
            run_digest(&env(&["AB", "C"])),
            run_digest(&env(&["A", "BC"]))
        );
    }

    #[test]
    fn moving_text_between_adjacent_fields_changes_the_digest() {
        let pair = |first: &str, second: &str| {
            (
                PendingRun {
                    agent: first.to_owned(),
                    cwd: second.to_owned(),
                    ..base()
                },
                PendingRun {
                    purpose: first.to_owned(),
                    risk: second.to_owned(),
                    ..base()
                },
                PendingRun {
                    user_request: first.to_owned(),
                    request_source: second.to_owned(),
                    ..base()
                },
                PendingRun {
                    request_source: first.to_owned(),
                    agent_request: second.to_owned(),
                    ..base()
                },
            )
        };
        let (a1, b1, c1, d1) = pair("ab", "c");
        let (a2, b2, c2, d2) = pair("a", "bc");
        assert_ne!(run_digest(&a1), run_digest(&a2));
        assert_ne!(run_digest(&b1), run_digest(&b2));
        assert_ne!(run_digest(&c1), run_digest(&c2));
        assert_ne!(run_digest(&d1), run_digest(&d2));
        // The same text in two different fields is a different run.
        assert_ne!(run_digest(&a1), run_digest(&b1));
        assert_ne!(run_digest(&c1), run_digest(&d1));
        // A text that moves from the last text field to the remember pattern.
        let moved_out = PendingRun {
            agent_request: "npm run migrate".to_owned(),
            remember: None,
            ..base()
        };
        let moved_in = PendingRun {
            agent_request: String::new(),
            remember: Some(RememberOffer {
                pattern: "npm run migrate".to_owned(),
                approvals: 0,
                needed: 0,
            }),
            ..base()
        };
        assert_ne!(run_digest(&moved_out), run_digest(&moved_in));
    }

    #[test]
    fn an_empty_offer_pattern_differs_from_no_offer() {
        let none = PendingRun {
            remember: None,
            ..base()
        };
        let empty = PendingRun {
            remember: Some(RememberOffer {
                pattern: String::new(),
                approvals: 0,
                needed: 0,
            }),
            ..base()
        };
        assert_ne!(run_digest(&none), run_digest(&empty));
    }

    #[test]
    fn a_text_with_a_newline_or_a_length_look_alike_does_not_collide() {
        let a = PendingRun {
            purpose: "x\ny".to_owned(),
            ..base()
        };
        let b = PendingRun {
            purpose: "x".to_owned(),
            risk: "y".to_owned(),
            ..base()
        };
        assert_ne!(run_digest(&a), run_digest(&b));
        // A text that starts with the 8-byte length of the next field.
        let prefix = String::from_utf8(vec![0, 0, 0, 0, 0, 0, 0, 1]).expect("ascii");
        let c = PendingRun {
            agent: format!("a{prefix}b"),
            cwd: String::new(),
            ..base()
        };
        let d = PendingRun {
            agent: "a".to_owned(),
            cwd: "b".to_owned(),
            ..base()
        };
        assert_ne!(run_digest(&c), run_digest(&d));
    }

    // ---- Question digest v2 (relay-questions-v1, sections 8 and 20.1). ----

    use crate::broker::approvals::{QuestionInfo, QuestionItem};
    use crate::broker::project::Project;

    /// The question of section 7.1 of the contract.
    fn question() -> QuestionInfo {
        QuestionInfo {
            id: 123_456_789_012_345,
            item_ids: vec![7, 9],
            project: Some(Project {
                key: "/tmp/synthetic-shop/.git".to_owned(),
                label: "synthetic-shop".to_owned(),
                root: std::path::PathBuf::from("/tmp/synthetic-shop"),
            }),
            action: ActionKind::Deploy,
            production: true,
            why: "A production credential goes to a deploy.".to_owned(),
            items: vec![
                QuestionItem {
                    item_id: 7,
                    name: "Shop database".to_owned(),
                    production: true,
                    unconfirmed: false,
                    always_ask: false,
                },
                QuestionItem {
                    item_id: 9,
                    name: "API token".to_owned(),
                    production: false,
                    unconfirmed: true,
                    always_ask: false,
                },
            ],
            valid_answers: vec![
                AnswerKind::Once,
                AnswerKind::Production(ActionKind::Deploy),
                AnswerKind::CorrectEnvironment,
                AnswerKind::NeverForAgent,
                AnswerKind::AlwaysAskForAgent,
                AnswerKind::Disconnect,
            ],
        }
    }

    fn asked() -> PendingRun {
        PendingRun {
            remember: None,
            question: question(),
            ..base()
        }
    }

    #[test]
    fn the_contract_vectors_reproduce() {
        assert_eq!(
            run_digest_hex(&base()),
            "f9eaafb74648d988f9d086cd06f21f1f5f9a2429fa30e23ffa3a9d167dab4245"
        );
        assert_eq!(
            question_digest_v2_hex(&asked()),
            "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"
        );
        assert_eq!(
            question_digest_v2_hex(&base()),
            "0807a3e555dbde9f82b73ab8a6660911c1a28149eb1fe6382460166a798bf274"
        );
        // The root of the project is not in the digest: the wire has no root.
        let mut moved = asked();
        moved.question.project.as_mut().unwrap().root = std::path::PathBuf::from("/other");
        assert_eq!(question_digest_v2(&moved), question_digest_v2(&asked()));
    }

    #[test]
    fn every_question_field_changes_the_digest_v2() {
        let original = question_digest_v2(&asked());
        assert_ne!(original, run_digest(&asked()), "another tag");
        let change = |edit: fn(&mut QuestionInfo)| {
            let mut run = asked();
            edit(&mut run.question);
            run
        };
        let variants: Vec<(&str, PendingRun)> = vec![
            ("id", change(|q| q.id = 1)),
            ("item_ids", change(|q| q.item_ids = vec![7])),
            ("item_ids order", change(|q| q.item_ids = vec![9, 7])),
            ("no project", change(|q| q.project = None)),
            (
                "project key",
                change(|q| q.project.as_mut().unwrap().key = "/tmp/other/.git".to_owned()),
            ),
            (
                "project label",
                change(|q| q.project.as_mut().unwrap().label = "other".to_owned()),
            ),
            ("action", change(|q| q.action = ActionKind::Change)),
            ("production", change(|q| q.production = false)),
            ("why", change(|q| q.why.clear())),
            ("item id", change(|q| q.items[0].item_id = 8)),
            ("item name", change(|q| q.items[0].name = "Shop".to_owned())),
            ("item production", change(|q| q.items[0].production = false)),
            (
                "item unconfirmed",
                change(|q| q.items[1].unconfirmed = false),
            ),
            ("item always_ask", change(|q| q.items[1].always_ask = true)),
            ("items", change(|q| q.items.truncate(1))),
            ("valid_answers", change(|q| q.valid_answers.truncate(5))),
            (
                "valid_answers kind",
                change(|q| q.valid_answers[1] = AnswerKind::InProject(ActionKind::Deploy)),
            ),
            (
                "risk",
                PendingRun {
                    risk: String::new(),
                    ..asked()
                },
            ),
        ];
        for (field, variant) in &variants {
            assert_ne!(question_digest_v2(variant), original, "{field}");
        }
        for (i, (a, left)) in variants.iter().enumerate() {
            for (b, right) in &variants[i + 1..] {
                assert_ne!(
                    question_digest_v2(left),
                    question_digest_v2(right),
                    "{a} and {b}"
                );
            }
        }
    }

    #[test]
    fn moving_text_between_why_and_items_changes_the_digest_v2() {
        let mut a = asked();
        a.question.why = "ab".to_owned();
        a.question.items[0].name = "c".to_owned();
        let mut b = asked();
        b.question.why = "a".to_owned();
        b.question.items[0].name = "bc".to_owned();
        assert_ne!(question_digest_v2(&a), question_digest_v2(&b));
        let mut c = asked();
        c.question.items[0].name = "ab".to_owned();
        c.question.items[1].name = "c".to_owned();
        let mut d = asked();
        d.question.items[0].name = "a".to_owned();
        d.question.items[1].name = "bc".to_owned();
        assert_ne!(question_digest_v2(&c), question_digest_v2(&d));
    }

    #[test]
    fn answer_kinds_round_trip_as_text() {
        let kinds = [
            AnswerKind::Once,
            AnswerKind::InProject(ActionKind::Read),
            AnswerKind::InProject(ActionKind::Delete),
            AnswerKind::Production(ActionKind::Deploy),
            AnswerKind::NeverForAgent,
            AnswerKind::AlwaysAskForAgent,
            AnswerKind::Disconnect,
            AnswerKind::CorrectEnvironment,
        ];
        for kind in kinds {
            assert_eq!(parse_answer_kind(&answer_kind_text(kind)), Some(kind));
        }
        for bad in ["", "Once", "in_project:", "production:ship", "deny"] {
            assert_eq!(parse_answer_kind(bad), None, "{bad}");
        }
    }
}
