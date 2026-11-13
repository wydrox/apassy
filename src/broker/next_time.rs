//! "Next time" of a past decision (ADR 0046): the project answer that a question
//! offered, saved later from Decisions › History.
//!
//! Only the broker writes answers (`vault::answers`). This module keeps that: the app
//! calls [`save`] only after the owner check `OwnerAction::ChangeItemRules` for the
//! item, and it calls [`later_answer`] again under the proof. The saved answer is the
//! one the card offered: "Allow ACTION in PROJECT" for one credential, for every agent
//! in the project (ADR 0025 §3c). Every hard rule still runs before it at each use.
//!
//! [`later_answer`] offers an answer only when all of these hold:
//!
//! 1. The decision asked the owner, and the owner allowed it or did not answer. An
//!    owner denial offers nothing.
//! 2. Its question offered a project answer (`offered in_project:ACTION`). A
//!    production allowance is not saved from here.
//! 3. It used one credential and had no rule flag.
//! 4. A use of the decision names the credential, a project, and the same action.
//! 5. The credential exists now, is not archived, needs no review, has "Always ask me"
//!    off, and has a declaration that is not production.
//! 6. No answer covers the use already.

use super::action_kind::ActionKind;
use crate::vault::answers::{AnswerScope, OwnerAnswer, ProjectRef, normal_host};
use crate::vault::usage::ItemUse;
use crate::vault::{DecidedBy, DecisionEntry, LoggedDecision, Vault, VaultResult};

/// The project answer that a past question offered, as [`save`] stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaterAnswer {
    pub decision_id: u64,
    pub item_id: u64,
    /// The title of the credential now.
    pub item_name: String,
    pub project: ProjectRef,
    pub action: ActionKind,
    /// The destination hosts of the use.
    pub hosts: Vec<String>,
    /// `Some` when the run used the one-time codes of the credential: `true` when it
    /// also used the stored value.
    pub codes: Option<bool>,
}

/// Why a past decision offers no answer to save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotOffered {
    /// The question offered none, or the decision cannot give one.
    NoOffer,
    /// An answer covers the run already: its ID.
    Covered(u64),
    /// The credential or the use is not as the question showed it.
    Changed,
}

/// The decision asked the owner, and the owner allowed it or did not answer.
fn asked_without_denial(entry: &DecisionEntry) -> bool {
    entry.asked
        && match entry.decided_by {
            DecidedBy::Owner => entry.decision == LoggedDecision::Allow,
            DecidedBy::NoAnswer => true,
            _ => false,
        }
}

/// The credential can take a project answer now (condition 5). A read error counts as
/// a change.
fn still_answerable(vault: &Vault, item_id: u64) -> Result<String, NotOffered> {
    let changed = |_| NotOffered::Changed;
    let details = vault.details(item_id).map_err(changed)?;
    if vault.is_archived(item_id).map_err(changed)?
        || vault.needs_review(item_id).map_err(changed)?
        || vault.always_ask(item_id).map_err(changed)?
    {
        return Err(NotOffered::Changed);
    }
    match vault.declaration(item_id).map_err(changed)? {
        Some(declaration) if !declaration.is_production() => Ok(details.summary.title),
        _ => Err(NotOffered::Changed),
    }
}

/// `answer` already covers `use_row` with these codes, as the broker checks a later run.
fn covers(answer: &OwnerAnswer, use_row: &ItemUse, codes: Option<bool>) -> bool {
    let values = match codes {
        None => answer.includes_values,
        Some(with_value) => answer.includes_codes && (!with_value || answer.includes_values),
    };
    values
        && use_row
            .hosts
            .iter()
            .filter_map(|host| normal_host(host))
            .all(|host| answer.hosts.contains(&host))
}

/// The project answer that decision `decision_id` offered and that can still be saved.
pub fn later_answer(vault: &Vault, decision_id: u64) -> Result<LaterAnswer, NotOffered> {
    let entry = match vault.decision(decision_id) {
        Ok(Some(record)) => record.entry,
        _ => return Err(NotOffered::NoOffer),
    };
    if !asked_without_denial(&entry) {
        return Err(NotOffered::NoOffer);
    }
    let why = entry.why();
    let Some(action) = why
        .offered
        .strip_prefix("in_project:")
        .and_then(ActionKind::parse)
    else {
        return Err(NotOffered::NoOffer);
    };
    let &[item_id] = entry.items.as_slice() else {
        return Err(NotOffered::NoOffer);
    };
    if !entry.rule_flags.is_empty() {
        return Err(NotOffered::NoOffer);
    }
    let uses = vault
        .uses_of_decision(decision_id)
        .map_err(|_| NotOffered::Changed)?;
    let Some(use_row) = uses.into_iter().find(|use_row| {
        use_row.item_id == item_id
            && !use_row.project_key.is_empty()
            && !use_row.project_label.is_empty()
    }) else {
        return Err(NotOffered::Changed);
    };
    if use_row.action != action {
        return Err(NotOffered::Changed);
    }
    let item_name = still_answerable(vault, item_id)?;
    let codes = match why.codes.as_str() {
        "with_value" => Some(true),
        "only" => Some(false),
        _ => None,
    };
    if let Ok(Some(answer)) =
        vault.answer_for(item_id, &use_row.project_key, action, AnswerScope::Project)
        && covers(&answer, &use_row, codes)
    {
        return Err(NotOffered::Covered(answer.id));
    }
    Ok(LaterAnswer {
        decision_id,
        item_id,
        item_name,
        project: ProjectRef {
            key: use_row.project_key,
            label: use_row.project_label,
        },
        action,
        hosts: use_row.hosts,
        codes,
    })
}

/// Save `answer` as the project answer that its question offered. The caller passed
/// the owner check for the item and called [`later_answer`] again under it.
pub(crate) fn save(vault: &mut Vault, answer: &LaterAnswer, answered_on: &str) -> VaultResult<u64> {
    match answer.codes {
        None => vault.remember_answer(
            answer.item_id,
            &answer.project,
            answer.action,
            answered_on,
            &answer.hosts,
        ),
        Some(with_value) => vault.store_answer(
            answer.item_id,
            &answer.project,
            answer.action,
            AnswerScope::Project,
            answered_on,
            &answer.hosts,
            true,
            with_value,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
    use crate::vault::{
        DecisionWhy, Declaration, Environment, Field, ItemDraft, RequestSource, Reversibility,
        RiskLevel, Scope, SecretValue,
    };

    const PASS: &str = "synthetic-next-time-pass";
    const KEY: &str = "/synthetic/apassy/.git";

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        item: u64,
    }

    fn declaration(environment: Environment) -> Declaration {
        Declaration {
            project: "apassy".to_owned(),
            environment,
            risk: RiskLevel::Medium,
            scope: Scope::ReadWrite,
            reversibility: Reversibility::Reversible,
        }
    }

    fn add_item(vault: &mut Vault, title: &str) -> u64 {
        let item = vault
            .add(ItemDraft {
                title: title.to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(format!("SYNTH-{title}-value")),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        vault
            .save_declaration(item, &declaration(Environment::Staging), None, None)
            .unwrap();
        item
    }

    fn fixture() -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("next.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = add_item(&mut vault, "Synthetic devbox key");
        Fixture {
            _dir: dir,
            vault,
            item,
        }
    }

    /// One asked decision about `items` and its uses, as the broker writes them.
    struct Asked<'a> {
        items: &'a [u64],
        decided_by: DecidedBy,
        decision: LoggedDecision,
        offered: &'a str,
        codes: &'a str,
        flags: &'a [&'a str],
        action: ActionKind,
    }

    impl Default for Asked<'_> {
        fn default() -> Self {
            Self {
                items: &[],
                decided_by: DecidedBy::NoAnswer,
                decision: LoggedDecision::Deny,
                offered: "in_project:change",
                codes: "",
                flags: &[],
                action: ActionKind::Change,
            }
        }
    }

    fn record(fx: &mut Fixture, asked: Asked<'_>) -> u64 {
        let entry = DecisionEntry {
            at: 1_793_707_200,
            agent_id: 1,
            agent_name: "Claude Code".to_owned(),
            project_dir: "/synthetic/apassy".to_owned(),
            cwd_rel: ".".to_owned(),
            items: asked.items.to_vec(),
            user_request: "Start the devbox.".to_owned(),
            user_request_source: RequestSource::Host,
            command: vec!["devbox".to_owned(), "up".to_owned()],
            purpose: "Start the devbox.".to_owned(),
            env_names: Vec::new(),
            declarations: Vec::new(),
            rule_flags: asked.flags.iter().map(|flag| (*flag).to_owned()).collect(),
            known_safe: false,
            model_facts: Vec::new(),
            pattern: String::new(),
            grant_asks: false,
            asked: true,
            decision: asked.decision,
            decided_by: asked.decided_by,
            remembered: false,
            policy: "apassy-bouncer-v9".to_owned(),
            note: String::new(),
            instruction: String::new(),
        }
        .with_why(&DecisionWhy {
            reason: "ForeignProject".to_owned(),
            code: String::new(),
            offered: asked.offered.to_owned(),
            codes: asked.codes.to_owned(),
            ..DecisionWhy::default()
        });
        let id = fx.vault.record_decision(&entry).unwrap();
        for item in asked.items {
            fx.vault
                .record_item_use(&NewItemUse {
                    item_id: *item,
                    agent_id: Some(1),
                    agent_name: "Claude Code".to_owned(),
                    project_key: KEY.to_owned(),
                    project_label: "apassy".to_owned(),
                    action: asked.action,
                    command_summary: "run devbox up".to_owned(),
                    hosts: vec!["api.hetzner.cloud".to_owned()],
                    outcome: UseOutcome::TimedOut,
                    decided_by: UseDecidedBy::Owner,
                    answered_on: String::new(),
                    decision_log_id: Some(id),
                })
                .unwrap();
        }
        id
    }

    #[test]
    fn a_timed_out_question_that_offered_an_answer_can_be_remembered_later() {
        let mut fx = fixture();
        let items = [fx.item];
        let id = record(
            &mut fx,
            Asked {
                items: &items,
                ..Asked::default()
            },
        );
        let answer = later_answer(&fx.vault, id).expect("offered");
        assert_eq!(answer.item_name, "Synthetic devbox key");
        assert_eq!(answer.project.key, KEY);
        assert_eq!(answer.project.label, "apassy");
        assert_eq!(answer.action, ActionKind::Change);
        assert_eq!(answer.codes, None);
        let saved = save(&mut fx.vault, &answer, "this computer").unwrap();
        let stored = fx
            .vault
            .answer_for(fx.item, KEY, ActionKind::Change, AnswerScope::Project)
            .unwrap()
            .expect("answer");
        assert_eq!(stored.id, saved);
        assert!(stored.includes_values && !stored.includes_codes);
        assert_eq!(stored.answered_on, "this computer");
        assert_eq!(
            later_answer(&fx.vault, id),
            Err(NotOffered::Covered(saved)),
            "the second save is reported, not repeated"
        );
    }

    #[test]
    fn an_approved_question_remembers_its_hosts() {
        let mut fx = fixture();
        let items = [fx.item];
        let id = record(
            &mut fx,
            Asked {
                items: &items,
                decided_by: DecidedBy::Owner,
                decision: LoggedDecision::Allow,
                ..Asked::default()
            },
        );
        let answer = later_answer(&fx.vault, id).expect("offered");
        assert_eq!(answer.hosts, vec!["api.hetzner.cloud".to_owned()]);
        save(&mut fx.vault, &answer, "this computer").unwrap();
        let stored = fx
            .vault
            .answer_for(fx.item, KEY, ActionKind::Change, AnswerScope::Project)
            .unwrap()
            .expect("answer");
        assert_eq!(stored.hosts, vec!["api.hetzner.cloud".to_owned()]);
    }

    #[test]
    fn a_denied_flagged_or_unoffered_decision_offers_nothing() {
        let mut fx = fixture();
        let items = [fx.item];
        let denied = record(
            &mut fx,
            Asked {
                items: &items,
                decided_by: DecidedBy::Owner,
                decision: LoggedDecision::Deny,
                ..Asked::default()
            },
        );
        let flagged = record(
            &mut fx,
            Asked {
                items: &items,
                flags: &["injection_phrase"],
                ..Asked::default()
            },
        );
        let unoffered = record(
            &mut fx,
            Asked {
                items: &items,
                offered: "",
                ..Asked::default()
            },
        );
        let production = record(
            &mut fx,
            Asked {
                items: &items,
                offered: "production:read",
                ..Asked::default()
            },
        );
        let other_action = record(
            &mut fx,
            Asked {
                items: &items,
                action: ActionKind::Read,
                ..Asked::default()
            },
        );
        for id in [denied, flagged, unoffered, production] {
            assert_eq!(
                later_answer(&fx.vault, id),
                Err(NotOffered::NoOffer),
                "{id}"
            );
        }
        assert_eq!(
            later_answer(&fx.vault, other_action),
            Err(NotOffered::Changed)
        );
        assert_eq!(later_answer(&fx.vault, 999), Err(NotOffered::NoOffer));
        // A decision that did not ask (the model allowed it) offers nothing either.
        let mut automatic = fx.vault.decision(unoffered).unwrap().unwrap().entry;
        automatic.asked = false;
        automatic.decided_by = DecidedBy::Model;
        automatic.decision = LoggedDecision::Allow;
        automatic.policy = "apassy-bouncer-v9; offered in_project:change".to_owned();
        let automatic = fx.vault.record_decision(&automatic).unwrap();
        assert_eq!(later_answer(&fx.vault, automatic), Err(NotOffered::NoOffer));
    }

    #[test]
    fn a_production_always_ask_or_archived_credential_offers_nothing() {
        let mut fx = fixture();
        let items = [fx.item];
        let id = record(
            &mut fx,
            Asked {
                items: &items,
                ..Asked::default()
            },
        );
        assert!(later_answer(&fx.vault, id).is_ok());
        fx.vault
            .save_declaration(fx.item, &declaration(Environment::Production), None, None)
            .unwrap();
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
        fx.vault
            .save_declaration(fx.item, &declaration(Environment::Staging), None, None)
            .unwrap();
        fx.vault.set_always_ask(fx.item, true).unwrap();
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
        fx.vault.set_always_ask(fx.item, false).unwrap();
        assert!(later_answer(&fx.vault, id).is_ok());
        fx.vault.set_archived(fx.item, true).unwrap();
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
    }

    #[test]
    fn a_run_with_two_credentials_offers_nothing() {
        let mut fx = fixture();
        let second = add_item(&mut fx.vault, "Synthetic second key");
        let items = [fx.item, second];
        let id = record(
            &mut fx,
            Asked {
                items: &items,
                ..Asked::default()
            },
        );
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::NoOffer));
    }

    #[test]
    fn a_code_run_remembers_codes_only_when_they_were_offered() {
        let mut fx = fixture();
        let items = [fx.item];
        for (word, codes, values) in [
            ("with_value", Some(true), true),
            ("only", Some(false), false),
        ] {
            for earlier in fx.vault.answers_for_item(fx.item).unwrap() {
                fx.vault.remove_answer(earlier.id).unwrap();
            }
            let id = record(
                &mut fx,
                Asked {
                    items: &items,
                    codes: word,
                    ..Asked::default()
                },
            );
            let answer = later_answer(&fx.vault, id).expect("offered");
            assert_eq!(answer.codes, codes, "{word}");
            save(&mut fx.vault, &answer, "this computer").unwrap();
            let stored = fx
                .vault
                .answer_for(fx.item, KEY, ActionKind::Change, AnswerScope::Project)
                .unwrap()
                .expect("answer");
            assert!(stored.includes_codes, "{word}");
            assert_eq!(stored.includes_values, values, "{word}");
        }
        // A code-only answer does not cover a run that also uses the stored value.
        let with_value = record(
            &mut fx,
            Asked {
                items: &items,
                codes: "with_value",
                ..Asked::default()
            },
        );
        assert!(later_answer(&fx.vault, with_value).is_ok());
        // A run without codes gets an answer without codes.
        let plain = record(
            &mut fx,
            Asked {
                items: &items,
                ..Asked::default()
            },
        );
        assert_eq!(later_answer(&fx.vault, plain).unwrap().codes, None);
    }

    #[test]
    fn an_answer_that_covers_the_run_is_reported() {
        let mut fx = fixture();
        let items = [fx.item];
        let project = ProjectRef {
            key: KEY.to_owned(),
            label: "apassy".to_owned(),
        };
        let existing = fx
            .vault
            .remember_answer(
                fx.item,
                &project,
                ActionKind::Change,
                "iPhone",
                &["api.hetzner.cloud".to_owned()],
            )
            .unwrap();
        let id = record(
            &mut fx,
            Asked {
                items: &items,
                ..Asked::default()
            },
        );
        assert_eq!(
            later_answer(&fx.vault, id),
            Err(NotOffered::Covered(existing))
        );
        // An answer without the host of the use does not cover it.
        fx.vault.remove_answer(existing).unwrap();
        fx.vault
            .remember_answer(fx.item, &project, ActionKind::Change, "iPhone", &[])
            .unwrap();
        assert!(later_answer(&fx.vault, id).is_ok());
    }
}
