//! "Next time" of a past decision (ADR 0046): the project answer that a question
//! offered, saved later from Decisions › History.
//!
//! Only the broker writes answers (`vault::answers`). This module keeps that: the app
//! calls [`save`] only after the owner check `OwnerAction::RememberAnswer`, which the
//! "How often to ask" window never covers and no phone can give, and it calls
//! [`later_answer`] again under the proof. The saved answer is the one the card offered:
//! "Allow ACTION in PROJECT" for one credential, for every agent in the project (ADR
//! 0025 §3c). Every hard rule still runs before it at each use.
//!
//! [`later_answer`] offers an answer only when all of these hold:
//!
//! 1. The decision was a run that asked the owner, and the owner allowed it or did not
//!    answer. An owner denial, a refusal, and a browser fill offer nothing.
//! 2. Its question offered a project answer (`offered in_project:ACTION`). A
//!    production allowance is not saved from here.
//! 3. It used one credential, had no rule flag, and its one-time codes are recorded
//!    as they were used.
//! 4. Its agent is still connected, and the vault was not restored after it.
//! 5. A use of the decision names the credential, a project, and the same action.
//! 6. The credential exists now, is not archived, needs no review, has "Always ask me"
//!    off, and has a confirmed declaration that is not production.
//! 7. Every host of the use is a known host of the credential now: History never adds
//!    a host.
//! 8. No answer exists for the credential, the project, and the action. One that fits
//!    is reported; one that does not fit is never changed from here.

use super::action_kind::ActionKind;
use crate::vault::answers::{AnswerScope, OwnerAnswer, ProjectRef};
use crate::vault::{
    DecidedBy, DecisionEntry, ItemEventKind, LoggedDecision, MAX_ITEM_EVENTS, RequestKind, Vault,
    VaultResult,
};

/// The project answer that a past question offered, as [`save`] stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaterAnswer {
    pub decision_id: u64,
    pub item_id: u64,
    /// The title of the credential now.
    pub item_name: String,
    pub project: ProjectRef,
    pub action: ActionKind,
    /// The destination hosts of the use, all known hosts of the credential.
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
    /// The credential, the use, or an answer is not as the question showed it.
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

/// The agent of the decision is still connected, and no restore of the vault came after
/// the decision (condition 4).
fn still_current(vault: &Vault, entry: &DecisionEntry, item_id: u64) -> bool {
    let connected = vault.list_agents().is_ok_and(|agents| {
        agents
            .iter()
            .any(|agent| agent.id == entry.agent_id && !agent.revoked)
    });
    let restored_after = match vault.item_events(item_id, MAX_ITEM_EVENTS) {
        Ok(events) => events
            .iter()
            .any(|event| event.kind == ItemEventKind::Restored && event.at >= entry.at),
        Err(_) => true,
    };
    connected && !restored_after
}

/// The one-time codes of the decision's run, from its closed word and its variables
/// (condition 3): `Ok(None)` without codes, `Ok(Some(with_value))` with them.
fn codes_of(entry: &DecisionEntry, item_id: u64) -> Result<Option<bool>, NotOffered> {
    let code_name = crate::vault::mfa::code_env_name(item_id);
    let had_code = entry.env_names.iter().any(|name| *name == code_name);
    match entry.why().codes.as_str() {
        "with_value" => Ok(Some(true)),
        // A code-only run had no other variable of the credential.
        "only" if entry.env_names.iter().all(|name| *name == code_name) => Ok(Some(false)),
        "" if !had_code => Ok(None),
        _ => Err(NotOffered::NoOffer),
    }
}

/// The credential can take a project answer now (condition 6). A read error counts as
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
    // A missing declaration, or production from any source (also only by default, the
    // environment the Mac card cannot remember), is not saved from here.
    match vault.declaration(item_id).map_err(changed)? {
        Some(declaration) if !declaration.is_production() => Ok(details.summary.title),
        _ => Err(NotOffered::Changed),
    }
}

/// `answer` fits a use with these codes, as the broker checks a later run: it includes
/// the stored value when the use had it, and the codes when the use had them. The hosts
/// of the use are known hosts of the credential (condition 7), which every answer covers.
fn fits(answer: &OwnerAnswer, codes: Option<bool>) -> bool {
    let value = codes != Some(false);
    (!value || answer.includes_values) && (codes.is_none() || answer.includes_codes)
}

/// The project answer that decision `decision_id` offered and that can still be saved.
pub fn later_answer(vault: &Vault, decision_id: u64) -> Result<LaterAnswer, NotOffered> {
    let entry = match vault.decision(decision_id) {
        Ok(Some(record)) => record.entry,
        _ => return Err(NotOffered::NoOffer),
    };
    let request = vault
        .decision_meta(decision_id)
        .ok()
        .flatten()
        .map(|meta| meta.request);
    if request != Some(RequestKind::Run) || !asked_without_denial(&entry) {
        return Err(NotOffered::NoOffer);
    }
    let Some(action) = entry
        .why()
        .offered
        .strip_prefix("in_project:")
        .and_then(ActionKind::parse)
    else {
        return Err(NotOffered::NoOffer);
    };
    let &[item_id] = entry.items.as_slice() else {
        return Err(NotOffered::NoOffer);
    };
    if !entry.rule_flags.is_empty() || !still_current(vault, &entry, item_id) {
        return Err(NotOffered::NoOffer);
    }
    let codes = codes_of(&entry, item_id)?;
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
    if !super::run::hosts_known_now(vault, item_id, &use_row.hosts) {
        return Err(NotOffered::Changed);
    }
    match vault.answer_for(item_id, &use_row.project_key, action, AnswerScope::Project) {
        Ok(None) => {}
        Ok(Some(answer)) if fits(&answer, codes) => return Err(NotOffered::Covered(answer.id)),
        _ => return Err(NotOffered::Changed),
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
/// the owner check for it and called [`later_answer`] again under it, so no answer for
/// the credential, the project, and the action exists.
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
        DecisionMeta, DecisionWhy, Declaration, Environment, Field, ItemDraft, RequestSource,
        Reversibility, RiskLevel, Scope, SecretValue,
    };

    const PASS: &str = "synthetic-next-time-pass";
    const KEY: &str = "/synthetic/apassy/.git";
    const HOST: &str = "sentry.io";

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        item: u64,
        agent: u64,
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

    /// A credential of the Sentry provider, so `sentry.io` is one of its known hosts.
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
            .save_declaration(
                item,
                &declaration(Environment::Staging),
                Some("sentry"),
                None,
            )
            .unwrap();
        item
    }

    fn fixture() -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("next.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = add_item(&mut vault, "Synthetic Sentry key");
        let (agent, _) = vault.register_agent("Claude Code").unwrap();
        Fixture {
            _dir: dir,
            vault,
            item,
            agent: agent.id,
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
        env_names: Vec<String>,
        action: ActionKind,
        hosts: &'a [&'a str],
        request: RequestKind,
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
                env_names: vec!["SYNTH_SENTRY_KEY".to_owned()],
                action: ActionKind::Change,
                hosts: &[HOST],
                request: RequestKind::Run,
            }
        }
    }

    fn record(fx: &mut Fixture, asked: Asked<'_>) -> u64 {
        let entry = DecisionEntry {
            at: crate::broker::learning::now(),
            agent_id: fx.agent,
            agent_name: "Claude Code".to_owned(),
            project_dir: "/synthetic/apassy".to_owned(),
            cwd_rel: ".".to_owned(),
            items: asked.items.to_vec(),
            user_request: "Check the Sentry project.".to_owned(),
            user_request_source: RequestSource::Host,
            command: vec!["sentry-cli".to_owned(), "releases".to_owned()],
            purpose: "Check the Sentry project.".to_owned(),
            env_names: asked.env_names,
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
            offered: asked.offered.to_owned(),
            codes: asked.codes.to_owned(),
            ..DecisionWhy::default()
        });
        let meta = DecisionMeta {
            request: asked.request,
            wait_ms: None,
        };
        let id = fx.vault.record_decision_with(&entry, &meta).unwrap();
        for item in asked.items {
            fx.vault
                .record_item_use(&NewItemUse {
                    item_id: *item,
                    agent_id: Some(fx.agent),
                    agent_name: "Claude Code".to_owned(),
                    project_key: KEY.to_owned(),
                    project_label: "apassy".to_owned(),
                    action: asked.action,
                    command_summary: "run sentry-cli releases".to_owned(),
                    hosts: asked.hosts.iter().map(|host| (*host).to_owned()).collect(),
                    outcome: UseOutcome::TimedOut,
                    decided_by: UseDecidedBy::Owner,
                    answered_on: String::new(),
                    decision_log_id: Some(id),
                })
                .unwrap();
        }
        id
    }

    fn one(fx: &mut Fixture, asked: Asked<'_>) -> u64 {
        let items = [fx.item];
        record(
            fx,
            Asked {
                items: &items,
                ..asked
            },
        )
    }

    fn stored(fx: &Fixture) -> Option<OwnerAnswer> {
        fx.vault
            .answer_for(fx.item, KEY, ActionKind::Change, AnswerScope::Project)
            .unwrap()
    }

    #[test]
    fn a_timed_out_question_that_offered_an_answer_can_be_remembered_later() {
        let mut fx = fixture();
        let id = one(&mut fx, Asked::default());
        let answer = later_answer(&fx.vault, id).expect("offered");
        assert_eq!(answer.item_name, "Synthetic Sentry key");
        assert_eq!(answer.project.key, KEY);
        assert_eq!(answer.project.label, "apassy");
        assert_eq!(answer.action, ActionKind::Change);
        assert_eq!(answer.codes, None);
        let saved = save(&mut fx.vault, &answer, "this computer").unwrap();
        let answer = stored(&fx).expect("answer");
        assert_eq!(answer.id, saved);
        assert!(answer.includes_values && !answer.includes_codes);
        assert_eq!(answer.answered_on, "this computer");
        assert_eq!(
            later_answer(&fx.vault, id),
            Err(NotOffered::Covered(saved)),
            "the second save is reported, not repeated"
        );
    }

    #[test]
    fn an_approved_question_remembers_its_hosts() {
        let mut fx = fixture();
        let id = one(
            &mut fx,
            Asked {
                decided_by: DecidedBy::Owner,
                decision: LoggedDecision::Allow,
                ..Asked::default()
            },
        );
        let answer = later_answer(&fx.vault, id).expect("offered");
        assert_eq!(answer.hosts, vec![HOST.to_owned()]);
        save(&mut fx.vault, &answer, "this computer").unwrap();
        assert_eq!(stored(&fx).expect("answer").hosts, vec![HOST.to_owned()]);
    }

    #[test]
    fn a_use_host_outside_the_known_hosts_is_never_saved_from_history() {
        let mut fx = fixture();
        let foreign = one(
            &mut fx,
            Asked {
                hosts: &[HOST, "collector.example.net"],
                ..Asked::default()
            },
        );
        assert_eq!(later_answer(&fx.vault, foreign), Err(NotOffered::Changed));
        assert!(stored(&fx).is_none());
    }

    #[test]
    fn a_denied_flagged_or_unoffered_decision_offers_nothing() {
        let mut fx = fixture();
        let denied = one(
            &mut fx,
            Asked {
                decided_by: DecidedBy::Owner,
                decision: LoggedDecision::Deny,
                ..Asked::default()
            },
        );
        let flagged = one(
            &mut fx,
            Asked {
                flags: &["injection_phrase"],
                ..Asked::default()
            },
        );
        let unoffered = one(
            &mut fx,
            Asked {
                offered: "",
                ..Asked::default()
            },
        );
        let production = one(
            &mut fx,
            Asked {
                offered: "production:read",
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
        let other_action = one(
            &mut fx,
            Asked {
                action: ActionKind::Read,
                ..Asked::default()
            },
        );
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
    fn a_browser_fill_and_a_disconnected_agent_offer_nothing() {
        let mut fx = fixture();
        let fill = one(
            &mut fx,
            Asked {
                request: RequestKind::BrowserFill,
                ..Asked::default()
            },
        );
        assert_eq!(later_answer(&fx.vault, fill), Err(NotOffered::NoOffer));
        // A restore revokes every agent (`prepare_restored`), so a decision before it
        // has a disconnected agent.
        let mut fx = fixture();
        let run = one(&mut fx, Asked::default());
        fx.vault.revoke_agent(fx.agent).unwrap();
        assert_eq!(later_answer(&fx.vault, run), Err(NotOffered::NoOffer));
    }

    #[test]
    fn a_production_always_ask_or_archived_credential_offers_nothing() {
        let mut fx = fixture();
        let id = one(&mut fx, Asked::default());
        assert!(later_answer(&fx.vault, id).is_ok());
        let save_as = |fx: &mut Fixture, environment| {
            fx.vault
                .save_declaration(fx.item, &declaration(environment), Some("sentry"), None)
                .unwrap();
        };
        save_as(&mut fx, Environment::Production);
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
        save_as(&mut fx, Environment::Staging);
        fx.vault.set_always_ask(fx.item, true).unwrap();
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
        fx.vault.set_always_ask(fx.item, false).unwrap();
        assert!(later_answer(&fx.vault, id).is_ok());
        fx.vault.set_archived(fx.item, true).unwrap();
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
    }

    #[test]
    fn an_unconfirmed_environment_is_not_saved_from_history() {
        let mut fx = fixture();
        let id = one(&mut fx, Asked::default());
        // Production only by default: the environment the Mac card cannot remember.
        fx.vault
            .save_declaration(
                fx.item,
                &Declaration {
                    environment: crate::vault::providers::DEFAULT_ENVIRONMENT,
                    ..declaration(Environment::Staging)
                },
                Some("sentry"),
                None,
            )
            .unwrap();
        fx.vault
            .set_declaration_sources(fx.item, &crate::vault::DeclarationSources::default())
            .unwrap();
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
        let code_name = crate::vault::mfa::code_env_name;
        for (word, codes, values) in [
            ("with_value", Some(true), true),
            ("only", Some(false), false),
        ] {
            let mut fx = fixture();
            let env_names = if word == "only" {
                vec![code_name(fx.item)]
            } else {
                vec!["SYNTH_SENTRY_KEY".to_owned(), code_name(fx.item)]
            };
            let id = one(
                &mut fx,
                Asked {
                    codes: word,
                    env_names,
                    ..Asked::default()
                },
            );
            let answer = later_answer(&fx.vault, id).expect("offered");
            assert_eq!(answer.codes, codes, "{word}");
            save(&mut fx.vault, &answer, "this computer").unwrap();
            let answer = stored(&fx).expect("answer");
            assert!(answer.includes_codes, "{word}");
            assert_eq!(answer.includes_values, values, "{word}");
        }
        // A run without codes gets an answer without codes.
        let mut fx = fixture();
        let plain = one(&mut fx, Asked::default());
        assert_eq!(later_answer(&fx.vault, plain).unwrap().codes, None);
    }

    #[test]
    fn a_code_decision_without_its_codes_word_offers_nothing() {
        let mut fx = fixture();
        let code = crate::vault::mfa::code_env_name(fx.item);
        let missing = one(
            &mut fx,
            Asked {
                env_names: vec!["SYNTH_SENTRY_KEY".to_owned(), code.clone()],
                ..Asked::default()
            },
        );
        assert_eq!(later_answer(&fx.vault, missing), Err(NotOffered::NoOffer));
        // "only" with the stored value too does not agree with the variables.
        let only = one(
            &mut fx,
            Asked {
                codes: "only",
                env_names: vec!["SYNTH_SENTRY_KEY".to_owned(), code],
                ..Asked::default()
            },
        );
        assert_eq!(later_answer(&fx.vault, only), Err(NotOffered::NoOffer));
    }

    #[test]
    fn an_answer_that_covers_the_run_is_reported() {
        let mut fx = fixture();
        let project = ProjectRef {
            key: KEY.to_owned(),
            label: "apassy".to_owned(),
        };
        let existing = fx
            .vault
            .remember_answer(fx.item, &project, ActionKind::Change, "iPhone", &[])
            .unwrap();
        let id = one(&mut fx, Asked::default());
        assert_eq!(
            later_answer(&fx.vault, id),
            Err(NotOffered::Covered(existing))
        );
    }

    #[test]
    fn an_existing_answer_is_never_replaced_from_history() {
        let mut fx = fixture();
        let project = ProjectRef {
            key: KEY.to_owned(),
            label: "apassy".to_owned(),
        };
        // A code-only answer does not fit a run that used the stored value.
        fx.vault
            .store_answer(
                fx.item,
                &project,
                ActionKind::Change,
                AnswerScope::Project,
                "iPhone",
                &[HOST.to_owned()],
                true,
                false,
            )
            .unwrap();
        let before = stored(&fx).expect("answer");
        let id = one(&mut fx, Asked::default());
        assert_eq!(later_answer(&fx.vault, id), Err(NotOffered::Changed));
        assert_eq!(stored(&fx), Some(before), "the answer stays as it was");
    }
}
