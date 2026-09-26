//! Shadow mode, promotion, and rollback of a candidate model (ADR 0010, goal items B9
//! and B10).
//!
//! - [`models`] reads the vault for each request: the active model (the default bouncer,
//!   or a promoted model that is pinned to its version) and the candidate in shadow
//!   mode.
//! - [`begin`] asks the candidate on its own thread, in parallel with the active model,
//!   for each request that reaches the model step. The broker decides with the active
//!   model only. The candidate answer goes only to the vault, next to the real outcome
//!   and the owner decision. The broker does not wait for the candidate.
//! - [`promote`] and [`roll_back`] change the active model. Each needs a fresh owner
//!   check (`OwnerAction::PromoteModel`, `OwnerAction::RollbackModel`). A promotion also
//!   needs the shadow gate of ADR 0010: 100 owner decisions in shadow mode, 95%
//!   agreement, and no owner denial that the candidate would allow. Apassy never
//!   promotes a model by itself (`docs/concept.md`).

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::SharedVault;
use super::approvals::{OwnerAction, OwnerProof};
use super::bouncer::{
    BouncerClient, BouncerRequest, BouncerVerdict, DecisionContext, Learned, Thresholds,
    decide_learned,
};
use super::decide::lock;
use super::learning;
use super::shell_risk::Analysis;
use crate::vault::{
    CandidateAgreement, CandidateRecord, CandidateState, Declaration, ModelActivation, OwnerLabel,
    RealOutcome, ShadowAnswer, ShadowEntry, Vault, VaultError, VaultErrorKind,
};

/// Environment variable with the address of the candidate server.
pub const CANDIDATE_URL_ENV: &str = "APASSY_CANDIDATE_URL";
/// Default address of the candidate server. The active model uses 8770.
pub const DEFAULT_CANDIDATE_URL: &str = "http://127.0.0.1:8775";

/// The address for a new candidate: `APASSY_CANDIDATE_URL`, or the default.
pub fn candidate_url() -> String {
    std::env::var(CANDIDATE_URL_ENV)
        .ok()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| DEFAULT_CANDIDATE_URL.to_owned())
}

/// The candidate in shadow mode, with a client that accepts only its version.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: u64,
    pub version: String,
    pub client: BouncerClient,
}

/// The models for one request.
#[derive(Debug, Clone, Default)]
pub struct Models {
    /// The model that decides. `None`: every run at the model step asks the owner.
    pub active: Option<BouncerClient>,
    /// The candidate in shadow mode. Its answers have no effect.
    pub candidate: Option<Candidate>,
}

fn client_for(default: Option<&BouncerClient>, url: &str) -> Option<BouncerClient> {
    match default {
        Some(default) => default.at_url(url).ok(),
        None => BouncerClient::new(url).ok(),
    }
}

/// Read the active model and the candidate from the vault. Without a promotion, the
/// default bouncer decides. A promoted model is pinned to its version. A read error or
/// a bad address gives no active model, so the owner decides. It never falls back to
/// another model.
pub fn models(vault: &Vault, default: Option<&BouncerClient>) -> Models {
    let active = match vault.active_model() {
        Ok(None) => default.cloned(),
        Ok(Some(activation)) if activation.is_default() => default.cloned(),
        Ok(Some(activation)) => client_for(default, &activation.url)
            .map(|client| client.expect_model(&activation.version)),
        Err(_) => None,
    };
    let candidate = match vault.shadow_candidate() {
        Ok(Some(record)) => client_for(default, &record.url).map(|client| Candidate {
            id: record.id,
            client: client.expect_model(&record.version),
            version: record.version,
        }),
        _ => None,
    };
    Models { active, candidate }
}

/// What the candidate needs to decide with the policy of the broker.
#[derive(Debug, Clone)]
pub struct ShadowInput {
    pub analysis: Analysis,
    pub declarations: Vec<Option<Declaration>>,
    pub has_user_request: bool,
    /// The active `task_match` level. The candidate decides at the same level.
    pub thresholds: Thresholds,
}

/// The candidate outcome with the policy of the broker at the model step. A remembered
/// pattern does not apply: shadow mode runs only when the model step decides.
pub fn candidate_answer(verdict: &BouncerVerdict, input: &ShadowInput) -> ShadowAnswer {
    if matches!(verdict, BouncerVerdict::Unavailable(_)) {
        return ShadowAnswer::NoAnswer;
    }
    let context = DecisionContext {
        analysis: &input.analysis,
        declarations: &input.declarations,
        has_user_request: input.has_user_request,
    };
    let learned = Learned {
        thresholds: input.thresholds,
        pattern: None,
    };
    if decide_learned(verdict, &context, &learned).ask_owner {
        ShadowAnswer::Ask
    } else {
        ShadowAnswer::Run
    }
}

/// A candidate call in progress. [`ShadowCall::finish`] gives it the real outcome. Drop
/// without `finish` stores nothing.
#[derive(Debug)]
pub struct ShadowCall {
    sender: mpsc::Sender<(RealOutcome, OwnerLabel)>,
}

impl ShadowCall {
    /// The real outcome and the owner decision. The thread stores the row when the
    /// candidate answered. This call does not wait.
    pub fn finish(self, real: RealOutcome, owner: OwnerLabel) {
        let _ = self.sender.send((real, owner));
    }
}

/// Ask the candidate on a new thread. The thread waits up to `wait` for
/// [`ShadowCall::finish`], then stores one row if the vault is still unlocked in the
/// session `epoch`. `None` when the thread did not start.
pub fn begin(
    vault: SharedVault,
    epoch: [u8; 32],
    candidate: Candidate,
    request: BouncerRequest,
    input: ShadowInput,
    wait: Duration,
) -> Option<ShadowCall> {
    let (sender, receiver) = mpsc::channel::<(RealOutcome, OwnerLabel)>();
    thread::Builder::new()
        .name("apassy-shadow".to_owned())
        .spawn(move || {
            let verdict = candidate.client.evaluate(&request);
            let answer = candidate_answer(&verdict, &input);
            let Ok((real, owner)) = receiver.recv_timeout(wait) else {
                return;
            };
            let facts = match &verdict {
                BouncerVerdict::Scored { facts, .. } => facts
                    .iter()
                    .map(|fact| (fact.name.clone(), fact.probability))
                    .collect(),
                BouncerVerdict::Unavailable(_) => Vec::new(),
            };
            let mut guard = lock(&vault);
            if let Some(vault) = guard
                .as_mut()
                .filter(|vault| !vault.is_locked() && vault.epoch() == epoch)
            {
                let _ = vault.record_shadow(&ShadowEntry {
                    candidate_id: candidate.id,
                    at: learning::now(),
                    real,
                    candidate: answer,
                    owner,
                    facts,
                });
            }
        })
        .ok()
        .map(|_| ShadowCall { sender })
}

/// Why the shadow gate of ADR 0010 refuses a promotion. `None` when it passes.
pub fn promotion_refusal(agreement: &CandidateAgreement) -> Option<String> {
    let mut reasons = Vec::new();
    if agreement.shadow_decisions < CandidateAgreement::NEEDED_DECISIONS {
        reasons.push(format!(
            "It has {} of {} owner decisions in shadow mode.",
            agreement.shadow_decisions,
            CandidateAgreement::NEEDED_DECISIONS
        ));
    }
    match agreement.agreement() {
        Some(share) if share >= CandidateAgreement::NEEDED_AGREEMENT => {}
        share => reasons.push(format!(
            "Its agreement with you is {}, and promotion needs {:.0}%.",
            share.map_or_else(|| "not known".to_owned(), |s| format!("{:.1}%", s * 100.0)),
            CandidateAgreement::NEEDED_AGREEMENT * 100.0
        )),
    }
    if agreement.allowed_owner_denials > 0 {
        reasons.push(format!(
            "It would allow {} request(s) that you denied. Promotion needs zero.",
            agreement.allowed_owner_denials
        ));
    }
    (!reasons.is_empty()).then(|| reasons.join(" "))
}

fn vault_message(error: &VaultError) -> String {
    match error.kind() {
        VaultErrorKind::Locked => "The vault is locked.".to_owned(),
        VaultErrorKind::NotFound => "The vault has no such model record.".to_owned(),
        _ => "The vault did not change the model.".to_owned(),
    }
}

/// The owner promotes a candidate (ADR 0010). The proof must name this candidate and its
/// version, in this vault session. The shadow gate runs again with the rows of now.
/// The call holds the vault, so no shadow row can arrive between the gate and the
/// change.
pub fn promote(
    vault: &mut Vault,
    candidate_id: u64,
    proof: OwnerProof,
    now: u64,
) -> Result<ModelActivation, String> {
    let candidate: CandidateRecord = vault
        .candidate(candidate_id)
        .map_err(|error| vault_message(&error))?
        .ok_or_else(|| "The vault has no such candidate model.".to_owned())?;
    proof
        .check(
            &OwnerAction::PromoteModel {
                candidate_id,
                version: candidate.version.clone(),
            },
            &vault.epoch(),
        )
        .map_err(|refusal| refusal.message().to_owned())?;
    if candidate.state != CandidateState::Shadow {
        return Err(format!(
            "Not promoted. The candidate {} is not in shadow mode.",
            candidate.version
        ));
    }
    let summary = vault
        .shadow_summary(candidate_id)
        .map_err(|error| vault_message(&error))?;
    if let Some(reason) = promotion_refusal(&summary.agreement) {
        return Err(format!("Not promoted. {reason}"));
    }
    vault
        .promote_candidate(candidate_id, now)
        .map_err(|error| vault_message(&error))
}

/// The owner rolls back the newest promotion. The proof must name it, in this vault
/// session. The model before the promotion decides again.
pub fn roll_back(
    vault: &mut Vault,
    activation_id: u64,
    proof: OwnerProof,
    now: u64,
) -> Result<ModelActivation, String> {
    proof
        .check(
            &OwnerAction::RollbackModel { activation_id },
            &vault.epoch(),
        )
        .map_err(|refusal| refusal.message().to_owned())?;
    vault
        .roll_back_model(activation_id, now)
        .map_err(|error| match error.kind() {
            VaultErrorKind::InvalidInput | VaultErrorKind::NotFound => {
                "Not rolled back. The newest model change is not this promotion.".to_owned()
            }
            _ => vault_message(&error),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::bouncer::Fact;
    use crate::vault::{Environment, Reversibility, RiskLevel, Scope};

    fn input() -> ShadowInput {
        ShadowInput {
            analysis: Analysis::default(),
            declarations: vec![Some(Declaration {
                project: "demo".to_owned(),
                environment: Environment::Staging,
                risk: RiskLevel::Medium,
                scope: Scope::ReadWrite,
                reversibility: Reversibility::Reversible,
            })],
            has_user_request: true,
            thresholds: Thresholds::default(),
        }
    }

    fn scored(task_match: f64) -> BouncerVerdict {
        BouncerVerdict::Scored {
            facts: vec![
                Fact {
                    name: "task_match".to_owned(),
                    probability: task_match,
                },
                Fact {
                    name: "writes".to_owned(),
                    probability: 0.5,
                },
            ],
            model: Some("apassy-local-v1+00000000".to_owned()),
        }
    }

    /// The candidate decides with the policy of the broker, at the active level.
    #[test]
    fn candidate_answer_uses_the_broker_policy() {
        assert_eq!(candidate_answer(&scored(0.9), &input()), ShadowAnswer::Run);
        assert_eq!(candidate_answer(&scored(0.7), &input()), ShadowAnswer::Ask);
        let calibrated = ShadowInput {
            thresholds: Thresholds { task_match: 0.65 },
            ..input()
        };
        assert_eq!(
            candidate_answer(&scored(0.7), &calibrated),
            ShadowAnswer::Run
        );
        assert_eq!(
            candidate_answer(&BouncerVerdict::Unavailable("down".into()), &input()),
            ShadowAnswer::NoAnswer
        );
        // A rule flag asks, whatever the candidate answers.
        let flagged = ShadowInput {
            analysis: Analysis {
                flags: vec!["data_loss".to_owned()],
                known_safe: false,
                known_command: false,
            },
            ..input()
        };
        assert_eq!(candidate_answer(&scored(1.0), &flagged), ShadowAnswer::Ask);
    }

    /// The refusal names each threshold of ADR 0010 that fails.
    #[test]
    fn promotion_refusal_names_each_failed_threshold() {
        let gate = |decisions, agreed, denials| {
            promotion_refusal(&CandidateAgreement {
                model_version: "v".to_owned(),
                started_at: 0,
                shadow_decisions: decisions,
                agreed,
                allowed_owner_denials: denials,
            })
        };
        assert_eq!(gate(100, 95, 0), None);
        assert!(gate(99, 99, 0).is_some_and(|r| r.contains("99 of 100")));
        assert!(gate(100, 94, 0).is_some_and(|r| r.contains("94.0%")));
        assert!(gate(200, 199, 1).is_some_and(|r| r.contains("1 request(s) that you denied")));
        assert!(gate(0, 0, 0).is_some_and(|r| r.contains("not known")));
    }
}
