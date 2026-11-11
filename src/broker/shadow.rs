//! Shadow mode, promotion, and rollback of a candidate model (ADR 0010, goal items B9
//! and B10; shadow in one request: ADR 0035, plan 0035 unit F).
//!
//! - [`models`] reads the vault for each request: the active model (the default bouncer,
//!   or a promoted head set that is pinned to its version and head hash) on the current
//!   bouncer brain client, and the candidate in shadow mode with its [`ShadowPin`].
//! - The candidate rides in the request of the active model as `shadow_heads`
//!   ([`BouncerClient::evaluate_with_shadow`], contract bouncer-brain-v1 section 3): one
//!   request, one encoder pass, no second server. The broker decides with the active
//!   answer only. [`begin`] keeps the shadow answer, and [`ShadowCall::finish`] stores it
//!   in the vault next to the real outcome and the owner decision. A missing shadow
//!   part, a `shadow.error`, another head set or version, or a head file that is not on
//!   the host records [`ShadowAnswer::NoAnswer`]; none of them changes the active
//!   decision.
//! - [`promote`] and [`roll_back`] change the active model. Each needs a fresh owner
//!   check (`OwnerAction::PromoteModel`, `OwnerAction::RollbackModel`). A promotion also
//!   needs the shadow gate of ADR 0010 (100 owner decisions in shadow mode, 95%
//!   agreement, and no owner denial that the candidate would allow) and the head file on
//!   the host of the bouncer brain ([`placement_refusal`]). Apassy never promotes a model
//!   by itself (`docs/concept.md`).

use std::fmt;

use super::SharedVault;
use super::approvals::{OwnerAction, OwnerProof};
use super::bouncer::{
    BouncerClient, BouncerVerdict, DecisionContext, Learned, ShadowPin, Thresholds, decide_learned,
    decide_routed,
};
use super::decide::lock;
use super::learning;
use super::shell_risk::Analysis;
use crate::vault::{
    BouncerHostKind, BouncerHostRole, CandidateAgreement, CandidateRecord, CandidateState,
    Declaration, ModelActivation, OwnerLabel, RealOutcome, ShadowAnswer, ShadowEntry,
    THIS_MAC_HOST, Vault, VaultError, VaultErrorKind, normalize_url,
};

/// The host key of `client` for `model_candidate.uploaded_to`: [`THIS_MAC_HOST`] for the
/// bouncer brain on this Mac, else the `https://` address of the remote host.
pub fn host_key(client: &BouncerClient) -> String {
    if client.is_remote() {
        normalize_url(client.url())
    } else {
        THIS_MAC_HOST.to_owned()
    }
}

/// The host key of the hosting choice in the vault (ADR 0035): no row or "this Mac" is
/// [`THIS_MAC_HOST`], else the address of the row.
pub fn hosting_key(vault: &Vault) -> Result<String, VaultError> {
    Ok(match vault.bouncer_host(BouncerHostRole::Hosting)? {
        Some(host) if !matches!(host.kind, BouncerHostKind::ThisMac) => normalize_url(&host.url),
        _ => THIS_MAC_HOST.to_owned(),
    })
}

/// The candidate in shadow mode.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: u64,
    pub version: String,
    /// The head set as `shadow_heads`, when the host of the bouncer brain has its head
    /// file. `None`: the request goes without it, and the row records `NoAnswer`.
    pub pin: Option<ShadowPin>,
}

/// The models for one request.
#[derive(Debug, Clone, Default)]
pub struct Models {
    /// The model that decides. `None`: every run at the model step asks the owner.
    pub active: Option<BouncerClient>,
    /// The candidate in shadow mode. Its answers have no effect.
    pub candidate: Option<Candidate>,
}

/// Read the active model and the candidate from the vault, for the bouncer brain client
/// `current` (`ModelGate::bouncer_client` of this request, or the client of the broker
/// start). Without a promotion, the default head set of `current` decides. A promoted
/// head set is pinned to its version and its head hash, on the same host. A read error,
/// no client, or a promotion without a known head hash gives no active model, so the
/// owner decides. It never falls back to another model.
pub fn models(vault: &Vault, current: Option<&BouncerClient>) -> Models {
    let active = match vault.active_model() {
        Ok(None) => current.cloned(),
        Ok(Some(activation)) if activation.is_default() => current.cloned(),
        Ok(Some(activation)) => match (current, vault.activation_heads(&activation)) {
            (Some(client), Ok(Some(heads))) => Some(
                client
                    .clone()
                    .expect_model(&activation.version)
                    .expect_heads(&heads),
            ),
            _ => None,
        },
        Err(_) => None,
    };
    let candidate = match vault.shadow_candidate() {
        Ok(Some(record)) => {
            let on_host = current.is_some_and(|client| record.is_on_host(&host_key(client)));
            Some(Candidate {
                id: record.id,
                pin: on_host.then(|| ShadowPin::new(record.heads_sha256(), &record.version)),
                version: record.version,
            })
        }
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
    /// The broker has already checked all routing vetoes, including production.
    pub routed: bool,
    /// At least one declaration has default environment or risk.
    pub default_source: bool,
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
    let decision = if input.routed {
        decide_routed(verdict, &context, &learned, input.default_source)
    } else {
        decide_learned(verdict, &context, &learned)
    };
    if decision.ask_owner {
        ShadowAnswer::Ask
    } else {
        ShadowAnswer::Run
    }
}

/// A shadow answer that waits for the real outcome. [`ShadowCall::finish`] stores it.
/// Drop without `finish` stores nothing.
pub struct ShadowCall {
    vault: SharedVault,
    epoch: [u8; 32],
    candidate_id: u64,
    answer: ShadowAnswer,
    facts: Vec<(String, f64)>,
}

impl fmt::Debug for ShadowCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowCall")
            .field("candidate_id", &self.candidate_id)
            .field("answer", &self.answer)
            .finish_non_exhaustive()
    }
}

impl ShadowCall {
    /// The answer of the candidate with the policy of the broker.
    pub fn answer(&self) -> ShadowAnswer {
        self.answer
    }

    /// The real outcome and the owner decision. Stores one row if the vault is still
    /// unlocked in the same session. The caller must not hold the vault lock.
    pub fn finish(self, real: RealOutcome, owner: OwnerLabel) {
        let mut guard = lock(&self.vault);
        if let Some(vault) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == self.epoch)
        {
            let _ = vault.record_shadow(&ShadowEntry {
                candidate_id: self.candidate_id,
                at: learning::now(),
                real,
                candidate: self.answer,
                owner,
                facts: self.facts,
            });
        }
    }
}

/// Keep the shadow answer of `candidate` from the request of the active model.
/// `verdict` is the second value of [`BouncerClient::evaluate_with_shadow`]: `None` when
/// the request went without the candidate (its head file is not on the host, or no
/// active model was asked), which records `NoAnswer`. The row is stored in the vault
/// session `epoch` at [`ShadowCall::finish`].
pub fn begin(
    vault: SharedVault,
    epoch: [u8; 32],
    candidate: &Candidate,
    verdict: Option<&BouncerVerdict>,
    input: &ShadowInput,
) -> ShadowCall {
    let (answer, facts) = match verdict {
        Some(verdict) => {
            let facts = match verdict {
                BouncerVerdict::Scored { facts, .. } => facts
                    .iter()
                    .map(|fact| (fact.name.clone(), fact.probability))
                    .collect(),
                BouncerVerdict::Unavailable(_) => Vec::new(),
            };
            (candidate_answer(verdict, input), facts)
        }
        None => (ShadowAnswer::NoAnswer, Vec::new()),
    };
    ShadowCall {
        vault,
        epoch,
        candidate_id: candidate.id,
        answer,
        facts,
    }
}

/// Why a candidate cannot be promoted on the host `host` (a key of [`host_key`] or
/// [`hosting_key`]): its head file is not there yet. `None` when it is.
pub fn placement_refusal(candidate: &CandidateRecord, host: &str) -> Option<String> {
    if candidate.is_on_host(host) {
        return None;
    }
    let place = if host == THIS_MAC_HOST {
        concat!("the bouncer brain on this ", crate::computer!()).to_owned()
    } else {
        format!("the bouncer brain server {host}")
    };
    Some(format!(
        "Its head set is not on {place} yet, so it gives no shadow answers there. Apassy uploads it first."
    ))
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
        VaultErrorKind::NotFound => "The vault has no such brain record.".to_owned(),
        _ => "The vault did not change the bouncer brain.".to_owned(),
    }
}

/// The owner promotes a candidate (ADR 0010). The proof must name this candidate and its
/// version, in this vault session. The shadow gate runs again with the rows of now, and
/// the head file must be on the host of the bouncer brain ([`placement_refusal`]).
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
        .ok_or_else(|| "The vault has no such candidate brain.".to_owned())?;
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
    // The promoted head set answers on the host of the bouncer brain, pinned by its
    // hash: without its head file there, every run would ask the owner.
    let host = hosting_key(vault).map_err(|error| vault_message(&error))?;
    if let Some(reason) = placement_refusal(&candidate, &host) {
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
                "Not rolled back. The newest brain change is not this promotion.".to_owned()
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
            routed: false,
            default_source: false,
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
                ..Analysis::default()
            },
            ..input()
        };
        assert_eq!(candidate_answer(&scored(1.0), &flagged), ShadowAnswer::Ask);
    }

    const PASS: &str = "shadow-unit-pass";
    const HEADS: &str = "0badc0de0123456789abcdef0123456789abcdef0123456789abcdef01234567";
    const VERSION: &str = "apassy-local-v1+0badc0de";
    const REMOTE: &str = "https://brain.synthetic.ts.net";

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("shadow.db"), PASS).expect("create");
        vault.unlock(PASS).expect("unlock");
        vault
    }

    fn register(vault: &mut Vault, url: &str) -> CandidateRecord {
        vault
            .register_candidate(
                &crate::vault::NewCandidate {
                    version: VERSION.to_owned(),
                    url: url.to_owned(),
                    checkpoint: "/tmp/apassy-test/candidate.safetensors".to_owned(),
                    checkpoint_sha256: HEADS.to_owned(),
                    report: "{}".to_owned(),
                },
                1,
            )
            .expect("candidate")
    }

    fn local() -> BouncerClient {
        BouncerClient::new("http://127.0.0.1:8770").expect("local")
    }

    fn remote() -> BouncerClient {
        let tls = std::sync::Arc::new(super::super::http::TlsClient::platform().expect("TLS"));
        let bearer = super::super::bouncer::StaticBearer::new(zeroize::Zeroizing::new(
            "SYNTH-shadow-unit-bearer-0123456789".to_owned(),
        ))
        .expect("bearer");
        BouncerClient::remote(&format!("{REMOTE}/"), std::sync::Arc::new(bearer), tls)
            .expect("remote")
    }

    /// The host key: this Mac for a loopback client, the address for a remote one.
    #[test]
    fn the_host_key_names_this_mac_or_the_remote_address() {
        assert_eq!(host_key(&local()), THIS_MAC_HOST);
        assert_eq!(host_key(&remote()), REMOTE);
        let dir = tempfile::TempDir::new().expect("dir");
        let mut vault = vault(&dir);
        assert_eq!(hosting_key(&vault).expect("key"), THIS_MAC_HOST);
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &crate::vault::BouncerHostChange {
                    kind: BouncerHostKind::OwnServer,
                    url: REMOTE.to_owned(),
                    bearer: Some(crate::vault::SecretValue::new(
                        "SYNTH-shadow-unit-bearer-0123456789".to_owned(),
                    )),
                    consent_version: crate::vault::HOSTING_CONSENT_VERSION,
                },
                2,
            )
            .expect("host");
        assert_eq!(hosting_key(&vault).expect("key"), REMOTE);
    }

    /// The candidate rides as `shadow_heads` only on the host that has its head file.
    /// The old `url` of the row is not read.
    #[test]
    fn the_candidate_has_a_pin_only_on_the_host_with_its_head_file() {
        let dir = tempfile::TempDir::new().expect("dir");
        let mut vault = vault(&dir);
        let record = register(&mut vault, "http://127.0.0.1:8775");
        let first = models(&vault, Some(&local()));
        assert_eq!(
            first.active.as_ref().map(BouncerClient::url),
            Some("http://127.0.0.1:8770"),
            "the default head set of the current client decides"
        );
        let candidate = first.candidate.expect("candidate");
        assert_eq!(candidate.id, record.id);
        assert_eq!(candidate.pin, None, "no host has the head file yet");
        vault
            .mark_candidate_uploaded(record.id, Some(THIS_MAC_HOST))
            .expect("mark");
        let pin = models(&vault, Some(&local()))
            .candidate
            .and_then(|candidate| candidate.pin);
        assert_eq!(pin, Some(ShadowPin::new(HEADS, VERSION)));
        assert_eq!(
            models(&vault, Some(&remote()))
                .candidate
                .and_then(|candidate| candidate.pin),
            None,
            "the remote host does not have it"
        );
        vault
            .mark_candidate_uploaded(record.id, Some(REMOTE))
            .expect("mark");
        assert!(
            models(&vault, Some(&remote()))
                .candidate
                .is_some_and(|candidate| candidate.pin.is_some())
        );
        // No client: nothing decides and nothing rides.
        let none = models(&vault, None);
        assert!(none.active.is_none());
        assert_eq!(none.candidate.and_then(|candidate| candidate.pin), None);
    }

    /// A promoted head set decides on the current client, pinned by version and hash.
    #[test]
    fn a_promoted_head_set_is_pinned_on_the_current_client() {
        let dir = tempfile::TempDir::new().expect("dir");
        let mut vault = vault(&dir);
        let record = register(&mut vault, "");
        vault
            .mark_candidate_uploaded(record.id, Some(REMOTE))
            .expect("mark");
        for _ in 0..100 {
            vault
                .record_shadow(&ShadowEntry {
                    candidate_id: record.id,
                    at: 1,
                    real: RealOutcome::Ask,
                    candidate: ShadowAnswer::Run,
                    owner: OwnerLabel::Allow,
                    facts: Vec::new(),
                })
                .expect("row");
        }
        vault.promote_candidate(record.id, 2).expect("promote");
        let active = models(&vault, Some(&remote())).active.expect("active");
        assert_eq!(active.url(), REMOTE);
        assert!(active.is_remote());
        assert_eq!(active.expected_model(), Some(VERSION));
        assert_eq!(active.expected_heads(), Some(HEADS));
        let active = models(&vault, Some(&local())).active.expect("active");
        assert_eq!(active.url(), "http://127.0.0.1:8770");
        assert_eq!(active.expected_heads(), Some(HEADS));
    }

    /// The shadow answer comes from the request of the active model. No shadow verdict
    /// and an unavailable one record `NoAnswer` with no facts.
    #[test]
    fn begin_keeps_the_shadow_answer_and_no_answer_without_one() {
        let shared: SharedVault = std::sync::Arc::new(std::sync::Mutex::new(None));
        let candidate = Candidate {
            id: 7,
            version: VERSION.to_owned(),
            pin: Some(ShadowPin::new(HEADS, VERSION)),
        };
        let call = begin(
            std::sync::Arc::clone(&shared),
            [0; 32],
            &candidate,
            Some(&scored(0.9)),
            &input(),
        );
        assert_eq!(call.answer(), ShadowAnswer::Run);
        assert_eq!(call.facts.len(), 2);
        let unavailable = BouncerVerdict::Unavailable("the shadow head set failed".into());
        for verdict in [None, Some(&unavailable)] {
            let call = begin(
                std::sync::Arc::clone(&shared),
                [0; 32],
                &candidate,
                verdict,
                &input(),
            );
            assert_eq!(call.answer(), ShadowAnswer::NoAnswer);
            assert!(call.facts.is_empty());
            // A closed vault stores nothing and does not panic.
            call.finish(RealOutcome::Run, OwnerLabel::None);
        }
    }

    /// The placement refusal names the host.
    #[test]
    fn the_placement_refusal_names_the_host() {
        let dir = tempfile::TempDir::new().expect("dir");
        let mut vault = vault(&dir);
        let record = register(&mut vault, "");
        let refusal = placement_refusal(&record, THIS_MAC_HOST).expect("refused");
        assert!(
            refusal.contains(concat!("on this ", crate::computer!())),
            "{refusal}"
        );
        let refusal = placement_refusal(&record, REMOTE).expect("refused");
        assert!(refusal.contains(REMOTE), "{refusal}");
        vault
            .mark_candidate_uploaded(record.id, Some(REMOTE))
            .expect("mark");
        let record = vault.candidate(record.id).expect("read").expect("some");
        assert_eq!(placement_refusal(&record, REMOTE), None);
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
