//! Dormant run-to-context adapter; no runtime decision path calls this module.
//! Evidence is retained local-device history, not a cross-device owner preference.

use super::{
    action_kind::ActionKind,
    bouncer::BouncerRequest,
    project::Project,
    run::{foreign_project, host_matches},
    secret_facts::{
        ContextInput, ContextRefusal, ContextV1, HostFit, ItemRunMatch, MAX_SECRETS, ProjectFit,
        build_input, facts_from_evidence,
    },
};
use crate::vault::{Declaration, EvidenceQuery, Vault};

pub struct RunItem<'a> {
    pub item_id: u64,
    pub declaration: Option<&'a Declaration>,
    /// This item's known hosts, computed by the caller.
    pub known_hosts: &'a [String],
}

pub struct RunContext<'a> {
    /// Caller must supply exactly the sanitized request used for BouncerClient::evaluate.
    /// This adapter does not read secret values or attempt to mask the request.
    pub request: &'a BouncerRequest,
    pub action: ActionKind,
    pub project: Option<&'a Project>,
    pub project_key: &'a str,
    pub agent_id: Option<u64>,
    /// Normalized run destinations, supplied by the caller.
    pub hosts: &'a [String],
    /// Items in request order.
    pub items: &'a [RunItem<'a>],
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextAsk {
    NoSecrets,
    TooManySecrets(usize),
    OverBudget { bound: u32, room: u32 },
    MissingAgent,
    DuplicateItem,
    Storage,
}

impl From<ContextRefusal> for ContextAsk {
    fn from(refusal: ContextRefusal) -> Self {
        match refusal {
            ContextRefusal::NoSecrets => Self::NoSecrets,
            ContextRefusal::TooManySecrets(count) => Self::TooManySecrets(count),
            ContextRefusal::OverBudget { bound, room } => Self::OverBudget { bound, room },
        }
    }
}

pub fn item_run_match(
    item: &RunItem<'_>,
    project: Option<&Project>,
    hosts: &[String],
) -> ItemRunMatch {
    let project = match item.declaration {
        None => ProjectFit::Undeclared,
        Some(declaration) if declaration.project.trim().is_empty() => ProjectFit::Undeclared,
        Some(declaration) => match project {
            None => ProjectFit::Other,
            Some(project) => {
                if foreign_project(&declaration.project, Some(project)).is_none() {
                    ProjectFit::Match
                } else {
                    ProjectFit::Other
                }
            }
        },
    };
    let hosts = if hosts.is_empty() {
        HostFit::None
    } else if hosts.iter().all(|host| {
        item.known_hosts
            .iter()
            .any(|known| host_matches(host, known))
    }) {
        HostFit::Known
    } else {
        HostFit::Unknown
    };
    ItemRunMatch { project, hosts }
}

pub fn context_input(vault: &Vault, run: &RunContext<'_>) -> Result<ContextInput, ContextAsk> {
    if run.agent_id.is_none() {
        return Err(ContextAsk::MissingAgent);
    }
    match run.items.len() {
        0 => return Err(ContextRefusal::NoSecrets.into()),
        count if count > MAX_SECRETS => {
            return Err(ContextRefusal::TooManySecrets(count).into());
        }
        _ => {}
    }
    for (index, item) in run.items.iter().enumerate() {
        if run.items[..index]
            .iter()
            .any(|previous| previous.item_id == item.item_id)
        {
            return Err(ContextAsk::DuplicateItem);
        }
    }

    let mut secrets = Vec::with_capacity(run.items.len());
    for item in run.items {
        let evidence = vault
            .decision_evidence(&EvidenceQuery {
                item_id: item.item_id,
                agent_id: run.agent_id,
                project_key: run.project_key,
                action: run.action,
                hosts: run.hosts,
                now: run.now,
            })
            .map_err(|_| ContextAsk::Storage)?;
        secrets.push(facts_from_evidence(
            &evidence,
            item_run_match(item, run.project, run.hosts),
            run.now,
        ));
    }
    // Build only after all local evidence reads succeed; never return partial input.
    build_input(
        run.request,
        &ContextV1 {
            action: run.action,
            secrets,
        },
    )
    .map_err(ContextAsk::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Environment, Reversibility, RiskLevel, Scope};

    fn declaration(project: &str) -> Declaration {
        Declaration {
            project: project.to_owned(),
            environment: Environment::Development,
            risk: RiskLevel::Low,
            scope: Scope::ReadOnly,
            reversibility: Reversibility::Reversible,
        }
    }

    #[test]
    fn project_fit_requires_a_current_project_for_a_named_declaration() {
        let project = Project {
            key: "synthetic-project".into(),
            label: "example".into(),
            root: "/synthetic/example".into(),
        };
        for (declared, current, expected) in [
            (None, None, ProjectFit::Undeclared),
            (Some("  "), None, ProjectFit::Undeclared),
            (Some("example"), None, ProjectFit::Other),
            (Some("example"), Some(&project), ProjectFit::Match),
            (Some("elsewhere"), Some(&project), ProjectFit::Other),
        ] {
            let declaration = declared.map(declaration);
            let item = RunItem {
                item_id: 1,
                declaration: declaration.as_ref(),
                known_hosts: &[],
            };
            assert_eq!(item_run_match(&item, current, &[]).project, expected);
        }
    }

    #[test]
    fn host_fit_uses_only_the_items_own_hosts_and_requires_all_destinations() {
        let known_hosts = vec!["api.example.test".into(), "*.service.test".into()];
        let item = RunItem {
            item_id: 1,
            declaration: None,
            known_hosts: &known_hosts,
        };
        for (hosts, expected) in [
            (vec![], HostFit::None),
            (vec!["api.example.test".into()], HostFit::Known),
            (
                vec!["api.example.test".into(), "one.service.test".into()],
                HostFit::Known,
            ),
            (vec!["service.test".into()], HostFit::Unknown),
            (vec!["notservice.test".into()], HostFit::Unknown),
            (
                vec!["api.example.test".into(), "other.test".into()],
                HostFit::Unknown,
            ),
        ] {
            assert_eq!(item_run_match(&item, None, &hosts).hosts, expected);
        }
        let other = RunItem {
            item_id: 2,
            declaration: None,
            known_hosts: &[],
        };
        assert_eq!(
            item_run_match(&other, None, &["api.example.test".into()]).hosts,
            HostFit::Unknown,
        );
    }
}
