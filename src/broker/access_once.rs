//! Access consent precedes ordinary routing. It never supplies execution consent.
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use super::approvals::{OwnerAction, OwnerProof};
use crate::agent::wire::WireResponse;
use crate::questions::access_request::{
    self as wire, Choice, DeviceKind, Outcome, Receipt, ReceiptChoice,
};
use crate::relay::membership::{questions_membership, this_device};
use crate::vault::{AgentSummary, EnvDelivery, Vault, VaultErrorKind};

fn fail() -> WireResponse {
    WireResponse::failure(
        "access_once_unavailable",
        "This scoped allowance is unavailable or consumed. Check its status; do not repeat the use.",
    )
}
fn short(s: &str, n: usize) -> String {
    let mut out = String::new();
    for c in wire::display_text(s).chars() {
        if out.len() + c.len_utf8() > n {
            break;
        }
        out.push(c);
    }
    out
}
pub fn create(
    vault: &mut Vault,
    agent: &AgentSummary,
    item: u64,
    reason: &str,
    cwd: Option<&str>,
    scope: &wire::Scope,
) -> WireResponse {
    let result = (|| {
        let details = vault.details(item).map_err(|e| e.kind())?;
        if !vault
            .agent_view(agent.id)
            .map_err(|e| e.kind())?
            .visible(item)
            || vault.is_archived(item).map_err(|e| e.kind())?
            || vault.needs_review(item).map_err(|e| e.kind())?
        {
            return Err(VaultErrorKind::NotFound);
        }
        let binding = vault
            .process_binding(item)
            .map_err(|e| e.kind())?
            .ok_or(VaultErrorKind::InvalidInput)?;
        let uuid = vault
            .item_uuid(item)
            .map_err(|e| e.kind())?
            .ok_or(VaultErrorKind::InvalidInput)?;
        let canonical = cwd
            .and_then(|s| std::fs::canonicalize(s).ok())
            .filter(|p| p.is_dir());
        let cwd = canonical.as_ref().and_then(|p| p.to_str()).unwrap_or("");
        let project = canonical
            .as_deref()
            .and_then(|p| {
                super::project::project_of(p, std::env::var_os("HOME").as_deref().map(Path::new))
            })
            .filter(|p| {
                std::fs::canonicalize(&p.key)
                    .ok()
                    .as_deref()
                    .and_then(Path::to_str)
                    == Some(p.key.as_str())
                    && p.root.to_str().is_some()
            })
            .map(|p| wire::Project {
                key: p.key,
                label: short(&p.label, 256),
            });
        let mut hosts: Vec<_> = scope
            .hosts
            .iter()
            .map(|h| wire::normal_host(h).ok_or(VaultErrorKind::InvalidInput))
            .collect::<Result<_, _>>()?;
        hosts.sort();
        if !wire::hosts_valid(&hosts) || hosts.len() != scope.hosts.len() {
            return Err(VaultErrorKind::InvalidInput);
        }
        if let EnvDelivery::Placeholder(allowed) = &binding.delivery {
            for h in &hosts {
                let actual =
                    super::proxy::HostRule::parse(h).map_err(|_| VaultErrorKind::InvalidInput)?;
                if !allowed
                    .iter()
                    .filter_map(|h| super::proxy::HostRule::parse(h).ok())
                    .any(|r| r.covers(actual.host(), actual.port()))
                {
                    return Err(VaultErrorKind::InvalidInput);
                }
            }
        }
        let membership = questions_membership(vault).map_err(|e| e.kind())?;
        let device = membership
            .as_ref()
            .map(|m| this_device(vault, m))
            .transpose()
            .map_err(|e| e.kind())?
            .flatten();
        let key = vault.question_key().map_err(|e| e.kind())?;
        let complete = project.is_some() && !cwd.is_empty() && !hosts.is_empty();
        let created_at = crate::vault::access_once::now();
        let ids: Vec<_> = vault
            .item_uuids()
            .map_err(|e| e.kind())?
            .keys()
            .copied()
            .collect();
        let reason = vault
            .command_mask(&ids)
            .map_err(|e| e.kind())?
            .summary(reason, 500);
        let environment = match vault
            .declaration(item)
            .map_err(|e| e.kind())?
            .map(|d| d.environment)
        {
            Some(crate::vault::Environment::Development) => wire::Environment::Development,
            Some(crate::vault::Environment::Staging) => wire::Environment::Staging,
            Some(crate::vault::Environment::Production) => {
                if vault
                    .declaration_sources(item)
                    .map_err(|e| e.kind())?
                    .environment
                    == crate::vault::DeclarationSource::Default
                {
                    wire::Environment::Unconfirmed
                } else {
                    wire::Environment::Production
                }
            }
            None => wire::Environment::Unconfirmed,
            Some(crate::vault::Environment::Local) => return Err(VaultErrorKind::InvalidInput),
        };
        let policy_digest = vault
            .access_policy_digest(
                agent.id,
                item,
                cwd,
                project.as_ref().map_or("", |p| p.key.as_str()),
            )
            .map_err(|e| e.kind())?;
        let card=wire::Card {
            vault_id:vault.sync_identity().map_err(|e|e.kind())?.vault_id,
            team_id:membership.as_ref().map_or("local",|m|m.team_id.as_str()).into(),
            qid:crate::questions::envelope::new_qid().ok_or(VaultErrorKind::Storage)?,
            key_id:key.map_or_else(||"0000000000000000".into(),|k|k.key_id()),to:"member".into(),request_id:"1".into(),
            asker:wire::Asker{device:device.as_ref().map_or("00000000-0000-0000-0000-000000000000",|d|d.uuid.as_str()).into(),
                relay_device_id:membership.as_ref().map_or(1,|m|m.device_id),name:device.as_ref().map_or_else(||"this Mac".into(),|d|short(&d.name,64))},
            vault_name:"Vault".into(),agent:wire::Agent{id:agent.id.to_string(),name:short(&agent.name,64),host:None,host_source:wire::HostSource::Unknown},
            item:wire::Item{local_id:item.to_string(),uuid,revision:details.summary.revision.to_string(),name:short(&details.summary.title,128),
                environment,delivery:if matches!(binding.delivery,EnvDelivery::Value){wire::Delivery::RealValue}else{wire::Delivery::Placeholder},
                binding_name:binding.env_name},
            project,cwd:cwd.into(),action:Some(scope.action),hosts,scope_source:wire::ScopeSource::AgentRequestedMacChecked,
            reason:short(&reason,500),policy_digest,created_at,expires_at:created_at+300,
            valid_answers:if complete{vec![Choice::Deny,Choice::AllowOnce]}else{vec![Choice::Deny]},
            local_review_reason:(!complete).then(||"This request does not specify a lossless canonical project, folder and destination hosts.".into()),
        };
        vault
            .create_scoped_access_request(card)
            .map_err(|e| e.kind())
    })();
    match result {
        Ok((id, new)) => WireResponse::success(
            serde_json::json!({"request_id":id,"new":new,"state":"open","note":"Access consent only. The bouncer still checks each command. Query status, then explicitly attach access_request_id to one matching one-item run. Cancel if abandoning this request."}),
        ),
        Err(VaultErrorKind::Busy) => WireResponse::failure(
            "access_request_waiting",
            "Another scope is active, or this Mac's conservative request budget is exhausted. Review on this Mac.",
        ),
        Err(_) => WireResponse::failure(
            "not_visible",
            "This credential or scope is unavailable to this agent. Review on this Mac.",
        ),
    }
}

/// A remote proof is non-Clone and contains the original signed time. It never touches OwnerWindow.
#[derive(Debug)]
pub struct RemoteAccessAnswer {
    id: u64,
    digest: String,
    answer: wire::Answer,
    device: crate::vault::TrustedDevice,
    epoch: [u8; 32],
}
impl RemoteAccessAnswer {
    pub fn verify(
        vault: &Vault,
        id: u64,
        answer: wire::Answer,
        stamped: u64,
    ) -> Result<Self, wire::Error> {
        let r = vault
            .scoped_access_request(id)
            .map_err(|_| wire::Error::Identity)?;
        if !vault.access_record_live(&r) {
            return Err(wire::Error::Expired);
        }
        let device = vault
            .trusted_device(&answer.by)
            .map_err(|_| wire::Error::Identity)?
            .ok_or(wire::Error::Identity)?;
        if device.kind != crate::vault::TrustedDeviceKind::Iphone
            || device.relay_devices.get(&r.card.card.team_id) != Some(&stamped)
        {
            return Err(wire::Error::Identity);
        }
        let key = match answer.kind {
            Choice::Deny => &device.sign_key,
            Choice::AllowOnce => device.answer_key.as_ref().ok_or(wire::Error::Identity)?,
        };
        answer.verify(&r.card, key, crate::vault::access_once::now())?;
        Ok(Self {
            id,
            digest: r.card.digest,
            answer,
            device,
            epoch: vault.epoch(),
        })
    }
    pub fn commit(self, vault: &mut Vault) -> Result<(), wire::Error> {
        if self.epoch != vault.epoch()
            || vault
                .trusted_device(&self.device.uuid)
                .ok()
                .flatten()
                .as_ref()
                != Some(&self.device)
        {
            return Err(wire::Error::Identity);
        }
        let r = vault
            .scoped_access_request(self.id)
            .map_err(|_| wire::Error::Identity)?;
        if r.card.digest != self.digest {
            return Err(wire::Error::Identity);
        }
        self.answer
            .check(&r.card, crate::vault::access_once::now())?;
        let receipt = receipt(
            &r,
            self.answer.kind,
            &self.device.uuid,
            &self.device.name,
            DeviceKind::Iphone,
        );
        vault
            .commit_access_answer(self.id, self.answer.kind, receipt)
            .map_err(|_| wire::Error::Expired)
    }
}
fn receipt(
    r: &crate::vault::access_once::AccessRecord,
    choice: Choice,
    by: &str,
    name: &str,
    kind: DeviceKind,
) -> Receipt {
    let c = &r.card.card;
    Receipt {
        vault_id: c.vault_id.clone(),
        team_id: c.team_id.clone(),
        qid: c.qid.clone(),
        request_id: c.request_id.clone(),
        asker: c.asker.device.clone(),
        digest: r.card.digest.clone(),
        outcome: if choice == Choice::Deny {
            Outcome::Denied
        } else {
            Outcome::AllowedOnce
        },
        answered_by: Some(by.into()),
        device_name: Some(short(name, 64)),
        device_kind: Some(kind),
        kind: Some(if choice == Choice::Deny {
            ReceiptChoice::Deny
        } else {
            ReceiptChoice::AllowOnce
        }),
        at: crate::vault::access_once::now(),
        expires_at: c.expires_at,
    }
}
pub fn local_answer(
    vault: &mut Vault,
    id: u64,
    choice: Choice,
    proof: Option<OwnerProof>,
) -> Result<(), String> {
    let r = vault
        .scoped_access_request(id)
        .map_err(|_| "The request is unavailable.")?;
    if choice == Choice::AllowOnce {
        proof
            .ok_or("A fresh owner check is required.")?
            .check(
                &OwnerAction::AllowAccessOnce {
                    request_id: id,
                    digest: r.card.digest.clone(),
                },
                &vault.epoch(),
            )
            .map_err(|e| e.message())?;
    }
    let receipt = receipt(
        &r,
        choice,
        &r.card.card.asker.device,
        &r.card.card.asker.name,
        DeviceKind::Mac,
    );
    vault
        .commit_access_answer(id, choice, receipt)
        .map_err(|_| "The request was answered, expired or changed.".into())
}

/// A private operation ticket survives downstream waits, but never restores a burned permit.
#[derive(Debug, Clone)]
pub(crate) struct Admission {
    vault: Weak<Mutex<Option<Vault>>>,
    id: u64,
    operation: [u8; 32],
    pub hosts: Vec<String>,
}
impl Admission {
    pub fn consume(
        shared: &super::SharedVault,
        id: u64,
        agent: u64,
        item: u64,
        cwd: &str,
        project: &str,
        action: wire::Action,
        hosts: &[String],
    ) -> Result<Self, WireResponse> {
        let mut guard = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let v = guard.as_mut().ok_or_else(fail)?;
        let operation = v
            .consume_access_once(id, agent, item, cwd, project, action, hosts)
            .map_err(|_| fail())?;
        Ok(Self {
            vault: Arc::downgrade(shared),
            id,
            operation,
            hosts: hosts.into(),
        })
    }
    pub fn live_in(&self, vault: &Vault) -> bool {
        vault.access_admission_live(self.id, &self.operation)
    }
    pub fn live(&self) -> bool {
        self.vault.upgrade().is_some_and(|v| {
            v.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|v| self.live_in(v))
        })
    }
    pub fn covers(&self, host: &str, port: u16) -> bool {
        let exact = if port == 443 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        self.hosts.contains(&exact) && self.live()
    }
    pub fn remaining(&self) -> std::time::Duration {
        self.vault
            .upgrade()
            .and_then(|v| {
                v.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .and_then(|v| v.scoped_access_request(self.id).ok())
            })
            .map_or(std::time::Duration::ZERO, |r| {
                std::time::Duration::from_secs(
                    r.card
                        .card
                        .expires_at
                        .saturating_sub(crate::vault::access_once::now()),
                )
            })
    }
}

/// V1 refuses command forms whose destination port cannot be established.
pub(crate) fn exact_run_hosts(command: &[String]) -> Option<Vec<String>> {
    if command.iter().any(|s| {
        [
            "--connect-to",
            "--resolve",
            "--proxy",
            "--socks",
            "--config",
            "--unix-socket",
        ]
        .iter()
        .any(|p| s.starts_with(p))
            || s == "-x"
            || s == "-K"
    }) {
        return None;
    }
    let detected = super::shell_risk::command_hosts(command);
    let mut exact = Vec::new();
    for text in command {
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("://") {
            let scheme = rest[..pos]
                .rsplit(|c: char| !c.is_ascii_alphanumeric())
                .next()?;
            let default = match scheme {
                "https" => 443,
                "http" => 80,
                _ => return None,
            };
            rest = &rest[pos + 3..];
            let authority = rest
                .split(|c: char| c.is_whitespace() || "/?#\"'\u{60}<>();|\\".contains(c))
                .next()?;
            if authority.contains('@') {
                return None;
            }
            let host = if authority.contains(':') || default == 443 {
                authority.to_owned()
            } else {
                format!("{authority}:{default}")
            };
            exact.push(wire::normal_host(&host)?);
        }
    }
    exact.sort();
    exact.dedup();
    if exact.is_empty() || !wire::hosts_valid(&exact) {
        return None;
    }
    let mut names: Vec<_> = exact
        .iter()
        .map(|h| h.split(':').next().unwrap_or("").to_owned())
        .collect();
    names.sort();
    names.dedup();
    let mut detected: Vec<_> = detected
        .iter()
        .map(|h| wire::normal_host(h))
        .collect::<Option<_>>()?;
    detected.sort();
    detected.dedup();
    (names == detected).then_some(exact)
}
