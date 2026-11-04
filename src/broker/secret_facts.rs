//! Secret-free facts and the sdc-text-v1 serializer. No vault reads occur here.
//!
//! `segment_tokens`, when measured, is an object mapping exact segment strings
//! (including leading space and terminal punctuation) to integer token costs.
//! Missing entries fall back to ASCII byte length; invalid budgets fail closed.
//! Golden JSON shape: request (BouncerRequest fields), action, secrets (ordered
//! contract-key objects), model_text (successful serialization before budgeting),
//! token_bound, refusal (null or {kind, bound?, room?, secrets?}). A refusal never
//! exposes model_text through build_input; fixtures retain it solely for parity.

use super::{
    action_kind::ActionKind,
    bouncer::{BouncerRequest, state_text},
};
use crate::{
    contracts::CredentialKind,
    vault::{DeclarationSource, Environment, EventAge, ItemDecisionEvidence, Scope, UseCount},
};
use ring::digest;
use serde_json::Value;
use std::{fmt, sync::OnceLock};

pub const CONTRACT_NAME: &str = "secret-decision-context-v1";
pub const SERIALIZER: &str = "sdc-text-v1";
pub const MAX_SECRETS: usize = 3;
pub fn contract_json() -> &'static [u8] {
    include_bytes!("../../tools/basemodel/contracts/secret-decision-context-v1.json")
}
fn contract() -> &'static Value {
    static VALUE: OnceLock<Value> = OnceLock::new();
    VALUE
        .get_or_init(|| serde_json::from_slice(contract_json()).expect("embedded context contract"))
}
pub fn contract_sha256() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        digest::digest(&digest::SHA256, contract_json())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    })
}
macro_rules! vocabulary {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $text),+ } }
        }
    }
}
vocabulary!(KindFact { ApiKey => "api_key", Login => "login", Database => "database", SshKey => "ssh_key", Custom => "custom" });
vocabulary!(EnvFact { Local => "local", Development => "development", Staging => "staging", Production => "production", Unknown => "unknown" });
vocabulary!(Provenance { Owner => "owner", Signal => "signal", Usage => "usage", Default => "default", LegacyUnknown => "legacy_unknown", None => "none" });
vocabulary!(ScopeFact { ReadOnly => "read_only", ReadWrite => "read_write", Admin => "admin", Unknown => "unknown" });
vocabulary!(Tri { Yes => "yes", No => "no", Unknown => "unknown" });
vocabulary!(ProjectFit { Match => "match", Other => "other", Undeclared => "undeclared" });
vocabulary!(HostFit { None => "none", Known => "known", Unknown => "unknown" });
vocabulary!(Recorded { Yes => "yes", NotRecorded => "not_recorded" });
vocabulary!(Age { None => "none", Lt1d => "lt1d", Lt7d => "lt7d", Lt30d => "lt30d", Unknown => "unknown" });
vocabulary!(Count { Zero => "0", One => "1", TwoToFour => "2-4", FivePlus => "5+", Unknown => "unknown" });
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFact {
    Listed(&'static str),
    Other,
    None,
}
impl ProviderFact {
    /// The listed marker is a vocabulary category, never a provider model token.
    pub const ALL: &'static [Self] = &[Self::Listed("<listed>"), Self::Other, Self::None];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Listed("<listed>") => "<listed>",
            Self::Listed(id) => listed_provider(id).unwrap_or("other"),
            Self::Other => "other",
            Self::None => "none",
        }
    }
}
fn listed_provider(id: &str) -> Option<&'static str> {
    contract()["providers"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|v| {
            *v == id
                && !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemRunMatch {
    pub project: ProjectFit,
    pub hosts: HostFit,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFactsV1 {
    pub kind: KindFact,
    pub provider: ProviderFact,
    pub env: EnvFact,
    pub env_from: Provenance,
    pub scope: ScopeFact,
    pub scope_from: Provenance,
    pub sensitive: Tri,
    pub project: ProjectFit,
    pub hosts: HostFit,
    pub made_by_agent: Recorded,
    pub agent_used: Recorded,
    pub secret_changed: Age,
    pub access_changed: Age,
    pub owner_allowed: Count,
    pub owner_denied: Count,
    pub owner_denied_other: Count,
    pub conflict: bool,
}
fn provenance(s: DeclarationSource) -> Provenance {
    match s {
        DeclarationSource::Owner => Provenance::Owner,
        DeclarationSource::Signal => Provenance::Signal,
        DeclarationSource::Usage => Provenance::Usage,
        DeclarationSource::Default => Provenance::Default,
    }
}
fn age(event: EventAge, now: u64) -> Age {
    match event {
        EventAge::None => Age::None,
        EventAge::Unknown => Age::Unknown,
        EventAge::At(t) if t.saturating_sub(now) > 300 => Age::Unknown,
        EventAge::At(t) => match now.saturating_sub(t) {
            0..=86_399 => Age::Lt1d,
            86_400..=604_799 => Age::Lt7d,
            604_800..=2_591_999 => Age::Lt30d,
            _ => Age::None,
        },
    }
}
fn count(c: UseCount) -> Count {
    match c {
        UseCount::Known(0) => Count::Zero,
        UseCount::Known(1) => Count::One,
        UseCount::Known(2..=4) => Count::TwoToFour,
        UseCount::Known(_) => Count::FivePlus,
        UseCount::Unknown => Count::Unknown,
    }
}
pub fn facts_from_evidence(e: &ItemDecisionEvidence, fit: ItemRunMatch, now: u64) -> SecretFactsV1 {
    let (env, scope, sensitive, env_from, scope_from) = match &e.declaration {
        None => (
            EnvFact::Unknown,
            ScopeFact::Unknown,
            Tri::Unknown,
            Provenance::None,
            Provenance::None,
        ),
        Some(d) => (
            match d.environment {
                Environment::Local => EnvFact::Local,
                Environment::Development => EnvFact::Development,
                Environment::Staging => EnvFact::Staging,
                Environment::Production => EnvFact::Production,
            },
            match d.scope {
                Scope::ReadOnly => ScopeFact::ReadOnly,
                Scope::ReadWrite => ScopeFact::ReadWrite,
                Scope::Admin => ScopeFact::Admin,
            },
            if d.is_sensitive() { Tri::Yes } else { Tri::No },
            e.declaration_sources
                .map(|s| provenance(s.environment))
                .unwrap_or(Provenance::LegacyUnknown),
            e.declaration_sources
                .map(|s| provenance(s.scope))
                .unwrap_or(Provenance::LegacyUnknown),
        ),
    };
    SecretFactsV1 {
        kind: match e.kind {
            CredentialKind::ApiKey => KindFact::ApiKey,
            CredentialKind::Login => KindFact::Login,
            CredentialKind::Database => KindFact::Database,
            CredentialKind::SshKey => KindFact::SshKey,
            CredentialKind::Custom => KindFact::Custom,
        },
        provider: match e.provider.as_deref() {
            None => ProviderFact::None,
            Some(id) => listed_provider(id)
                .map(ProviderFact::Listed)
                .unwrap_or(ProviderFact::Other),
        },
        env,
        env_from,
        scope,
        scope_from,
        sensitive,
        project: fit.project,
        hosts: fit.hosts,
        made_by_agent: if e.agent_created_here {
            Recorded::Yes
        } else {
            Recorded::NotRecorded
        },
        agent_used: if e.agent_allowed_before {
            Recorded::Yes
        } else {
            Recorded::NotRecorded
        },
        secret_changed: age(e.last_secret_change, now),
        access_changed: age(e.last_access_change, now),
        owner_allowed: count(e.owner_allowed_same_scope),
        owner_denied: count(e.owner_denied_same_scope),
        owner_denied_other: count(e.owner_denied_other_scope),
        conflict: matches!(
            (e.owner_allowed_same_scope, e.owner_denied_same_scope),
            (UseCount::Known(1..), UseCount::Known(1..))
        ),
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextV1 {
    pub action: ActionKind,
    pub secrets: Vec<SecretFactsV1>,
}
pub struct ContextInput {
    model_text: String,
    token_bound: u32,
    secrets: usize,
}
impl fmt::Debug for ContextInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextInput")
            .field("secrets", &self.secrets)
            .field("token_bound", &self.token_bound)
            .field("text_len", &self.model_text.len())
            .finish()
    }
}
impl ContextInput {
    pub fn model_text(&self) -> &str {
        &self.model_text
    }
    pub fn token_bound(&self) -> u32 {
        self.token_bound
    }
    pub fn secrets(&self) -> usize {
        self.secrets
    }
    pub fn contract_sha256(&self) -> &'static str {
        contract_sha256()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextRefusal {
    NoSecrets,
    TooManySecrets(usize),
    OverBudget { bound: u32, room: u32 },
}
pub fn agent_text_bound(text: &str) -> u32 {
    text.chars().fold(0u32, |sum, c| {
        sum.saturating_add(if c.is_ascii() {
            1
        } else {
            3 * c.len_utf8() as u32
        })
    })
}
fn fields(s: &SecretFactsV1) -> [(&'static str, &'static str); 17] {
    [
        ("kind", s.kind.as_str()),
        (
            "provider",
            match s.provider {
                ProviderFact::Listed(id) => listed_provider(id).unwrap_or("other"),
                p => p.as_str(),
            },
        ),
        ("env", s.env.as_str()),
        ("env_from", s.env_from.as_str()),
        ("scope", s.scope.as_str()),
        ("scope_from", s.scope_from.as_str()),
        ("sensitive", s.sensitive.as_str()),
        ("project", s.project.as_str()),
        ("hosts", s.hosts.as_str()),
        ("made_by_agent", s.made_by_agent.as_str()),
        ("agent_used", s.agent_used.as_str()),
        ("secret_changed", s.secret_changed.as_str()),
        ("access_changed", s.access_changed.as_str()),
        ("owner_allowed", s.owner_allowed.as_str()),
        ("owner_denied", s.owner_denied.as_str()),
        ("owner_denied_other", s.owner_denied_other.as_str()),
        ("conflict", if s.conflict { "yes" } else { "no" }),
    ]
}
fn segments(context: &ContextV1) -> Vec<String> {
    let mut out = vec![
        " Context:".to_owned(),
        format!(" action={}", context.action.as_str()),
        format!(" secrets={}", context.secrets.len()),
        " history=local_device".to_owned(),
        " window=30d.".to_owned(),
    ];
    for (i, s) in context.secrets.iter().enumerate() {
        out.push(format!(" secret_{}:", i + 1));
        for (j, (k, v)) in fields(s).iter().enumerate() {
            out.push(format!(" {k}={v}{}", if j == 16 { "." } else { "" }));
        }
    }
    out
}
fn state(request: &BouncerRequest) -> String {
    let mut request = request.clone();
    request.instruction.clear();
    state_text(&request)
}
fn budget_bound(state: &str, parts: &[String], budget: &Value) -> (u32, u32) {
    let integer = |v: &Value| v.as_u64().and_then(|n| u32::try_from(n).ok());
    let Some(max) = integer(&budget["max_len"]) else {
        return (u32::MAX, 0);
    };
    let header = if budget["header_tokens"].is_null() {
        integer(&budget["header_reserve_tokens"])
    } else {
        integer(&budget["header_tokens"])
    };
    let Some(room) = header.and_then(|h| max.checked_sub(h)) else {
        return (u32::MAX, 0);
    };
    let table = &budget["segment_tokens"];
    if !table.is_null() && !table.is_object() {
        return (u32::MAX, 0);
    }
    let cost = parts.iter().try_fold(0u32, |sum, p| {
        let c = match table.get(p) {
            Some(v) => integer(v)?,
            None => u32::try_from(p.len()).ok()?,
        };
        sum.checked_add(c)
    });
    let bound = cost
        .and_then(|c| c.checked_add(agent_text_bound(state)))
        .unwrap_or(u32::MAX);
    // Saturation is a refusal even if a malformed contract allows MAX tokens.
    if bound == u32::MAX {
        (bound, 0)
    } else {
        (bound, room)
    }
}
/// Caller supplies the same sanitized request as for BouncerClient::evaluate.
/// No secret masking is attempted here: this layer never receives secret values.
pub fn build_input(
    request: &BouncerRequest,
    context: &ContextV1,
) -> Result<ContextInput, ContextRefusal> {
    match context.secrets.len() {
        0 => return Err(ContextRefusal::NoSecrets),
        n if n > MAX_SECRETS => return Err(ContextRefusal::TooManySecrets(n)),
        _ => {}
    }
    let state = state(request);
    let parts = segments(context);
    let (bound, room) = budget_bound(&state, &parts, &contract()["budget"]);
    if bound > room {
        return Err(ContextRefusal::OverBudget { bound, room });
    }
    Ok(ContextInput {
        model_text: state + &parts.concat(),
        token_bound: bound,
        secrets: context.secrets.len(),
    })
}
#[cfg(test)]
#[path = "secret_facts_tests.rs"]
mod tests;
