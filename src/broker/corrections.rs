//! Corrections from the use log (ADR 0025 §5).
//!
//! After each use that the broker allowed, [`consider`] reads the use log of the item
//! and proposes a correction of its declaration when the use does not fit it:
//!
//! - **Development.** An item that is production only by default (no signal), whose
//!   value has no production signal, and that was used at least [`MIN_ENVIRONMENT_USES`]
//!   times, each time with a host that looks like development or test (`sandbox`,
//!   `test`, `dev` as a word of the host, or a `.test` name), and with no other host. A
//!   host of this computer (`localhost`, `127.0.0.1`, `::1`, `*.local`) counts for
//!   nothing: a tunnel to production has the same address. The agent chose the hosts of
//!   its command, so the facts say [`UNVERIFIED_FACT`]. Looser: it waits for the owner
//!   and changes nothing before.
//! - **Production.** An item declared local, development, or staging whose value has a
//!   strong production signal of the provider catalog (`sk_live_`, ...). When the
//!   environment did not come from the owner, it is stricter at once: the environment
//!   becomes production with the source `usage`, so the bouncer uses the more careful
//!   value until the owner answers ([`APPLIED_FACT`] true; [`RAISED_FROM_FACT`] and
//!   [`PREVIOUS_ENVIRONMENT_FACT`] name the earlier environment). Ignoring the correction
//!   gives the item its earlier environment back, which is looser. When the owner set
//!   the environment, Apassy never changes it: the correction only waits for the owner
//!   ([`APPLIED_FACT`] false, no [`RAISED_FROM_FACT`]).
//! - **Project.** An item without a project in its declaration that was used at least
//!   [`MIN_PROJECT_USES`] times, every time in one project. Accepting names the project in
//!   the declaration; the bouncer then asks for a use in another project.
//!
//! Each correction is made once (`UNIQUE (item, kind, proposed)`): an ignored one never
//! comes again. The facts name hosts, the project, counts, and the kind of signal; never
//! a value. A failure here never stops a run.
//!
//! **Cost.** [`consider`] runs with the vault lock held after each allowed run. It
//! remembers, for each item of the vault session, what it saw last: the revision of the
//! item (a new value raises it), the declaration, its sources, and the field of the
//! variable. It reveals the value and runs the detection only after one of them
//! changed. It reads the use log while the item has fewer uses than a usage correction
//! needs, after a change, and else every [`RECHECK_USES`] allowed uses.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, PoisonError};

use serde_json::json;

use crate::vault::agent_items::{CorrectionKind, RAISED_FROM_FACT};
use crate::vault::detect::{self, Source};
use crate::vault::usage::{ItemUse, UseOutcome};
use crate::vault::{Declaration, DeclarationSource, DeclarationSources, Environment, Vault};

/// Uses that a "development" correction needs.
pub const MIN_ENVIRONMENT_USES: usize = 3;
/// Uses that a "project" correction needs.
pub const MIN_PROJECT_USES: usize = 5;
/// Allowed uses after which [`consider`] reads the use log again when nothing changed.
pub const RECHECK_USES: u32 = 10;
/// The fact key of the environment before an environment correction.
pub const PREVIOUS_ENVIRONMENT_FACT: &str = "previous_environment";
/// The fact key that says whether an environment correction already changed the
/// declaration until the owner answers (`true`), or only waits for the owner (`false`).
pub const APPLIED_FACT: &str = "applied";
/// The fact key that says that the facts come from what an agent chose, such as the
/// hosts of its command, and that Apassy did not check them.
pub const UNVERIFIED_FACT: &str = "unverified";
/// The newest uses that the check reads.
const USES_READ: usize = 200;
/// Words of a host name that say development or test.
const DEVELOPMENT_WORDS: &[&str] = &[
    "sandbox",
    "sbx",
    "test",
    "testing",
    "testnet",
    "dev",
    "development",
    "devnet",
];
/// Reserved names for tests (RFC 2606).
const DEVELOPMENT_SUFFIXES: &[&str] = &[".test", ".example", ".invalid"];

/// What a host says about the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// A development or test host.
    Development,
    /// A host of this computer. It says nothing: a tunnel to production looks the same.
    Local,
    /// Any other host.
    Other,
}

/// What `host` (a host name, with or without a port) says about the environment.
pub fn host_kind(host: &str) -> HostKind {
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_start_matches('[');
    let name = match host.split_once(']') {
        Some((inner, _)) => inner.to_owned(),
        None => match host.rsplit_once(':') {
            Some((name, port))
                if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                name.to_owned()
            }
            _ => host.to_owned(),
        },
    };
    let name = name.trim_end_matches('.');
    if name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.starts_with("127.")
        || name == "::1"
        || name == "0.0.0.0"
    {
        return HostKind::Local;
    }
    if DEVELOPMENT_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return HostKind::Development;
    }
    let development = name
        .split(['.', '-', '_'])
        .any(|word| DEVELOPMENT_WORDS.contains(&word));
    if development {
        HostKind::Development
    } else {
        HostKind::Other
    }
}

// ---- What consider saw last ----

/// What makes a value check or a usage check stale: a change of the item (its revision
/// grows with each new value), of its declaration and sources, or of the variable field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    revision: u64,
    declaration: Declaration,
    sources: DeclarationSources,
    field: Option<String>,
}

/// What [`consider`] remembers for one item. No value.
#[derive(Debug)]
struct Considered {
    fingerprint: Fingerprint,
    /// The value has a strong production signal. `None`: not checked since the change.
    live: Option<bool>,
    /// The allowed uses that the last usage check read.
    uses_seen: usize,
    /// Considerations since the last usage check.
    since_usage: u32,
    /// What [`consider`] did for the item in the vault session.
    checks: Checks,
}

/// What [`consider`] did for one item in the vault session (see [`checks`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Checks {
    /// Reveals of the value with the detection.
    pub values: u64,
    /// Reads of the use log.
    pub uses: u64,
}

/// The vault file, its session (a new one at each unlock), and the item.
type Key = (PathBuf, [u8; 32], u64);

fn seen() -> &'static Mutex<HashMap<Key, Considered>> {
    static SEEN: OnceLock<Mutex<HashMap<Key, Considered>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key(vault: &Vault, item_id: u64) -> Key {
    (vault.path().to_path_buf(), vault.epoch(), item_id)
}

/// Take the entry of `key` out, so that no lock is held during the vault work. The
/// entries of an earlier session of the same vault file go away.
fn take(key: &Key) -> Option<Considered> {
    let mut seen = seen().lock().unwrap_or_else(PoisonError::into_inner);
    seen.retain(|(path, epoch, _), _| path != &key.0 || epoch == &key.1);
    seen.remove(key)
}

fn put(key: Key, considered: Considered) {
    seen()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, considered);
}

/// How many times [`consider`] revealed the value of `item_id` with the detection, and
/// read its use log, in the vault session. For tests and diagnostics; no value.
pub fn checks(vault: &Vault, item_id: u64) -> Checks {
    seen()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key(vault, item_id))
        .map_or_else(Checks::default, |considered| considered.checks)
}

fn fingerprint(
    vault: &Vault,
    item_id: u64,
    declaration: &Declaration,
    sources: DeclarationSources,
) -> Option<Fingerprint> {
    let revision = vault.details(item_id).ok()?.summary.revision;
    let field = vault
        .process_binding(item_id)
        .ok()?
        .map(|binding| binding.field);
    Some(Fingerprint {
        revision,
        declaration: declaration.clone(),
        sources,
        field,
    })
}

/// The provider of a strong production signal of the value of `field`. Reveals the
/// value; [`consider`] calls it at most once after each change of the item. `None`
/// without a variable, without a value, or without a signal.
fn live_provider(
    vault: &Vault,
    item_id: u64,
    field: Option<&str>,
    considered: &mut Considered,
) -> Option<String> {
    let value = vault.reveal(item_id, field?).ok()?;
    considered.checks.values += 1;
    let provider = live_signal(value.expose());
    considered.live = Some(provider.is_some());
    provider
}

/// The provider of a strong production signal of `value` (a prefix such as `sk_live_`).
fn live_signal(value: &str) -> Option<String> {
    detect::detect(value)
        .into_iter()
        .find(|one| {
            one.environment == Environment::Production && one.sources.environment == Source::Signal
        })
        .map(|one| one.provider.unwrap_or_default())
}

/// [`consider`] for each item of a run.
pub fn consider_items(vault: &mut Vault, items: &[u64]) {
    for item in items {
        consider(vault, *item);
    }
}

/// Propose the corrections that the use log of `item_id` supports. Returns the IDs of
/// the new corrections. The module documentation says what it skips when nothing
/// changed.
pub fn consider(vault: &mut Vault, item_id: u64) -> Vec<u64> {
    let mut proposed = Vec::new();
    let Ok(Some(declaration)) = vault.declaration(item_id) else {
        return proposed;
    };
    let Ok(sources) = vault.declaration_sources(item_id) else {
        return proposed;
    };
    let Some(now) = fingerprint(vault, item_id, &declaration, sources) else {
        return proposed;
    };
    let key = key(vault, item_id);
    let (mut considered, changed) = match take(&key) {
        Some(before) if before.fingerprint == now => (before, false),
        before => (
            Considered {
                fingerprint: now,
                live: None,
                uses_seen: 0,
                since_usage: 0,
                checks: before.map_or_else(Checks::default, |before| before.checks),
            },
            true,
        ),
    };
    considered.since_usage = considered.since_usage.saturating_add(1);
    let field = considered.fingerprint.field.clone();
    let mut raised = false;

    // The value: only after a change of the item.
    if changed
        && declaration.environment != Environment::Production
        && let Some(provider) = live_provider(vault, item_id, field.as_deref(), &mut considered)
        && let Some(outcome) = raise(vault, item_id, &declaration, sources, &provider)
    {
        raised = outcome.applied;
        proposed.push(outcome.id);
    }

    // The use log: while it is short, after a change, and every RECHECK_USES uses.
    let usage_due = changed
        || considered.uses_seen < MIN_ENVIRONMENT_USES.max(MIN_PROJECT_USES)
        || considered.since_usage >= RECHECK_USES;
    if usage_due {
        considered.since_usage = 0;
        considered.checks.uses += 1;
        let uses: Vec<ItemUse> = vault
            .item_uses(item_id, USES_READ)
            .unwrap_or_default()
            .into_iter()
            .filter(|item_use| item_use.outcome == UseOutcome::Allowed)
            .collect();
        considered.uses_seen = uses.len();
        if !raised
            && development_due(&declaration, sources, &uses)
            && let Some(hosts) = development_hosts(&uses)
        {
            // The hosts are the agent's choice: a value with a production signal wins.
            let live = match considered.live {
                Some(live) => live,
                None => live_provider(vault, item_id, field.as_deref(), &mut considered).is_some(),
            };
            if !live {
                let facts = json!({
                    "signal": "every use went to a development or test host",
                    "hosts": hosts,
                    "uses": uses.len(),
                    UNVERIFIED_FACT: true,
                    PREVIOUS_ENVIRONMENT_FACT: declaration.environment.as_str(),
                    APPLIED_FACT: false,
                });
                if let Ok(Some(id)) = vault.propose_correction(
                    item_id,
                    CorrectionKind::Environment,
                    "development",
                    &facts,
                ) {
                    proposed.push(id);
                }
            }
        }
        if let Some(id) = propose_project(vault, item_id, &declaration, &uses) {
            proposed.push(id);
        }
    }

    // A raise changed the declaration: remember the state after it, so that the next
    // run does not count it as a change of the item.
    if raised
        && let Ok(Some(after)) = vault.declaration(item_id)
        && let Ok(after_sources) = vault.declaration_sources(item_id)
        && let Some(after) = fingerprint(vault, item_id, &after, after_sources)
    {
        considered.fingerprint = after;
    }
    put(key, considered);
    proposed
}

/// A "development" correction can come: production only by default, and enough uses.
fn development_due(
    declaration: &Declaration,
    sources: DeclarationSources,
    uses: &[ItemUse],
) -> bool {
    declaration.environment == Environment::Production
        && sources.environment == DeclarationSource::Default
        && uses.len() >= MIN_ENVIRONMENT_USES
}

/// The "project" correction (see the module documentation).
fn propose_project(
    vault: &mut Vault,
    item_id: u64,
    declaration: &Declaration,
    uses: &[ItemUse],
) -> Option<u64> {
    if !declaration.project.trim().is_empty() || uses.len() < MIN_PROJECT_USES {
        return None;
    }
    let keys: BTreeSet<&str> = uses.iter().map(|u| u.project_key.as_str()).collect();
    let label = uses[0].project_label.clone();
    if keys.len() != 1 || keys.contains("") || label.is_empty() {
        return None;
    }
    let agents: BTreeSet<&str> = uses.iter().map(|u| u.agent_name.as_str()).collect();
    let facts = json!({
        "project_key": uses[0].project_key,
        "project_label": label,
        "uses": uses.len(),
        "agents": agents,
    });
    vault
        .propose_correction(item_id, CorrectionKind::Project, &label, &facts)
        .ok()
        .flatten()
}

/// The development hosts of the uses, when every use went to at least one development
/// host and to no other host than development hosts and hosts of this computer.
fn development_hosts(uses: &[ItemUse]) -> Option<Vec<String>> {
    let mut hosts = BTreeSet::new();
    for item_use in uses {
        let mut development = false;
        for host in &item_use.hosts {
            match host_kind(host) {
                HostKind::Development => {
                    development = true;
                    hosts.insert(host.clone());
                }
                HostKind::Local => {}
                HostKind::Other => return None,
            }
        }
        if !development {
            return None;
        }
    }
    Some(hosts.into_iter().collect())
}

/// A new "production" correction.
struct Raised {
    id: u64,
    /// The declaration is production now, until the owner answers.
    applied: bool,
}

/// An item that is not declared production and whose value has a strong production
/// signal (a provider prefix such as `sk_live_`) gets the correction "production".
/// When the owner did not set the environment, it becomes production at once with the
/// source `usage` (ADR 0025 §5: the more careful value until the owner answers). When
/// the owner set it, nothing changes before the owner answers. Returns the new
/// correction. Nothing happens when the correction was made before, also when the owner
/// ignored it.
pub fn raise_for_value(vault: &mut Vault, item_id: u64, value: &str) -> Option<u64> {
    let declaration = vault.declaration(item_id).ok().flatten()?;
    if declaration.environment == Environment::Production {
        return None;
    }
    let sources = vault.declaration_sources(item_id).ok()?;
    let provider = live_signal(value)?;
    raise(vault, item_id, &declaration, sources, &provider).map(|raised| raised.id)
}

fn raise(
    vault: &mut Vault,
    item_id: u64,
    declaration: &Declaration,
    sources: DeclarationSources,
    provider: &str,
) -> Option<Raised> {
    if declaration.environment == Environment::Production {
        return None;
    }
    // The owner decided the environment: propose, and wait for the owner.
    let apply = sources.environment != DeclarationSource::Owner;
    let previous = declaration.environment.as_str();
    let mut facts = json!({
        "signal": "the value has a production prefix of its provider",
        "provider": provider,
        "previous_source": sources.environment.as_str(),
        PREVIOUS_ENVIRONMENT_FACT: previous,
        APPLIED_FACT: apply,
    });
    if apply {
        facts[RAISED_FROM_FACT] = json!(previous);
    }
    let id = vault
        .propose_correction(item_id, CorrectionKind::Environment, "production", &facts)
        .ok()
        .flatten()?;
    let mut applied = false;
    if apply
        && vault
            .set_declaration_environment(item_id, Environment::Production)
            .is_ok()
        && let Ok(mut sources) = vault.declaration_sources(item_id)
    {
        sources.environment = DeclarationSource::Usage;
        applied = vault.set_declaration_sources(item_id, &sources).is_ok();
    }
    Some(Raised { id, applied })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_say_development_local_or_nothing() {
        for host in [
            "api.sandbox.paypal.com",
            "sandbox-api.example.org",
            "dev.example.com",
            "api-test.example.com",
            "service.test",
            "api.sbx.example.com:8443",
        ] {
            assert_eq!(host_kind(host), HostKind::Development, "{host}");
        }
        for host in [
            "localhost",
            "localhost:5432",
            "127.0.0.1",
            "[::1]:8080",
            "db.local",
        ] {
            assert_eq!(host_kind(host), HostKind::Local, "{host}");
        }
        for host in [
            "api.stripe.com",
            "contest.example.com",
            "devops.example.com",
            "latest.io",
        ] {
            assert_eq!(host_kind(host), HostKind::Other, "{host}");
        }
    }
}
