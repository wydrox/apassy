//! Corrections from the use log (ADR 0025 §5).
//!
//! After each use that the broker allowed, [`consider`] reads the use log of the item
//! and proposes a correction of its declaration when the use does not fit it:
//!
//! - **Development.** An item that is production only by default (no signal) and that
//!   was used at least [`MIN_ENVIRONMENT_USES`] times, each time with a host that looks
//!   like development or test (`sandbox`, `test`, `dev` as a word of the host, or a
//!   `.test` name), and with no other host. A host of this computer (`localhost`,
//!   `127.0.0.1`, `::1`, `*.local`) counts for nothing: a tunnel to production has the same
//!   address. Looser: it waits for the owner and changes nothing before.
//! - **Production.** An item declared local, development, or staging whose value has a
//!   strong production signal of the provider catalog (`sk_live_`, ...). Stricter: the
//!   environment becomes production at once, with the source `usage`, so the bouncer
//!   uses the more careful value until the owner answers. Ignoring the correction gives
//!   the item its environment back.
//! - **Project.** An item without a project in its declaration that was used at least
//!   [`MIN_PROJECT_USES`] times, every time in one project. Accepting names the project in
//!   the declaration; the bouncer then asks for a use in another project.
//!
//! Each correction is made once (`UNIQUE (item, kind, proposed)`): an ignored one never
//! comes again. The facts name hosts, the project, counts, and the kind of signal; never
//! a value. A failure here never stops a run.

use std::collections::BTreeSet;

use serde_json::json;

use crate::vault::agent_items::{CorrectionKind, RAISED_FROM_FACT};
use crate::vault::detect::{self, Source};
use crate::vault::usage::{ItemUse, UseOutcome};
use crate::vault::{DeclarationSource, Environment, Vault};

/// Uses that a "development" correction needs.
pub const MIN_ENVIRONMENT_USES: usize = 3;
/// Uses that a "project" correction needs.
pub const MIN_PROJECT_USES: usize = 5;
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

/// [`consider`] for each item of a run.
pub fn consider_items(vault: &mut Vault, items: &[u64]) {
    for item in items {
        consider(vault, *item);
    }
}

/// Propose the corrections that the use log of `item_id` supports. Returns the IDs of
/// the new corrections.
pub fn consider(vault: &mut Vault, item_id: u64) -> Vec<u64> {
    let mut proposed = Vec::new();
    let Ok(Some(declaration)) = vault.declaration(item_id) else {
        return proposed;
    };
    let Ok(sources) = vault.declaration_sources(item_id) else {
        return proposed;
    };
    let uses: Vec<ItemUse> = vault
        .item_uses(item_id, USES_READ)
        .unwrap_or_default()
        .into_iter()
        .filter(|item_use| item_use.outcome == UseOutcome::Allowed)
        .collect();
    if uses.is_empty() {
        return proposed;
    }
    if declaration.environment == Environment::Production
        && sources.environment == DeclarationSource::Default
        && uses.len() >= MIN_ENVIRONMENT_USES
        && let Some(hosts) = development_hosts(&uses)
    {
        let facts = json!({
            "signal": "every use went to a development or test host",
            "hosts": hosts,
            "uses": uses.len(),
        });
        if let Ok(Some(id)) =
            vault.propose_correction(item_id, CorrectionKind::Environment, "development", &facts)
        {
            proposed.push(id);
        }
    }
    if declaration.environment != Environment::Production {
        let value = vault
            .process_binding(item_id)
            .ok()
            .flatten()
            .and_then(|binding| vault.reveal(item_id, &binding.field).ok());
        if let Some(value) = value
            && let Some(id) = raise_for_value(vault, item_id, value.expose())
        {
            proposed.push(id);
        }
    }
    if declaration.project.trim().is_empty() && uses.len() >= MIN_PROJECT_USES {
        let keys: BTreeSet<&str> = uses.iter().map(|u| u.project_key.as_str()).collect();
        let label = uses[0].project_label.clone();
        if keys.len() == 1 && !keys.contains("") && !label.is_empty() {
            let agents: BTreeSet<&str> = uses.iter().map(|u| u.agent_name.as_str()).collect();
            let facts = json!({
                "project_key": uses[0].project_key,
                "project_label": label,
                "uses": uses.len(),
                "agents": agents,
            });
            if let Ok(Some(id)) =
                vault.propose_correction(item_id, CorrectionKind::Project, &label, &facts)
            {
                proposed.push(id);
            }
        }
    }
    proposed
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

/// An item that is not declared production and whose value has a strong production
/// signal (a provider prefix such as `sk_live_`) gets the correction "production", and
/// its environment becomes production at once with the source `usage` (ADR 0025 §5: the
/// more careful value until the owner answers). Returns the new correction. Nothing
/// happens when the correction was made before, also when the owner ignored it.
pub fn raise_for_value(vault: &mut Vault, item_id: u64, value: &str) -> Option<u64> {
    let declaration = vault.declaration(item_id).ok().flatten()?;
    if declaration.environment == Environment::Production {
        return None;
    }
    let found = detect::detect(value);
    let live = found.iter().find(|one| {
        one.environment == Environment::Production && one.sources.environment == Source::Signal
    })?;
    let facts = json!({
        "signal": "the value has a production prefix of its provider",
        "provider": live.provider,
        RAISED_FROM_FACT: declaration.environment.as_str(),
    });
    let id = vault
        .propose_correction(item_id, CorrectionKind::Environment, "production", &facts)
        .ok()
        .flatten()?;
    if vault
        .set_declaration_environment(item_id, Environment::Production)
        .is_ok()
        && let Ok(mut sources) = vault.declaration_sources(item_id)
    {
        sources.environment = DeclarationSource::Usage;
        let _ = vault.set_declaration_sources(item_id, &sources);
    }
    Some(id)
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
