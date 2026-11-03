//! The catalog mirror of the node (ADR 0037, cloud slice, decision 2).
//!
//! The node holds one item of metadata for each vault item that a cloud agent may see
//! and that is eligible; never a value. An item is eligible when:
//!
//! - it is not archived and needs no review after a restore;
//! - its process binding is in placeholder mode (ADR 0011) with hosts, none of them a
//!   public suffix, and its variable is one that the node takes;
//! - its value passes the value rules of the node (`RunningNode::check_value`), so a
//!   release of it cannot fail on its form. The value is read for this check only, and
//!   only when the item revision is new to this mirror.
//!
//! [`build`] makes the list and the item list of each cloud agent from the vault; the
//! node then makes its live items exactly that list (`RunningNode::sync_items`: the
//! others are archived, which ends their runs and sessions). A second build of the same
//! vault gives the same list, so a second sync changes nothing.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::backend::{CatalogItem, NodeAgentId, NodeError, NodeSecret, RunningNode};
use crate::vault::{EnvDelivery, Vault, checked_env_name, providers};

/// The longest item name of the node, in bytes.
const MAX_NAME_BYTES: usize = 64;
/// Variables that the relay sets itself (`server::env::RESERVED_NAMES` of the relay).
const RELAY_RESERVED_NAMES: [&str; 4] = [
    "STRIPE_API_BASE",
    "OPENAI_BASE_URL",
    "ANTHROPIC_BASE_URL",
    "GITHUB_API_URL",
];
/// The environment of an item without a declaration: the most careful one.
const DEFAULT_ENVIRONMENT: &str = "production";

/// The mirror of one build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mirror {
    /// The live items of the node, by vault item id.
    pub items: Vec<CatalogItem>,
    /// The vault item of each uid of `items`.
    pub by_uid: BTreeMap<String, u64>,
    /// The item list of each cloud agent (the node's agent id), in item order.
    pub agents: Vec<(NodeAgentId, Vec<String>)>,
    /// Items that a cloud agent sees but that are not eligible, with the reason.
    pub skipped: Vec<(u64, &'static str)>,
}

/// The item revisions whose value passed the node's rules, so that a later build does
/// not read the value again.
#[derive(Debug, Default)]
pub struct Checked {
    revisions: HashMap<u64, u64>,
}

fn storage(_: crate::vault::VaultError) -> NodeError {
    NodeError::new("vault_error", "The vault cannot be read for the cloud catalog.")
}

/// The name of an item for the node: no control character, at most 64 bytes.
fn node_name(title: &str, item_id: u64) -> String {
    let clean: String = title
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    let mut end = clean.len().min(MAX_NAME_BYTES);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    let name = clean[..end].trim_end();
    if name.is_empty() {
        format!("Item {item_id}")
    } else {
        name.to_owned()
    }
}

/// A host of the vault that the node would refuse even as a broad host: a public
/// suffix, such as `co.uk` or `github.io`.
fn public_suffix(rule: &str) -> bool {
    let host = rule.rsplit_once(':').map_or(rule, |(host, _)| host);
    let bytes = host.as_bytes();
    psl::suffix(bytes).is_some_and(|suffix| suffix.as_bytes() == bytes)
}

/// The catalog item of `item_id` without its uid, or why it is not eligible.
fn eligible(
    vault: &Vault,
    node: &dyn RunningNode,
    checked: &mut Checked,
    item_id: u64,
) -> Result<Result<CatalogItem, &'static str>, NodeError> {
    if vault.is_archived(item_id).map_err(storage)? {
        return Ok(Err("archived"));
    }
    if vault.needs_review(item_id).map_err(storage)? {
        return Ok(Err("waits for the review after a restore"));
    }
    let Some(binding) = vault.process_binding(item_id).map_err(storage)? else {
        return Ok(Err("no process field"));
    };
    let EnvDelivery::Placeholder(hosts) = &binding.delivery else {
        return Ok(Err("not in placeholder mode"));
    };
    if hosts.is_empty() {
        return Ok(Err("no placeholder host"));
    }
    if hosts.iter().any(|host| public_suffix(host)) {
        return Ok(Err("a placeholder host is a public suffix"));
    }
    if checked_env_name(&binding.env_name).is_err()
        || RELAY_RESERVED_NAMES.contains(&binding.env_name.as_str())
    {
        return Ok(Err("a variable name that the node does not take"));
    }
    let details = vault.details(item_id).map_err(storage)?;
    let revision = details.summary.revision;
    if checked.revisions.get(&item_id) != Some(&revision) {
        let Ok(value) = vault.reveal(item_id, &binding.field) else {
            return Ok(Err("no value"));
        };
        let mut text = value.into_zeroizing();
        let secret = NodeSecret::new(std::mem::take(&mut *text));
        if node.check_value(&secret).is_err() {
            return Ok(Err("the value breaks the rules of the node"));
        }
        checked.revisions.insert(item_id, revision);
    }
    let declaration = vault.declaration(item_id).map_err(storage)?;
    let provider = vault
        .declaration_provider(item_id)
        .map_err(storage)?
        .filter(|id| providers::find(id).is_some());
    Ok(Ok(CatalogItem {
        uid: String::new(),
        name: node_name(&details.summary.title, item_id),
        env_name: binding.env_name.clone(),
        hosts: hosts.clone(),
        provider,
        environment: declaration.as_ref().map_or_else(
            || DEFAULT_ENVIRONMENT.to_owned(),
            |declaration| declaration.environment.as_str().to_owned(),
        ),
        risk: declaration
            .as_ref()
            .map(|declaration| declaration.risk.as_str().to_owned()),
        scope: declaration
            .as_ref()
            .map(|declaration| declaration.scope.as_str().to_owned()),
        reversibility: declaration
            .as_ref()
            .map(|declaration| declaration.reversibility.as_str().to_owned()),
        // The owner chose each host in the vault, and public suffixes are left out above.
        allow_broad_host: true,
    }))
}

/// The mirror of the vault: the eligible items that an active cloud agent sees, and
/// `extra` (the items of an agent that is about to be made), with their uids, and the
/// item list of each cloud agent. Items in id order; of two items with one variable,
/// the first stays.
pub fn build(
    vault: &mut Vault,
    node: &dyn RunningNode,
    checked: &mut Checked,
    extra: &[u64],
) -> Result<Mirror, NodeError> {
    let agents = vault.cloud_agents().map_err(storage)?;
    let mut wanted: BTreeSet<u64> = extra.iter().copied().collect();
    for agent in &agents {
        wanted.extend(agent.items.iter().copied());
    }
    let mut mirror = Mirror::default();
    let mut ids = Vec::new();
    let mut names = BTreeSet::new();
    for item_id in wanted {
        match eligible(vault, node, checked, item_id)? {
            Ok(item) if names.insert(item.env_name.clone()) => {
                ids.push(item_id);
                mirror.items.push(item);
            }
            Ok(_) => mirror.skipped.push((item_id, "another item has its variable")),
            Err(why) => mirror.skipped.push((item_id, why)),
        }
    }
    let uids = vault.cloud_item_uids(&ids).map_err(storage)?;
    let mut uid_of = BTreeMap::new();
    for ((item, uid), item_id) in mirror.items.iter_mut().zip(uids).zip(&ids) {
        item.uid.clone_from(&uid);
        uid_of.insert(*item_id, uid.clone());
        mirror.by_uid.insert(uid, *item_id);
    }
    for agent in &agents {
        let list = agent
            .items
            .iter()
            .filter_map(|item| uid_of.get(item).cloned())
            .collect();
        mirror
            .agents
            .push((NodeAgentId(agent.relay_agent_id), list));
    }
    Ok(mirror)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{FakeBackend, synthetic_vault};
    use super::*;
    use crate::node::backend::{NodeBackend, NodeConfig};

    #[test]
    fn the_mirror_is_idempotent_and_archives_what_no_cloud_agent_sees() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, items) = synthetic_vault(&dir);
        let backend = FakeBackend::default();
        let node = backend
            .start(NodeConfig {
                data_dir: dir.path().join("node"),
                master_key: NodeSecret::new("synthetic master key 0123456789".to_owned()),
                public_url: "https://mac.example-tailnet.ts.net:8443".to_owned(),
                public_listen: None,
            })
            .unwrap();
        let team = node.create_team("Personal").unwrap();
        let mut checked = Checked::default();

        // An agent that sees the two placeholder items and the value-mode item.
        let agent = vault
            .add_cloud_agent("Grok Bot", &[items.stripe, items.httpbin, items.plain], 5, 4_000_000_000)
            .unwrap();
        let first = build(&mut vault, node.as_ref(), &mut checked, &[]).unwrap();
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.skipped, [(items.plain, "not in placeholder mode")]);
        assert_eq!(first.items[0].env_name, "SYNTH_STRIPE_KEY");
        assert_eq!(first.items[0].hosts, ["api.stripe.com"]);
        assert_eq!(first.items[0].environment, "production", "no declaration");
        assert_eq!(first.agents.len(), 1);
        assert_eq!(first.agents[0].0, NodeAgentId(5));
        assert_eq!(first.agents[0].1.len(), 2);
        assert!(first.items.iter().all(|item| item.uid.len() == 32));
        assert!(!format!("{first:?}").contains("SYNTH-"), "no value in the mirror");
        let report = node.sync_items(&team, &first.items).unwrap();
        assert_eq!((report.added, report.unchanged), (2, 0));

        // The same vault again: the same mirror, and the sync changes nothing.
        let second = build(&mut vault, node.as_ref(), &mut checked, &[]).unwrap();
        assert_eq!(second, first);
        let report = node.sync_items(&team, &second.items).unwrap();
        assert_eq!((report.added, report.changed, report.archived), (0, 0, 0));
        assert_eq!(report.unchanged, 2);

        // "Not for this agent" takes one item away: it is archived in the node.
        vault
            .add_agent_exception(
                agent,
                items.httpbin,
                crate::vault::exceptions::ExceptionKind::Never,
            )
            .unwrap();
        let third = build(&mut vault, node.as_ref(), &mut checked, &[]).unwrap();
        assert_eq!(third.items.len(), 1);
        assert_eq!(third.items[0].uid, first.items[0].uid, "the uid stays");
        let report = node.sync_items(&team, &third.items).unwrap();
        assert_eq!((report.archived, report.unchanged), (1, 1));

        // A revoked agent sees nothing: everything is archived.
        vault.revoke_agent(agent).unwrap();
        let empty = build(&mut vault, node.as_ref(), &mut checked, &[]).unwrap();
        assert!(empty.items.is_empty() && empty.agents.is_empty());
        assert_eq!(node.sync_items(&team, &empty.items).unwrap().archived, 1);

        // An item of an agent about to be made is in the mirror.
        let extra = build(&mut vault, node.as_ref(), &mut checked, &[items.httpbin]).unwrap();
        assert_eq!(extra.items.len(), 1);
        assert_eq!(extra.by_uid.get(&extra.items[0].uid), Some(&items.httpbin));
        node.stop();
    }

    #[test]
    fn names_are_cut_and_public_suffixes_are_refused() {
        assert_eq!(node_name("  Stripe\nlive key ", 3), "Stripe live key");
        assert_eq!(node_name("\u{7}", 3), "Item 3");
        let long = "é".repeat(40);
        assert!(node_name(&long, 1).len() <= MAX_NAME_BYTES);
        assert!(public_suffix("co.uk"));
        assert!(public_suffix("github.io:8443"));
        assert!(!public_suffix("api.stripe.com"));
        assert!(!public_suffix("httpbin.org"));
    }
}
