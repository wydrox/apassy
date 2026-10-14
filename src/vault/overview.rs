//! What the Agents page of the Mac shows about the agents of this vault (ADR 0025 §1,
//! §3f; ADR 0026 §2), computed once for both readers: the Agents page
//! (`desktop::owner_store::decisions`) and the feed of the agents that this Mac publishes
//! through the relay (`questions::feed`, contract relay-feed-v1). Both call the functions
//! here, so the iPhone shows the figures that the Mac shows.
//!
//! Nothing here returns a secret value. [`Vault::mask_item_text`] masks the current
//! secret values of an item in a text, as the use log masks a command when it stores it.

use std::collections::BTreeMap;

use super::exceptions::AgentException;
use super::types::{VaultErrorKind, VaultResult, err};
use super::usage::{ItemUse, UseOutcome};
use super::{Vault, to_public_id, to_sql_id};
use crate::broker::action_kind::ActionKind;

pub const DAY: u64 = 86_400;
pub const WEEK: u64 = 7 * DAY;
/// How many uses of one agent the overview reads, newest first.
pub const AGENT_USES: usize = 2_000;

/// The line under the Decisions title (ADR 0025 §1, ADR 0026 §2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WeekCounts {
    /// Owner interactions in the last 7 days: questions, approvals, owner checks, and
    /// corrections.
    pub by_you: u64,
    /// Decisions of the last 7 days that did not wait for the owner.
    pub automatic: u64,
}

impl WeekCounts {
    /// "3 by you · 128 automatic this week".
    pub fn line(&self) -> String {
        format!(
            "{} by you · {} automatic this week",
            self.by_you, self.automatic
        )
    }
}

/// One kind of action that an agent used in the last 7 days (ADR 0025 §3a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionUse {
    pub action: ActionKind,
    /// The uses that were allowed.
    pub allowed: usize,
    /// The uses that were denied, refused, or not answered in time.
    pub not_allowed: usize,
    /// The projects of its uses, the most used first.
    pub projects: Vec<String>,
}

/// The overview of one agent, without the names of its credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFacts {
    pub uses_this_week: usize,
    /// The kinds of action of its uses this week, the most used first.
    pub actions: Vec<ActionUse>,
    /// The project labels of its uses, the most used first.
    pub projects: Vec<String>,
    /// The sentence of the owner for the bouncer. Empty when there is none.
    pub note: String,
    /// The agent sees only the listed credentials ("only these items").
    pub restricted: bool,
    /// The exceptions of the agent, without the marker of a restriction, by item.
    pub exceptions: Vec<AgentException>,
    /// The newest uses (at most [`AGENT_USES`]), newest first.
    pub uses: Vec<ItemUse>,
}

impl AgentFacts {
    /// The time of the newest use, if any.
    pub fn last_use_at(&self) -> Option<u64> {
        self.uses.iter().map(|item_use| item_use.at).max()
    }
}

/// An item as another device of the vault names it: its sync UUID and its title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub uuid: String,
    pub title: String,
}

/// The projects of `labels`, the most frequent first, then by name.
pub fn projects_by_use<'a>(labels: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for label in labels.filter(|label| !label.is_empty()) {
        *counts.entry(label).or_default() += 1;
    }
    let mut projects: Vec<(&str, usize)> = counts.into_iter().collect();
    projects.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    projects
        .into_iter()
        .map(|(label, _)| label.to_owned())
        .collect()
}

/// The danger of a kind of action, for the order of equal counts: the more dangerous
/// first.
fn danger(action: ActionKind) -> u8 {
    match action {
        ActionKind::Read => 0,
        ActionKind::Change => 1,
        ActionKind::Deploy => 2,
        ActionKind::Delete => 3,
    }
}

/// The kinds of action of `uses` at or after `since`: the most allowed uses first, then
/// the most uses that were not allowed, then the more dangerous kind.
pub fn actions_by_use(uses: &[ItemUse], since: u64) -> Vec<ActionUse> {
    let mut by_kind: Vec<(ActionKind, usize, usize, Vec<&str>)> = Vec::new();
    for item_use in uses.iter().filter(|item_use| item_use.at >= since) {
        let index = match by_kind
            .iter()
            .position(|(action, ..)| *action == item_use.action)
        {
            Some(index) => index,
            None => {
                by_kind.push((item_use.action, 0, 0, Vec::new()));
                by_kind.len() - 1
            }
        };
        let entry = &mut by_kind[index];
        if item_use.outcome == UseOutcome::Allowed {
            entry.1 += 1;
        } else {
            entry.2 += 1;
        }
        entry.3.push(item_use.project_label.as_str());
    }
    let mut actions: Vec<ActionUse> = by_kind
        .into_iter()
        .map(|(action, allowed, not_allowed, labels)| ActionUse {
            action,
            allowed,
            not_allowed,
            projects: projects_by_use(labels.into_iter()),
        })
        .collect();
    actions.sort_by(|a, b| {
        b.allowed
            .cmp(&a.allowed)
            .then(b.not_allowed.cmp(&a.not_allowed))
            .then(danger(b.action).cmp(&danger(a.action)))
    });
    actions
}

/// An item UUID in the native form of the vault (`item.uuid`, `merge.rs`): 32
/// lowercase hexadecimal characters, no hyphens. The feed and the action string carry
/// it as it is (relay-feed-v1, decision of 2026-10-14 over the 36-character form of
/// section 4).
pub fn valid_item_uuid(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Vault {
    /// The owner interactions and the automatic decisions of the 7 days before `now`.
    pub fn week_counts(&self, now: u64) -> VaultResult<WeekCounts> {
        let by_you = self
            .interactions_per_week(1)?
            .last()
            .map_or(0, |(_, count)| *count);
        let since = (now / DAY).saturating_sub(6) * DAY;
        let automatic = self
            .ask_rate_by_day(since)?
            .iter()
            .map(|day| u64::from(day.decisions.saturating_sub(day.asked)))
            .sum();
        Ok(WeekCounts { by_you, automatic })
    }

    /// The uses, the kinds of action, the projects, the note, and the exceptions of one
    /// agent, for the week before `now`. `NotFound`: no such agent.
    pub fn agent_facts(&self, agent_id: u64, now: u64) -> VaultResult<AgentFacts> {
        let since = now.saturating_sub(WEEK);
        let uses = self.agent_uses(agent_id, AGENT_USES)?;
        let note = self.agent_note(agent_id)?;
        let view = self.agent_view(agent_id)?;
        let exceptions = self.agent_exceptions(agent_id)?;
        Ok(AgentFacts {
            uses_this_week: uses.iter().filter(|item_use| item_use.at >= since).count(),
            actions: actions_by_use(&uses, since),
            projects: projects_by_use(uses.iter().map(|item_use| item_use.project_label.as_str())),
            note,
            restricted: view.restricted,
            exceptions,
            uses,
        })
    }

    /// Each item with its sync UUID ([`Vault::item_uuids`], the native form of
    /// [`valid_item_uuid`]) and its title, by item ID. An item whose UUID has another
    /// form is left out.
    pub fn item_refs(&self) -> VaultResult<BTreeMap<u64, ItemRef>> {
        let uuids = self.item_uuids()?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare("SELECT id, title FROM item")
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut refs = BTreeMap::new();
        for row in rows {
            let (id, title) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            let id = to_public_id(id)?;
            if let Some(uuid) = uuids.get(&id).filter(|uuid| valid_item_uuid(uuid)) {
                refs.insert(
                    id,
                    ItemRef {
                        uuid: uuid.clone(),
                        title,
                    },
                );
            }
        }
        Ok(refs)
    }

    /// The sync UUID of item `item_id` ([`valid_item_uuid`]), or `None` when there is no
    /// such item.
    pub fn item_uuid(&self, item_id: u64) -> VaultResult<Option<String>> {
        use rusqlite::OptionalExtension;
        let stored: Option<Option<String>> = self
            .conn_ref()?
            .query_row(
                "SELECT uuid FROM item WHERE id = ?1",
                [to_sql_id(item_id)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(stored.flatten().filter(|uuid| valid_item_uuid(uuid)))
    }

    /// The ID of the item whose sync UUID is exactly `uuid` ([`valid_item_uuid`]), or
    /// `None`.
    pub fn item_by_uuid(&self, uuid: &str) -> VaultResult<Option<u64>> {
        use rusqlite::OptionalExtension;
        if !valid_item_uuid(uuid) {
            return Ok(None);
        }
        let id: Option<i64> = self
            .conn_ref()?
            .query_row("SELECT id FROM item WHERE uuid = ?1", [uuid], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        id.map(to_public_id).transpose()
    }

    /// `text` with each current secret value of item `item_id` replaced by the mask, as
    /// the use log masks a command summary when it stores it (`record_item_use`).
    pub fn mask_item_text(&self, item_id: u64, text: &str) -> VaultResult<String> {
        let values = self.secret_values(&[item_id])?;
        Ok(super::learning::mask_values(text, &values))
    }

    /// The number of rows that this unlocked connection changed since it opened. It
    /// grows with every write, so a reader that keeps it knows when to look again.
    pub fn change_count(&self) -> VaultResult<u64> {
        Ok(self.conn_ref()?.total_changes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::usage::UseDecidedBy;

    #[test]
    fn the_week_line_and_the_projects_by_use() {
        assert_eq!(
            WeekCounts {
                by_you: 7,
                automatic: 128
            }
            .line(),
            "7 by you · 128 automatic this week"
        );
        assert_eq!(
            projects_by_use(["apassy", "", "acme", "apassy", "zeta", "acme", "apassy"].into_iter()),
            ["apassy", "acme", "zeta"]
        );
    }

    fn item_use(at: u64, action: ActionKind, project: &str, outcome: UseOutcome) -> ItemUse {
        ItemUse {
            id: at,
            at,
            item_id: 1,
            agent_id: Some(1),
            agent_name: "Claude Code".to_owned(),
            project_key: format!("/code/{project}"),
            project_label: project.to_owned(),
            action,
            command_summary: String::new(),
            hosts: Vec::new(),
            outcome,
            decided_by: UseDecidedBy::Bouncer,
            answered_on: String::new(),
            decision_log_id: None,
        }
    }

    #[test]
    fn the_actions_count_allowed_uses_apart_and_put_the_most_used_first() {
        use ActionKind::{Change, Delete, Deploy, Read};
        let uses = [
            item_use(100, Deploy, "acme-billing", UseOutcome::Allowed),
            item_use(101, Read, "apassy", UseOutcome::Allowed),
            item_use(102, Deploy, "apassy", UseOutcome::Allowed),
            item_use(103, Deploy, "acme-billing", UseOutcome::Allowed),
            item_use(104, Delete, "apassy", UseOutcome::Denied),
            item_use(105, Change, "", UseOutcome::TimedOut),
            item_use(106, Delete, "apassy", UseOutcome::Refused),
            item_use(107, Read, "apassy", UseOutcome::Allowed),
            item_use(108, Deploy, "zeta", UseOutcome::TimedOut),
            // Older than the week: left out.
            item_use(10, Change, "old", UseOutcome::Allowed),
        ];
        let actions = actions_by_use(&uses, 50);
        assert_eq!(
            actions,
            [
                ActionUse {
                    action: Deploy,
                    allowed: 3,
                    not_allowed: 1,
                    projects: vec![
                        "acme-billing".to_owned(),
                        "apassy".to_owned(),
                        "zeta".to_owned()
                    ],
                },
                ActionUse {
                    action: Read,
                    allowed: 2,
                    not_allowed: 0,
                    projects: vec!["apassy".to_owned()],
                },
                ActionUse {
                    action: Delete,
                    allowed: 0,
                    not_allowed: 2,
                    projects: vec!["apassy".to_owned()],
                },
                ActionUse {
                    action: Change,
                    allowed: 0,
                    not_allowed: 1,
                    projects: Vec::new(),
                },
            ]
        );
        assert!(actions_by_use(&uses, 1_000).is_empty());
    }

    #[test]
    fn equal_counts_put_the_more_dangerous_action_first() {
        use ActionKind::{Change, Delete, Read};
        let uses = [
            item_use(1, Read, "a", UseOutcome::Allowed),
            item_use(2, Delete, "a", UseOutcome::Allowed),
            item_use(3, Change, "a", UseOutcome::Allowed),
        ];
        let order: Vec<ActionKind> = actions_by_use(&uses, 0)
            .into_iter()
            .map(|action| action.action)
            .collect();
        assert_eq!(order, [Delete, Change, Read]);
    }

    #[test]
    fn an_item_uuid_has_the_native_form() {
        assert!(valid_item_uuid("3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c"));
        for bad in [
            "",
            "3C9E1F7A2B4D4C6E8F0A1B3D5E7F9A2C",
            "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2",
            "3c9e1f7a-2b4d-4c6e-8f0a-1b3d5e7f9a2c",
        ] {
            assert!(!valid_item_uuid(bad), "{bad}");
        }
    }

    #[test]
    fn items_are_found_by_their_uuid_and_masked_with_their_values() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault =
            Vault::create(&dir.path().join("overview.db"), "overview-unit-pass").expect("create");
        vault.unlock("overview-unit-pass").expect("unlock");
        let item = vault
            .add(crate::vault::ItemDraft {
                title: "Shop database".to_owned(),
                kind: crate::contracts::CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![crate::vault::Field {
                    name: "token".to_owned(),
                    value: crate::vault::SecretValue::new("SYNTH-overview-secret".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        let uuid = vault.item_uuid(item).unwrap().expect("a uuid");
        assert_eq!(uuid.len(), 32);
        assert_eq!(vault.item_uuids().unwrap()[&item], uuid);
        assert_eq!(vault.item_by_uuid(&uuid).unwrap(), Some(item));
        let dashed = format!(
            "{}-{}-{}-{}-{}",
            &uuid[..8],
            &uuid[8..12],
            &uuid[12..16],
            &uuid[16..20],
            &uuid[20..]
        );
        assert_eq!(vault.item_by_uuid(&dashed).unwrap(), None);
        assert_eq!(vault.item_refs().unwrap()[&item].uuid, uuid);
        assert_eq!(
            vault
                .mask_item_text(item, "deploy --token SYNTH-overview-secret")
                .unwrap(),
            "deploy --token [apassy:secret]"
        );
        let before = vault.change_count().unwrap();
        let agent = vault.register_agent("x").unwrap().0.id;
        vault.set_agent_note(agent, "n").unwrap();
        assert!(vault.change_count().unwrap() > before);
    }

    /// relay-feed-v1 section 7.2: the feed masks every command with the values of every
    /// item of the vault, also those of an item whose UUID has another form (it has no
    /// reference in the feed), and also in the rows of such an item.
    #[cfg(feature = "vault")]
    #[test]
    fn the_feed_masks_the_values_of_an_item_without_a_native_uuid() {
        use crate::vault::usage::{NewItemUse, UseDecidedBy};
        const SHOP: &str = "SYNTH-shop-value-1234";
        const ODD: &str = "SYNTH-odd-uuid-value-5678";
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault =
            Vault::create(&dir.path().join("feed.db"), "overview-unit-pass").expect("create");
        vault.unlock("overview-unit-pass").expect("unlock");
        let item = |vault: &mut Vault, title: &str, value: &str| {
            vault
                .add(crate::vault::ItemDraft {
                    title: title.to_owned(),
                    kind: crate::contracts::CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![crate::vault::Field {
                        name: "token".to_owned(),
                        value: crate::vault::SecretValue::new(value.to_owned()),
                        secret: true,
                    }],
                })
                .unwrap()
                .id
        };
        let shop = item(&mut vault, "Shop database", SHOP);
        let odd = item(&mut vault, "Odd item", ODD);
        // An item merged from a copy with an upper-case UUID: not the native form.
        vault
            .conn_mut()
            .unwrap()
            .execute(
                "UPDATE item SET uuid = upper(uuid) WHERE id = ?1",
                [to_sql_id(odd).unwrap()],
            )
            .unwrap();
        assert!(!vault.item_refs().unwrap().contains_key(&odd));
        let agent = vault.register_agent("Claude Code").unwrap().0.id;
        // Each row is masked with the values of its own item when it is written: the value
        // of the other item stays in it.
        for (item_id, command) in [
            (shop, format!("deploy --other {ODD}")),
            (odd, format!("deploy --other {SHOP}")),
        ] {
            vault
                .record_item_use(&NewItemUse {
                    item_id,
                    agent_id: Some(agent),
                    agent_name: "Claude Code".to_owned(),
                    project_key: String::new(),
                    project_label: String::new(),
                    action: ActionKind::Deploy,
                    command_summary: command,
                    hosts: Vec::new(),
                    outcome: UseOutcome::Allowed,
                    decided_by: UseDecidedBy::Bouncer,
                    answered_on: String::new(),
                    decision_log_id: None,
                })
                .unwrap();
        }
        let me = crate::vault::TrustedDevice {
            uuid: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d".to_owned(),
            name: "Synthetic Mac".to_owned(),
            kind: crate::vault::TrustedDeviceKind::Mac,
            relay_devices: std::collections::BTreeMap::new(),
            sign_key: vec![4; 65],
            answer_key: None,
            created_at: 0,
            updated_at: 0,
            updated_by: String::new(),
        };
        let feed =
            crate::questions::feed::build_feed(&vault, &me, 1, super::super::agents::now_unix())
                .unwrap();
        let recent = &feed.agents[0].recent;
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].item, None, "the odd item has no reference");
        assert_eq!(recent[0].command, "deploy --other [apassy:secret]");
        assert!(recent[1].item.is_some());
        assert_eq!(recent[1].command, "deploy --other [apassy:secret]");
        let plaintext = String::from_utf8(feed.to_plaintext().to_vec()).unwrap();
        assert!(
            !plaintext.contains(SHOP) && !plaintext.contains(ODD),
            "{plaintext}"
        );
    }
}
