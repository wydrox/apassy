//! Answers of the owner, remembered for an item, a project, and a kind of action
//! (ADR 0025 §3, §3b, §3c). The table `owner_answer` is in schema 18 (`schema18.rs`).
//!
//! An answer covers every agent in the project; an exception of one agent
//! (`exceptions.rs`) is stronger. A `project` answer lets later uses of the item in the
//! project with the same kind of action start without a question. A `production`
//! answer is the only thing that lets a production item start without the owner
//! (ADR 0010, ADR 0025 §3b).
//!
//! Both writers are `pub(crate)`: only the broker calls them, after an owner answer to a
//! waiting question that passed an owner check (`OwnerAction::ApproveInProject`,
//! `OwnerAction::AllowProduction`). The bouncer, a remembered pattern, and the usage log
//! never write an answer. Removing an answer is stricter and needs no owner check.
//! A restore from a backup removes every answer (`forget_all`).

use rusqlite::{OptionalExtension, TransactionBehavior};

use super::agents::{from_sql_time, now_unix, require_item, to_sql_time};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};
use crate::broker::action_kind::ActionKind;

/// The longest project key (a canonical path), in bytes.
pub const MAX_PROJECT_KEY_BYTES: usize = 4096;
/// The longest project label, in bytes.
pub const MAX_PROJECT_LABEL_BYTES: usize = 256;
/// The longest name of the device that answered, in bytes.
pub const MAX_ANSWERED_ON_BYTES: usize = 64;

/// A project as the vault stores it: the key of `broker::project::Project` and its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRef {
    pub key: String,
    pub label: String,
}

/// What an answer covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerScope {
    /// A use of a non-production item.
    Project,
    /// A use of a production item (ADR 0025 §3b).
    Production,
}

impl AnswerScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Production => "production",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "project" => Ok(Self::Project),
            "production" => Ok(Self::Production),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// One remembered answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAnswer {
    pub id: u64,
    pub item_id: u64,
    pub project: ProjectRef,
    pub action: ActionKind,
    pub scope: AnswerScope,
    pub created_at: u64,
    /// The device where the owner answered, for example "this Mac".
    pub answered_on: String,
}

/// Plain text without control characters, at most `max` bytes. `InvalidInput` when it
/// is empty.
fn checked(text: &str, max: usize) -> VaultResult<String> {
    let text = text.trim();
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    Ok(text.to_owned())
}

/// Remove every answer. A restore calls it: restored answers would give access without
/// the owner (ADR 0025, goal item V4).
pub(super) fn forget_all(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute("DELETE FROM owner_answer", [])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

impl Vault {
    /// Remember a `project` answer for `item_id`, `project`, and `action`. The same
    /// answer again keeps its row and returns its ID. Only the broker calls it, after
    /// an owner check (`OwnerAction::ApproveInProject`). `NotFound`: no such item.
    pub(crate) fn remember_answer(
        &mut self,
        item_id: u64,
        project: &ProjectRef,
        action: ActionKind,
        answered_on: &str,
    ) -> VaultResult<u64> {
        self.store_answer(item_id, project, action, AnswerScope::Project, answered_on)
    }

    /// Allow production for `item_id`, `project`, and `action`. Only the broker calls
    /// it, after an owner check (`OwnerAction::AllowProduction`). `NotFound`: no such
    /// item.
    pub(crate) fn allow_production(
        &mut self,
        item_id: u64,
        project: &ProjectRef,
        action: ActionKind,
        answered_on: &str,
    ) -> VaultResult<u64> {
        self.store_answer(
            item_id,
            project,
            action,
            AnswerScope::Production,
            answered_on,
        )
    }

    fn store_answer(
        &mut self,
        item_id: u64,
        project: &ProjectRef,
        action: ActionKind,
        scope: AnswerScope,
        answered_on: &str,
    ) -> VaultResult<u64> {
        let item = to_sql_id(item_id)?;
        let key = checked(&project.key, MAX_PROJECT_KEY_BYTES)?;
        let label = checked(&project.label, MAX_PROJECT_LABEL_BYTES)?;
        let on = checked(answered_on, MAX_ANSWERED_ON_BYTES)?;
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        require_item(&tx, item)?;
        tx.execute(
            "INSERT INTO owner_answer
                 (item_id, project_key, project_label, action_kind, scope, created_at, answered_on)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(item_id, project_key, action_kind, scope)
             DO UPDATE SET project_label = excluded.project_label",
            (
                item,
                key.as_str(),
                label.as_str(),
                action.as_str(),
                scope.as_str(),
                at,
                on.as_str(),
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id: i64 = tx
            .query_row(
                "SELECT id FROM owner_answer
                 WHERE item_id = ?1 AND project_key = ?2 AND action_kind = ?3 AND scope = ?4",
                (item, key.as_str(), action.as_str(), scope.as_str()),
                |row| row.get(0),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        to_public_id(id)
    }

    /// The answer for exactly this item, project key, action, and scope. An answer
    /// for another kind of action does not count.
    pub fn answer_for(
        &self,
        item_id: u64,
        project_key: &str,
        action: ActionKind,
        scope: AnswerScope,
    ) -> VaultResult<Option<OwnerAnswer>> {
        let item = to_sql_id(item_id)?;
        let row = self
            .conn_ref()?
            .query_row(
                "SELECT id, item_id, project_key, project_label, action_kind, scope,
                     created_at, answered_on
                 FROM owner_answer
                 WHERE item_id = ?1 AND project_key = ?2 AND action_kind = ?3 AND scope = ?4",
                (item, project_key, action.as_str(), scope.as_str()),
                answer_row,
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        row.map(parse_answer).transpose()
    }

    /// Every answer for one item, newest first. The item screen lists them.
    pub fn answers_for_item(&self, item_id: u64) -> VaultResult<Vec<OwnerAnswer>> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, item_id, project_key, project_label, action_kind, scope,
                     created_at, answered_on
                 FROM owner_answer WHERE item_id = ?1 ORDER BY id DESC",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([item], answer_row)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut answers = Vec::new();
        for row in rows {
            answers.push(parse_answer(
                row.map_err(|_| err(VaultErrorKind::Storage))?,
            )?);
        }
        Ok(answers)
    }

    /// Remove one answer. It takes authority away and needs no owner check (ADR 0025
    /// §3b). Returns false when there was none.
    pub fn remove_answer(&mut self, id: u64) -> VaultResult<bool> {
        let id = to_sql_id(id)?;
        let removed = self
            .conn_mut()?
            .execute("DELETE FROM owner_answer WHERE id = ?1", [id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(removed > 0)
    }
}

type AnswerRow = (i64, i64, String, String, String, String, i64, String);

fn answer_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AnswerRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn parse_answer(row: AnswerRow) -> VaultResult<OwnerAnswer> {
    let (id, item, key, label, action, scope, at, on) = row;
    Ok(OwnerAnswer {
        id: to_public_id(id)?,
        item_id: to_public_id(item)?,
        project: ProjectRef { key, label },
        action: ActionKind::parse(&action).ok_or_else(|| err(VaultErrorKind::Storage))?,
        scope: AnswerScope::parse(&scope)?,
        created_at: from_sql_time(at)?,
        answered_on: on,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue};

    const PASS: &str = "synthetic-answers-pass";

    #[test]
    fn answers_are_exact_and_production_is_separate() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("answers.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault
            .add(ItemDraft {
                title: "Synthetic".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("SYNTH-answer".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        let project = ProjectRef {
            key: "/tmp/synthetic/.git".to_owned(),
            label: "synthetic".to_owned(),
        };
        let id = vault
            .remember_answer(item, &project, ActionKind::Read, "this Mac")
            .unwrap();
        assert_eq!(
            vault
                .remember_answer(item, &project, ActionKind::Read, "this Mac")
                .unwrap(),
            id,
            "the same answer keeps its row"
        );
        let found = vault
            .answer_for(item, &project.key, ActionKind::Read, AnswerScope::Project)
            .unwrap()
            .unwrap();
        assert_eq!(found.project, project);
        for (action, scope) in [
            (ActionKind::Change, AnswerScope::Project),
            (ActionKind::Read, AnswerScope::Production),
        ] {
            assert!(
                vault
                    .answer_for(item, &project.key, action, scope)
                    .unwrap()
                    .is_none()
            );
        }
        let production = vault
            .allow_production(item, &project, ActionKind::Deploy, "this Mac")
            .unwrap();
        assert_ne!(production, id);
        assert_eq!(vault.answers_for_item(item).unwrap().len(), 2);
        assert!(vault.remove_answer(production).unwrap());
        assert!(!vault.remove_answer(production).unwrap());
        assert_eq!(
            vault
                .remember_answer(999, &project, ActionKind::Read, "this Mac")
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );
        let empty = ProjectRef {
            key: String::new(),
            label: "x".to_owned(),
        };
        assert_eq!(
            vault
                .remember_answer(item, &empty, ActionKind::Read, "this Mac")
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
    }
}
