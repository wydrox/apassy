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
//!
//! Each answer keeps the destination hosts of the runs that the owner saw (`hosts`, a
//! JSON array): the hosts of the command and the known hosts of the item then. A later
//! run with a host outside them and outside the known hosts of the item asks the owner
//! again (`broker::run`). Password-only answers add hosts only to password authority.
//! Schema 23 records code and stored-value coverage separately. A code-bearing answer
//! replaces destination history; a password-only answer clears code authority.

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
/// An answer keeps at most this many destination hosts.
pub const MAX_ANSWER_HOSTS: usize = 64;
/// The longest host name, in bytes.
const MAX_HOST_BYTES: usize = 253;

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
    /// The destination hosts that the answer covers, lowercase, sorted.
    pub hosts: Vec<String>,
    pub includes_codes: bool,
    pub includes_values: bool,
}

/// A host in the form that answers store and compare: lowercase, without a port and a
/// trailing dot. `None` for a text that is no host name.
pub fn normal_host(host: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let host = host.strip_prefix('[').map_or(host.as_str(), |rest| {
        rest.split(']').next().unwrap_or_default()
    });
    // A port goes, but an IPv6 address keeps its colons.
    let host = if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or_default()
    } else {
        host
    };
    let host = host.trim_end_matches('.');
    let valid = !host.is_empty()
        && host.len() <= MAX_HOST_BYTES
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '*'));
    valid.then(|| host.to_owned())
}

/// Each host of `hosts` in normal form, without doubles, sorted, at most
/// [`MAX_ANSWER_HOSTS`].
fn normal_hosts<'a>(hosts: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = hosts.into_iter().filter_map(|h| normal_host(h)).collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_ANSWER_HOSTS);
    out
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
        hosts: &[String],
    ) -> VaultResult<u64> {
        self.store_answer(
            item_id,
            project,
            action,
            AnswerScope::Project,
            answered_on,
            hosts,
            false,
            true,
        )
    }

    /// Allow production for `item_id`, `project`, and `action`. In the app only the
    /// broker calls it, after an owner check (`OwnerAction::AllowProduction`); the
    /// screenshot seed (examples/screenshots.rs) calls it for its synthetic vault.
    /// `NotFound`: no such item.
    pub fn allow_production(
        &mut self,
        item_id: u64,
        project: &ProjectRef,
        action: ActionKind,
        answered_on: &str,
        hosts: &[String],
    ) -> VaultResult<u64> {
        self.store_answer(
            item_id,
            project,
            action,
            AnswerScope::Production,
            answered_on,
            hosts,
            false,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_answer(
        &mut self,
        item_id: u64,
        project: &ProjectRef,
        action: ActionKind,
        scope: AnswerScope,
        answered_on: &str,
        hosts: &[String],
        includes_codes: bool,
        includes_values: bool,
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
        // The same answer again adds the hosts of its run.
        let known: Option<(String, bool)> = tx
            .query_row(
                "SELECT hosts, includes_codes FROM owner_answer
                 WHERE item_id = ?1 AND project_key = ?2 AND action_kind = ?3 AND scope = ?4",
                (item, key.as_str(), action.as_str(), scope.as_str()),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        // Crossing into or out of code coverage replaces destinations. Otherwise a
        // password-only answer could silently expand where an earlier code may go.
        let mut all = if !includes_codes && known.as_ref().is_none_or(|(_, codes)| !*codes) {
            known
                .as_ref()
                .map(|(hosts, _)| parse_hosts(hosts))
                .transpose()?
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        all.extend(hosts.iter().cloned());
        let all =
            serde_json::to_string(&normal_hosts(&all)).map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO owner_answer
                 (item_id, project_key, project_label, action_kind, scope, created_at, answered_on,
                  hosts, includes_codes, includes_values)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(item_id, project_key, action_kind, scope)
             DO UPDATE SET project_label = excluded.project_label, hosts = excluded.hosts,
                 includes_codes = excluded.includes_codes, includes_values = excluded.includes_values",
            rusqlite::params![
                item,
                key.as_str(),
                label.as_str(),
                action.as_str(),
                scope.as_str(),
                at,
                on.as_str(),
                all,
                includes_codes,
                includes_values,
            ],
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
                     created_at, answered_on, hosts, includes_codes, includes_values
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
                     created_at, answered_on, hosts, includes_codes, includes_values
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

type AnswerRow = (
    i64,
    i64,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    bool,
    bool,
);

fn parse_hosts(text: &str) -> VaultResult<Vec<String>> {
    serde_json::from_str(text).map_err(|_| err(VaultErrorKind::Storage))
}

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
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn parse_answer(row: AnswerRow) -> VaultResult<OwnerAnswer> {
    let (id, item, key, label, action, scope, at, on, hosts, includes_codes, includes_values) = row;
    Ok(OwnerAnswer {
        id: to_public_id(id)?,
        item_id: to_public_id(item)?,
        project: ProjectRef { key, label },
        action: ActionKind::parse(&action).ok_or_else(|| err(VaultErrorKind::Storage))?,
        scope: AnswerScope::parse(&scope)?,
        created_at: from_sql_time(at)?,
        answered_on: on,
        hosts: parse_hosts(&hosts)?,
        includes_codes,
        includes_values,
    })
}

/// Schema 23: old password answers never authorize a code.
pub(super) fn add_code_schema(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch("ALTER TABLE owner_answer ADD COLUMN includes_codes INTEGER NOT NULL DEFAULT 0 CHECK (includes_codes IN (0,1)); ALTER TABLE owner_answer ADD COLUMN includes_values INTEGER NOT NULL DEFAULT 1 CHECK (includes_values IN (0,1)); UPDATE vault_meta SET schema_version = 23 WHERE id = 1; PRAGMA user_version = 23;")
        .map_err(|_| err(VaultErrorKind::Storage))
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
            .remember_answer(item, &project, ActionKind::Read, "this Mac", &[])
            .unwrap();
        assert_eq!(
            vault
                .remember_answer(item, &project, ActionKind::Read, "this Mac", &[])
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
            .allow_production(item, &project, ActionKind::Deploy, "this Mac", &[])
            .unwrap();
        assert_ne!(production, id);
        assert_eq!(vault.answers_for_item(item).unwrap().len(), 2);
        assert!(vault.remove_answer(production).unwrap());
        assert!(!vault.remove_answer(production).unwrap());
        assert_eq!(
            vault
                .remember_answer(999, &project, ActionKind::Read, "this Mac", &[])
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );
        // The hosts of each answer add up, in normal form.
        let hosts = vec!["API.Example.test:443".to_owned(), "bad host".to_owned()];
        vault
            .remember_answer(item, &project, ActionKind::Read, "this Mac", &hosts)
            .unwrap();
        vault
            .remember_answer(
                item,
                &project,
                ActionKind::Read,
                "this Mac",
                &["db.example.test".to_owned()],
            )
            .unwrap();
        let found = vault
            .answer_for(item, &project.key, ActionKind::Read, AnswerScope::Project)
            .unwrap()
            .unwrap();
        assert_eq!(found.hosts, vec!["api.example.test", "db.example.test"]);
        let empty = ProjectRef {
            key: String::new(),
            label: "x".to_owned(),
        };
        assert_eq!(
            vault
                .remember_answer(item, &empty, ActionKind::Read, "this Mac", &[])
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
    }
}

#[cfg(test)]
mod code_scope_tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue};
    #[test]
    fn schema22_answer_migrates_without_code_authority_and_password_hosts_cannot_expand_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("synthetic.db");
        let pass = "synthetic-mfa-schema";
        let mut v = Vault::create(&file, pass).unwrap();
        v.unlock(pass).unwrap();
        let item = v
            .add(ItemDraft {
                title: "Synthetic".into(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: vec![],
                fields: vec![Field {
                    name: "token".into(),
                    value: SecretValue::new("synthetic-password".into()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        let project = ProjectRef {
            key: "/synthetic/.git".into(),
            label: "Synthetic".into(),
        };
        v.remember_answer(
            item,
            &project,
            ActionKind::Change,
            "test",
            &["password.example".into()],
        )
        .unwrap();
        v.lock().unwrap();
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", pass).unwrap();
        conn.execute_batch("ALTER TABLE owner_answer DROP COLUMN includes_codes; ALTER TABLE owner_answer DROP COLUMN includes_values; UPDATE vault_meta SET schema_version=22; PRAGMA user_version=22;").unwrap();
        conn.close().unwrap();
        v.unlock(pass).unwrap();
        let answer = v
            .answer_for(item, &project.key, ActionKind::Change, AnswerScope::Project)
            .unwrap()
            .unwrap();
        assert!(!answer.includes_codes);
        v.store_answer(
            item,
            &project,
            ActionKind::Change,
            AnswerScope::Project,
            "test",
            &["code.example".into()],
            true,
            false,
        )
        .unwrap();
        let answer = v
            .answer_for(item, &project.key, ActionKind::Change, AnswerScope::Project)
            .unwrap()
            .unwrap();
        assert!(answer.includes_codes);
        assert!(!answer.includes_values);
        assert_eq!(answer.hosts, vec!["code.example"]);
        v.remember_answer(
            item,
            &project,
            ActionKind::Change,
            "test",
            &["new-password.example".into()],
        )
        .unwrap();
        let answer = v
            .answer_for(item, &project.key, ActionKind::Change, AnswerScope::Project)
            .unwrap()
            .unwrap();
        assert!(!answer.includes_codes);
        assert_eq!(answer.hosts, vec!["new-password.example"]);
    }
}
