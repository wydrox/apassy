//! Explicit, local owner permission for bouncer evaluation, never automatic execution.
//!
//! Only the broker writes scopes, after checking a proof for the exact waiting offer.
//! Ordinary approvals and remembered execution answers never create one. Each scope
//! has a unique lifetime ID; invalidation deletes it, so edit/revert cannot revive it.

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, TransactionBehavior};

use super::answers::{
    MAX_ANSWER_HOSTS, MAX_ANSWERED_ON_BYTES, MAX_PROJECT_KEY_BYTES, MAX_PROJECT_LABEL_BYTES,
    ProjectRef, normal_host,
};
use super::types::{VaultError, VaultErrorKind, VaultResult, err};
use super::{
    Declaration, DeclarationSource, DeclarationSources, Environment, RiskLevel, Vault, agents,
    to_public_id, to_sql_id,
};
use crate::broker::action_kind::ActionKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationConfirmation {
    pub item_id: u64,
    /// The credential revision displayed when the owner check began.
    pub revision: u64,
    pub environment: Environment,
    pub risk: RiskLevel,
    /// The exact destination hosts offered to the owner, not future inferred hosts.
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationScope {
    pub id: u64,
    pub agent_id: u64,
    pub item_id: u64,
    pub project: ProjectRef,
    pub action: ActionKind,
    pub revision: u64,
    pub hosts: Vec<String>,
    /// An opaque digest binding uncertain commands to the displayed command.
    pub command_binding: Option<String>,
    pub answered_on: String,
}

fn storage<E>(_: E) -> VaultError {
    err(VaultErrorKind::Storage)
}

fn valid_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn checked_hosts(hosts: &[String]) -> VaultResult<Vec<String>> {
    if hosts.len() > MAX_ANSWER_HOSTS {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    let mut result = BTreeSet::new();
    for host in hosts {
        let host = normal_host(host)
            .filter(|host| !host.contains('*'))
            .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        result.insert(host);
    }
    Ok(result.into_iter().collect())
}

const SELECT: &str = "SELECT s.id, s.agent_id, s.item_id, s.project_key, s.project_label,
    s.action_kind, s.revision, s.hosts, s.command_binding, s.answered_on
    FROM bouncer_scope s JOIN item i ON i.id = s.item_id AND i.uuid = s.item_uuid AND i.revision = s.revision
    JOIN agent a ON a.id = s.agent_id AND a.revoked_at IS NULL
    WHERE NOT EXISTS (SELECT 1 FROM item_archive x WHERE x.item_id = s.item_id)";

type ScopeRow = (
    i64,
    i64,
    i64,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    String,
);

fn scope_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScopeRow> {
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
    ))
}

fn parse_scope(row: ScopeRow) -> VaultResult<EvaluationScope> {
    let (id, agent, item, key, label, action, revision, hosts, command_binding, answered_on) = row;
    let hosts: Vec<String> = serde_json::from_str(&hosts).map_err(storage)?;
    if checked_hosts(&hosts).map_err(storage)? != hosts {
        return Err(err(VaultErrorKind::Storage));
    }
    Ok(EvaluationScope {
        id: to_public_id(id)?,
        agent_id: to_public_id(agent)?,
        item_id: to_public_id(item)?,
        project: ProjectRef { key, label },
        action: ActionKind::parse(&action).ok_or_else(|| err(VaultErrorKind::Storage))?,
        revision: to_public_id(revision)?,
        hosts,
        command_binding,
        answered_on,
    })
}

impl Vault {
    /// Save the exact owner-confirmed classification and evaluation scope atomically.
    /// Call only after the broker validates the owner proof and its complete offer.
    /// Every displayed revision is checked before the first write. This does not
    /// grant agent access, approve a command, or change any production/host veto.
    pub(crate) fn authorize_evaluation(
        &mut self,
        agent_id: u64,
        project: &ProjectRef,
        action: ActionKind,
        confirmations: &[EvaluationConfirmation],
        command_binding: Option<&str>,
        answered_on: &str,
    ) -> VaultResult<()> {
        if confirmations.is_empty()
            || !valid_text(&project.key, MAX_PROJECT_KEY_BYTES)
            || !valid_text(&project.label, MAX_PROJECT_LABEL_BYTES)
            || !valid_text(answered_on, MAX_ANSWERED_ON_BYTES)
            || command_binding.is_some_and(|binding| !valid_text(binding, 128))
        {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let agent = to_sql_id(agent_id)?;
        let mut seen = BTreeSet::new();
        let mut hosts = Vec::with_capacity(confirmations.len());
        for confirmation in confirmations {
            if !seen.insert(confirmation.item_id) {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            hosts.push(
                serde_json::to_string(&checked_hosts(&confirmation.hosts)?).map_err(storage)?,
            );
        }
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        agents::require_active_agent(&tx, agent)?;
        for confirmation in confirmations {
            let item = to_sql_id(confirmation.item_id)?;
            let revision: Option<i64> = tx
                .query_row(
                    "SELECT revision FROM item WHERE id = ?1 AND uuid IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM item_archive WHERE item_id = ?1)",
                    [item],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            match revision {
                None => return Err(err(VaultErrorKind::NotFound)),
                Some(revision) if to_public_id(revision)? != confirmation.revision => {
                    return Err(err(VaultErrorKind::Conflict));
                }
                _ => {}
            }
        }
        // Classify all items before creating any scope: classification triggers
        // invalidate prior authority, but must not erase a scope just saved here.
        for confirmation in confirmations {
            confirm_classification(&tx, confirmation)?;
        }
        for (confirmation, hosts) in confirmations.iter().zip(hosts) {
            let item = to_sql_id(confirmation.item_id)?;
            // Replacement always allocates a new lifetime ID, including identical
            // reauthorization. An in-flight decision cannot borrow the new permission.
            tx.execute("DELETE FROM bouncer_scope WHERE agent_id = ?1 AND item_id = ?2 AND project_key = ?3 AND action_kind = ?4",
                rusqlite::params![agent, item, project.key, action.as_str()]).map_err(storage)?;
            tx.execute(
                "INSERT INTO bouncer_scope (agent_id, item_id, item_uuid, project_key, project_label,
                     action_kind, revision, hosts, command_binding, answered_on)
                 SELECT ?1, id, uuid, ?3, ?4, ?5, revision, ?6, ?7, ?8 FROM item WHERE id = ?2",
                rusqlite::params![agent, item, project.key, project.label, action.as_str(), hosts, command_binding, answered_on],
            ).map_err(storage)?;
        }
        tx.commit().map_err(storage)
    }

    pub fn evaluation_scope(
        &self,
        item_id: u64,
        agent_id: u64,
        project_key: &str,
        action: ActionKind,
    ) -> VaultResult<Option<EvaluationScope>> {
        let sql = format!(
            "{SELECT} AND s.item_id = ?1 AND s.agent_id = ?2 AND s.project_key = ?3 AND s.action_kind = ?4"
        );
        self.conn_ref()?
            .query_row(
                &sql,
                rusqlite::params![
                    to_sql_id(item_id)?,
                    to_sql_id(agent_id)?,
                    project_key,
                    action.as_str()
                ],
                scope_row,
            )
            .optional()
            .map_err(storage)?
            .map(parse_scope)
            .transpose()
    }

    /// Active local scopes shown to the owner, with their exact revocation IDs.
    pub fn evaluation_scopes(&self, item_id: u64) -> VaultResult<Vec<EvaluationScope>> {
        let sql = format!("{SELECT} AND s.item_id = ?1 ORDER BY s.id DESC");
        let mut stmt = self.conn_ref()?.prepare(&sql).map_err(storage)?;
        stmt.query_map([to_sql_id(item_id)?], scope_row)
            .map_err(storage)?
            .map(|row| parse_scope(row.map_err(storage)?))
            .collect()
    }

    /// Taking authority away needs no owner check.
    pub fn remove_evaluation_scope(&mut self, id: u64) -> VaultResult<bool> {
        self.conn_mut()?
            .execute("DELETE FROM bouncer_scope WHERE id = ?1", [to_sql_id(id)?])
            .map(|rows| rows > 0)
            .map_err(storage)
    }
}

fn confirm_classification(
    tx: &rusqlite::Transaction<'_>,
    confirmation: &EvaluationConfirmation,
) -> VaultResult<()> {
    let item = to_sql_id(confirmation.item_id)?;
    let stored: Option<(String, String, String, String, String, String)> = tx.query_row(
        "SELECT project, environment, risk, scope, reversibility, provider FROM declaration WHERE item_id = ?1",
        [item], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).optional().map_err(storage)?;
    let had_declaration = stored.is_some();
    let same_values = stored.as_ref().is_some_and(|row| {
        row.1 == confirmation.environment.as_str() && row.2 == confirmation.risk.as_str()
    });
    let (declaration, provider) = match stored {
        Some((project, _, _, scope, reversibility, provider)) => (
            Declaration {
                project,
                environment: confirmation.environment,
                risk: confirmation.risk,
                scope: agents::Scope::parse(&scope).map_err(storage)?,
                reversibility: agents::Reversibility::parse(&reversibility).map_err(storage)?,
            },
            provider,
        ),
        None => (
            Declaration {
                project: String::new(),
                environment: confirmation.environment,
                risk: confirmation.risk,
                scope: super::providers::DEFAULT_SCOPE,
                reversibility: super::providers::DEFAULT_REVERSIBILITY,
            },
            String::new(),
        ),
    };
    let saved_sources: Option<[String; 4]> = tx.query_row(
        "SELECT environment, risk, scope, reversibility FROM declaration_source WHERE item_id = ?1",
        [item], |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
    ).optional().map_err(storage)?;
    let parse =
        |text: &str| DeclarationSource::parse(text).ok_or_else(|| err(VaultErrorKind::Storage));
    let mut sources = match saved_sources {
        Some(values) => DeclarationSources {
            environment: parse(&values[0])?,
            risk: parse(&values[1])?,
            scope: parse(&values[2])?,
            reversibility: parse(&values[3])?,
        },
        None if had_declaration => DeclarationSources::default(),
        None => DeclarationSources {
            environment: DeclarationSource::Default,
            risk: DeclarationSource::Default,
            scope: DeclarationSource::Default,
            reversibility: DeclarationSource::Default,
        },
    };
    if same_values
        && sources.environment == DeclarationSource::Owner
        && sources.risk == DeclarationSource::Owner
    {
        return Ok(());
    }
    sources.environment = DeclarationSource::Owner;
    sources.risk = DeclarationSource::Owner;
    tx.execute(
        "INSERT INTO declaration (item_id, project, environment, risk, scope, reversibility, provider)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(item_id) DO UPDATE SET environment = excluded.environment, risk = excluded.risk",
        rusqlite::params![item, declaration.project, declaration.environment.as_str(), declaration.risk.as_str(), declaration.scope.as_str(), declaration.reversibility.as_str(), provider],
    ).map_err(storage)?;
    tx.execute(
        "INSERT INTO declaration_source (item_id, environment, risk, scope, reversibility)
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(item_id) DO UPDATE SET environment = excluded.environment, risk = excluded.risk",
        rusqlite::params![item, sources.environment.as_str(), sources.risk.as_str(), sources.scope.as_str(), sources.reversibility.as_str()],
    ).map_err(storage)?;
    super::history::record(
        tx,
        item,
        super::history::ItemEventKind::Declaration,
        &declaration.history_detail(Some(&provider)),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue, SyncScope};

    const PASS: &str = "synthetic-evaluation-scope-pass";

    fn draft(title: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new("SYNTH-evaluation-token".to_owned()),
                secret: true,
            }],
        }
    }

    fn fixture(dir: &tempfile::TempDir) -> (Vault, u64, u64) {
        let mut vault = Vault::create(&dir.path().join("scope.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(draft("Scope credential")).unwrap().id;
        let agent = vault.register_agent("scope-test").unwrap().0.id;
        (vault, item, agent)
    }

    fn project() -> ProjectRef {
        ProjectRef {
            key: "/synthetic/project/.git".to_owned(),
            label: "project".to_owned(),
        }
    }

    fn confirmation(vault: &Vault, item_id: u64) -> EvaluationConfirmation {
        EvaluationConfirmation {
            item_id,
            revision: vault.details(item_id).unwrap().summary.revision,
            environment: Environment::Staging,
            risk: RiskLevel::Medium,
            hosts: vec!["API.EXAMPLE.TEST.".to_owned()],
        }
    }

    fn authorize(vault: &mut Vault, item: u64, agent: u64) -> EvaluationScope {
        let offered = confirmation(vault, item);
        vault
            .authorize_evaluation(
                agent,
                &project(),
                ActionKind::Read,
                &[offered],
                None,
                "this Mac",
            )
            .unwrap();
        vault
            .evaluation_scope(item, agent, &project().key, ActionKind::Read)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn confirmation_preserves_other_declaration_fields_and_sources() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        let declaration = Declaration {
            project: "declared-project".to_owned(),
            environment: Environment::Production,
            risk: RiskLevel::High,
            scope: agents::Scope::ReadOnly,
            reversibility: agents::Reversibility::Reversible,
        };
        vault
            .save_declaration(item, &declaration, Some("stripe"), None)
            .unwrap();
        let sources = DeclarationSources {
            environment: DeclarationSource::Default,
            risk: DeclarationSource::Default,
            scope: DeclarationSource::Signal,
            reversibility: DeclarationSource::Usage,
        };
        vault.set_declaration_sources(item, &sources).unwrap();
        let scope = authorize(&mut vault, item, agent);
        assert_eq!(scope.hosts, ["api.example.test"]);
        let changed = vault.declaration(item).unwrap().unwrap();
        assert_eq!(
            changed,
            Declaration {
                environment: Environment::Staging,
                risk: RiskLevel::Medium,
                ..declaration
            }
        );
        assert_eq!(
            vault.declaration_provider(item).unwrap().as_deref(),
            Some("stripe")
        );
        assert_eq!(
            vault.declaration_sources(item).unwrap(),
            DeclarationSources {
                environment: DeclarationSource::Owner,
                risk: DeclarationSource::Owner,
                ..sources
            }
        );
        assert!(
            vault.answers_for_item(item).unwrap().is_empty(),
            "evaluation is not an execution answer"
        );
    }

    #[test]
    fn scope_is_exact_and_additional_actions_preserve_previous_scope() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
        let scope = authorize(&mut vault, item, agent);
        assert!(
            vault
                .evaluation_scope(item, agent, "/other", ActionKind::Read)
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .evaluation_scope(item, agent, &project().key, ActionKind::Change)
                .unwrap()
                .is_none()
        );
        let other = vault.register_agent("other-agent").unwrap().0.id;
        assert!(
            vault
                .evaluation_scope(item, other, &project().key, ActionKind::Read)
                .unwrap()
                .is_none()
        );
        let offered = confirmation(&vault, item);
        vault
            .authorize_evaluation(
                agent,
                &project(),
                ActionKind::Change,
                &[offered],
                Some("synthetic-command-digest"),
                "this Mac",
            )
            .unwrap();
        assert_eq!(
            vault
                .evaluation_scope(item, agent, &project().key, ActionKind::Read)
                .unwrap()
                .unwrap()
                .id,
            scope.id
        );
        assert_eq!(
            vault
                .evaluation_scope(item, agent, &project().key, ActionKind::Change)
                .unwrap()
                .unwrap()
                .command_binding
                .as_deref(),
            Some("synthetic-command-digest")
        );
        assert_eq!(vault.evaluation_scopes(item).unwrap().len(), 2);
    }

    #[test]
    fn removal_and_reauthorization_have_distinct_lifetime_ids() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        let first = authorize(&mut vault, item, agent);
        assert!(vault.remove_evaluation_scope(first.id).unwrap());
        assert!(!vault.remove_evaluation_scope(first.id).unwrap());
        let second = authorize(&mut vault, item, agent);
        assert!(second.id > first.id);
        let third = authorize(&mut vault, item, agent);
        assert!(third.id > second.id);
    }

    #[test]
    fn stale_revision_and_late_storage_failure_roll_back_every_confirmation() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        let other = vault.add(draft("Other credential")).unwrap().id;
        let first = confirmation(&vault, item);
        let mut second = confirmation(&vault, other);
        second.revision += 1;
        assert_eq!(
            vault
                .authorize_evaluation(
                    agent,
                    &project(),
                    ActionKind::Read,
                    &[first.clone(), second],
                    None,
                    "this Mac"
                )
                .unwrap_err()
                .kind(),
            VaultErrorKind::Conflict
        );
        assert!(vault.declaration(item).unwrap().is_none());
        let second = confirmation(&vault, other);
        vault.conn_ref().unwrap().execute_batch(&format!(
            "CREATE TRIGGER fail_scope_insert BEFORE INSERT ON bouncer_scope WHEN NEW.item_id = {other}
             BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END;"
        )).unwrap();
        assert_eq!(
            vault
                .authorize_evaluation(
                    agent,
                    &project(),
                    ActionKind::Read,
                    &[first, second],
                    None,
                    "this Mac"
                )
                .unwrap_err()
                .kind(),
            VaultErrorKind::Storage
        );
        assert!(vault.declaration(item).unwrap().is_none());
        assert!(vault.declaration(other).unwrap().is_none());
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
    }

    #[test]
    fn edit_revert_stricter_policy_and_agent_revocation_cannot_revive_scope() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        authorize(&mut vault, item, agent);
        let revision = vault.details(item).unwrap().summary.revision;
        vault.update(item, revision, draft("Changed")).unwrap();
        let revision = vault.details(item).unwrap().summary.revision;
        vault
            .update(item, revision, draft("Scope credential"))
            .unwrap();
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
        authorize(&mut vault, item, agent);
        vault.set_always_ask(item, true).unwrap();
        vault.set_always_ask(item, false).unwrap();
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
        authorize(&mut vault, item, agent);
        vault
            .add_agent_exception(
                agent,
                item,
                super::super::exceptions::ExceptionKind::AlwaysAsk,
            )
            .unwrap();
        vault
            .remove_agent_exception(
                agent,
                item,
                super::super::exceptions::ExceptionKind::AlwaysAsk,
            )
            .unwrap();
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
        authorize(&mut vault, item, agent);
        vault.revoke_agent(agent).unwrap();
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
        let offered = confirmation(&vault, item);
        assert!(
            vault
                .authorize_evaluation(
                    agent,
                    &project(),
                    ActionKind::Read,
                    &[offered],
                    None,
                    "this Mac"
                )
                .is_err()
        );
    }

    #[test]
    fn archive_and_classification_revert_discard_scope() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        authorize(&mut vault, item, agent);
        vault
            .set_declaration_environment(item, Environment::Production)
            .unwrap();
        vault
            .set_declaration_environment(item, Environment::Staging)
            .unwrap();
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
        authorize(&mut vault, item, agent);
        vault.set_archived(item, true).unwrap();
        vault.set_archived(item, false).unwrap();
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
    }

    #[test]
    fn export_and_restore_strip_scopes_without_revoking_source_scope() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        let scope = authorize(&mut vault, item, agent);
        let copy = dir.path().join("pushed.db");
        vault.write_sync_copy(&copy, "Mac A").unwrap();
        assert_eq!(vault.evaluation_scopes(item).unwrap(), [scope]);
        let conn =
            rusqlite::Connection::open_with_flags(&copy, super::super::OPEN_READONLY).unwrap();
        super::super::apply_key(&conn, PASS).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM bouncer_scope", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        super::super::close_conn(conn).unwrap();
        let backup = dir.path().join("backup.db");
        vault.backup(&backup).unwrap();
        let mut restored = Vault::restore(&backup, &dir.path().join("restored.db"), PASS).unwrap();
        restored.unlock(PASS).unwrap();
        assert!(restored.evaluation_scopes(item).unwrap().is_empty());
    }

    #[test]
    fn stricter_remote_conflict_invalidates_scope_even_when_local_record_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, item, agent) = fixture(&dir);
        authorize(&mut vault, item, agent);
        let seed = dir.path().join("seed.db");
        vault.write_sync_copy(&seed, "Mac A").unwrap();
        let (mut remote, _) =
            Vault::adopt_sync_copy(&seed, &dir.path().join("remote.db"), PASS).unwrap();
        remote.unlock(PASS).unwrap();
        let remote_item = remote.search("Scope credential").unwrap()[0].id;
        remote
            .set_declaration_environment(remote_item, Environment::Production)
            .unwrap();
        // Use controlled synthetic timestamps, not timing sleeps, to make the local
        // concurrent content win. Stamping clocks leaves these timestamps intact.
        remote
            .conn_ref()
            .unwrap()
            .execute(
                "UPDATE item SET updated_at = 2000000000000 WHERE id = ?1",
                [to_sql_id(remote_item).unwrap()],
            )
            .unwrap();
        let revision = vault.details(item).unwrap().summary.revision;
        vault.update(item, revision, draft("Local winner")).unwrap();
        authorize(&mut vault, item, agent);
        vault
            .conn_ref()
            .unwrap()
            .execute(
                "UPDATE item SET updated_at = 2000000001000 WHERE id = ?1",
                [to_sql_id(item).unwrap()],
            )
            .unwrap();
        let push = dir.path().join("remote-push.db");
        remote.write_sync_copy(&push, "Mac B").unwrap();
        let report = vault.merge_from(&push, &SyncScope::vault()).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(vault.details(item).unwrap().summary.title, "Local winner");
        assert_eq!(
            vault.declaration(item).unwrap().unwrap().environment,
            Environment::Staging
        );
        assert!(vault.evaluation_scopes(item).unwrap().is_empty());
    }
}
