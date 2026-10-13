//! Settings of a credential for the bouncer (schema 18, ADR 0025): "Always ask" and the
//! source of each declaration value.
//!
//! Both are child rows of the credential (`item_policy`, `declaration_source`), so they
//! sync with it. The default has no row: "Always ask" off, and each declaration value
//! from the owner. A change writes a row only when it changes something, so the version
//! of the credential stays the same otherwise.

use rusqlite::{OptionalExtension, TransactionBehavior};

use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, agents, to_sql_id};

/// Where a declaration value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationSource {
    /// The owner set or confirmed it.
    Owner,
    /// A signal of the credential (the provider, a prefix, a host) suggested it.
    Signal,
    /// The use of the credential suggested it.
    Usage,
    /// Nothing suggested it: the default value.
    Default,
}

impl DeclarationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Signal => "signal",
            Self::Usage => "usage",
            Self::Default => "default",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "owner" => Some(Self::Owner),
            "signal" => Some(Self::Signal),
            "usage" => Some(Self::Usage),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
}

/// The source of each declaration value of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationSources {
    pub environment: DeclarationSource,
    pub risk: DeclarationSource,
    pub scope: DeclarationSource,
    pub reversibility: DeclarationSource,
}

impl Default for DeclarationSources {
    /// Every value from the owner: the meaning of a credential without a row.
    fn default() -> Self {
        Self {
            environment: DeclarationSource::Owner,
            risk: DeclarationSource::Owner,
            scope: DeclarationSource::Owner,
            reversibility: DeclarationSource::Owner,
        }
    }
}

impl Vault {
    /// Whether each use of the credential waits for the owner. `NotFound`: no such
    /// credential.
    pub fn always_ask(&self, item_id: u64) -> VaultResult<bool> {
        let item = to_sql_id(item_id)?;
        let found: Option<Option<i64>> = self
            .conn_ref()?
            .query_row(
                "SELECT p.always_ask FROM item i
                 LEFT JOIN item_policy p ON p.item_id = i.id WHERE i.id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let value = found.ok_or_else(|| err(VaultErrorKind::NotFound))?;
        Ok(value == Some(1))
    }

    /// Turn "Always ask" on or off for the credential. The same value changes nothing.
    /// The caller asks for the owner check before it turns it off. `NotFound`: no such
    /// credential.
    pub fn set_always_ask(&mut self, item_id: u64, on: bool) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let current = self.always_ask(item_id)?;
        if current == on {
            return Ok(());
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        if on {
            tx.execute(
                "INSERT INTO item_policy (item_id, always_ask) VALUES (?1, 1)
                 ON CONFLICT(item_id) DO UPDATE SET always_ask = 1",
                [item],
            )
        } else {
            tx.execute("DELETE FROM item_policy WHERE item_id = ?1", [item])
        }
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// The source of each declaration value. Each is [`DeclarationSource::Owner`] when
    /// the credential has no row. `NotFound`: no such credential.
    pub fn declaration_sources(&self, item_id: u64) -> VaultResult<DeclarationSources> {
        let item = to_sql_id(item_id)?;
        type Row = Option<[String; 4]>;
        let found: Option<Row> = self
            .conn_ref()?
            .query_row(
                "SELECT s.environment, s.risk, s.scope, s.reversibility FROM item i
                 LEFT JOIN declaration_source s ON s.item_id = i.id WHERE i.id = ?1",
                [item],
                |row| {
                    let values: [Option<String>; 4] =
                        [row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?];
                    Ok(match values {
                        [Some(a), Some(b), Some(c), Some(d)] => Some([a, b, c, d]),
                        _ => None,
                    })
                },
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let Some(values) = found.ok_or_else(|| err(VaultErrorKind::NotFound))? else {
            return Ok(DeclarationSources::default());
        };
        let parse =
            |text: &str| DeclarationSource::parse(text).ok_or_else(|| err(VaultErrorKind::Storage));
        Ok(DeclarationSources {
            environment: parse(&values[0])?,
            risk: parse(&values[1])?,
            scope: parse(&values[2])?,
            reversibility: parse(&values[3])?,
        })
    }

    /// Store the source of each declaration value. Every value from the owner removes
    /// the row. The same sources change nothing. `NotFound`: no such credential.
    pub fn set_declaration_sources(
        &mut self,
        item_id: u64,
        sources: &DeclarationSources,
    ) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        if self.declaration_sources(item_id)? == *sources {
            return Ok(());
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        if *sources == DeclarationSources::default() {
            tx.execute("DELETE FROM declaration_source WHERE item_id = ?1", [item])
        } else {
            tx.execute(
                "INSERT INTO declaration_source (item_id, environment, risk, scope, reversibility)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(item_id) DO UPDATE SET environment = excluded.environment,
                     risk = excluded.risk, scope = excluded.scope,
                     reversibility = excluded.reversibility",
                (
                    item,
                    sources.environment.as_str(),
                    sources.risk.as_str(),
                    sources.scope.as_str(),
                    sources.reversibility.as_str(),
                ),
            )
        }
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Set only the environment of the declaration, as the answer of the owner: its
    /// source becomes [`DeclarationSource::Owner`]. The project (it may be empty on
    /// purpose), the other values, their sources, and the provider stay. Without a
    /// declaration the credential gets one with the conservative defaults and this
    /// environment; the other values then count as defaults. A declaration event goes
    /// to the history. The same environment from the owner changes nothing.
    /// `NotFound`: no such credential.
    pub fn set_declaration_environment(
        &mut self,
        item_id: u64,
        environment: agents::Environment,
    ) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        fn storage<E>(_: E) -> super::types::VaultError {
            err(VaultErrorKind::Storage)
        }
        let stored: Option<(String, String, String, String, String, String)> = tx
            .query_row(
                "SELECT project, environment, risk, scope, reversibility, provider
                 FROM declaration WHERE item_id = ?1",
                [item],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let has_row = stored.is_some();
        let same_environment = stored
            .as_ref()
            .is_some_and(|row| row.1 == environment.as_str());
        let (declaration, provider) = match stored {
            Some((project, _, risk, scope, reversibility, provider)) => (
                agents::Declaration {
                    project,
                    environment,
                    risk: agents::RiskLevel::parse(&risk).map_err(storage)?,
                    scope: agents::Scope::parse(&scope).map_err(storage)?,
                    reversibility: agents::Reversibility::parse(&reversibility).map_err(storage)?,
                },
                provider,
            ),
            None => (
                agents::Declaration {
                    project: String::new(),
                    environment,
                    risk: super::providers::DEFAULT_RISK,
                    scope: super::providers::DEFAULT_SCOPE,
                    reversibility: super::providers::DEFAULT_REVERSIBILITY,
                },
                String::new(),
            ),
        };
        let mut sources = if has_row {
            let current = tx
                .query_row(
                    "SELECT environment, risk, scope, reversibility FROM declaration_source
                     WHERE item_id = ?1",
                    [item],
                    |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
                )
                .optional()
                .map_err(storage)?;
            match current {
                Some::<[String; 4]>(values) => {
                    let parse = |text: &str| {
                        DeclarationSource::parse(text).ok_or_else(|| err(VaultErrorKind::Storage))
                    };
                    DeclarationSources {
                        environment: parse(&values[0])?,
                        risk: parse(&values[1])?,
                        scope: parse(&values[2])?,
                        reversibility: parse(&values[3])?,
                    }
                }
                None => DeclarationSources::default(),
            }
        } else {
            DeclarationSources {
                environment: DeclarationSource::Owner,
                risk: DeclarationSource::Default,
                scope: DeclarationSource::Default,
                reversibility: DeclarationSource::Default,
            }
        };
        if has_row && same_environment && sources.environment == DeclarationSource::Owner {
            return Ok(());
        }
        sources.environment = DeclarationSource::Owner;
        tx.execute(
            "INSERT INTO declaration
                 (item_id, project, environment, risk, scope, reversibility, provider)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(item_id) DO UPDATE SET environment = excluded.environment",
            (
                item,
                declaration.project.as_str(),
                declaration.environment.as_str(),
                declaration.risk.as_str(),
                declaration.scope.as_str(),
                declaration.reversibility.as_str(),
                provider.as_str(),
            ),
        )
        .map_err(storage)?;
        if sources == DeclarationSources::default() {
            tx.execute("DELETE FROM declaration_source WHERE item_id = ?1", [item])
        } else {
            tx.execute(
                "INSERT INTO declaration_source (item_id, environment, risk, scope, reversibility)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(item_id) DO UPDATE SET environment = excluded.environment,
                     risk = excluded.risk, scope = excluded.scope,
                     reversibility = excluded.reversibility",
                (
                    item,
                    sources.environment.as_str(),
                    sources.risk.as_str(),
                    sources.scope.as_str(),
                    sources.reversibility.as_str(),
                ),
            )
        }
        .map_err(storage)?;
        super::history::record(
            &tx,
            item,
            super::history::ItemEventKind::Declaration,
            &declaration.history_detail(Some(provider.as_str())),
        )?;
        tx.commit().map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue, SyncScope};

    const PASS: &str = "synthetic-policy-pass";

    fn vault_with_item(dir: &tempfile::TempDir) -> (Vault, u64) {
        let mut vault = Vault::create(&dir.path().join("policy.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let id = vault
            .add(ItemDraft {
                title: "Stripe".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("SYNTH-policy-token".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        (vault, id)
    }

    #[test]
    fn always_ask_round_trips_and_is_synced_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, id) = vault_with_item(&dir);
        let scope = SyncScope::vault();
        let before = vault.sync_content(&scope).unwrap();
        assert!(!vault.always_ask(id).unwrap());
        vault.set_always_ask(id, true).unwrap();
        assert!(vault.always_ask(id).unwrap());
        let on = vault.sync_content(&scope).unwrap();
        assert_ne!(on, before, "a change of the credential");
        // The same value changes nothing, not even the version.
        vault.set_always_ask(id, true).unwrap();
        assert_eq!(vault.sync_content(&scope).unwrap(), on);
        vault.set_always_ask(id, false).unwrap();
        assert!(!vault.always_ask(id).unwrap());
        assert_eq!(
            vault.always_ask(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            vault.set_always_ask(999, true).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn declaration_sources_default_to_the_owner_and_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, id) = vault_with_item(&dir);
        assert_eq!(
            vault.declaration_sources(id).unwrap(),
            DeclarationSources::default()
        );
        let sources = DeclarationSources {
            environment: DeclarationSource::Signal,
            risk: DeclarationSource::Usage,
            scope: DeclarationSource::Default,
            reversibility: DeclarationSource::Owner,
        };
        vault.set_declaration_sources(id, &sources).unwrap();
        assert_eq!(vault.declaration_sources(id).unwrap(), sources);
        vault
            .set_declaration_sources(id, &DeclarationSources::default())
            .unwrap();
        let rows: i64 = vault
            .conn_ref()
            .unwrap()
            .query_row("SELECT count(*) FROM declaration_source", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0, "the default has no row");
        for source in [
            DeclarationSource::Owner,
            DeclarationSource::Signal,
            DeclarationSource::Usage,
            DeclarationSource::Default,
        ] {
            assert_eq!(DeclarationSource::parse(source.as_str()), Some(source));
        }
        assert_eq!(DeclarationSource::parse("other"), None);
        assert_eq!(
            vault.declaration_sources(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn set_declaration_environment_changes_only_the_environment() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, id) = vault_with_item(&dir);
        // No declaration: a new one with the careful defaults and an empty project.
        vault
            .set_declaration_environment(id, agents::Environment::Development)
            .unwrap();
        let created = vault.declaration(id).unwrap().expect("declaration");
        assert_eq!(created.environment, agents::Environment::Development);
        assert!(created.project.is_empty());
        assert_eq!(created.risk, super::super::providers::DEFAULT_RISK);
        let sources = vault.declaration_sources(id).unwrap();
        assert_eq!(sources.environment, DeclarationSource::Owner);
        assert_eq!(sources.risk, DeclarationSource::Default);

        // A declaration with a project, other values, and a source: only the
        // environment and its source change.
        let declaration = agents::Declaration {
            project: "web".to_owned(),
            environment: agents::Environment::Production,
            risk: agents::RiskLevel::Low,
            scope: agents::Scope::ReadOnly,
            reversibility: agents::Reversibility::Reversible,
        };
        vault
            .save_declaration(id, &declaration, Some("stripe"), None)
            .unwrap();
        let signal = DeclarationSources {
            environment: DeclarationSource::Signal,
            risk: DeclarationSource::Usage,
            scope: DeclarationSource::Default,
            reversibility: DeclarationSource::Signal,
        };
        vault.set_declaration_sources(id, &signal).unwrap();
        vault
            .set_declaration_environment(id, agents::Environment::Staging)
            .unwrap();
        let after = vault.declaration(id).unwrap().expect("declaration");
        assert_eq!(
            after,
            agents::Declaration {
                environment: agents::Environment::Staging,
                ..declaration
            }
        );
        assert_eq!(
            vault.declaration_provider(id).unwrap().as_deref(),
            Some("stripe")
        );
        assert_eq!(
            vault.declaration_sources(id).unwrap(),
            DeclarationSources {
                environment: DeclarationSource::Owner,
                ..signal
            }
        );
        // The same answer changes nothing.
        let scope = SyncScope::vault();
        let content = vault.sync_content(&scope).unwrap();
        vault
            .set_declaration_environment(id, agents::Environment::Staging)
            .unwrap();
        assert_eq!(vault.sync_content(&scope).unwrap(), content);
        assert_eq!(
            vault
                .set_declaration_environment(999, agents::Environment::Staging)
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );
    }
}
