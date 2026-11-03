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

impl DeclarationSources {
    /// The owner labeled the credential development or local: "Allow as dev" on a
    /// question, or the environment of the credential (ADR 0031, 2026-11-03). A
    /// development environment from a signal or from usage is no label of the owner.
    pub fn owner_development(&self, declaration: &agents::Declaration) -> bool {
        self.environment == DeclarationSource::Owner
            && declaration.environment <= agents::Environment::Development
    }

    /// The declaration that the bouncer judges (ADR 0031, 2026-11-03). "Allow as dev"
    /// means development: for a credential that the owner labeled development or local
    /// ([`Self::owner_development`]), a risk or a reversibility with the source
    /// `default` (no owner value, no strong signal) is at most the development default
    /// ([`super::providers::DEVELOPMENT_RISK`],
    /// [`super::providers::DEVELOPMENT_REVERSIBILITY`]). A value from the owner, a
    /// signal, or usage, the environment, the scope, and every other credential stay.
    ///
    /// [`Vault::set_declaration_environment`] stores the same values when the owner
    /// labels a credential. A credential labeled before 0.5.16 still has the stored
    /// production defaults (high risk, irreversible); this computed view covers it
    /// without a rewrite, so its revision, its sync content, and the authorization
    /// recheck of the broker (which compares the stored values) stay the same.
    pub fn judged(&self, declaration: &agents::Declaration) -> agents::Declaration {
        let mut judged = declaration.clone();
        if self.owner_development(declaration) {
            if self.risk == DeclarationSource::Default {
                judged.risk = judged.risk.min(super::providers::DEVELOPMENT_RISK);
            }
            if self.reversibility == DeclarationSource::Default {
                judged.reversibility = judged
                    .reversibility
                    .min(super::providers::DEVELOPMENT_REVERSIBILITY);
            }
        }
        judged
    }

    /// The classification is only a default, so the bouncer needs 80% task match even
    /// for a known safe command or a read (ADR 0031): the environment is a default, or
    /// the risk is a default of a credential that the owner did not label development
    /// or local. After such a label the default risk follows from the owner's
    /// environment ([`Self::judged`]), so the bouncer judges the credential as any
    /// development credential.
    pub fn weak(&self, declaration: Option<&agents::Declaration>) -> bool {
        self.environment == DeclarationSource::Default
            || (self.risk == DeclarationSource::Default
                && !declaration.is_some_and(|declaration| self.owner_development(declaration)))
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

    /// Set the environment of the declaration, as the answer of the owner: its source
    /// becomes [`DeclarationSource::Owner`]. The project (it may be empty on purpose),
    /// the scope, the sources of the other values, and the provider stay. Without a
    /// declaration the credential gets one with the conservative defaults and this
    /// environment; the other values then count as defaults.
    ///
    /// A risk or a reversibility with the source `default` (no owner value, no strong
    /// signal) follows the environment (ADR 0031, 2026-11-03): development or local
    /// gives at most the development default ([`DeclarationSources::judged`]: "Allow as
    /// dev" means development), staging or production the most sensitive default
    /// again. A value from the owner, a signal, or usage never changes. A declaration
    /// event goes to the history. The same environment from the owner, with values
    /// that already follow it, changes nothing. `NotFound`: no such credential.
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
        let labeled = sources.environment == DeclarationSource::Owner;
        let stored_values = (declaration.risk, declaration.reversibility);
        sources.environment = DeclarationSource::Owner;
        let declaration = if sources.owner_development(&declaration) {
            sources.judged(&declaration)
        } else {
            let mut declaration = declaration;
            if sources.risk == DeclarationSource::Default {
                declaration.risk = super::providers::DEFAULT_RISK;
            }
            if sources.reversibility == DeclarationSource::Default {
                declaration.reversibility = super::providers::DEFAULT_REVERSIBILITY;
            }
            declaration
        };
        if has_row
            && same_environment
            && labeled
            && stored_values == (declaration.risk, declaration.reversibility)
        {
            return Ok(());
        }
        tx.execute(
            "INSERT INTO declaration
                 (item_id, project, environment, risk, scope, reversibility, provider)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(item_id) DO UPDATE SET environment = excluded.environment,
                 risk = excluded.risk, reversibility = excluded.reversibility",
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
        // No declaration: a new one with the careful scope, an empty project, and the
        // development defaults of the owner's label (ADR 0031, 2026-11-03).
        vault
            .set_declaration_environment(id, agents::Environment::Development)
            .unwrap();
        let created = vault.declaration(id).unwrap().expect("declaration");
        assert_eq!(created.environment, agents::Environment::Development);
        assert!(created.project.is_empty());
        assert_eq!(created.risk, super::super::providers::DEVELOPMENT_RISK);
        assert_eq!(
            created.reversibility,
            super::super::providers::DEVELOPMENT_REVERSIBILITY
        );
        assert_eq!(created.scope, super::super::providers::DEFAULT_SCOPE);
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

    /// An unlabeled credential: production, high risk, admin, irreversible, and every
    /// value only a default (a pasted value without a signal).
    fn unlabeled(vault: &mut Vault, id: u64) {
        vault
            .save_declaration(
                id,
                &agents::Declaration {
                    project: "synthetic".to_owned(),
                    environment: super::super::providers::DEFAULT_ENVIRONMENT,
                    risk: super::super::providers::DEFAULT_RISK,
                    scope: super::super::providers::DEFAULT_SCOPE,
                    reversibility: super::super::providers::DEFAULT_REVERSIBILITY,
                },
                None,
                None,
            )
            .unwrap();
        vault
            .set_declaration_sources(id, &all(DeclarationSource::Default))
            .unwrap();
    }

    fn all(source: DeclarationSource) -> DeclarationSources {
        DeclarationSources {
            environment: source,
            risk: source,
            scope: source,
            reversibility: source,
        }
    }

    fn stored(vault: &Vault, id: u64) -> (agents::Declaration, DeclarationSources) {
        (
            vault.declaration(id).unwrap().expect("declaration"),
            vault.declaration_sources(id).unwrap(),
        )
    }

    /// ADR 0031, 2026-11-03: "Allow as dev" means development. The default risk and
    /// reversibility become the development defaults; production gets the careful
    /// defaults back; the scope and the values of the owner or a signal never change.
    #[test]
    fn a_development_label_gives_the_default_values_the_development_defaults() {
        use super::super::providers::{
            DEFAULT_REVERSIBILITY, DEFAULT_RISK, DEFAULT_SCOPE, DEVELOPMENT_REVERSIBILITY,
            DEVELOPMENT_RISK,
        };
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, id) = vault_with_item(&dir);
        unlabeled(&mut vault, id);
        let (declaration, sources) = stored(&vault, id);
        // Unlabeled: production by default, judged as stored, and only a default.
        assert!(!sources.owner_development(&declaration));
        assert_eq!(sources.judged(&declaration), declaration);
        assert!(sources.weak(Some(&declaration)));

        // "Allow as dev" stores the development defaults; the scope stays admin.
        vault
            .set_declaration_environment(id, agents::Environment::Development)
            .unwrap();
        let (declaration, sources) = stored(&vault, id);
        assert_eq!(declaration.environment, agents::Environment::Development);
        assert_eq!(declaration.risk, DEVELOPMENT_RISK);
        assert_eq!(declaration.reversibility, DEVELOPMENT_REVERSIBILITY);
        assert_eq!(declaration.scope, DEFAULT_SCOPE);
        assert!(!declaration.is_sensitive());
        assert_eq!(
            sources,
            DeclarationSources {
                environment: DeclarationSource::Owner,
                ..all(DeclarationSource::Default)
            }
        );
        assert!(sources.owner_development(&declaration));
        assert!(!sources.weak(Some(&declaration)));
        assert_eq!(sources.judged(&declaration), declaration);
        // The same answer again changes nothing.
        let scope = SyncScope::vault();
        let content = vault.sync_content(&scope).unwrap();
        vault
            .set_declaration_environment(id, agents::Environment::Development)
            .unwrap();
        assert_eq!(vault.sync_content(&scope).unwrap(), content);

        // "Allow as prod" (or the environment set to production) gives the careful
        // defaults back, so production stays as strict as before.
        vault
            .set_declaration_environment(id, agents::Environment::Production)
            .unwrap();
        let (declaration, sources) = stored(&vault, id);
        assert_eq!(declaration.risk, DEFAULT_RISK);
        assert_eq!(declaration.reversibility, DEFAULT_REVERSIBILITY);
        assert!(declaration.is_sensitive());
        assert!(sources.weak(Some(&declaration)), "the risk is a default");
        // Staging is no development label either.
        vault
            .set_declaration_environment(id, agents::Environment::Staging)
            .unwrap();
        let (declaration, sources) = stored(&vault, id);
        assert_eq!(declaration.risk, DEFAULT_RISK);
        assert_eq!(declaration.reversibility, DEFAULT_REVERSIBILITY);
        assert!(sources.weak(Some(&declaration)));
        // Local is less than development, so it gets the development defaults too.
        vault
            .set_declaration_environment(id, agents::Environment::Local)
            .unwrap();
        let (declaration, _) = stored(&vault, id);
        assert_eq!(declaration.risk, DEVELOPMENT_RISK);
        assert_eq!(declaration.reversibility, DEVELOPMENT_REVERSIBILITY);

        // A value of the owner or of a strong signal never changes.
        for source in [DeclarationSource::Owner, DeclarationSource::Signal] {
            unlabeled(&mut vault, id);
            vault
                .set_declaration_sources(
                    id,
                    &DeclarationSources {
                        risk: source,
                        reversibility: source,
                        ..all(DeclarationSource::Default)
                    },
                )
                .unwrap();
            vault
                .set_declaration_environment(id, agents::Environment::Development)
                .unwrap();
            let (declaration, sources) = stored(&vault, id);
            assert_eq!(declaration.risk, DEFAULT_RISK, "{source:?}");
            assert_eq!(
                declaration.reversibility, DEFAULT_REVERSIBILITY,
                "{source:?}"
            );
            assert_eq!(sources.judged(&declaration), declaration, "{source:?}");
            assert!(declaration.is_sensitive(), "{source:?}");
            assert!(!sources.weak(Some(&declaration)), "{source:?}");
        }
        // A lower default value stays: the development defaults are a ceiling.
        let low = agents::Declaration {
            project: String::new(),
            environment: agents::Environment::Development,
            risk: agents::RiskLevel::Low,
            scope: agents::Scope::ReadOnly,
            reversibility: agents::Reversibility::Reversible,
        };
        let labeled = DeclarationSources {
            environment: DeclarationSource::Owner,
            ..all(DeclarationSource::Default)
        };
        assert_eq!(labeled.judged(&low), low);
    }

    /// A credential that the owner labeled development before 0.5.16 kept the stored
    /// high risk and irreversibility. The bouncer judges it with the development
    /// defaults without a rewrite; a development environment from a signal or usage is
    /// no label of the owner.
    #[test]
    fn an_earlier_development_label_is_judged_with_the_development_defaults() {
        use super::super::providers::{DEVELOPMENT_REVERSIBILITY, DEVELOPMENT_RISK};
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, id) = vault_with_item(&dir);
        unlabeled(&mut vault, id);
        let mut earlier = vault.declaration(id).unwrap().expect("declaration");
        earlier.environment = agents::Environment::Development;
        vault.save_declaration(id, &earlier, None, None).unwrap();
        let labeled = DeclarationSources {
            environment: DeclarationSource::Owner,
            ..all(DeclarationSource::Default)
        };
        vault.set_declaration_sources(id, &labeled).unwrap();
        let (declaration, sources) = stored(&vault, id);
        assert!(declaration.is_sensitive(), "the stored values stay");
        let judged = sources.judged(&declaration);
        assert_eq!(
            judged,
            agents::Declaration {
                risk: DEVELOPMENT_RISK,
                reversibility: DEVELOPMENT_REVERSIBILITY,
                ..declaration.clone()
            }
        );
        assert!(!judged.is_sensitive());
        assert!(!sources.weak(Some(&declaration)));
        assert_eq!(stored(&vault, id).0, declaration, "nothing is rewritten");
        for source in [DeclarationSource::Signal, DeclarationSource::Usage] {
            let found = DeclarationSources {
                environment: source,
                ..labeled
            };
            assert_eq!(found.judged(&declaration), declaration, "{source:?}");
            assert!(found.weak(Some(&declaration)), "{source:?}");
        }
        // The same answer again now stores the development defaults.
        vault
            .set_declaration_environment(id, agents::Environment::Development)
            .unwrap();
        assert_eq!(stored(&vault, id).0, judged);
    }
}
