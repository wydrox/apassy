//! The provider of a declaration and the outcome of each suggested declaration
//! (schema v8, goal item B4).
//!
//! - A declaration names the provider that the owner confirmed, or none. The broker
//!   gives the known hosts of that provider to the command analysis.
//! - The first save of a declaration for an item records how the saved declaration
//!   compares with the suggested form: accepted as it was, or changed, and which fields
//!   changed. The record has the provider name and the field values only, never a
//!   secret value. A later change of a stored declaration is not a new record.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, TransactionBehavior};

use super::agents::{
    Declaration, Environment, MAX_PROJECT_BYTES, Reversibility, RiskLevel, Scope, checked_text,
};
use super::providers::{self, FactField, ItemFacts, Suggestion};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// The column and the table added in schema version 8 (goal item B4).
pub(super) const SCHEMA_V8_SQL: &str = "
ALTER TABLE declaration ADD COLUMN provider TEXT NOT NULL DEFAULT '';
CREATE TABLE suggestion_outcome (
    item_id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    provider TEXT NOT NULL,
    environment TEXT NOT NULL,
    risk TEXT NOT NULL,
    scope TEXT NOT NULL,
    reversibility TEXT NOT NULL,
    from_signals TEXT NOT NULL,
    changed TEXT NOT NULL,
    accepted INTEGER NOT NULL CHECK (accepted IN (0, 1))
);
UPDATE vault_meta SET schema_version = 8 WHERE id = 1;
PRAGMA user_version = 8;
";

pub(super) const SCHEMA_V8_COLUMNS: [&str; 2] = [
    "SELECT provider FROM declaration LIMIT 0",
    "SELECT item_id, at, provider, environment, risk, scope, reversibility, from_signals,
            changed, accepted FROM suggestion_outcome LIMIT 0",
];

/// A field of the declaration form that a suggestion can fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeclarationField {
    Provider,
    Environment,
    Risk,
    Scope,
    Reversibility,
}

impl DeclarationField {
    pub const ALL: [Self; 5] = [
        Self::Provider,
        Self::Environment,
        Self::Risk,
        Self::Scope,
        Self::Reversibility,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Environment => "environment",
            Self::Risk => "risk",
            Self::Scope => "scope",
            Self::Reversibility => "reversibility",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        Self::ALL
            .into_iter()
            .find(|field| field.as_str() == text)
            .ok_or_else(|| err(VaultErrorKind::Storage))
    }
}

/// The declaration form that the owner saw: the suggested values, and the most
/// sensitive default for each field without a suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedDeclaration {
    pub provider: Option<String>,
    pub environment: Environment,
    pub risk: RiskLevel,
    pub scope: Scope,
    pub reversibility: Reversibility,
    /// The fields that came from a signal, in [`DeclarationField::ALL`] order.
    pub from_signals: Vec<DeclarationField>,
}

impl SuggestedDeclaration {
    /// The fields of `saved` that differ from this form.
    pub fn changed_fields(
        &self,
        saved: &Declaration,
        provider: Option<&str>,
    ) -> Vec<DeclarationField> {
        let same = [
            self.provider.as_deref() == provider,
            self.environment == saved.environment,
            self.risk == saved.risk,
            self.scope == saved.scope,
            self.reversibility == saved.reversibility,
        ];
        DeclarationField::ALL
            .into_iter()
            .zip(same)
            .filter(|(_, same)| !same)
            .map(|(field, _)| field)
            .collect()
    }
}

/// The outcome of one suggested declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestionOutcome {
    pub item_id: u64,
    pub at: u64,
    pub suggested: SuggestedDeclaration,
    /// The fields that the owner changed before the save. Empty: accepted as it was.
    pub changed: Vec<DeclarationField>,
}

impl SuggestionOutcome {
    pub fn accepted(&self) -> bool {
        self.changed.is_empty()
    }
}

/// The share of suggestions that the owner accepted without a change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuggestionStats {
    pub total: u32,
    pub accepted: u32,
    /// For each field: the number of saves that changed it.
    pub changed: Vec<(DeclarationField, u32)>,
}

impl SuggestionStats {
    /// Accepted suggestions divided by all suggestions. `None` before the first one.
    pub fn share(&self) -> Option<f64> {
        (self.total > 0).then(|| f64::from(self.accepted) / f64::from(self.total))
    }
}

fn join_fields(fields: &[DeclarationField]) -> String {
    fields
        .iter()
        .map(|field| field.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn split_fields(text: &str) -> VaultResult<Vec<DeclarationField>> {
    text.split(',')
        .filter(|part| !part.is_empty())
        .map(DeclarationField::parse)
        .collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Vault {
    /// Suggest a declaration from the item (goal item B4). Only the owner flow calls
    /// this, with the vault unlocked. The detection reads the field values in this
    /// process, and the values are erased after it. The suggestion has no secret value.
    pub fn suggest_declaration(&self, item_id: u64) -> VaultResult<Suggestion> {
        let details = self.details(item_id)?;
        let env_name = self.env_binding(item_id)?.map(|binding| binding.env_name);
        let mut fields = Vec::with_capacity(details.fields.len());
        for field in &details.fields {
            fields.push(FactField {
                name: field.name.clone(),
                value: self.reveal(item_id, &field.name)?.into_zeroizing(),
                secret: field.secret,
            });
        }
        let facts = ItemFacts {
            title: details.summary.title,
            notes: details.notes,
            tags: details.tags,
            env_name,
            fields,
        };
        Ok(providers::suggest(&facts))
    }

    /// The provider of the declaration of an item. `None` without a declaration or
    /// without a provider.
    pub fn declaration_provider(&self, item_id: u64) -> VaultResult<Option<String>> {
        let item = to_sql_id(item_id)?;
        let provider: Option<String> = self
            .conn_ref()?
            .query_row(
                "SELECT provider FROM declaration WHERE item_id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(provider.filter(|provider| !provider.is_empty()))
    }

    /// Set or replace the declaration of an item and its provider. `provider` must be a
    /// built-in provider. `suggested` is the form that the owner saw. For the first
    /// declaration of the item, the vault records the outcome of the suggestion and
    /// returns it.
    pub fn save_declaration(
        &mut self,
        item_id: u64,
        declaration: &Declaration,
        provider: Option<&str>,
        suggested: Option<&SuggestedDeclaration>,
    ) -> VaultResult<Option<SuggestionOutcome>> {
        let item = to_sql_id(item_id)?;
        let project = checked_text(declaration.project.trim(), MAX_PROJECT_BYTES)?;
        if provider.is_some_and(|id| providers::find(id).is_none()) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let at = now_unix();
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let exists: Option<i64> = tx
            .query_row("SELECT id FROM item WHERE id = ?1", [item], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if exists.is_none() {
            return Err(err(VaultErrorKind::NotFound));
        }
        let first: bool = tx
            .query_row(
                "SELECT NOT EXISTS (SELECT 1 FROM declaration WHERE item_id = ?1)",
                [item],
                |row| row.get(0),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO declaration
                 (item_id, project, environment, risk, scope, reversibility, provider)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(item_id) DO UPDATE SET project = excluded.project,
                 environment = excluded.environment, risk = excluded.risk,
                 scope = excluded.scope, reversibility = excluded.reversibility,
                 provider = excluded.provider",
            (
                item,
                project,
                declaration.environment.as_str(),
                declaration.risk.as_str(),
                declaration.scope.as_str(),
                declaration.reversibility.as_str(),
                provider.unwrap_or_default(),
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let outcome = match suggested {
            Some(suggested) if first => {
                let outcome = SuggestionOutcome {
                    item_id,
                    at,
                    suggested: suggested.clone(),
                    changed: suggested.changed_fields(declaration, provider),
                };
                tx.execute(
                    "INSERT OR REPLACE INTO suggestion_outcome (item_id, at, provider,
                         environment, risk, scope, reversibility, from_signals, changed, accepted)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    (
                        item,
                        i64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))?,
                        suggested.provider.as_deref().unwrap_or_default(),
                        suggested.environment.as_str(),
                        suggested.risk.as_str(),
                        suggested.scope.as_str(),
                        suggested.reversibility.as_str(),
                        join_fields(&suggested.from_signals),
                        join_fields(&outcome.changed),
                        i64::from(outcome.accepted()),
                    ),
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
                Some(outcome)
            }
            _ => None,
        };
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(outcome)
    }

    /// Every recorded suggestion outcome, oldest first.
    pub fn suggestion_outcomes(&self) -> VaultResult<Vec<SuggestionOutcome>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT item_id, at, provider, environment, risk, scope, reversibility,
                        from_signals, changed
                 FROM suggestion_outcome ORDER BY at ASC, item_id ASC",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let storage = |_| err(VaultErrorKind::Storage);
        let mut outcomes = Vec::new();
        for row in rows {
            let (item, at, provider, environment, risk, scope, reversibility, from, changed) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            outcomes.push(SuggestionOutcome {
                item_id: to_public_id(item)?,
                at: u64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))?,
                suggested: SuggestedDeclaration {
                    provider: Some(provider).filter(|provider| !provider.is_empty()),
                    environment: Environment::parse(&environment).map_err(storage)?,
                    risk: RiskLevel::parse(&risk).map_err(storage)?,
                    scope: Scope::parse(&scope).map_err(storage)?,
                    reversibility: Reversibility::parse(&reversibility).map_err(storage)?,
                    from_signals: split_fields(&from)?,
                },
                changed: split_fields(&changed)?,
            });
        }
        Ok(outcomes)
    }

    /// The acceptance share and the changes for each field.
    pub fn suggestion_stats(&self) -> VaultResult<SuggestionStats> {
        let outcomes = self.suggestion_outcomes()?;
        let count = |test: &dyn Fn(&SuggestionOutcome) -> bool| {
            u32::try_from(outcomes.iter().filter(|o| test(o)).count())
                .map_err(|_| err(VaultErrorKind::Storage))
        };
        let mut changed = Vec::new();
        for field in DeclarationField::ALL {
            changed.push((field, count(&|o| o.changed.contains(&field))?));
        }
        Ok(SuggestionStats {
            total: count(&|_| true)?,
            accepted: count(&SuggestionOutcome::accepted)?,
            changed,
        })
    }
}

/// Remove the outcome of a deleted item in the same transaction.
pub(super) fn forget_item(tx: &rusqlite::Transaction<'_>, item_id: i64) -> VaultResult<()> {
    tx.execute(
        "DELETE FROM suggestion_outcome WHERE item_id = ?1",
        [item_id],
    )
    .map(|_| ())
    .map_err(|_| err(VaultErrorKind::Storage))
}
