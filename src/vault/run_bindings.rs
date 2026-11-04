//! The variables that a run gets for one item beside its process binding, and the rule
//! that a source whose way C is on gets no long-lived value (contract private-sharing-v1
//! rules 2 and 4, plan s6 units D and F).
//!
//! Until unit F makes leases in the run paths, [`LEASES_IN_RUNS`] is `false`:
//!
//! - Detection writes the `short_lived` row of a new source off (`enabled = 0`), so a
//!   pasted AWS pair or service-account key is a static key that runs can use.
//! - A static source gets the variables of its static form ([`static_variable`]): an
//!   AWS source `AWS_ACCESS_KEY_ID` ← `access_key_id` and `AWS_SECRET_ACCESS_KEY` ←
//!   `secret_access_key`; a Google service account its key JSON in the variable of the
//!   provider (`GOOGLE_API_KEY`, as before unit D). The key JSON never goes into
//!   `CLOUDSDK_AUTH_ACCESS_TOKEN`, the variable of an access token.
//! - A run of a source whose way C is on fails with `lease_failed` before the owner is
//!   asked and again before the values are read ([`Vault::run_extra_bindings`]); no run
//!   path gives the long-lived value, a placeholder of it, or an older lease instead.

use rusqlite::OptionalExtension;

use super::agents::{EnvBinding, EnvDelivery};
use super::short_lived::ShortLivedKind;
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_sql_id};

/// Whether the run paths make a lease for a source whose way C is on (plan s6 unit F).
/// `false` until unit F lands; unit F flips it.
pub const LEASES_IN_RUNS: bool = false;

/// The variable of the AWS access key id in the static form of an AWS source.
pub const AWS_KEY_ID_VARIABLE: &str = "AWS_ACCESS_KEY_ID";
/// The variable of the AWS secret access key in the static form of an AWS source.
pub const AWS_SECRET_VARIABLE: &str = "AWS_SECRET_ACCESS_KEY";
/// The variable of a Google service-account key JSON in its static form: the variable
/// of the `gcp` provider pack, which a pasted key JSON had before unit D.
pub const GOOGLE_KEY_VARIABLE: &str = "GOOGLE_API_KEY";

/// The variable of the bound field of a static source of `kind`, when the kind has a
/// fixed static form: `AWS_SECRET_ACCESS_KEY` (field `secret_access_key`; the run adds
/// `AWS_ACCESS_KEY_ID` from `access_key_id`) or `GOOGLE_API_KEY` (field `key_json`).
pub fn static_variable(kind: ShortLivedKind) -> Option<(&'static str, &'static str)> {
    match kind {
        ShortLivedKind::AwsSts => Some((AWS_SECRET_VARIABLE, "secret_access_key")),
        ShortLivedKind::GoogleServiceAccount => Some((GOOGLE_KEY_VARIABLE, "key_json")),
        _ => None,
    }
}

/// The variables that a run of a static source of `kind` gets, for the owner's texts.
pub fn static_variable_names(kind: ShortLivedKind) -> Option<&'static str> {
    match kind {
        ShortLivedKind::AwsSts => Some("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"),
        ShortLivedKind::GoogleServiceAccount => Some(GOOGLE_KEY_VARIABLE),
        _ => None,
    }
}

/// Why a run cannot take an item as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunBindingError {
    /// Way C is on and this build makes no lease in a run (rule 4: no fallback).
    LeaseFailed,
    /// The static form needs a field that the item does not have, or a variable that
    /// does not fit the static form (the key JSON in `CLOUDSDK_AUTH_ACCESS_TOKEN`, the
    /// secret in `AWS_ACCESS_KEY_ID`).
    NeedsField(&'static str),
    /// The vault could not be read.
    Vault(VaultErrorKind),
}

impl RunBindingError {
    /// The wire code of the refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::LeaseFailed => "lease_failed",
            Self::NeedsField(_) => "needs_field",
            Self::Vault(_) => "broker_error",
        }
    }

    /// The text of the refusal for item `item_id`. It names no value.
    pub fn message(&self, item_id: u64) -> String {
        match self {
            Self::LeaseFailed => format!(
                "Item {item_id} gives temporary credentials, and this version of Apassy does not make them in runs yet. The run did not start; the long-lived key is not given instead. The owner can stop temporary credentials for the item in Apassy."
            ),
            Self::NeedsField(why) => format!("Item {item_id} cannot be used as it is: {why}"),
            Self::Vault(_) => {
                format!("The broker cannot read the temporary credentials of item {item_id}.")
            }
        }
    }
}

impl From<super::types::VaultError> for RunBindingError {
    fn from(error: super::types::VaultError) -> Self {
        Self::Vault(error.kind())
    }
}

impl Vault {
    /// The variables that a run of `item_id` gets beside its process binding
    /// ([`Vault::process_binding`]), checked against the binding:
    ///
    /// - [`RunBindingError::LeaseFailed`]: the item has a `short_lived` row that is on.
    ///   The run paths call this before they ask the owner and again before they read
    ///   the values. While [`LEASES_IN_RUNS`] is `false` no run path makes the lease, so
    ///   such a run never starts (rule 4).
    /// - A static AWS source: `AWS_ACCESS_KEY_ID` from the plain field `access_key_id`,
    ///   real value. Its binding must not be `AWS_ACCESS_KEY_ID` itself (the layout of a
    ///   lease), and the field must have a value.
    /// - A static Google source: nothing more; its binding must not be
    ///   `CLOUDSDK_AUTH_ACCESS_TOKEN`.
    /// - Any other item: nothing more.
    pub fn run_extra_bindings(&self, item_id: u64) -> Result<Vec<EnvBinding>, RunBindingError> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let row: Option<(String, bool)> = conn
            .query_row(
                "SELECT kind, enabled FROM short_lived WHERE item_id = ?1",
                [item],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let Some((kind, enabled)) = row else {
            return Ok(Vec::new());
        };
        if enabled {
            return Err(RunBindingError::LeaseFailed);
        }
        let binding = self.process_binding(item_id)?;
        match ShortLivedKind::parse(&kind) {
            Some(ShortLivedKind::AwsSts) => {
                if binding
                    .as_ref()
                    .is_some_and(|binding| binding.env_name == AWS_KEY_ID_VARIABLE)
                {
                    return Err(RunBindingError::NeedsField(
                        "AWS_ACCESS_KEY_ID takes the access key id, not the secret access key. The owner can bind the secret to AWS_SECRET_ACCESS_KEY in Apassy.",
                    ));
                }
                let has_id: bool = conn
                    .query_row(
                        "SELECT EXISTS (SELECT 1 FROM item_field
                         WHERE item_id = ?1 AND name = 'access_key_id' AND length(value) > 0)",
                        [item],
                        |row| row.get(0),
                    )
                    .map_err(|_| err(VaultErrorKind::Storage))?;
                if !has_id {
                    return Err(RunBindingError::NeedsField(
                        "the AWS item has no access key id.",
                    ));
                }
                Ok(vec![EnvBinding {
                    item_id,
                    env_name: AWS_KEY_ID_VARIABLE.to_owned(),
                    field: "access_key_id".to_owned(),
                    delivery: EnvDelivery::Value,
                }])
            }
            Some(ShortLivedKind::GoogleServiceAccount) => {
                if binding.as_ref().is_some_and(|binding| {
                    binding.env_name
                        == ShortLivedKind::GoogleServiceAccount
                            .detected_variable()
                            .unwrap_or_default()
                }) {
                    return Err(RunBindingError::NeedsField(
                        "CLOUDSDK_AUTH_ACCESS_TOKEN takes an access token, not a service-account key. The owner can bind the key to GOOGLE_API_KEY in Apassy.",
                    ));
                }
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Whether a run of `item_id` would fail with `lease_failed`: the item has a
    /// `short_lived` row that is on (see [`Vault::run_extra_bindings`]).
    pub fn run_needs_lease(&self, item_id: u64) -> VaultResult<bool> {
        let item = to_sql_id(item_id)?;
        self.conn_ref()?
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM short_lived WHERE item_id = ?1 AND enabled = 1)",
                [item],
                |row| row.get(0),
            )
            .map_err(|_| err(VaultErrorKind::Storage))
    }
}
