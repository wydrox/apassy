//! Reading a `vault_secret` row (schema 18): a named secret of the vault that syncs
//! last-writer-wins, for example the question key `question-key-v1` (contract
//! relay-questions-v1, section 5.1). The iPhone core reads the key that a Mac made; it
//! never makes one.

use rusqlite::OptionalExtension;
use zeroize::Zeroizing;

use super::Vault;
use super::types::{VaultErrorKind, VaultResult, err};

impl Vault {
    /// The value of the vault secret `name`, or `None` when the vault has none. The value
    /// is erased on drop.
    pub fn read_vault_secret(&self, name: &str) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        let conn = self.conn_ref()?;
        let value: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM vault_secret WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(value.map(Zeroizing::new))
    }
}
