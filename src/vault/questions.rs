//! The question key of the vault (stage 5, contract relay-questions-v1 section 5.1).
//!
//! The key seals the questions and the answers that go through the relay. It is 32
//! random bytes in the synced `vault_secret` row `question-key-v1`, so every device that
//! holds the vault gets it through its sync, and the row merges last-writer-wins by
//! `(updated_at, updated_by)` like the other rows of `vault_secret`. The first Mac that
//! turns "Send questions through the relay" on makes it ([`Vault::ensure_question_key`]).
//!
//! The key never leaves the vault in clear: it is never sent to the relay, never logged,
//! and lives in a [`Zeroizing`] buffer while Apassy holds it. The wire names it by its
//! `key_id` ([`question_key_id`]). Removing a trusted device writes a new key
//! ([`Vault::remove_trusted_device_and_rotate`]); the questions already posted keep the
//! key that sealed them in the memory of the asking Mac until they end.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::Vault;
use super::types::{VaultErrorKind, VaultResult, err};

/// The `vault_secret` row of the question key.
pub const QUESTION_KEY_NAME: &str = "question-key-v1";
/// The `vault_secret` row that names the questions team of the vault (its team ID), so a
/// second Mac joins that team instead of making another one.
pub const QUESTIONS_TEAM_NAME: &str = "questions-team-v1";
/// The length of the question key.
pub const QUESTION_KEY_BYTES: usize = 32;

/// The question key: 32 bytes, erased on drop. Debug is redacted.
#[derive(Clone)]
pub struct QuestionKey(Zeroizing<[u8; QUESTION_KEY_BYTES]>);

impl std::fmt::Debug for QuestionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuestionKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl QuestionKey {
    /// A key from its bytes, for a test vector or a key that a device already holds.
    pub fn from_bytes(bytes: [u8; QUESTION_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The key bytes. Never print them.
    pub fn bytes(&self) -> &[u8; QUESTION_KEY_BYTES] {
        &self.0
    }

    /// The name of the key on the wire: `hex(SHA-256(key)[0..8])`.
    pub fn key_id(&self) -> String {
        question_key_id(self.bytes())
    }
}

/// `hex(SHA-256(key)[0..8])`: 16 lowercase hex characters.
pub fn question_key_id(key: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key);
    super::to_hex(&digest.as_ref()[..8])
}

fn storage<E>(_: E) -> super::VaultError {
    err(VaultErrorKind::Storage)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// The stored key, or `None`. A row of another length is `Storage`.
fn read_key(conn: &Connection) -> VaultResult<Option<(QuestionKey, i64)>> {
    let row: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT value, updated_at FROM vault_secret WHERE name = ?1",
            [QUESTION_KEY_NAME],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let Some((value, updated_at)) = row else {
        return Ok(None);
    };
    let value = Zeroizing::new(value);
    let bytes: [u8; QUESTION_KEY_BYTES] = value
        .as_slice()
        .try_into()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(Some((QuestionKey::from_bytes(bytes), updated_at)))
}

/// Write `key` as a new version of the row after `previous`, by this device.
fn write_key(conn: &Connection, key: &QuestionKey, previous: Option<i64>) -> VaultResult<()> {
    write_secret(conn, QUESTION_KEY_NAME, key.bytes().as_slice(), previous)
}

/// Write the `vault_secret` row `name` as a new version after `previous`, by this device.
fn write_secret(
    conn: &Connection,
    name: &str,
    value: &[u8],
    previous: Option<i64>,
) -> VaultResult<()> {
    let device: Option<String> = conn
        .query_row(
            "SELECT device_id FROM sync_device WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    let at = match previous {
        Some(previous) => now_ms().max(previous.saturating_add(1)),
        None => now_ms(),
    };
    conn.execute(
        "INSERT INTO vault_secret (name, value, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(name) DO UPDATE SET value = excluded.value,
             updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        rusqlite::params![name, value, at, device.unwrap_or_default()],
    )
    .map_err(storage)?;
    Ok(())
}

fn random_key() -> VaultResult<QuestionKey> {
    let mut bytes = Zeroizing::new([0u8; QUESTION_KEY_BYTES]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(QuestionKey(bytes))
}

impl Vault {
    /// The question key of the vault, or `None` when no Mac made one yet.
    pub fn question_key(&self) -> VaultResult<Option<QuestionKey>> {
        Ok(read_key(self.conn_ref()?)?.map(|(key, _)| key))
    }

    /// The question key; a new random key when the vault has none.
    pub fn ensure_question_key(&mut self) -> VaultResult<QuestionKey> {
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some((key, _)) = read_key(&tx)? {
            return Ok(key);
        }
        let key = random_key()?;
        write_key(&tx, &key, None)?;
        tx.commit().map_err(storage)?;
        Ok(key)
    }

    /// Write a new random question key, also when the vault has none. A new question
    /// uses it; the devices get it through the sync.
    pub fn rotate_question_key(&mut self) -> VaultResult<QuestionKey> {
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let previous = read_key(&tx)?.map(|(_, at)| at);
        let key = random_key()?;
        write_key(&tx, &key, previous)?;
        tx.commit().map_err(storage)?;
        Ok(key)
    }

    /// The team ID of the questions team of the vault, when a Mac made or joined one
    /// (`vault_secret` row [`QUESTIONS_TEAM_NAME`]). A row of a bad shape is no team.
    pub fn questions_team(&self) -> VaultResult<Option<String>> {
        let value: Option<Vec<u8>> = self
            .conn_ref()?
            .query_row(
                "SELECT value FROM vault_secret WHERE name = ?1",
                [QUESTIONS_TEAM_NAME],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        Ok(value
            .and_then(|value| String::from_utf8(value).ok())
            .filter(|team| super::relay_device::valid_team_id(team)))
    }

    /// Name `team_id` as the questions team of the vault. The same team changes nothing.
    /// `InvalidInput`: a team ID of a bad shape.
    pub fn set_questions_team(&mut self, team_id: &str) -> VaultResult<()> {
        if !super::relay_device::valid_team_id(team_id) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if self.questions_team()?.as_deref() == Some(team_id) {
            return Ok(());
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT updated_at FROM vault_secret WHERE name = ?1",
                [QUESTIONS_TEAM_NAME],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        write_secret(&tx, QUESTIONS_TEAM_NAME, team_id.as_bytes(), previous)?;
        tx.commit().map_err(storage)
    }

    /// Remove a trusted device (Settings > Devices) and, when it was live and the vault
    /// has a question key, write a new key: the removed device cannot read the next
    /// questions. Returns whether a live device was removed.
    pub fn remove_trusted_device_and_rotate(&mut self, uuid: &str) -> VaultResult<bool> {
        if !self.remove_trusted_device(uuid)? {
            return Ok(false);
        }
        if self.question_key()?.is_some() {
            self.rotate_question_key()?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::TrustedDeviceKind;

    const PASS: &str = "synthetic-question-pass";

    fn unlocked(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("q.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    #[test]
    fn the_contract_key_gives_its_key_id() {
        let mut bytes = [0u8; 32];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = at as u8;
        }
        assert_eq!(question_key_id(&bytes), "630dcd2966c43366");
        let key = QuestionKey::from_bytes(bytes);
        assert_eq!(key.key_id(), "630dcd2966c43366");
        let debug = format!("{key:?}");
        assert!(
            debug.contains("630dcd2966c43366") && !debug.contains("[0, 1"),
            "{debug}"
        );
    }

    #[test]
    fn ensure_makes_one_key_and_rotate_replaces_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        assert!(vault.question_key().unwrap().is_none());
        let first = vault.ensure_question_key().unwrap();
        assert_eq!(vault.ensure_question_key().unwrap().bytes(), first.bytes());
        assert_eq!(
            vault.question_key().unwrap().unwrap().bytes(),
            first.bytes()
        );
        let second = vault.rotate_question_key().unwrap();
        assert_ne!(second.bytes(), first.bytes());
        assert_ne!(second.key_id(), first.key_id());
        assert_eq!(
            vault.question_key().unwrap().unwrap().bytes(),
            second.bytes()
        );
        vault.lock().unwrap();
        assert_eq!(
            vault.question_key().unwrap_err().kind(),
            VaultErrorKind::Locked
        );
    }

    #[test]
    fn the_questions_team_is_named_in_the_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        assert_eq!(vault.questions_team().unwrap(), None);
        vault.set_questions_team("t_7k2m5q4x3c").unwrap();
        assert_eq!(
            vault.questions_team().unwrap().as_deref(),
            Some("t_7k2m5q4x3c")
        );
        vault.set_questions_team("t_7k2m5q4x3c").unwrap();
        assert_eq!(
            vault.set_questions_team("team").unwrap_err().kind(),
            VaultErrorKind::InvalidInput
        );
        vault.set_questions_team("t_aaaaaaaaaa").unwrap();
        assert_eq!(
            vault.questions_team().unwrap().as_deref(),
            Some("t_aaaaaaaaaa")
        );
    }

    #[test]
    fn removing_a_device_rotates_the_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        let mut point = vec![0x04];
        point.extend_from_slice(&[5u8; 64]);
        vault
            .register_trusted_device("phone-1", "Phone", TrustedDeviceKind::Iphone, &point, None)
            .unwrap();
        // No key yet: a removal makes none.
        assert!(vault.remove_trusted_device_and_rotate("phone-1").unwrap());
        assert!(vault.question_key().unwrap().is_none());
        // The removed key never registers again: the next phone has its own.
        point[1] = 6;
        vault
            .register_trusted_device("phone-2", "Phone", TrustedDeviceKind::Iphone, &point, None)
            .unwrap();
        let before = vault.ensure_question_key().unwrap();
        assert!(!vault.remove_trusted_device_and_rotate("nobody").unwrap());
        assert_eq!(
            vault.question_key().unwrap().unwrap().bytes(),
            before.bytes()
        );
        assert!(vault.remove_trusted_device_and_rotate("phone-2").unwrap());
        assert_ne!(
            vault.question_key().unwrap().unwrap().bytes(),
            before.bytes()
        );
    }
}
