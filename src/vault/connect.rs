//! Local, SQLCipher-encrypted Connect staging. Commit the key before any network write.
//! Schema 21 adds no synced data. An adopted/exported copy never carries this key.
use super::types::err;
use super::{Vault, VaultErrorKind, VaultResult};
use rusqlite::OptionalExtension;
use zeroize::Zeroizing;

pub(super) const COLUMNS: [&str; 1] = [
    "SELECT id, relay_url, team_name, device_name, key_pkcs8, team_id, device_id FROM relay_connect_pending LIMIT 0",
];

pub(super) fn add_schema(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(
        "CREATE TABLE relay_connect_pending (
        id INTEGER PRIMARY KEY CHECK (id = 1), relay_url TEXT NOT NULL,
        team_name TEXT NOT NULL, device_name TEXT NOT NULL, key_pkcs8 BLOB NOT NULL,
        team_id TEXT, device_id INTEGER);
        UPDATE vault_meta SET schema_version = 21 WHERE id = 1; PRAGMA user_version = 21;",
    )
    .map_err(|_| err(VaultErrorKind::Storage))
}

/// A recoverable creation attempt. Debug never prints its key.
pub struct PendingConnect {
    pub relay_url: String,
    pub team_name: String,
    pub device_name: String,
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    pub created: Option<(String, u64)>,
}

impl std::fmt::Debug for PendingConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingConnect")
            .field("relay_url", &self.relay_url)
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

impl Vault {
    pub fn pending_connect(&self) -> VaultResult<Option<PendingConnect>> {
        self.conn_ref()?.query_row(
            "SELECT relay_url, team_name, device_name, key_pkcs8, team_id, device_id FROM relay_connect_pending WHERE id = 1", [],
            |row| {
                let team: Option<String> = row.get(4)?;
                let device: Option<i64> = row.get(5)?;
                Ok(PendingConnect { relay_url: row.get(0)?, team_name: row.get(1)?, device_name: row.get(2)?,
                    key_pkcs8: Zeroizing::new(row.get(3)?), created: team.zip(device.and_then(|n| u64::try_from(n).ok())) })
            }).optional().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Insert only: an ambiguous attempt is never replaced by a fresh key or origin.
    pub fn keep_pending_connect(&mut self, pending: &PendingConnect) -> VaultResult<()> {
        self.conn_mut()?.execute(
            "INSERT INTO relay_connect_pending (id, relay_url, team_name, device_name, key_pkcs8) VALUES (1, ?1, ?2, ?3, ?4)",
            (&pending.relay_url, &pending.team_name, &pending.device_name, pending.key_pkcs8.as_slice()))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(())
    }

    /// Keep the response before adoption. Re-enabling uses this identity without creating a team.
    pub fn keep_connect_result(&mut self, membership: &super::RelayMembership) -> VaultResult<()> {
        let changed = self.conn_mut()?.execute(
            "UPDATE relay_connect_pending SET team_id = ?1, device_id = ?2 WHERE id = 1 AND relay_url = ?3 AND key_pkcs8 = ?4",
            (&membership.team_id, i64::try_from(membership.device_id).map_err(|_| err(VaultErrorKind::InvalidInput))?, &membership.relay_url, membership.key_pkcs8.as_slice()))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if changed != 1 {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        Ok(())
    }
}

impl Vault {
    /// Preserve the sync version of the key when handing it to a confirmed device.
    pub fn question_key_for_handoff(&self) -> VaultResult<(super::QuestionKey, i64, String)> {
        let key = self
            .question_key()?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        let (at, by) = self
            .conn_ref()?
            .query_row(
                "SELECT updated_at, updated_by FROM vault_secret WHERE name = 'question-key-v1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok((key, at, by))
    }

    /// Import only a QR-authenticated handoff for the same iCloud vault, after confirmed join.
    /// Keep original sync versions and never revive a removed key or row. All writes commit together.
    pub fn adopt_question_handoff(
        &mut self,
        handoff: &crate::relay::pairing::Handoff,
        membership: &super::RelayMembership,
        answer_key: &[u8],
        replaces: Option<&str>,
    ) -> VaultResult<()> {
        let recipient = membership.public_key.as_slice();
        let device_id = membership.device_id;
        let invalid = || err(VaultErrorKind::InvalidInput);
        if !super::relay_device::valid_relay_identity(
            &membership.relay_url,
            &membership.team_id,
            membership.device_id,
            &membership.public_key,
            &membership.key_pkcs8,
        ) || membership.purposes
            != std::collections::BTreeSet::from([super::MembershipPurpose::Questions])
            || handoff.team_id != membership.team_id
            || handoff.v != 1
            || handoff.vault_id != self.sync_identity()?.vault_id
            || handoff.recipient != recipient
            || handoff.question_key.len() != 32
            || handoff.key_updated_at < 0
            || handoff.devices.len() > 50
            || !handoff.devices.iter().any(|d| {
                d.sign_key == recipient
                    && d.answer_key.as_deref() == Some(answer_key)
                    && d.relay_devices.get(&handoff.team_id) == Some(&device_id)
            })
        {
            return Err(invalid());
        }
        let tx = self
            .conn_mut()?
            .transaction()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        for device in &handoff.devices {
            if !crate::relay::membership::valid_device_uuid(&device.uuid)
                || device.name.trim().is_empty()
                || device.name.len() > 64
                || device.name.chars().any(char::is_control)
                || device.sign_key.len() != 65
                || device.sign_key[0] != 4
                || device
                    .answer_key
                    .as_ref()
                    .is_some_and(|k| k.len() != 65 || k[0] != 4)
                || device
                    .relay_devices
                    .get(&handoff.team_id)
                    .is_none_or(|id| *id == 0 || i64::try_from(*id).is_err())
                || device.relay_devices.len() > 10
                || device.relay_devices.iter().any(|(t, id)| {
                    !super::relay_device::valid_team_id(t)
                        || *id == 0
                        || i64::try_from(*id).is_err()
                })
                || device.updated_at < 0
                || super::trusted_device::key_removed(&tx, &device.sign_key)?
                || device
                    .answer_key
                    .as_ref()
                    .is_some_and(|k| super::trusted_device::key_removed(&tx, k).unwrap_or(true))
            {
                return Err(invalid());
            }
            let deleted: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM trusted_device WHERE uuid = ?1 AND deleted_at IS NOT NULL)", [&device.uuid], |r| r.get(0)).map_err(|_| err(VaultErrorKind::Storage))?;
            if deleted {
                return Err(invalid());
            }
            let relay_devices =
                serde_json::to_string(&device.relay_devices).map_err(|_| invalid())?;
            tx.execute("INSERT INTO trusted_device (uuid, name, kind, relay_devices, sign_key, answer_key, created_at, updated_at, updated_by)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(uuid) DO UPDATE SET name=excluded.name, kind=excluded.kind, relay_devices=excluded.relay_devices,
                    sign_key=excluded.sign_key, answer_key=excluded.answer_key, updated_at=excluded.updated_at, updated_by=excluded.updated_by
                WHERE trusted_device.deleted_at IS NULL AND (trusted_device.updated_at, trusted_device.updated_by) < (excluded.updated_at, excluded.updated_by)",
                rusqlite::params![device.uuid, device.name, device.kind.as_str(), relay_devices, device.sign_key, device.answer_key,
                    i64::try_from(device.created_at).map_err(|_| invalid())?, device.updated_at, device.updated_by]).map_err(|_| err(VaultErrorKind::Storage))?;
        }
        let newer: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM vault_secret WHERE name = 'question-key-v1' AND value != ?1 AND (updated_at, updated_by) > (?2, ?3))",
            rusqlite::params![handoff.question_key.as_slice(), handoff.key_updated_at, handoff.key_updated_by], |r| r.get(0)).map_err(|_| err(VaultErrorKind::Storage))?;
        if newer {
            return Err(invalid());
        }
        tx.execute("INSERT INTO vault_secret (name, value, updated_at, updated_by) VALUES ('question-key-v1', ?1, ?2, ?3)
            ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by
            WHERE (vault_secret.updated_at, vault_secret.updated_by) <= (excluded.updated_at, excluded.updated_by)",
            rusqlite::params![handoff.question_key.as_slice(), handoff.key_updated_at, handoff.key_updated_by]).map_err(|_| err(VaultErrorKind::Storage))?;
        if let Some(team) = replaces {
            if team != membership.team_id {
                return Err(invalid());
            }
            let previous = super::trusted_device::load_memberships(&tx, Some(team))?;
            let Some(previous) = previous.first() else {
                return Err(invalid());
            };
            if previous.purposes != membership.purposes
                || !super::trusted_device::key_removed(&tx, &previous.public_key)?
            {
                return Err(invalid());
            }
            tx.execute("DELETE FROM relay_membership WHERE team_id = ?1", [team])
                .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        tx.execute("INSERT INTO relay_membership (team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, '[\"questions\"]', ?6)",
            rusqlite::params![membership.team_id, membership.relay_url, i64::try_from(device_id).map_err(|_| invalid())?,
                membership.public_key, membership.key_pkcs8.as_slice(), super::agents::to_sql_time(super::agents::now_unix())?])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema20_upgrades_without_recreating_existing_scopes_or_a_pending_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("synthetic-schema20.apassy");
        let pass = "synthetic-connect-migration";
        let mut vault = Vault::create(&file, pass).unwrap();
        vault.unlock(pass).unwrap();
        vault.lock().unwrap();
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", pass).unwrap();
        conn.execute_batch("DROP TABLE relay_connect_pending; UPDATE vault_meta SET schema_version=20; PRAGMA user_version=20;").unwrap();
        conn.close().unwrap();
        vault.unlock(pass).unwrap();
        assert!(vault.pending_connect().unwrap().is_none());
        let version: i64 = vault
            .conn_ref()
            .unwrap()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 21);
        let count: i64 = vault
            .conn_ref()
            .unwrap()
            .query_row("SELECT count(*) FROM bouncer_scope", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
