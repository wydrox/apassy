//! Schema version 16: the device key of relay sync (ADR 0022, contract relay-sync-v1,
//! section 14.3).
//!
//! One row holds the relay address, the team, the device number on the relay, and the
//! P-256 key of this Mac. The table is local (`merge::LOCAL_TABLES`): a pushed copy
//! never carries it, so another Mac never gets this key. The agent sandbox cannot read
//! the vault file, and the row is encrypted at rest with the rest of the vault.
//!
//! The private key is the PKCS#8 document of `ring`. It lives in a [`Zeroizing`]
//! buffer while Apassy holds it. A restore keeps the row: a backup is the owner's own
//! file. An adopted copy has no row, also when the source is a raw vault file.

use std::fmt;

use rusqlite::{OptionalExtension, Transaction};
use zeroize::Zeroizing;

use super::Vault;
use super::agents::{from_sql_time, now_unix, to_sql_time};
use super::types::{VaultErrorKind, VaultResult, err};

/// Tables added in schema version 16.
pub(super) const SCHEMA_V16_SQL: &str = "
CREATE TABLE relay_device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    relay_url TEXT NOT NULL,
    team_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
UPDATE vault_meta SET schema_version = 16 WHERE id = 1;
PRAGMA user_version = 16;
";

pub(super) const SCHEMA_V16_COLUMNS: [&str; 1] = [
    "SELECT id, relay_url, team_id, device_id, public_key, key_pkcs8, created_at FROM relay_device LIMIT 0",
];

/// The longest relay address that the row keeps.
const MAX_URL_BYTES: usize = 2048;
/// The longest PKCS#8 document that the row keeps. A P-256 document of `ring` has 138
/// bytes.
const MAX_KEY_BYTES: usize = 512;

/// The relay identity of this Mac for the vault: where it syncs, as which device, with
/// which key.
pub struct RelayDevice {
    /// The relay origin, for example `https://apassy-relay.wyderka.cc`.
    pub relay_url: String,
    /// The team of the vault on the relay, for example `t_7k2m5q4x3c`.
    pub team_id: String,
    /// The device number on the relay (`"device_id": 2`).
    pub device_id: u64,
    /// The public key, a P-256 point in X9.63 form (65 bytes).
    pub public_key: Vec<u8>,
    /// The private key, PKCS#8. It is erased on drop.
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    /// Unix time when the row was written.
    pub created_at: u64,
}

impl fmt::Debug for RelayDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayDevice")
            .field("relay_url", &self.relay_url)
            .field("team_id", &self.team_id)
            .field("device_id", &self.device_id)
            .field("key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl RelayDevice {
    fn is_valid(&self) -> bool {
        let url = self.relay_url.as_str();
        let team = self.team_id.as_bytes();
        !url.is_empty()
            && url.len() <= MAX_URL_BYTES
            && url.is_ascii()
            && !url.chars().any(char::is_control)
            && team.len() == 12
            && team.starts_with(b"t_")
            && team[2..]
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && self.device_id >= 1
            && i64::try_from(self.device_id).is_ok()
            && self.public_key.len() == 65
            && self.public_key[0] == 0x04
            && !self.key_pkcs8.is_empty()
            && self.key_pkcs8.len() <= MAX_KEY_BYTES
    }
}

fn storage<T>(result: Result<T, rusqlite::Error>) -> VaultResult<T> {
    result.map_err(|_| err(VaultErrorKind::Storage))
}

/// An adopted copy never keeps the key of another Mac, also when the source is a raw
/// vault file and not a stripped copy.
pub(super) fn prepare_adopted(tx: &Transaction<'_>) -> VaultResult<()> {
    storage(tx.execute("DELETE FROM relay_device", []))?;
    Ok(())
}

impl Vault {
    /// The relay identity of this vault, or `None` when relay sync is off. The vault
    /// must be unlocked.
    pub fn relay_device(&self) -> VaultResult<Option<RelayDevice>> {
        type Row = (String, String, i64, Vec<u8>, Vec<u8>, i64);
        let row: Option<Row> = storage(
            self.conn_ref()?
                .query_row(
                    "SELECT relay_url, team_id, device_id, public_key, key_pkcs8, created_at
                     FROM relay_device WHERE id = 1",
                    [],
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
                .optional(),
        )?;
        let Some((relay_url, team_id, device_id, public_key, key, created_at)) = row else {
            return Ok(None);
        };
        let device = RelayDevice {
            relay_url,
            team_id,
            device_id: u64::try_from(device_id).map_err(|_| err(VaultErrorKind::Storage))?,
            public_key,
            key_pkcs8: Zeroizing::new(key),
            created_at: from_sql_time(created_at)?,
        };
        if device.is_valid() {
            Ok(Some(device))
        } else {
            Err(err(VaultErrorKind::Storage))
        }
    }

    /// Store the relay identity of this vault. It replaces an earlier row. The time is
    /// now; `device.created_at` is ignored. A value of a bad shape is `InvalidInput`.
    pub fn set_relay_device(&mut self, device: &RelayDevice) -> VaultResult<()> {
        if !device.is_valid() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let device_id =
            i64::try_from(device.device_id).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        storage(self.conn_ref()?.execute(
            "INSERT OR REPLACE INTO relay_device
                 (id, relay_url, team_id, device_id, public_key, key_pkcs8, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                device.relay_url,
                device.team_id,
                device_id,
                device.public_key,
                device.key_pkcs8.as_slice(),
                to_sql_time(now_unix())?,
            ],
        ))?;
        Ok(())
    }

    /// Remove the relay identity (relay sync off). Returns whether there was one.
    pub fn remove_relay_device(&mut self) -> VaultResult<bool> {
        let removed = storage(self.conn_ref()?.execute("DELETE FROM relay_device", []))?;
        Ok(removed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> RelayDevice {
        let mut public_key = vec![0x04];
        public_key.extend_from_slice(&[7u8; 64]);
        RelayDevice {
            relay_url: "https://relay.example.test".to_owned(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            device_id: 2,
            public_key,
            key_pkcs8: Zeroizing::new(vec![1u8; 138]),
            created_at: 0,
        }
    }

    #[test]
    fn the_row_round_trips_and_refuses_a_bad_shape() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("r.db"), "synthetic-relay-pass").unwrap();
        vault.unlock("synthetic-relay-pass").unwrap();
        assert!(vault.relay_device().unwrap().is_none());
        vault.set_relay_device(&device()).unwrap();
        let read = vault.relay_device().unwrap().expect("row");
        assert_eq!(read.team_id, "t_7k2m5q4x3c");
        assert_eq!(read.device_id, 2);
        assert_eq!(read.key_pkcs8.as_slice(), &[1u8; 138][..]);
        assert!(read.created_at > 0);
        assert!(!format!("{read:?}").contains("1, 1"), "the key is redacted");
        let mut other = device();
        other.device_id = 3;
        vault.set_relay_device(&other).unwrap();
        assert_eq!(vault.relay_device().unwrap().unwrap().device_id, 3);
        for bad in [
            RelayDevice {
                team_id: "t_UPPER12345".to_owned(),
                ..device()
            },
            RelayDevice {
                device_id: 0,
                ..device()
            },
            RelayDevice {
                public_key: vec![0x04; 33],
                ..device()
            },
            RelayDevice {
                relay_url: String::new(),
                ..device()
            },
            RelayDevice {
                key_pkcs8: Zeroizing::new(Vec::new()),
                ..device()
            },
        ] {
            assert_eq!(
                vault.set_relay_device(&bad).unwrap_err().kind(),
                VaultErrorKind::InvalidInput
            );
        }
        assert!(vault.remove_relay_device().unwrap());
        assert!(!vault.remove_relay_device().unwrap());
        assert!(vault.relay_device().unwrap().is_none());
        vault.lock().unwrap();
        assert_eq!(
            vault.relay_device().unwrap_err().kind(),
            VaultErrorKind::Locked
        );
    }
}
