//! Schema version 16: the device key of relay sync (ADR 0022, contract relay-sync-v1,
//! section 14.3).
//!
//! The relay identity of the vault for sync: the relay address, the team, the device
//! number on the relay, and the P-256 key of this Mac. Schema 16 kept it in the one-row
//! table `relay_device`; schema 19 moved the row to `relay_membership` with the purpose
//! `sync` (one key pair per relay team, [`super::trusted_device`]) and dropped the old
//! table. [`RelayDevice`] and the methods here are the view of relay sync on that
//! membership, so the sync code keeps its API.
//!
//! The table is local (`merge::LOCAL_TABLES`): a pushed copy never carries it, so
//! another Mac never gets this key. The agent sandbox cannot read the vault file, and
//! the row is encrypted at rest with the rest of the vault.
//!
//! The private key is the PKCS#8 document of `ring`. It lives in a [`Zeroizing`]
//! buffer while Apassy holds it. A restore keeps the row: a backup is the owner's own
//! file. An adopted copy has no row, also when the source is a raw vault file.

use std::fmt;

use rusqlite::{Connection, Transaction, TransactionBehavior};
use zeroize::Zeroizing;

use super::Vault;
use super::agents::{now_unix, to_sql_time};
use super::trusted_device::{MembershipPurpose, RelayMembership, load_memberships, purposes_json};
use super::types::{VaultErrorKind, VaultResult, err};

/// Tables added in schema version 16. Schema 19 drops the table after it moves the row.
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

/// The columns of `relay_device`, for a file or a copy of schema 16, 17, or 18.
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
        valid_relay_identity(
            &self.relay_url,
            &self.team_id,
            self.device_id,
            &self.public_key,
            &self.key_pkcs8,
        )
    }
}

/// The shape of a relay identity: an ASCII address without control characters, a team
/// `t_` with 10 lowercase letters or digits, a device number from 1, a P-256 point in
/// X9.63 form, and a PKCS#8 document of at most [`MAX_KEY_BYTES`].
pub(super) fn valid_relay_identity(
    relay_url: &str,
    team_id: &str,
    device_id: u64,
    public_key: &[u8],
    key_pkcs8: &[u8],
) -> bool {
    !relay_url.is_empty()
        && relay_url.len() <= MAX_URL_BYTES
        && relay_url.is_ascii()
        && !relay_url.chars().any(char::is_control)
        && valid_team_id(team_id)
        && device_id >= 1
        && i64::try_from(device_id).is_ok()
        && public_key.len() == 65
        && public_key[0] == 0x04
        && !key_pkcs8.is_empty()
        && key_pkcs8.len() <= MAX_KEY_BYTES
}

/// A relay team ID: `t_` and 10 lowercase letters or digits.
pub(super) fn valid_team_id(team_id: &str) -> bool {
    let team = team_id.as_bytes();
    team.len() == 12
        && team.starts_with(b"t_")
        && team[2..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn storage<T>(result: Result<T, rusqlite::Error>) -> VaultResult<T> {
    result.map_err(|_| err(VaultErrorKind::Storage))
}

/// An adopted copy never keeps the keys of another Mac, also when the source is a raw
/// vault file and not a stripped copy. The new file has the current schema here.
pub(super) fn prepare_adopted(tx: &Transaction<'_>) -> VaultResult<()> {
    storage(tx.execute("DELETE FROM relay_membership", []))?;
    Ok(())
}

/// The membership with the purpose `sync`. At most one has it.
pub(super) fn sync_membership(conn: &Connection) -> VaultResult<Option<RelayMembership>> {
    Ok(load_memberships(conn, None)?
        .into_iter()
        .find(|membership| membership.purposes.contains(&MembershipPurpose::Sync)))
}

/// Take the purpose `sync` from `membership`: the row goes when it has no other purpose.
fn drop_sync(tx: &Transaction<'_>, membership: &RelayMembership) -> VaultResult<()> {
    let mut rest = membership.purposes.clone();
    rest.remove(&MembershipPurpose::Sync);
    if rest.is_empty() {
        storage(tx.execute(
            "DELETE FROM relay_membership WHERE team_id = ?1",
            [&membership.team_id],
        ))?;
    } else {
        storage(tx.execute(
            "UPDATE relay_membership SET purposes = ?1 WHERE team_id = ?2",
            (purposes_json(&rest), &membership.team_id),
        ))?;
    }
    Ok(())
}

impl Vault {
    /// The relay identity of this vault, or `None` when relay sync is off: the relay
    /// membership with the purpose `sync`. The vault must be unlocked.
    pub fn relay_device(&self) -> VaultResult<Option<RelayDevice>> {
        let Some(membership) = sync_membership(self.conn_ref()?)? else {
            return Ok(None);
        };
        let device = RelayDevice {
            relay_url: membership.relay_url,
            team_id: membership.team_id,
            device_id: membership.device_id,
            public_key: membership.public_key,
            key_pkcs8: membership.key_pkcs8,
            created_at: membership.created_at,
        };
        if device.is_valid() {
            Ok(Some(device))
        } else {
            Err(err(VaultErrorKind::Storage))
        }
    }

    /// Store the relay identity of this vault: the membership of its team gets the
    /// purpose `sync` and this address, device number, and key (one key pair per team).
    /// It replaces an earlier identity: another team loses the purpose `sync`, and its
    /// row goes when it has no other purpose. The time is now; `device.created_at` is
    /// ignored. A value of a bad shape is `InvalidInput`.
    pub fn set_relay_device(&mut self, device: &RelayDevice) -> VaultResult<()> {
        if !device.is_valid() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let device_id =
            i64::try_from(device.device_id).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let now = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = storage(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if let Some(old) = sync_membership(&tx)?
            && old.team_id != device.team_id
        {
            drop_sync(&tx, &old)?;
        }
        let mut purposes = load_memberships(&tx, Some(&device.team_id))?
            .pop()
            .map(|membership| membership.purposes)
            .unwrap_or_default();
        purposes.insert(MembershipPurpose::Sync);
        storage(tx.execute(
            "INSERT INTO relay_membership
                 (team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(team_id) DO UPDATE SET relay_url = excluded.relay_url,
                 device_id = excluded.device_id, public_key = excluded.public_key,
                 key_pkcs8 = excluded.key_pkcs8, purposes = excluded.purposes,
                 created_at = excluded.created_at",
            rusqlite::params![
                device.team_id,
                device.relay_url,
                device_id,
                device.public_key,
                device.key_pkcs8.as_slice(),
                purposes_json(&purposes),
                now,
            ],
        ))?;
        storage(tx.commit())
    }

    /// Remove the relay identity (relay sync off): the membership loses the purpose
    /// `sync`, and the row goes when it has no other purpose, so the questions keep
    /// theirs. Returns whether there was one.
    pub fn remove_relay_device(&mut self) -> VaultResult<bool> {
        let conn = self.conn_mut()?;
        let tx = storage(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let Some(old) = sync_membership(&tx)? else {
            return Ok(false);
        };
        drop_sync(&tx, &old)?;
        storage(tx.commit())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

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

    /// Relay sync is the purpose `sync` of one membership: turning sync off keeps a
    /// membership that the questions use, and sync on another team moves the purpose.
    #[test]
    fn the_sync_purpose_lives_on_one_membership() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("m.db"), "synthetic-relay-pass").unwrap();
        vault.unlock("synthetic-relay-pass").unwrap();
        vault.set_relay_device(&device()).unwrap();
        let both = BTreeSet::from([MembershipPurpose::Sync, MembershipPurpose::Questions]);
        vault
            .set_membership_purposes("t_7k2m5q4x3c", &both)
            .unwrap();
        // Sync off: the questions keep the membership and its key.
        assert!(vault.remove_relay_device().unwrap());
        assert!(vault.relay_device().unwrap().is_none());
        let kept = vault.relay_membership("t_7k2m5q4x3c").unwrap().unwrap();
        assert_eq!(
            kept.purposes,
            BTreeSet::from([MembershipPurpose::Questions])
        );
        assert_eq!(kept.key_pkcs8.as_slice(), &[1u8; 138][..]);
        // Sync on the same team again: one row, both purposes, the new key.
        let mut again = device();
        again.key_pkcs8 = Zeroizing::new(vec![2u8; 138]);
        vault.set_relay_device(&again).unwrap();
        let memberships = vault.relay_memberships().unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].purposes, both);
        assert_eq!(memberships[0].key_pkcs8.as_slice(), &[2u8; 138][..]);
        // Sync on another team: the first team keeps the questions only.
        let other = RelayDevice {
            team_id: "t_0000000001".to_owned(),
            ..device()
        };
        vault.set_relay_device(&other).unwrap();
        assert_eq!(
            vault.relay_device().unwrap().unwrap().team_id,
            "t_0000000001"
        );
        assert_eq!(
            vault
                .relay_membership("t_7k2m5q4x3c")
                .unwrap()
                .unwrap()
                .purposes,
            BTreeSet::from([MembershipPurpose::Questions])
        );
        // A sync-only membership goes with sync.
        assert!(vault.remove_relay_device().unwrap());
        assert!(vault.relay_membership("t_0000000001").unwrap().is_none());
        assert_eq!(vault.relay_memberships().unwrap().len(), 1);
    }
}
