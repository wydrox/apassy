//! Schema version 15: the iPhone companion (ADR 0020).
//!
//! The vault keeps the setting (off by default), the port, the self-signed certificate
//! of the listener with its private key, and the paired devices. A device has two public
//! keys: the request key signs each request, and the approval key signs each approval.
//! No table holds a secret value or a private key of a phone.
//!
//! The certificate key is the one private key here. It is PKCS#8 and lives in a
//! [`Zeroizing`] buffer while Apassy holds it, as the key-memory review asks
//! (`docs/reviews/key-memory.md`, F3). The database copy is encrypted with the rest of
//! the vault.
//!
//! Adding a device gives authority, so [`Vault::add_companion_device`] takes an
//! [`OwnerProof`] for `OwnerAction::PairCompanion` and checks it in this vault session.
//! Removing one device, resetting the pairing, and turning the setting on take authority
//! away or give none, so they need no proof. A restore removes the devices and the
//! certificate (`agents::prepare_restored`), as it revokes the agents.

use std::fmt;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::Vault;
use super::agents::{from_sql_time, now_unix, to_sql_time};
use super::types::{VaultError, VaultErrorKind, VaultResult, err};
use crate::broker::approvals::{OwnerAction, OwnerProof, ProofRefusal};
use crate::companion::crypto::is_public_key_shape;
use crate::companion::wire::{valid_device_id, valid_device_name};

/// The default port of the listener.
pub const DEFAULT_COMPANION_PORT: u16 = 48620;
/// The lowest port that the owner can choose.
pub const MIN_COMPANION_PORT: u16 = 1024;
/// A vault has at most this many paired devices (ADR 0020, D6).
pub const MAX_COMPANION_DEVICES: usize = 5;

/// Tables added in schema version 15. The setting starts off.
pub(super) const SCHEMA_V15_SQL: &str = "
CREATE TABLE companion_setting (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    port INTEGER NOT NULL CHECK (port BETWEEN 1024 AND 65535)
);
INSERT INTO companion_setting (id, enabled, port) VALUES (1, 0, 48620);
CREATE TABLE companion_certificate (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    cert_der BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE companion_device (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    request_key BLOB NOT NULL,
    approval_key BLOB NOT NULL,
    paired_at INTEGER NOT NULL,
    last_seen_at INTEGER
);
UPDATE vault_meta SET schema_version = 15 WHERE id = 1;
PRAGMA user_version = 15;
";

pub(super) const SCHEMA_V15_COLUMNS: [&str; 3] = [
    "SELECT id, enabled, port FROM companion_setting LIMIT 0",
    "SELECT id, cert_der, key_pkcs8, created_at FROM companion_certificate LIMIT 0",
    "SELECT device_id, name, request_key, approval_key, paired_at, last_seen_at FROM companion_device LIMIT 0",
];

/// The companion setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompanionSetting {
    /// "Allow the iPhone app on this network". Off by default.
    pub enabled: bool,
    pub port: u16,
}

/// A paired device, without its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionDevice {
    pub device_id: String,
    pub name: String,
    pub paired_at: u64,
    /// The time of the last signed request, or `None` when the device has made none.
    pub last_seen_at: Option<u64>,
}

/// The public keys of a paired device, in X9.63 form (65 bytes each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionDeviceKeys {
    pub request_key: Vec<u8>,
    pub approval_key: Vec<u8>,
}

/// The certificate of the listener and its private key.
pub struct CompanionCertificate {
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// The private key, PKCS#8. It is erased on drop.
    pub key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for CompanionCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompanionCertificate")
            .field("der_bytes", &self.der.len())
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Why a device was not added.
#[derive(Debug)]
pub enum AddDeviceError {
    /// The owner proof does not name this pairing, or it is stale or from another
    /// vault session.
    Proof(ProofRefusal),
    /// The device ID, the name, or a key has a bad format.
    Invalid,
    /// The device ID is paired already.
    AlreadyPaired,
    /// The vault has [`MAX_COMPANION_DEVICES`] devices.
    TooManyDevices,
    Vault(VaultError),
}

impl AddDeviceError {
    /// Text for the owner.
    pub fn message(&self) -> String {
        match self {
            Self::Proof(refusal) => refusal.message().to_owned(),
            Self::Invalid => "The device data is not valid. Nothing was paired.".to_owned(),
            Self::AlreadyPaired => "This iPhone is already paired. Nothing was paired.".to_owned(),
            Self::TooManyDevices => format!(
                "Apassy pairs at most {MAX_COMPANION_DEVICES} devices. Remove one first. Nothing was paired."
            ),
            Self::Vault(error) => match error.kind() {
                VaultErrorKind::Locked => "The vault is locked. Nothing was paired.".to_owned(),
                _ => "The vault did not store the device. Nothing was paired.".to_owned(),
            },
        }
    }
}

impl From<VaultError> for AddDeviceError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

fn storage<T>(result: Result<T, rusqlite::Error>) -> VaultResult<T> {
    result.map_err(|_| err(VaultErrorKind::Storage))
}

fn device_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, i64, Option<i64>)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn device_from_parts(parts: (String, String, i64, Option<i64>)) -> VaultResult<CompanionDevice> {
    let (device_id, name, paired_at, last_seen_at) = parts;
    Ok(CompanionDevice {
        device_id,
        name,
        paired_at: from_sql_time(paired_at)?,
        last_seen_at: last_seen_at.map(from_sql_time).transpose()?,
    })
}

/// Make the certificate of the listener: ECDSA P-256, self-signed, valid for 20 years.
/// The phone pins the certificate by its hash and ignores its name and dates, so the
/// long validity only keeps other TLS code quiet.
fn generate_certificate() -> VaultResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let fail = |_| err(VaultErrorKind::Storage);
    let now = OffsetDateTime::now_utc();
    let mut params =
        CertificateParams::new(vec!["apassy-companion.local".to_owned()]).map_err(fail)?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Apassy companion");
    name.push(DnType::OrganizationName, "Apassy");
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365 * 20);
    let key = KeyPair::generate().map_err(fail)?;
    let cert = params.self_signed(&key).map_err(fail)?;
    Ok((cert.der().to_vec(), Zeroizing::new(key.serialize_der())))
}

/// Remove every device and the certificate.
fn forget_all(tx: &Transaction<'_>) -> VaultResult<()> {
    storage(tx.execute("DELETE FROM companion_device", []))?;
    storage(tx.execute("DELETE FROM companion_certificate", []))?;
    Ok(())
}

/// A restore removes every device and the certificate, and turns the setting off, in
/// the transaction of the restore. A copy of a vault does not open the network on its
/// own: the owner turns the setting on again.
pub(super) fn prepare_restored(tx: &Transaction<'_>) -> VaultResult<()> {
    forget_all(tx)?;
    storage(tx.execute("UPDATE companion_setting SET enabled = 0", []))?;
    Ok(())
}

/// A new Mac must never inherit the source Mac's pairing trust, even when the
/// source is a raw vault rather than a stripped sync export.
pub(super) fn prepare_adopted(tx: &Transaction<'_>) -> VaultResult<()> {
    forget_all(tx)?;
    storage(tx.execute(
        "INSERT OR REPLACE INTO companion_setting (id, enabled, port) VALUES (1, 0, ?1)",
        [DEFAULT_COMPANION_PORT],
    ))?;
    Ok(())
}

impl Vault {
    /// The companion setting: off, on port 48620, until the owner changes it.
    pub fn companion_setting(&self) -> VaultResult<CompanionSetting> {
        let (enabled, port): (i64, i64) = storage(self.conn_ref()?.query_row(
            "SELECT enabled, port FROM companion_setting WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ))?;
        Ok(CompanionSetting {
            enabled: enabled == 1,
            port: u16::try_from(port).map_err(|_| err(VaultErrorKind::Storage))?,
        })
    }

    /// Turn the companion on or off. Turning it on gives no authority: every endpoint
    /// except pairing needs a paired device, and pairing needs the owner check. It
    /// needs no proof.
    pub fn set_companion_enabled(&mut self, enabled: bool) -> VaultResult<()> {
        storage(self.conn_ref()?.execute(
            "UPDATE companion_setting SET enabled = ?1 WHERE id = 1",
            [i64::from(enabled)],
        ))?;
        Ok(())
    }

    /// Set the port of the listener. It must be at least [`MIN_COMPANION_PORT`]. A new
    /// port does not change the certificate or the paired devices.
    pub fn set_companion_port(&mut self, port: u16) -> VaultResult<()> {
        if port < MIN_COMPANION_PORT {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        storage(self.conn_ref()?.execute(
            "UPDATE companion_setting SET port = ?1 WHERE id = 1",
            [i64::from(port)],
        ))?;
        Ok(())
    }

    /// The certificate of the listener, or `None` before the first
    /// [`Self::ensure_companion_certificate`].
    pub fn companion_certificate(&self) -> VaultResult<Option<CompanionCertificate>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = storage(
            self.conn_ref()?
                .query_row(
                    "SELECT cert_der, key_pkcs8 FROM companion_certificate WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional(),
        )?;
        Ok(row.map(|(der, key)| CompanionCertificate {
            der,
            key: Zeroizing::new(key),
        }))
    }

    /// The certificate of the listener. The first call makes it. It changes only after
    /// [`Self::reset_companion_pairing`] or a restore.
    pub fn ensure_companion_certificate(&mut self) -> VaultResult<CompanionCertificate> {
        if let Some(existing) = self.companion_certificate()? {
            return Ok(existing);
        }
        let (der, key) = generate_certificate()?;
        let created = to_sql_time(now_unix())?;
        storage(self.conn_ref()?.execute(
            "INSERT INTO companion_certificate (id, cert_der, key_pkcs8, created_at)
             VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![der, key.as_slice(), created],
        ))?;
        Ok(CompanionCertificate { der, key })
    }

    /// The paired devices, oldest first.
    pub fn companion_devices(&self) -> VaultResult<Vec<CompanionDevice>> {
        let conn = self.conn_ref()?;
        let mut stmt = storage(conn.prepare(
            "SELECT device_id, name, paired_at, last_seen_at FROM companion_device
             ORDER BY paired_at, device_id",
        ))?;
        let rows = storage(stmt.query_map([], device_from_row))?;
        let mut devices = Vec::new();
        for row in rows {
            devices.push(device_from_parts(storage(row)?)?);
        }
        Ok(devices)
    }

    /// One paired device, or `None`.
    pub fn companion_device(&self, device_id: &str) -> VaultResult<Option<CompanionDevice>> {
        let row = storage(
            self.conn_ref()?
                .query_row(
                    "SELECT device_id, name, paired_at, last_seen_at FROM companion_device
                     WHERE device_id = ?1",
                    [device_id],
                    device_from_row,
                )
                .optional(),
        )?;
        row.map(device_from_parts).transpose()
    }

    /// The public keys of one paired device, or `None` when the device is not paired.
    pub fn companion_device_keys(
        &self,
        device_id: &str,
    ) -> VaultResult<Option<CompanionDeviceKeys>> {
        storage(
            self.conn_ref()?
                .query_row(
                    "SELECT request_key, approval_key FROM companion_device WHERE device_id = ?1",
                    [device_id],
                    |row| {
                        Ok(CompanionDeviceKeys {
                            request_key: row.get(0)?,
                            approval_key: row.get(1)?,
                        })
                    },
                )
                .optional(),
        )
    }

    /// Record that a paired device made a signed request at `at` (Unix seconds).
    /// Returns false when the device is not paired.
    pub fn touch_companion_device(&self, device_id: &str, at: u64) -> VaultResult<bool> {
        let at = to_sql_time(at)?;
        let changed = storage(self.conn_ref()?.execute(
            "UPDATE companion_device SET last_seen_at = ?2 WHERE device_id = ?1",
            rusqlite::params![device_id, at],
        ))?;
        Ok(changed > 0)
    }

    /// Remove one device. It needs no proof: it takes authority away. Returns false when
    /// the device is not paired.
    pub fn remove_companion_device(&mut self, device_id: &str) -> VaultResult<bool> {
        let removed = storage(self.conn_ref()?.execute(
            "DELETE FROM companion_device WHERE device_id = ?1",
            [device_id],
        ))?;
        Ok(removed > 0)
    }

    /// Remove every device and the certificate. The next listener start makes a new
    /// certificate, so a phone that pinned the old one cannot connect. It needs no
    /// proof: it takes authority away. The setting and the port stay.
    pub fn reset_companion_pairing(&mut self) -> VaultResult<()> {
        let conn = self.conn_mut()?;
        let tx = storage(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        forget_all(&tx)?;
        storage(tx.commit())
    }

    /// Add a paired device. `proof` must come from `OwnerGate::authorize` for
    /// `OwnerAction::PairCompanion` with exactly these values, in this vault session.
    /// The proof is used up, also when the call fails. The vault has at most
    /// [`MAX_COMPANION_DEVICES`] devices, and a device ID is paired once.
    pub fn add_companion_device(
        &mut self,
        proof: OwnerProof,
        device_id: &str,
        device_name: &str,
        request_key: &[u8],
        approval_key: &[u8],
    ) -> Result<CompanionDevice, AddDeviceError> {
        self.require_unlocked()?;
        let expected = OwnerAction::PairCompanion {
            device_id: device_id.to_owned(),
            device_name: device_name.to_owned(),
            request_key: request_key.to_vec(),
            approval_key: approval_key.to_vec(),
        };
        proof
            .check(&expected, &self.epoch())
            .map_err(AddDeviceError::Proof)?;
        if !valid_device_id(device_id)
            || !valid_device_name(device_name)
            || !is_public_key_shape(request_key)
            || !is_public_key_shape(approval_key)
        {
            return Err(AddDeviceError::Invalid);
        }
        let paired_at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = storage(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let known: i64 = storage(tx.query_row(
            "SELECT COUNT(*) FROM companion_device WHERE device_id = ?1",
            [device_id],
            |row| row.get(0),
        ))?;
        if known > 0 {
            return Err(AddDeviceError::AlreadyPaired);
        }
        let count: i64 = storage(tx.query_row(
            "SELECT COUNT(*) FROM companion_device",
            [],
            |row| row.get(0),
        ))?;
        if usize::try_from(count).map_or(true, |count| count >= MAX_COMPANION_DEVICES) {
            return Err(AddDeviceError::TooManyDevices);
        }
        storage(tx.execute(
            "INSERT INTO companion_device (device_id, name, request_key, approval_key, paired_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![device_id, device_name, request_key, approval_key, paired_at],
        ))?;
        storage(tx.commit())?;
        Ok(CompanionDevice {
            device_id: device_id.to_owned(),
            name: device_name.to_owned(),
            paired_at: from_sql_time(paired_at)?,
            last_seen_at: None,
        })
    }
}
