//! Trusted devices, relay memberships, and the homes of mirrored credentials (schema
//! 19, stage 5 plan §A1).
//!
//! - A trusted device ([`TrustedDevice`]) may answer the questions of this vault. Each
//!   device registers its own row with its relay key (`sign_key`) and, on an iPhone, its
//!   answer key; the relay's device list is never the source of these keys. The rows
//!   sync (`merge::SYNCED_TABLES`): the later `(updated_at, updated_by)` wins, and a
//!   removed device keeps its row with `deleted_at`. A removal wins over any edit, so
//!   a revoked device never comes back through a sync, and neither its UUID nor its
//!   keys can register again (`AlreadyExists`): a device that joins again gets a new
//!   UUID and a new relay key, and needs a new confirmation.
//!
//!   A device can be in more than one relay team (a notifications team and a shared
//!   vault team), with a device number in each. The numbers are a JSON object in the
//!   device row (`relay_devices`, team ID to device number), not a table of their own:
//!   they change with the row and merge with it under the same rule, so a removal takes
//!   them with it and two copies never disagree on half a device. Each device writes
//!   its own row, so two Macs rarely change the numbers of one device at once.
//! - A relay membership ([`RelayMembership`]) is one key pair of this Mac in one relay
//!   team (ADR 0019 §4), with the purposes that use it. It is local
//!   (`merge::LOCAL_TABLES`). At most one membership has the purpose `sync`; relay sync
//!   reads it as [`super::RelayDevice`].
//! - The home of a credential ([`ItemHome`]) marks a read-only mirror of a credential of
//!   a shared vault (V3). It is a child row of the credential and syncs with it.
//!
//! Keys are stored as given, after a check of their shape. The private key of a
//! membership is erased on drop and never printed: [`RelayMembership`] redacts it in
//! Debug output.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::Vault;
use super::agents::{from_sql_time, now_unix, to_sql_time};
use super::relay_device::{valid_relay_identity, valid_team_id};
use super::to_sql_id;
use super::types::{VaultErrorKind, VaultResult, err};

/// A device name has at most this many bytes.
pub const MAX_TRUSTED_DEVICE_NAME_BYTES: usize = 64;
/// A device UUID, a shared vault UUID, or a home UUID has at most this many bytes.
const MAX_UUID_BYTES: usize = 64;
/// A P-256 public key in X9.63 form.
const P256_POINT_BYTES: usize = 65;

fn storage<E>(_: E) -> super::VaultError {
    err(VaultErrorKind::Storage)
}

/// The kind of a trusted device.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum TrustedDeviceKind {
    Mac,
    Iphone,
}

impl TrustedDeviceKind {
    /// The stored name: `mac` or `iphone`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Iphone => "iphone",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "mac" => Some(Self::Mac),
            "iphone" => Some(Self::Iphone),
            _ => None,
        }
    }
}

/// A device that may answer the questions of this vault. The keys are public keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedDevice {
    /// The UUID that the device chose for itself.
    pub uuid: String,
    pub name: String,
    pub kind: TrustedDeviceKind,
    /// The device number of the device in each relay team that it is in, by team ID.
    pub relay_devices: BTreeMap<String, u64>,
    /// The relay device key, a P-256 point in X9.63 form (65 bytes).
    pub sign_key: Vec<u8>,
    /// iPhone: the Secure Enclave answer key, a P-256 point in X9.63 form.
    pub answer_key: Option<Vec<u8>>,
    /// Unix seconds of the first registration.
    pub created_at: u64,
    /// The version of the row: Unix milliseconds of the last change.
    pub updated_at: i64,
    /// The sync device ID of the vault file that made the last change.
    pub updated_by: String,
}

/// What a relay membership is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipPurpose {
    /// Relay sync of the vault (ADR 0022).
    Sync,
    /// Questions through the relay (stage 5).
    Questions,
    /// A shared vault (V3).
    Share,
}

impl MembershipPurpose {
    /// The stored name: `sync`, `questions`, or `share`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Questions => "questions",
            Self::Share => "share",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "sync" => Some(Self::Sync),
            "questions" => Some(Self::Questions),
            "share" => Some(Self::Share),
            _ => None,
        }
    }
}

/// One key pair of this Mac in one relay team.
pub struct RelayMembership {
    /// The team on the relay, for example `t_7k2m5q4x3c`.
    pub team_id: String,
    /// The relay origin.
    pub relay_url: String,
    /// The device number on the relay.
    pub device_id: u64,
    /// The public key, a P-256 point in X9.63 form (65 bytes).
    pub public_key: Vec<u8>,
    /// The private key, PKCS#8. It is erased on drop and never printed.
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    /// What uses the membership. Never empty in a stored row.
    pub purposes: BTreeSet<MembershipPurpose>,
    /// Unix seconds when the key was stored. A new row ignores the given value.
    pub created_at: u64,
}

impl fmt::Debug for RelayMembership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayMembership")
            .field("team_id", &self.team_id)
            .field("relay_url", &self.relay_url)
            .field("device_id", &self.device_id)
            .field("purposes", &self.purposes)
            .field("key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl RelayMembership {
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

/// The home of a mirrored credential: the shared vault and the credential there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHome {
    pub shared_vault_uuid: String,
    pub home_uuid: String,
}

/// The stored form of `purposes`: a JSON array of names, in order.
pub(super) fn purposes_json(purposes: &BTreeSet<MembershipPurpose>) -> String {
    let names: Vec<&str> = purposes.iter().map(|purpose| purpose.as_str()).collect();
    serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_owned())
}

/// The purposes of a stored row. A name that this build does not know is left out, so a
/// later build can add a purpose; text that is not a JSON array of strings is `Storage`.
fn parse_purposes(text: &str) -> VaultResult<BTreeSet<MembershipPurpose>> {
    let names: Vec<String> = serde_json::from_str(text).map_err(storage)?;
    Ok(names
        .iter()
        .filter_map(|name| MembershipPurpose::parse(name))
        .collect())
}

/// The memberships, by team; only the membership of `team` when it is given. A row of a
/// bad shape is `Storage`.
pub(super) fn load_memberships(
    conn: &Connection,
    team: Option<&str>,
) -> VaultResult<Vec<RelayMembership>> {
    type Row = (String, String, i64, Vec<u8>, Vec<u8>, String, i64);
    let mut stmt = conn
        .prepare(
            "SELECT team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at
             FROM relay_membership WHERE ?1 IS NULL OR team_id = ?1 ORDER BY team_id",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([team], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(storage)?;
    let mut out = Vec::new();
    for row in rows {
        let (team_id, relay_url, device_id, public_key, key, purposes, created_at): Row =
            row.map_err(storage)?;
        let membership = RelayMembership {
            team_id,
            relay_url,
            device_id: u64::try_from(device_id).map_err(storage)?,
            public_key,
            key_pkcs8: Zeroizing::new(key),
            purposes: parse_purposes(&purposes)?,
            created_at: from_sql_time(created_at)?,
        };
        if !membership.is_valid() {
            return Err(err(VaultErrorKind::Storage));
        }
        out.push(membership);
    }
    Ok(out)
}

/// The team that has the purpose `sync`, other than `except`.
fn other_sync_team(conn: &Connection, except: &str) -> VaultResult<Option<String>> {
    Ok(load_memberships(conn, None)?
        .into_iter()
        .find(|m| m.team_id != except && m.purposes.contains(&MembershipPurpose::Sync))
        .map(|m| m.team_id))
}

/// A device UUID, a shared vault UUID, or a home UUID: 1 to [`MAX_UUID_BYTES`] ASCII
/// letters, digits, and hyphens.
fn valid_uuid(uuid: &str) -> bool {
    !uuid.is_empty()
        && uuid.len() <= MAX_UUID_BYTES
        && uuid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A P-256 public key in X9.63 form: 65 bytes from `0x04`.
fn valid_point(key: &[u8]) -> bool {
    key.len() == P256_POINT_BYTES && key[0] == 0x04
}

/// A device name: trimmed, not empty, at most [`MAX_TRUSTED_DEVICE_NAME_BYTES`], no
/// control characters.
fn clean_name(name: &str) -> VaultResult<String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > MAX_TRUSTED_DEVICE_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    Ok(name.to_owned())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// The version of a change by this device after `previous`: now in Unix milliseconds,
/// later than `previous`, and the device ID.
fn next_version(conn: &Connection, previous: Option<i64>) -> VaultResult<(i64, String)> {
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
    Ok((at, device.unwrap_or_default()))
}

const DEVICE_COLUMNS: &str = "uuid, name, kind, relay_devices, sign_key, answer_key, \
                              created_at, updated_at, updated_by";

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawDevice> {
    Ok(RawDevice {
        uuid: row.get(0)?,
        name: row.get(1)?,
        kind: row.get(2)?,
        relay_devices: row.get(3)?,
        sign_key: row.get(4)?,
        answer_key: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        updated_by: row.get(8)?,
    })
}

/// A `trusted_device` row as stored.
struct RawDevice {
    uuid: String,
    name: String,
    kind: String,
    relay_devices: String,
    sign_key: Vec<u8>,
    answer_key: Option<Vec<u8>>,
    created_at: i64,
    updated_at: i64,
    updated_by: String,
}

impl RawDevice {
    fn into_device(self) -> VaultResult<TrustedDevice> {
        Ok(TrustedDevice {
            uuid: self.uuid,
            name: self.name,
            kind: TrustedDeviceKind::parse(&self.kind).ok_or_else(|| storage(()))?,
            relay_devices: parse_relay_devices(&self.relay_devices)?,
            sign_key: self.sign_key,
            answer_key: self.answer_key,
            created_at: from_sql_time(self.created_at)?,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
        })
    }
}

/// The relay device numbers of a stored row. A team ID or a number of a bad shape is
/// `Storage`.
fn parse_relay_devices(text: &str) -> VaultResult<BTreeMap<String, u64>> {
    let map: BTreeMap<String, u64> = serde_json::from_str(text).map_err(storage)?;
    if map
        .iter()
        .all(|(team, id)| valid_team_id(team) && valid_relay_number(*id))
    {
        Ok(map)
    } else {
        Err(err(VaultErrorKind::Storage))
    }
}

/// The stored form of the relay device numbers: a JSON object in team order.
fn relay_devices_json(map: &BTreeMap<String, u64>) -> VaultResult<String> {
    serde_json::to_string(map).map_err(storage)
}

/// A device number on the relay: from 1, and an SQLite integer.
fn valid_relay_number(id: u64) -> bool {
    id >= 1 && i64::try_from(id).is_ok()
}

/// The live device `uuid`. A removed device is `None`.
fn live_device(conn: &Connection, uuid: &str) -> VaultResult<Option<TrustedDevice>> {
    conn.query_row(
        &format!(
            "SELECT {DEVICE_COLUMNS} FROM trusted_device WHERE uuid = ?1 AND deleted_at IS NULL"
        ),
        [uuid],
        device_from_row,
    )
    .optional()
    .map_err(storage)?
    .map(RawDevice::into_device)
    .transpose()
}

/// Whether `key` is the `sign_key` or the `answer_key` of a removed device.
pub(super) fn key_removed(conn: &Connection, key: &[u8]) -> VaultResult<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM trusted_device WHERE deleted_at IS NOT NULL
                 AND (sign_key = ?1 OR answer_key = ?1) LIMIT 1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    Ok(found.is_some())
}

fn require_item(conn: &Connection, item: i64) -> VaultResult<()> {
    let found: Option<i64> = conn
        .query_row("SELECT id FROM item WHERE id = ?1", [item], |row| {
            row.get(0)
        })
        .optional()
        .map_err(storage)?;
    found
        .map(|_| ())
        .ok_or_else(|| err(VaultErrorKind::NotFound))
}

impl Vault {
    // ---- Trusted devices ----

    /// The trusted devices that are not removed, by registration time, name, and UUID.
    pub fn trusted_devices(&self) -> VaultResult<Vec<TrustedDevice>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DEVICE_COLUMNS} FROM trusted_device WHERE deleted_at IS NULL
                 ORDER BY created_at, name, uuid"
            ))
            .map_err(storage)?;
        let rows = stmt.query_map([], device_from_row).map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(storage)?.into_device()?);
        }
        Ok(out)
    }

    /// The trusted device `uuid`, or `None` when it is not registered or was removed.
    pub fn trusted_device(&self, uuid: &str) -> VaultResult<Option<TrustedDevice>> {
        live_device(self.conn_ref()?, uuid)
    }

    /// Whether `key` (a relay key or an answer key) belongs to a removed device. Such a
    /// device was taken out of the questions; its keys never register again.
    pub fn trusted_key_removed(&self, key: &[u8]) -> VaultResult<bool> {
        key_removed(self.conn_ref()?, key)
    }

    /// The live device with the device number `relay_device_id` in the relay team
    /// `team_id`, or `None`. Two live devices with the same number (two Macs can make
    /// that state) match no device, so an answer never goes to the wrong one.
    pub fn trusted_device_by_relay_id(
        &self,
        team_id: &str,
        relay_device_id: u64,
    ) -> VaultResult<Option<TrustedDevice>> {
        let mut found = self
            .trusted_devices()?
            .into_iter()
            .filter(|device| device.relay_devices.get(team_id) == Some(&relay_device_id));
        match (found.next(), found.next()) {
            (Some(device), None) => Ok(Some(device)),
            _ => Ok(None),
        }
    }

    /// Register a device, or update the name, kind, and keys of a device that is
    /// registered; its relay device numbers stay ([`Vault::set_trusted_device_relay_id`]).
    /// The keys are stored as given. Returns the stored row.
    ///
    /// - `InvalidInput`: the UUID is empty, longer than 64 bytes, or has a character
    ///   other than an ASCII letter, a digit, or a hyphen; the name is empty, longer than
    ///   [`MAX_TRUSTED_DEVICE_NAME_BYTES`], or has a control character; a key is not a
    ///   P-256 point in X9.63 form.
    /// - `AlreadyExists`: the device was removed, or `sign_key` or `answer_key` is a key
    ///   of a removed device. A removal is final: a removed device cannot come back under
    ///   a new UUID with the same keys; it needs a new relay key and a new confirmation.
    pub fn register_trusted_device(
        &mut self,
        uuid: &str,
        name: &str,
        kind: TrustedDeviceKind,
        sign_key: &[u8],
        answer_key: Option<&[u8]>,
    ) -> VaultResult<TrustedDevice> {
        let name = clean_name(name)?;
        if !valid_uuid(uuid)
            || !valid_point(sign_key)
            || answer_key.is_some_and(|key| !valid_point(key))
        {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if key_removed(&tx, sign_key)?
            || answer_key.map_or(Ok(false), |key| key_removed(&tx, key))?
        {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let existing: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT updated_at, deleted_at FROM trusted_device WHERE uuid = ?1",
                [uuid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        match existing {
            Some((_, Some(_))) => return Err(err(VaultErrorKind::AlreadyExists)),
            Some((previous, None)) => {
                let (at, by) = next_version(&tx, Some(previous))?;
                tx.execute(
                    "UPDATE trusted_device SET name = ?1, kind = ?2, sign_key = ?3,
                         answer_key = ?4, updated_at = ?5, updated_by = ?6
                     WHERE uuid = ?7",
                    rusqlite::params![name, kind.as_str(), sign_key, answer_key, at, by, uuid],
                )
                .map_err(storage)?;
            }
            None => {
                let (at, by) = next_version(&tx, None)?;
                tx.execute(
                    "INSERT INTO trusted_device (uuid, name, kind, sign_key, answer_key,
                         created_at, updated_at, updated_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        uuid,
                        name,
                        kind.as_str(),
                        sign_key,
                        answer_key,
                        to_sql_time(now_unix())?,
                        at,
                        by
                    ],
                )
                .map_err(storage)?;
            }
        }
        let stored = live_device(&tx, uuid)?.ok_or_else(|| storage(()))?;
        tx.commit().map_err(storage)?;
        Ok(stored)
    }

    /// Set the device number of the live device `uuid` in the relay team `team_id`. The
    /// same number changes nothing.
    ///
    /// - `InvalidInput`: a team ID of a bad shape (`t_` and 10 lowercase letters or
    ///   digits) or the number 0.
    /// - `NotFound`: no live device `uuid`.
    /// - `AlreadyExists`: another live device has this number in this team.
    pub fn set_trusted_device_relay_id(
        &mut self,
        uuid: &str,
        team_id: &str,
        relay_device_id: u64,
    ) -> VaultResult<()> {
        if !valid_team_id(team_id) || !valid_relay_number(relay_device_id) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        self.change_relay_devices(uuid, |others, map| {
            if others.iter().any(|device| {
                device.uuid != uuid && device.relay_devices.get(team_id) == Some(&relay_device_id)
            }) {
                return Err(err(VaultErrorKind::AlreadyExists));
            }
            Ok(map.insert(team_id.to_owned(), relay_device_id) != Some(relay_device_id))
        })
        .map(|_| ())
    }

    /// Remove the device number of the live device `uuid` in the relay team `team_id`.
    /// Returns whether it had one. `NotFound`: no live device `uuid`.
    pub fn clear_trusted_device_relay_id(
        &mut self,
        uuid: &str,
        team_id: &str,
    ) -> VaultResult<bool> {
        self.change_relay_devices(uuid, |_, map| Ok(map.remove(team_id).is_some()))
    }

    /// Change the relay device numbers of the live device `uuid` with `change`, which
    /// gets the live devices and the map and returns whether it changed the map. A change
    /// is a new version of the row.
    fn change_relay_devices(
        &mut self,
        uuid: &str,
        change: impl FnOnce(&[TrustedDevice], &mut BTreeMap<String, u64>) -> VaultResult<bool>,
    ) -> VaultResult<bool> {
        let devices = self.trusted_devices()?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let device = live_device(&tx, uuid)?.ok_or_else(|| err(VaultErrorKind::NotFound))?;
        let mut map = device.relay_devices;
        if !change(&devices, &mut map)? {
            return Ok(false);
        }
        let (at, by) = next_version(&tx, Some(device.updated_at))?;
        tx.execute(
            "UPDATE trusted_device SET relay_devices = ?1, updated_at = ?2, updated_by = ?3
             WHERE uuid = ?4",
            rusqlite::params![relay_devices_json(&map)?, at, by, uuid],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(true)
    }

    /// Remove a trusted device: its row stays with `deleted_at`, so the removal reaches
    /// the other devices and wins over any edit. Returns whether a live device was
    /// removed.
    pub fn remove_trusted_device(&mut self, uuid: &str) -> VaultResult<bool> {
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT updated_at FROM trusted_device WHERE uuid = ?1 AND deleted_at IS NULL",
                [uuid],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(previous) = previous else {
            return Ok(false);
        };
        let (at, by) = next_version(&tx, Some(previous))?;
        tx.execute(
            "UPDATE trusted_device SET deleted_at = ?1, updated_at = ?2, updated_by = ?3
             WHERE uuid = ?4",
            rusqlite::params![to_sql_time(now_unix())?, at, by, uuid],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(true)
    }

    // ---- Relay memberships ----

    /// The relay memberships of this Mac, by team.
    pub fn relay_memberships(&self) -> VaultResult<Vec<RelayMembership>> {
        load_memberships(self.conn_ref()?, None)
    }

    /// The membership of `team_id`, or `None`.
    pub fn relay_membership(&self, team_id: &str) -> VaultResult<Option<RelayMembership>> {
        Ok(load_memberships(self.conn_ref()?, Some(team_id))?.pop())
    }

    /// Store a new membership. The time is now; `membership.created_at` is ignored.
    ///
    /// - `InvalidInput`: a value of a bad shape (the checks of
    ///   [`Vault::set_relay_device`]), or no purpose.
    /// - `AlreadyExists`: the team has a membership, or the purpose `sync` is on another
    ///   team.
    pub fn add_relay_membership(&mut self, membership: &RelayMembership) -> VaultResult<()> {
        if !membership.is_valid() || membership.purposes.is_empty() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let device_id =
            i64::try_from(membership.device_id).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let now = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if !load_memberships(&tx, Some(&membership.team_id))?.is_empty()
            || (membership.purposes.contains(&MembershipPurpose::Sync)
                && other_sync_team(&tx, &membership.team_id)?.is_some())
        {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        tx.execute(
            "INSERT INTO relay_membership
                 (team_id, relay_url, device_id, public_key, key_pkcs8, purposes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                membership.team_id,
                membership.relay_url,
                device_id,
                membership.public_key,
                membership.key_pkcs8.as_slice(),
                purposes_json(&membership.purposes),
                now,
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// Set the purposes of the membership of `team_id`. `InvalidInput`: no purpose (use
    /// [`Vault::remove_relay_membership`]). `NotFound`: no membership. `AlreadyExists`:
    /// the purpose `sync` is on another team.
    pub fn set_membership_purposes(
        &mut self,
        team_id: &str,
        purposes: &BTreeSet<MembershipPurpose>,
    ) -> VaultResult<()> {
        if purposes.is_empty() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if load_memberships(&tx, Some(team_id))?.is_empty() {
            return Err(err(VaultErrorKind::NotFound));
        }
        if purposes.contains(&MembershipPurpose::Sync) && other_sync_team(&tx, team_id)?.is_some() {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        tx.execute(
            "UPDATE relay_membership SET purposes = ?1 WHERE team_id = ?2",
            (purposes_json(purposes), team_id),
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// Remove the membership of `team_id` with its key, whatever uses it. Returns whether
    /// there was one.
    pub fn remove_relay_membership(&mut self, team_id: &str) -> VaultResult<bool> {
        let removed = self
            .conn_ref()?
            .execute("DELETE FROM relay_membership WHERE team_id = ?1", [team_id])
            .map_err(storage)?;
        Ok(removed > 0)
    }

    // ---- Homes of mirrored credentials ----

    /// The home of the credential `item_id` when it is a mirror. `NotFound`: no such
    /// credential.
    pub fn item_home(&self, item_id: u64) -> VaultResult<Option<ItemHome>> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let found: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT h.shared_vault_uuid, h.home_uuid FROM item i
                 LEFT JOIN item_home h ON h.item_id = i.id WHERE i.id = ?1",
                [item],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        match found {
            None => Err(err(VaultErrorKind::NotFound)),
            Some((Some(shared_vault_uuid), Some(home_uuid))) => Ok(Some(ItemHome {
                shared_vault_uuid,
                home_uuid,
            })),
            Some(_) => Ok(None),
        }
    }

    /// Mark the credential `item_id` as the mirror of `home`. The same home changes
    /// nothing. `InvalidInput`: a UUID of a bad shape (see
    /// [`Vault::register_trusted_device`]). `NotFound`: no such credential.
    pub fn set_item_home(&mut self, item_id: u64, home: &ItemHome) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        if !valid_uuid(&home.shared_vault_uuid) || !valid_uuid(&home.home_uuid) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        require_item(&tx, item)?;
        // The upsert changes nothing for the same home, so the credential stays
        // unchanged for the sync.
        tx.execute(
            "INSERT INTO item_home (item_id, shared_vault_uuid, home_uuid) VALUES (?1, ?2, ?3)
             ON CONFLICT(item_id) DO UPDATE SET shared_vault_uuid = excluded.shared_vault_uuid,
                 home_uuid = excluded.home_uuid
             WHERE (item_home.shared_vault_uuid, item_home.home_uuid)
                 IS NOT (excluded.shared_vault_uuid, excluded.home_uuid)",
            (item, &home.shared_vault_uuid, &home.home_uuid),
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// The credential `item_id` is no longer a mirror. Returns whether it was one.
    /// `NotFound`: no such credential.
    pub fn clear_item_home(&mut self, item_id: u64) -> VaultResult<bool> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        require_item(&tx, item)?;
        let removed = tx
            .execute("DELETE FROM item_home WHERE item_id = ?1", [item])
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(removed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "synthetic-trusted-pass";

    fn unlocked(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("t.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    fn point(fill: u8) -> Vec<u8> {
        let mut key = vec![0x04];
        key.extend_from_slice(&[fill; 64]);
        key
    }

    fn membership(team: &str, purposes: &[MembershipPurpose]) -> RelayMembership {
        RelayMembership {
            team_id: team.to_owned(),
            relay_url: "https://relay.example.test".to_owned(),
            device_id: 3,
            public_key: point(7),
            key_pkcs8: Zeroizing::new(vec![0xab; 138]),
            purposes: purposes.iter().copied().collect(),
            created_at: 0,
        }
    }

    #[test]
    fn a_device_registers_updates_and_a_removal_is_final() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        assert!(vault.trusted_devices().unwrap().is_empty());
        let mac = vault
            .register_trusted_device(
                "mac-1",
                " Synthetic MacBook ",
                TrustedDeviceKind::Mac,
                &point(1),
                None,
            )
            .unwrap();
        assert_eq!(mac.name, "Synthetic MacBook");
        assert!(mac.relay_devices.is_empty());
        assert_eq!(mac.updated_by, vault.sync_device_id().unwrap());
        assert!(mac.created_at > 0);
        let phone = vault
            .register_trusted_device(
                "PHONE-2",
                "Synthetic iPhone",
                TrustedDeviceKind::Iphone,
                &point(2),
                Some(&point(3)),
            )
            .unwrap();
        assert_eq!(phone.answer_key, Some(point(3)));
        assert_eq!(vault.trusted_devices().unwrap(), [mac.clone(), phone]);

        // A new key: the same row, a later version, the same registration time, the
        // same relay numbers.
        vault
            .set_trusted_device_relay_id("mac-1", "t_aaaaaaaaaa", 2)
            .unwrap();
        let again = vault
            .register_trusted_device(
                "mac-1",
                "Synthetic MacBook",
                TrustedDeviceKind::Mac,
                &point(9),
                None,
            )
            .unwrap();
        assert!(again.updated_at > mac.updated_at);
        assert_eq!(again.created_at, mac.created_at);
        assert_eq!(again.sign_key, point(9));
        assert_eq!(
            again.relay_devices,
            BTreeMap::from([("t_aaaaaaaaaa".to_owned(), 2)])
        );
        assert_eq!(vault.trusted_device("mac-1").unwrap(), Some(again));

        assert!(vault.remove_trusted_device("mac-1").unwrap());
        assert!(!vault.remove_trusted_device("mac-1").unwrap());
        assert!(!vault.remove_trusted_device("nobody").unwrap());
        assert_eq!(vault.trusted_device("mac-1").unwrap(), None);
        assert_eq!(vault.trusted_devices().unwrap().len(), 1);
        assert_eq!(
            vault
                .register_trusted_device(
                    "mac-1",
                    "Synthetic MacBook",
                    TrustedDeviceKind::Mac,
                    &point(1),
                    None,
                )
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
        // Nor do its keys under a new UUID: the last sign key of the removed row, and
        // the answer key of a removed iPhone.
        assert!(vault.trusted_key_removed(&point(9)).unwrap());
        assert!(!vault.trusted_key_removed(&point(1)).unwrap());
        assert_eq!(
            vault
                .register_trusted_device("mac-2", "Mac", TrustedDeviceKind::Mac, &point(9), None)
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
        assert!(vault.remove_trusted_device("PHONE-2").unwrap());
        assert!(vault.trusted_key_removed(&point(3)).unwrap());
        for (sign, answer) in [(point(2), point(4)), (point(5), point(3))] {
            assert_eq!(
                vault
                    .register_trusted_device(
                        "phone-3",
                        "iPhone",
                        TrustedDeviceKind::Iphone,
                        &sign,
                        Some(&answer),
                    )
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::AlreadyExists
            );
        }
        // New keys register.
        vault
            .register_trusted_device(
                "phone-3",
                "iPhone",
                TrustedDeviceKind::Iphone,
                &point(5),
                Some(&point(6)),
            )
            .unwrap();
    }

    #[test]
    fn a_device_of_a_bad_shape_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        let long = "x".repeat(65);
        let short = vec![0x04; 33];
        let compressed = [&[0x02u8][..], &[1u8; 64][..]].concat();
        type Case<'a> = (&'a str, &'a str, &'a [u8], Option<&'a [u8]>);
        let cases: [Case<'_>; 7] = [
            ("", "Name", &point(1), None),
            (&long, "Name", &point(1), None),
            ("bad uuid", "Name", &point(1), None),
            ("ok", "  ", &point(1), None),
            ("ok", "Tab\tname", &point(1), None),
            ("ok", "Name", &short, None),
            ("ok", "Name", &point(1), Some(&compressed)),
        ];
        for (uuid, name, sign, answer) in cases {
            assert_eq!(
                vault
                    .register_trusted_device(uuid, name, TrustedDeviceKind::Mac, sign, answer)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput,
                "{uuid:?} {name:?}"
            );
        }
        assert!(vault.trusted_devices().unwrap().is_empty());
    }

    /// A device has one number in each relay team; the lookup by team and number finds
    /// the one live device with it.
    #[test]
    fn relay_numbers_are_per_team_and_find_one_device() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        for (uuid, fill) in [("mac-1", 1), ("phone-1", 2)] {
            vault
                .register_trusted_device(uuid, uuid, TrustedDeviceKind::Mac, &point(fill), None)
                .unwrap();
        }
        let questions = "t_questions1";
        let share = "t_share00001";
        vault
            .set_trusted_device_relay_id("mac-1", questions, 2)
            .unwrap();
        vault
            .set_trusted_device_relay_id("mac-1", share, 7)
            .unwrap();
        vault
            .set_trusted_device_relay_id("phone-1", share, 2)
            .unwrap();
        let before = vault.trusted_device("mac-1").unwrap().unwrap();
        assert_eq!(
            before.relay_devices,
            BTreeMap::from([(questions.to_owned(), 2), (share.to_owned(), 7)])
        );
        // The same number again changes nothing.
        vault
            .set_trusted_device_relay_id("mac-1", share, 7)
            .unwrap();
        assert_eq!(vault.trusted_device("mac-1").unwrap().unwrap(), before);

        let find = |vault: &Vault, team: &str, id: u64| {
            vault
                .trusted_device_by_relay_id(team, id)
                .unwrap()
                .map(|device| device.uuid)
        };
        assert_eq!(find(&vault, questions, 2).as_deref(), Some("mac-1"));
        assert_eq!(find(&vault, share, 2).as_deref(), Some("phone-1"));
        assert_eq!(find(&vault, share, 7).as_deref(), Some("mac-1"));
        assert_eq!(find(&vault, questions, 7), None);
        assert_eq!(find(&vault, "t_other00001", 2), None);

        // One number per team: another device cannot take it.
        assert_eq!(
            vault
                .set_trusted_device_relay_id("phone-1", questions, 2)
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
        for (team, id) in [("team", 3), ("t_UPPER00001", 3), (questions, 0)] {
            assert_eq!(
                vault
                    .set_trusted_device_relay_id("phone-1", team, id)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput
            );
        }
        assert_eq!(
            vault
                .set_trusted_device_relay_id("nobody", questions, 3)
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );

        // Two live devices with one number (as two Macs can make it) match no device.
        vault
            .conn_ref()
            .unwrap()
            .execute(
                "UPDATE trusted_device SET relay_devices = ?1 WHERE uuid = 'phone-1'",
                [r#"{"t_questions1":2}"#],
            )
            .unwrap();
        assert_eq!(find(&vault, questions, 2), None);

        assert!(
            vault
                .clear_trusted_device_relay_id("mac-1", questions)
                .unwrap()
        );
        assert!(
            !vault
                .clear_trusted_device_relay_id("mac-1", questions)
                .unwrap()
        );
        assert_eq!(find(&vault, questions, 2).as_deref(), Some("phone-1"));
        // A removed device is found by no number.
        assert!(vault.remove_trusted_device("mac-1").unwrap());
        assert_eq!(find(&vault, share, 7), None);
        assert_eq!(
            vault
                .clear_trusted_device_relay_id("mac-1", share)
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn memberships_keep_one_key_per_team_and_one_sync_purpose() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        let questions = membership("t_aaaaaaaaaa", &[MembershipPurpose::Questions]);
        vault.add_relay_membership(&questions).unwrap();
        let read = vault.relay_membership("t_aaaaaaaaaa").unwrap().unwrap();
        assert_eq!(read.key_pkcs8.as_slice(), &[0xab; 138][..]);
        assert!(read.created_at > 0);
        let debug = format!("{read:?}");
        assert!(
            debug.contains("[redacted]") && !debug.contains("171"),
            "{debug}"
        );
        // Questions only: relay sync stays off.
        assert!(vault.relay_device().unwrap().is_none());

        assert_eq!(
            vault.add_relay_membership(&questions).unwrap_err().kind(),
            VaultErrorKind::AlreadyExists
        );
        vault
            .add_relay_membership(&membership("t_bbbbbbbbbb", &[MembershipPurpose::Sync]))
            .unwrap();
        assert_eq!(
            vault.relay_device().unwrap().unwrap().team_id,
            "t_bbbbbbbbbb"
        );
        // A second team cannot take the purpose `sync`.
        assert_eq!(
            vault
                .add_relay_membership(&membership("t_cccccccccc", &[MembershipPurpose::Sync]))
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
        let with_sync = BTreeSet::from([MembershipPurpose::Questions, MembershipPurpose::Sync]);
        assert_eq!(
            vault
                .set_membership_purposes("t_aaaaaaaaaa", &with_sync)
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
        let share = BTreeSet::from([MembershipPurpose::Questions, MembershipPurpose::Share]);
        vault
            .set_membership_purposes("t_aaaaaaaaaa", &share)
            .unwrap();
        assert_eq!(
            vault
                .relay_membership("t_aaaaaaaaaa")
                .unwrap()
                .unwrap()
                .purposes,
            share
        );
        assert_eq!(
            vault
                .set_membership_purposes("t_aaaaaaaaaa", &BTreeSet::new())
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(
            vault
                .set_membership_purposes("t_dddddddddd", &share)
                .unwrap_err()
                .kind(),
            VaultErrorKind::NotFound
        );
        for bad in [
            membership("t_eeeeeeeeee", &[]),
            RelayMembership {
                team_id: "team".to_owned(),
                ..membership("t_eeeeeeeeee", &[MembershipPurpose::Share])
            },
            RelayMembership {
                public_key: vec![0x04; 10],
                ..membership("t_eeeeeeeeee", &[MembershipPurpose::Share])
            },
        ] {
            assert_eq!(
                vault.add_relay_membership(&bad).unwrap_err().kind(),
                VaultErrorKind::InvalidInput
            );
        }
        let teams: Vec<String> = vault
            .relay_memberships()
            .unwrap()
            .into_iter()
            .map(|m| m.team_id)
            .collect();
        assert_eq!(teams, ["t_aaaaaaaaaa", "t_bbbbbbbbbb"]);
        assert!(vault.remove_relay_membership("t_bbbbbbbbbb").unwrap());
        assert!(!vault.remove_relay_membership("t_bbbbbbbbbb").unwrap());
        assert!(vault.relay_device().unwrap().is_none());
    }

    #[test]
    fn purposes_are_a_json_array_and_unknown_names_are_left_out() {
        let set = BTreeSet::from([MembershipPurpose::Share, MembershipPurpose::Sync]);
        assert_eq!(purposes_json(&set), r#"["sync","share"]"#);
        assert_eq!(
            parse_purposes(r#"["questions","later"]"#).unwrap(),
            BTreeSet::from([MembershipPurpose::Questions])
        );
        assert_eq!(
            parse_purposes("sync").unwrap_err().kind(),
            VaultErrorKind::Storage
        );
    }

    #[test]
    fn an_item_home_is_a_child_row_of_the_credential() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = unlocked(&dir);
        let id = vault
            .add(super::super::ItemDraft {
                title: "Mirror".to_owned(),
                kind: crate::contracts::CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![super::super::Field {
                    name: "token".to_owned(),
                    value: super::super::SecretValue::new("SYNTH-mirror".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        let version = |vault: &Vault| -> i64 {
            vault
                .conn_ref()
                .unwrap()
                .query_row(
                    "SELECT updated_at FROM item WHERE id = ?1",
                    [id as i64],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(vault.item_home(id).unwrap(), None);
        let home = ItemHome {
            shared_vault_uuid: "0f".repeat(16),
            home_uuid: "1e".repeat(16),
        };
        let before = version(&vault);
        std::thread::sleep(std::time::Duration::from_millis(3));
        vault.set_item_home(id, &home).unwrap();
        let after = version(&vault);
        assert!(after > before, "the home marks a change of the credential");
        assert_eq!(vault.item_home(id).unwrap(), Some(home.clone()));
        std::thread::sleep(std::time::Duration::from_millis(3));
        vault.set_item_home(id, &home).unwrap();
        assert_eq!(version(&vault), after, "the same home changes nothing");
        assert_eq!(
            vault
                .set_item_home(
                    id,
                    &ItemHome {
                        home_uuid: String::new(),
                        ..home.clone()
                    }
                )
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(
            vault.set_item_home(id + 1, &home).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            vault.item_home(id + 1).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert!(vault.clear_item_home(id).unwrap());
        assert!(!vault.clear_item_home(id).unwrap());
        vault.set_item_home(id, &home).unwrap();
        let revision = vault.details(id).unwrap().summary.revision;
        vault.delete(id, revision).unwrap();
        let left: i64 = vault
            .conn_ref()
            .unwrap()
            .query_row("SELECT count(*) FROM item_home", [], |row| row.get(0))
            .unwrap();
        assert_eq!(left, 0, "a deleted credential takes its home with it");
    }
}
