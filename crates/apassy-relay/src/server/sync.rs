//! Vault sync (ADR 0022 of the core, stage 1; docs/SPEC.md section 24).
//!
//! A team holds one opaque snapshot of one vault, with a head signed by the device that
//! pushed it (`crate::sync_head`) and a version that grows by one for each push. The
//! relay checks the head, the chain, and the hash; it never opens a snapshot. The heads
//! are rows of `sync_head` in the team file; the snapshots are files in
//! `teams/<team id>.sync/`, the current and the previous version only. A push streams to
//! a temporary file while it is hashed, and the file is renamed only after every check
//! passed, under the team's sync mutex, so the relay never holds a partial snapshot.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::PoisonError;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{ReceiptRequest, SyncChainEntry, SyncHeadView, SyncReceipt, SyncSigner};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::encode_b64;
use crate::ids::DeviceId;
use crate::server::Core;
use crate::server::approvals::MAX_WAIT_SECS;
use crate::server::audit::member_actor;
use crate::server::auth::MemberAuth;
use crate::server::devices;
use crate::server::store::{db, to_i, to_u};
use crate::sync_head::{HEAD_HEADER, MAX_SNAPSHOT_BYTES, SIGNATURE_HEADER, SignedHead, ZERO_HASH};

/// The most chain entries in one answer.
pub const MAX_CHAIN: u64 = 1000;
/// The heads that maintenance keeps: the newest ones (`Limits::kept_heads`). The number is
/// a fixed part of relay-sync-v1 (section 12), one constant with the client's check of a
/// first download.
pub const KEPT_HEADS: u64 = apassy::sync::KEPT_HEADS;
/// A temporary file older than this is removed by maintenance.
const TEMP_MAX_AGE_SECS: u64 = 3600;
/// The piece of a snapshot that is read, hashed, and written at a time.
const COPY_BUFFER: usize = 64 * 1024;

/// An error of a sync endpoint. `current` is the current version when the answer
/// carries it as `ETag` (412).
#[derive(Debug)]
pub struct SyncError {
    pub error: RelayError,
    pub current: Option<u64>,
    /// The seconds of `Retry-After` (429 `rate_limited`).
    pub retry_after: Option<u64>,
}

impl From<RelayError> for SyncError {
    fn from(error: RelayError) -> Self {
        Self {
            error,
            current: None,
            retry_after: None,
        }
    }
}

pub type SyncResult<T> = Result<T, SyncError>;

/// 412: `If-Match` does not name the current version.
fn precondition(current: u64) -> SyncError {
    SyncError {
        error: RelayError::new(
            codes::PRECONDITION_FAILED,
            format!("The current version is {current}. Read the head and try again."),
        ),
        current: Some(current),
        retry_after: None,
    }
}

/// The seconds until a Connect team may push `incoming` more bytes: `None` while the
/// snapshots of the last 3600 seconds and `incoming` stay within
/// `CONNECT_SYNC_BYTES_PER_HOUR`, else the time when enough of them leave the window
/// (at least 1).
fn bytes_wait(conn: &Connection, now: u64, incoming: u64) -> RelayResult<Option<u64>> {
    let cap = crate::server::directory::CONNECT_SYNC_BYTES_PER_HOUR;
    let mut stmt = conn
        .prepare("SELECT pushed_at, size FROM sync_head WHERE pushed_at > ?1 ORDER BY pushed_at")
        .map_err(db)?;
    let rows = stmt
        .query_map(params![to_i(now.saturating_sub(3600))], |row| {
            Ok((to_u(row.get(0)?), to_u(row.get(1)?)))
        })
        .map_err(db)?
        .collect::<Result<Vec<(u64, u64)>, _>>()
        .map_err(db)?;
    let mut left: u64 = rows.iter().map(|(_, size)| *size).sum();
    if left.saturating_add(incoming) <= cap {
        return Ok(None);
    }
    for (at, size) in rows {
        left = left.saturating_sub(size);
        if left.saturating_add(incoming) <= cap {
            return Ok(Some(at.saturating_add(3600).saturating_sub(now).max(1)));
        }
    }
    Ok(Some(3600))
}

/// 403 `sync_head_invalid`, naming the check that failed.
fn head_invalid(check: &str) -> SyncError {
    RelayError::new(
        codes::SYNC_HEAD_INVALID,
        format!("The sync head fails the {check} check. Nothing is stored."),
    )
    .into()
}

/// A refused push: one `sync_refused` row, rate-limited as other refusals.
fn refused(core: &Core, now: u64, reason: &str) {
    core.audit.refusal(
        &core.store,
        now,
        "sync",
        "sync_refused",
        &json!({"reason": reason}),
    );
}

/// 403 `plan_required`: the team's `sync_bytes` is 0, so vault sync through the relay is
/// not in its plan (a Connect team on Free, docs/SPEC.md section 26).
fn plan_required() -> RelayError {
    RelayError::new(
        codes::PLAN_REQUIRED,
        "Vault sync through the relay is not in this team's plan.",
    )
}

/// The device of the caller. Sync is for devices only: a member token is 401.
fn device_of(by: &MemberAuth) -> RelayResult<DeviceId> {
    by.device
        .map(|device| device.id)
        .ok_or_else(RelayError::unauthenticated)
}

/// Marks the device as seen (`last_seen_at`, at most once a minute). A failure here does
/// not fail the sync call.
fn seen(core: &Core, device: DeviceId, now: u64) {
    let _ = core
        .store
        .with(|conn| devices::mark_seen(conn, device, now));
}

/// True for the name of a snapshot file: `<version>.bin`.
pub fn is_snapshot_name(name: &str) -> bool {
    name.strip_suffix(".bin")
        .is_some_and(|version| !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()))
}

/// Offline recovery check: current and previous heads must have regular snapshots
/// of their declared length and SHA-256. Older heads are chain metadata: their
/// snapshots are intentionally pruned by push (SPEC 24), so they need no file.
pub fn verify_snapshots(conn: &Connection, dir: &Path) -> RelayResult<()> {
    let mut statement = conn
        .prepare(
            "SELECT version, size, snapshot_sha256 FROM sync_head ORDER BY version DESC LIMIT 2",
        )
        .map_err(db)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                to_u(row.get(0)?),
                to_u(row.get(1)?),
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(db)?;
    for row in rows {
        let (version, size, digest) = row.map_err(db)?;
        let path = dir.join(format!("{version}.bin"));
        let failed = || {
            RelayError::internal(format!(
                "Snapshot {version} is missing or differs from its retained head."
            ))
        };
        let meta = fs::symlink_metadata(&path).map_err(|_| failed())?;
        if !meta.is_file() || meta.len() != size {
            return Err(failed());
        }
        let mut file = File::open(&path).map_err(|_| failed())?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|_| failed())?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        if hash.finalize().as_slice() != digest {
            return Err(failed());
        }
    }
    Ok(())
}

/// Validates a restored data directory, read-only, including suspended teams.
pub fn verify_restored(config: &crate::config::RelayConfig) -> RelayResult<usize> {
    use crate::server::store::Store;
    // `connect` mode: the files are plain (docs/SPEC.md section 37).
    let directory =
        Store::open_read_only_for(config, &config.directory_path(), &config.master_key)?;
    let rows = directory.with(crate::server::directory::read_teams)?;
    for row in &rows {
        let store = Store::open_read_only_for(config, &config.team_path(&row.id), &row.file_key)?;
        store.with(|conn| verify_snapshots(conn, &config.sync_dir(&row.id)))?;
    }
    Ok(rows.len())
}

fn snapshot_path(core: &Core, version: u64) -> PathBuf {
    core.config
        .sync_dir(&core.team)
        .join(format!("{version}.bin"))
}

/// The snapshot directory of the team, mode 0700.
fn prepare_dir(dir: &Path) -> RelayResult<()> {
    let cannot = || RelayError::internal("The snapshot folder cannot be created.");
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(_) => return Err(cannot()),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|_| cannot())
}

/// One stored head.
struct HeadRow {
    version: u64,
    vault_id: String,
    size: u64,
    head_sha256: Vec<u8>,
    device_id: DeviceId,
    head: String,
    signature: Vec<u8>,
    pushed_at: u64,
}

const HEAD_COLUMNS: &str =
    "version, vault_id, size, head_sha256, device_id, head, signature, pushed_at";

fn head_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HeadRow> {
    Ok(HeadRow {
        version: to_u(row.get(0)?),
        vault_id: row.get(1)?,
        size: to_u(row.get(2)?),
        head_sha256: row.get(3)?,
        device_id: DeviceId(to_u(row.get(4)?)),
        head: row.get(5)?,
        signature: row.get(6)?,
        pushed_at: to_u(row.get(7)?),
    })
}

/// The current head, or `None` when the team has no snapshot.
fn current(conn: &Connection) -> RelayResult<Option<HeadRow>> {
    conn.query_row(
        &format!("SELECT {HEAD_COLUMNS} FROM sync_head ORDER BY version DESC LIMIT 1"),
        [],
        head_row,
    )
    .optional()
    .map_err(db)
}

/// The current version: 0 when the team has no snapshot.
pub fn current_version(conn: &Connection) -> RelayResult<u64> {
    conn.query_row(
        "SELECT coalesce(max(version), 0) FROM sync_head",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(to_u)
    .map_err(db)
}

fn entry(row: &HeadRow) -> SyncChainEntry {
    SyncChainEntry {
        version: row.version,
        head: encode_b64(row.head.as_bytes()),
        signature: encode_b64(&row.signature),
        device_id: row.device_id,
        pushed_at: row.pushed_at,
    }
}

/// The receipts of the live devices.
fn receipts(conn: &Connection) -> RelayResult<Vec<SyncReceipt>> {
    let mut statement = conn
        .prepare(
            "SELECT r.device_id, d.name, r.version, r.at FROM sync_receipt r \
             JOIN device d ON d.id = r.device_id JOIN member m ON m.id = d.member_id \
             WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL ORDER BY r.device_id",
        )
        .map_err(db)?;
    let rows = statement
        .query_map([], |row| {
            Ok(SyncReceipt {
                device_id: DeviceId(to_u(row.get(0)?)),
                device_name: row.get(1)?,
                version: to_u(row.get(2)?),
                at: to_u(row.get(3)?),
            })
        })
        .map_err(db)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)
}

/// The signer of each head in `devices`: its public key, and for a removed device the
/// newest version it pushed. A device that the team file does not have is left out.
fn signers(conn: &Connection, devices: &[DeviceId]) -> RelayResult<Vec<SyncSigner>> {
    let mut ids: Vec<u64> = devices.iter().map(|device| device.0).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut statement = conn
        .prepare(
            "SELECT d.public_key, d.revoked_at IS NOT NULL OR m.revoked_at IS NOT NULL, \
             (SELECT max(version) FROM sync_head WHERE device_id = d.id) \
             FROM device d JOIN member m ON m.id = d.member_id WHERE d.id = ?1",
        )
        .map_err(db)?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let row = statement
            .query_row(params![to_i(id)], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .optional()
            .map_err(db)?;
        if let Some((key, removed, last)) = row {
            out.push(SyncSigner {
                device_id: DeviceId(id),
                public_key: encode_b64(&key),
                removed,
                last_version: if removed { last.map(to_u) } else { None },
            });
        }
    }
    Ok(out)
}

/// The state of the team for a device that has `since`: the current head, the heads of
/// the versions after `since` (the oldest `MAX_CHAIN`, oldest first: with more, the
/// device asks again from the last one), their signers, and the receipts.
pub fn view(conn: &Connection, since: u64) -> RelayResult<SyncHeadView> {
    let receipts = receipts(conn)?;
    let Some(head) = current(conn)? else {
        return Ok(SyncHeadView {
            version: 0,
            head: None,
            signature: None,
            device_id: None,
            device_name: None,
            pushed_at: None,
            chain: Vec::new(),
            chain_from: None,
            kept_from: None,
            receipts,
            signers: Vec::new(),
        });
    };
    let chain = {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {HEAD_COLUMNS} FROM sync_head WHERE version > ?1 ORDER BY version ASC LIMIT ?2"
            ))
            .map_err(db)?;
        let rows = statement
            .query_map(params![to_i(since), to_i(MAX_CHAIN)], head_row)
            .map_err(db)?;
        rows.map(|row| row.map(|row| entry(&row)))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?
    };
    // The oldest head that maintenance left: the chain of a device without an anchor
    // starts there.
    let kept_from: Option<i64> = conn
        .query_row("SELECT min(version) FROM sync_head", [], |row| row.get(0))
        .map_err(db)?;
    let device_name: Option<String> = conn
        .query_row(
            "SELECT name FROM device WHERE id = ?1",
            params![to_i(head.device_id.0)],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    let mut signed: Vec<DeviceId> = chain.iter().map(|entry| entry.device_id).collect();
    signed.push(head.device_id);
    let signers = signers(conn, &signed)?;
    let current = entry(&head);
    Ok(SyncHeadView {
        version: head.version,
        head: Some(current.head),
        signature: Some(current.signature),
        device_id: Some(head.device_id),
        device_name,
        pushed_at: Some(head.pushed_at),
        chain_from: chain.first().map(|entry| entry.version),
        kept_from: kept_from.map(to_u),
        chain,
        receipts,
        signers,
    })
}

/// `GET /v1/sync/head?since=N&wait=S`. While the current version equals `since`, holds
/// the answer up to `wait` seconds on the team notifier (a push or a delete wakes it).
/// A device has at most one sync long poll; a second is answered at once. A team whose
/// `sync_bytes` is 0 (`Core::sync_bytes`: also a free Connect team after the end of free
/// relay sync) can get no new version, so it is answered at once too, and so is a
/// Connect team's poll over `Limits::connect_long_polls`. Marks the device as seen, as a
/// push, a download, and a receipt do.
pub fn head(
    core: &Core,
    by: &MemberAuth,
    since: u64,
    wait_secs: u64,
    now: u64,
) -> RelayResult<SyncHeadView> {
    let device = device_of(by)?;
    seen(core, device, now);
    let poll = if wait_secs > 0 && core.sync_bytes() > 0 {
        core.sync_polls.enter(device.0)
    } else {
        None
    };
    let seat = poll.as_ref().and_then(|_| core.poll_seat());
    let wait_secs = if seat.is_some() { wait_secs } else { 0 };
    let deadline = Instant::now() + Duration::from_secs(wait_secs.min(MAX_WAIT_SECS));
    loop {
        let seen = core.notify.current();
        let view = core.store.with(|conn| view(conn, since))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if view.version != since || remaining.is_zero() || core.stopping() {
            return Ok(view);
        }
        core.notify
            .wait_from(seen, remaining.min(Duration::from_millis(500)));
    }
}

/// One snapshot transfer of the team and of the relay. Dropping it frees both.
pub struct TransferSlot<'a> {
    core: &'a Core,
}

impl<'a> TransferSlot<'a> {
    /// A slot, or 503 `busy` when the team's `sync_transfers` or the relay's
    /// `sync_transfers_total` are in use.
    pub fn take(core: &'a Core) -> RelayResult<Self> {
        let busy = || {
            RelayError::new(
                codes::BUSY,
                "The snapshot transfers are in use. Try again in a moment.",
            )
        };
        let team_max = usize::try_from(core.limits().sync_transfers).unwrap_or(usize::MAX);
        let relay_max = core.config.limits.sync_transfers_total;
        let take = |counter: &std::sync::atomic::AtomicUsize, max: usize| {
            counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                    (active < max).then_some(active + 1)
                })
                .is_ok()
        };
        if !take(&core.sync_transfers, team_max) {
            return Err(busy());
        }
        if !take(&core.relay_sync_transfers, relay_max) {
            core.sync_transfers.fetch_sub(1, Ordering::Relaxed);
            return Err(busy());
        }
        Ok(Self { core })
    }
}

impl Drop for TransferSlot<'_> {
    fn drop(&mut self) {
        self.core.sync_transfers.fetch_sub(1, Ordering::Relaxed);
        self.core
            .relay_sync_transfers
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// The headers of `PUT /v1/sync/snapshot`, checked before the token: 400 first, then
/// 413 for a `Content-Length` above 64 MiB, which no push can have.
#[derive(Debug, Clone)]
pub struct PushRequest {
    /// The version the device saw last.
    pub if_match: u64,
    pub content_length: u64,
    pub head: SignedHead,
}

/// A decimal `u64` with digits only.
fn decimal(text: &str) -> Option<u64> {
    let text = text.trim();
    (!text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse::<u64>().ok())
        .flatten()
}

/// `If-Match: "<decimal version>"`.
pub fn parse_if_match(text: &str) -> Option<u64> {
    decimal(text.trim().strip_prefix('"')?.strip_suffix('"')?)
}

impl PushRequest {
    /// Reads the request headers through `header` (a lookup by name).
    pub fn from_headers(header: impl Fn(&'static str) -> Option<String>) -> RelayResult<Self> {
        if header("Transfer-Encoding").is_some() {
            return Err(RelayError::invalid(
                "Send the snapshot with Content-Length, not Transfer-Encoding.",
            ));
        }
        let content_length = header("Content-Length")
            .as_deref()
            .and_then(decimal)
            .ok_or_else(|| RelayError::invalid("Content-Length is required."))?;
        let if_match = header("If-Match")
            .as_deref()
            .and_then(parse_if_match)
            .ok_or_else(|| {
                RelayError::invalid("If-Match is required: the version in quotes, such as \"0\".")
            })?;
        let (Some(head), Some(signature)) = (header(HEAD_HEADER), header(SIGNATURE_HEADER)) else {
            return Err(RelayError::invalid(format!(
                "{HEAD_HEADER} and {SIGNATURE_HEADER} are required."
            )));
        };
        let head = SignedHead::from_headers(head.trim(), signature.trim())
            .map_err(|_| RelayError::invalid("The sync head does not follow the grammar."))?;
        if content_length > MAX_SNAPSHOT_BYTES {
            return Err(RelayError::new(
                codes::PAYLOAD_TOO_LARGE,
                "The snapshot is larger than 64 MiB.",
            ));
        }
        Ok(Self {
            if_match,
            content_length,
            head,
        })
    }
}

/// A temporary snapshot file. Removed on drop unless it was moved into place.
struct TempFile {
    path: PathBuf,
    file: File,
    kept: bool,
}

impl TempFile {
    fn create(dir: &Path, version: u64) -> RelayResult<Self> {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|_| RelayError::internal("The system has no random source."))?;
        let path = dir.join(format!("{version}.{}.tmp", crate::sync_head::hex(&random)));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| RelayError::internal("The snapshot cannot be written."))?;
        Ok(Self {
            path,
            file,
            kept: false,
        })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.kept {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// `PUT /v1/sync/snapshot` after the headers and the token passed: the checks of
/// docs/SPEC.md section 24.3, in order, then the body, then the commit. `reauth` reads
/// the caller again after the body. Nothing is stored unless every check passes.
pub fn push(
    core: &Core,
    by: &MemberAuth,
    request: &PushRequest,
    body: &mut dyn Read,
    reauth: &dyn Fn() -> RelayResult<MemberAuth>,
    now: u64,
) -> SyncResult<SyncHeadView> {
    let device = device_of(by)?;
    seen(core, device, now);
    let head = &request.head.head;
    let limits = core.limits();
    // `sync_bytes` 0: the team has no vault sync on the relay (a Connect team on Free,
    // docs/SPEC.md section 26, or any free Connect team once free relay sync is over,
    // section 37). Before the size, so the answer names the plan.
    if core.sync_bytes() == 0 {
        refused(core, now, "plan_required");
        return Err(plan_required().into());
    }
    if request.content_length > limits.sync_bytes {
        refused(core, now, "too_large");
        return Err(RelayError::new(
            codes::PAYLOAD_TOO_LARGE,
            format!(
                "The snapshot is larger than the team's limit of {} bytes.",
                limits.sync_bytes
            ),
        )
        .into());
    }
    core.store.with(|conn| {
        let pushes: i64 = conn
            .query_row(
                "SELECT count(*) FROM sync_head WHERE pushed_at > ?1",
                params![to_i(now.saturating_sub(3600))],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(pushes) >= limits.sync_pushes_per_hour {
            return Err(core.limit_error_on(conn, now, "sync_pushes_per_hour")?);
        }
        // The bytes of a Connect team in the hour: anyone can make such a team.
        if core.kind == crate::api::TeamKind::Connect
            && let Some(wait) = bytes_wait(conn, now, request.content_length)?
        {
            core.limit_error_on(conn, now, "sync_bytes_per_hour")?;
            return Ok(Some(wait));
        }
        Ok(None)
    })
    .map_err(SyncError::from)
    .and_then(|wait| match wait {
        None => Ok(()),
        Some(wait) => Err(SyncError {
            error: RelayError::new(
                codes::RATE_LIMITED,
                format!(
                    "The team pushed its 512 MiB of snapshots for this hour. Try again in {wait} seconds."
                ),
            ),
            current: None,
            retry_after: Some(wait),
        }),
    })?;
    let _slot = TransferSlot::take(core)?;
    let (latest, public_key) = core.store.with(|conn| {
        let key: Option<Vec<u8>> = conn
            .query_row(
                "SELECT public_key FROM device WHERE id = ?1 AND revoked_at IS NULL",
                params![to_i(device.0)],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok((current(conn)?, key.ok_or_else(RelayError::unauthenticated)?))
    })?;
    let version = latest.as_ref().map_or(0, |row| row.version);
    if request.if_match != version {
        refused(core, now, "if_match");
        return Err(precondition(version));
    }
    let previous = latest
        .as_ref()
        .map_or(ZERO_HASH.to_vec(), |row| row.head_sha256.clone());
    let check = if head.team != core.team || head.device != device {
        Some("device")
    } else if !request.head.verifies(&public_key) {
        Some("signature")
    } else if head.version != version.saturating_add(1) {
        Some("version")
    } else if head.previous.as_slice() != previous.as_slice() {
        Some("previous")
    } else if latest
        .as_ref()
        .is_some_and(|row| row.vault_id != head.vault_id)
    {
        Some("vault id")
    } else if head.size != request.content_length {
        Some("size")
    } else {
        None
    };
    if let Some(check) = check {
        refused(core, now, check);
        return Err(head_invalid(check));
    }

    // The body streams to a temporary file while it is hashed.
    let dir = core.config.sync_dir(&core.team);
    prepare_dir(&dir)?;
    let mut temp = TempFile::create(&dir, head.version)?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; COPY_BUFFER];
    loop {
        match body.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total = total.saturating_add(read as u64);
                if total > request.content_length {
                    break;
                }
                hasher.update(&buffer[..read]);
                temp.file
                    .write_all(&buffer[..read])
                    .map_err(|_| RelayError::internal("The snapshot cannot be written."))?;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if total != request.content_length {
        refused(core, now, "length");
        return Err(RelayError::invalid("The body does not have Content-Length bytes.").into());
    }
    temp.file
        .sync_all()
        .map_err(|_| RelayError::internal("The snapshot cannot be written."))?;
    let hash: [u8; 32] = hasher.finalize().into();
    if hash != head.snapshot_sha256 {
        refused(core, now, "hash");
        return Err(head_invalid("hash"));
    }
    // A device revoked while the body was on its way counts for this push too.
    if device_of(&reauth()?)? != device {
        return Err(RelayError::unauthenticated().into());
    }

    // One commit at a time: another push may have committed while this one streamed.
    let _commit = core
        .sync_commit
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let latest = core.store.with(current)?;
    let latest_version = latest.as_ref().map_or(0, |row| row.version);
    let latest_hash = latest
        .as_ref()
        .map_or(ZERO_HASH.to_vec(), |row| row.head_sha256.clone());
    if latest_version != version || latest_hash != previous {
        refused(core, now, "if_match");
        return Err(precondition(latest_version));
    }
    let target = snapshot_path(core, head.version);
    fs::rename(&temp.path, &target)
        .map_err(|_| RelayError::internal("The snapshot cannot be moved into place."))?;
    temp.kept = true;
    if let Ok(folder) = File::open(&dir) {
        let _ = folder.sync_all();
    }
    let head_hash = request.head.hash();
    let text = String::from_utf8_lossy(&request.head.text).into_owned();
    let committed = core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        // A removal of the device or its member takes the store too: one that came after
        // the check above still stops the push, so a removed device never gets a head.
        let live: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM device d JOIN member m ON m.id = d.member_id \
                 WHERE d.id = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL)",
                params![to_i(device.0)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if !live {
            return Err(RelayError::unauthenticated());
        }
        tx.execute(
            "INSERT INTO sync_head (version, vault_id, snapshot_sha256, size, previous_sha256, \
             head_sha256, device_id, head_time, head, signature, pushed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                to_i(head.version),
                head.vault_id,
                head.snapshot_sha256.as_slice(),
                to_i(head.size),
                head.previous.as_slice(),
                head_hash.as_slice(),
                to_i(device.0),
                to_i(head.time),
                text,
                request.head.signature,
                to_i(now)
            ],
        )
        .map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "sync_pushed",
            None,
            &json!({"version": head.version, "device_id": device, "size": head.size}),
        )?;
        view(tx, head.version)
    });
    let view = match committed {
        Ok(view) => view,
        Err(error) => {
            let _ = fs::remove_file(&target);
            return Err(error.into());
        }
    };
    // Keep the current and the previous snapshot only.
    if let Some(old) = head.version.checked_sub(2).filter(|old| *old >= 1) {
        let _ = fs::remove_file(snapshot_path(core, old));
    }
    drop(_commit);
    core.notify.notify();
    Ok(view)
}

/// An open snapshot file for `GET /v1/sync/snapshot`, with its head and a transfer slot
/// that is held until the answer is sent.
pub struct Snapshot<'a> {
    pub file: File,
    pub size: u64,
    pub version: u64,
    /// The head text, base64url.
    pub head: String,
    /// The DER signature, base64url.
    pub signature: String,
    /// Held until the answer is sent.
    pub slot: TransferSlot<'a>,
}

/// `GET /v1/sync/snapshot?version=N`: the current or the previous version, else 404.
pub fn open_snapshot<'a>(
    core: &'a Core,
    by: &MemberAuth,
    version: u64,
    now: u64,
) -> RelayResult<Snapshot<'a>> {
    seen(core, device_of(by)?, now);
    let missing = || RelayError::not_found("snapshot");
    let (row, file) = {
        // A push or a delete cannot change the files between the lookup and the open.
        let _commit = core
            .sync_commit
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (latest, row) = core.store.with(|conn| {
            let row = conn
                .query_row(
                    &format!("SELECT {HEAD_COLUMNS} FROM sync_head WHERE version = ?1"),
                    params![to_i(version)],
                    head_row,
                )
                .optional()
                .map_err(db)?;
            Ok((current_version(conn)?, row))
        })?;
        let row = row
            .filter(|_| version == latest || version.saturating_add(1) == latest)
            .ok_or_else(missing)?;
        let file = match File::open(snapshot_path(core, version)) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Err(missing()),
            Err(_) => return Err(RelayError::internal("The snapshot cannot be read.")),
        };
        (row, file)
    };
    let size = file
        .metadata()
        .map_err(|_| RelayError::internal("The snapshot cannot be read."))?
        .len();
    if size != row.size {
        return Err(RelayError::internal(
            "The snapshot file does not match its head.",
        ));
    }
    let slot = TransferSlot::take(core)?;
    let entry = entry(&row);
    Ok(Snapshot {
        file,
        size,
        version,
        head: entry.head,
        signature: entry.signature,
        slot,
    })
}

/// Writes `sync_fetched` after a snapshot was sent: at most one row per device and
/// version (a version counts from its push, so a version number reused after a delete
/// gets its own row).
pub fn record_fetch(core: &Core, by: &MemberAuth, version: u64, now: u64) -> RelayResult<()> {
    let device = device_of(by)?;
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let pushed_at: Option<i64> = tx
            .query_row(
                "SELECT pushed_at FROM sync_head WHERE version = ?1",
                params![to_i(version)],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let Some(pushed_at) = pushed_at else {
            return Ok(());
        };
        let seen: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM audit WHERE action = 'sync_fetched' AND at >= ?1 \
                 AND json_extract(detail, '$.device_id') = ?2 AND json_extract(detail, '$.version') = ?3)",
                params![pushed_at, to_i(device.0), to_i(version)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if !seen {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "sync_fetched",
                None,
                &json!({"version": version, "device_id": device}),
            )?;
        }
        Ok(())
    })
}

/// `POST /v1/sync/receipt`: this device merged `version`. 403 `plan_required` when the
/// team's `sync_bytes` is 0 (`Core::sync_bytes`). The `sync_received` row is written only when the device's
/// version changes; the same receipt again only moves its time.
pub fn receipt(
    core: &Core,
    by: &MemberAuth,
    request: &ReceiptRequest,
    now: u64,
) -> RelayResult<Value> {
    let device = device_of(by)?;
    seen(core, device, now);
    if core.sync_bytes() == 0 {
        refused(core, now, "plan_required");
        return Err(plan_required());
    }
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let latest = current_version(tx)?;
        if request.version > latest {
            return Err(RelayError::new(
                codes::CONFLICT,
                format!(
                    "The relay has no version {}: the current version is {latest}.",
                    request.version
                ),
            ));
        }
        let before: Option<i64> = tx
            .query_row(
                "SELECT version FROM sync_receipt WHERE device_id = ?1",
                params![to_i(device.0)],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        tx.execute(
            "INSERT INTO sync_receipt (device_id, version, at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(device_id) DO UPDATE SET version = excluded.version, at = excluded.at",
            params![to_i(device.0), to_i(request.version), to_i(now)],
        )
        .map_err(db)?;
        if before.map(to_u) != Some(request.version) {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "sync_received",
                None,
                &json!({"version": request.version, "device_id": device}),
            )?;
        }
        Ok(json!({"version": request.version, "at": now}))
    })
}

/// `DELETE /v1/sync` by an owner's device: every head, every receipt, and every snapshot
/// file. `If-Match` must name the current version; `"0"` on an empty team is a no-op.
pub fn delete(core: &Core, by: &MemberAuth, if_match: u64, now: u64) -> SyncResult<Value> {
    device_of(by)?;
    let _commit = core
        .sync_commit
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let latest = core.store.with(current_version)?;
    if if_match != latest {
        return Err(precondition(latest));
    }
    if latest == 0 {
        return Ok(json!({"last_version": 0}));
    }
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Owner, now)?;
        tx.execute("DELETE FROM sync_head", []).map_err(db)?;
        tx.execute("DELETE FROM sync_receipt", []).map_err(db)?;
        core.audit.write_on(
            tx,
            now,
            &member_actor(by.id.0),
            "sync_deleted",
            None,
            &json!({"last_version": latest}),
        )?;
        Ok(())
    })?;
    // The rows are gone, so no file is served any more. A push in flight keeps its
    // temporary file and gets 412 at its commit.
    if let Ok(entries) = fs::read_dir(core.config.sync_dir(&core.team)) {
        for entry in entries.flatten() {
            if is_snapshot_name(&entry.file_name().to_string_lossy()) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    drop(_commit);
    core.notify.notify();
    Ok(json!({"last_version": latest}))
}

/// Every 5 seconds, per team: drops the heads older than the newest `Limits::kept_heads`
/// (`KEPT_HEADS`), and the temporary files older than one hour (a push that never
/// finished).
pub fn maintenance(core: &Core, now: u64) -> RelayResult<()> {
    let kept = core.config.limits.kept_heads.max(1);
    core.store.with(|conn| {
        conn.execute(
            "DELETE FROM sync_head WHERE version <= (SELECT max(version) FROM sync_head) - ?1",
            params![to_i(kept)],
        )
        .map(drop)
        .map_err(db)
    })?;
    if let Ok(entries) = fs::read_dir(core.config.sync_dir(&core.team)) {
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .is_some_and(|at| now.saturating_sub(at.as_secs()) > TEMP_MAX_AGE_SECS);
            if old && entry.file_name().to_string_lossy().ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A team file with the tables that `view` reads, `heads` heads pushed in turn by
    /// devices 1 and 2, and device 2 removed after its pushes.
    fn team_with_heads(heads: u64) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE member (id INTEGER PRIMARY KEY, revoked_at INTEGER);
             CREATE TABLE device (id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL,
               name TEXT NOT NULL, public_key BLOB NOT NULL, revoked_at INTEGER);
             CREATE TABLE sync_head (version INTEGER PRIMARY KEY, vault_id TEXT NOT NULL,
               snapshot_sha256 BLOB NOT NULL, size INTEGER NOT NULL, previous_sha256 BLOB NOT NULL,
               head_sha256 BLOB NOT NULL, device_id INTEGER NOT NULL, head_time INTEGER NOT NULL,
               head TEXT NOT NULL, signature BLOB NOT NULL, pushed_at INTEGER NOT NULL);
             CREATE TABLE sync_receipt (device_id INTEGER PRIMARY KEY, version INTEGER NOT NULL,
               at INTEGER NOT NULL);
             INSERT INTO member (id) VALUES (1);
             INSERT INTO device (id, member_id, name, public_key) VALUES
               (1, 1, 'MacBook', x'0401'), (2, 1, 'Mac mini', x'0402'), (3, 1, 'iMac', x'0403');",
        )
        .unwrap();
        for version in 1..=heads {
            // Device 2 pushes the even versions up to 10, device 1 every other one.
            let device = if version % 2 == 0 && version <= 10 {
                2
            } else {
                1
            };
            conn.execute(
                "INSERT INTO sync_head VALUES (?1, 'v', x'00', 1, x'00', x'00', ?2, 0, 'h', x'00', 0)",
                params![to_i(version), device],
            )
            .unwrap();
        }
        conn.execute("UPDATE device SET revoked_at = 5 WHERE id = 2", [])
            .unwrap();
        conn
    }

    /// SPEC 24.4: the chain is the oldest 1000 heads after `since`, so a device that is
    /// more than 1000 versions behind reads on from the last one and links every head.
    #[test]
    fn the_chain_pages_forward_from_since() {
        let conn = team_with_heads(2500);
        let mut since = 0;
        let mut pages = 0;
        loop {
            let page = view(&conn, since).unwrap();
            assert_eq!(page.version, 2500);
            if page.chain.is_empty() {
                break;
            }
            assert_eq!(page.chain_from, Some(since + 1));
            let versions: Vec<u64> = page.chain.iter().map(|entry| entry.version).collect();
            let expected: Vec<u64> = (since + 1..=(since + MAX_CHAIN).min(2500)).collect();
            assert_eq!(versions, expected);
            since = *versions.last().unwrap();
            pages += 1;
        }
        assert_eq!((since, pages), (2500, 3));
    }

    /// The answer says where the kept history starts: 1 while every head is kept; after
    /// maintenance dropped the older heads, the oldest kept version, which is where the
    /// chain of `since = 0` starts. A later page keeps saying it.
    #[test]
    fn the_answer_names_the_oldest_kept_head() {
        let conn = team_with_heads(30);
        assert_eq!(view(&conn, 0).unwrap().kept_from, Some(1));
        conn.execute("DELETE FROM sync_head WHERE version <= 20", [])
            .unwrap();
        let first = view(&conn, 0).unwrap();
        assert_eq!((first.chain_from, first.kept_from), (Some(21), Some(21)));
        assert_eq!(first.chain.len(), 10);
        let later = view(&conn, 25).unwrap();
        assert_eq!((later.chain_from, later.kept_from), (Some(26), Some(21)));
        let empty = team_with_heads(0);
        assert_eq!(view(&empty, 0).unwrap().kept_from, None);
    }

    /// The signers of a page carry the keys, and a removed device the newest version it
    /// pushed, so its old heads still verify and nothing above them does.
    #[test]
    fn a_removed_signer_keeps_its_key_with_its_last_version() {
        let conn = team_with_heads(12);
        let first = view(&conn, 0).unwrap();
        assert_eq!(
            first.signers,
            vec![
                SyncSigner {
                    device_id: DeviceId(1),
                    public_key: encode_b64(&[4, 1]),
                    removed: false,
                    last_version: None,
                },
                SyncSigner {
                    device_id: DeviceId(2),
                    public_key: encode_b64(&[4, 2]),
                    removed: true,
                    last_version: Some(10),
                },
            ]
        );
        // A page with heads of device 1 only names device 1.
        let later = view(&conn, 10).unwrap();
        assert_eq!(later.signers.len(), 1);
        assert_eq!(later.signers[0].device_id, DeviceId(1));
        // A removed member removes its devices.
        conn.execute("UPDATE member SET revoked_at = 6", [])
            .unwrap();
        let gone = view(&conn, 10).unwrap();
        assert!(gone.signers[0].removed);
        assert_eq!(gone.signers[0].last_version, Some(12));
    }

    #[test]
    fn names_and_preconditions() {
        assert!(is_snapshot_name("1.bin"));
        assert!(is_snapshot_name("10000.bin"));
        assert!(!is_snapshot_name(".bin"));
        assert!(!is_snapshot_name("1.0a1b.tmp"));
        assert!(!is_snapshot_name("x.bin"));
        assert_eq!(parse_if_match("\"0\""), Some(0));
        assert_eq!(parse_if_match(" \"17\" "), Some(17));
        for bad in ["0", "\"\"", "\"-1\"", "W/\"1\"", "\"1", "\"a\"", "\"1 \"x"] {
            assert_eq!(parse_if_match(bad), None, "{bad}");
        }
        assert_eq!(decimal("18"), Some(18));
        assert_eq!(decimal("+18"), None);
        assert_eq!(decimal("99999999999999999999"), None);
    }
}
