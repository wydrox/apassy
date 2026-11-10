//! The backup of a stopped relay (`apassy-relay backup`) and the cutover from the hosted
//! relay to Apassy Connect (`apassy-relay connect-cutover`), docs/SPEC.md section 37 and
//! docs/operations/connect.md. Both run with the relay stopped: they take `relay.lock`.
//!
//! **The backup of a stopped relay** copies every file that the relay keeps in its data
//! directory, byte for byte: `relay.db`, every file under `teams/` (the team files, their
//! `.pre-v*` copies, and the snapshot folders), the old `team.db`, `team.db.pre-teams`,
//! the files of a migration that stopped (`relay.db.migrating` and its journal), and
//! `audit-archive/`: every file that the cutover keeps, changes, or deletes. Each copy is
//! hashed again against its source. `MANIFEST.json` names each file with its size and
//! SHA-256 and says `"stopped": true`. The relay is stopped, so nothing changes between the
//! copies: the backup is the data directory as it is. The master key is never in it.
//!
//! **The cutover** is one way and destroys data by design. With the master key of the
//! relay (the configuration before the cutover) it:
//!
//! 1. refuses while the relay runs (`relay.lock`) and while a write journal remains;
//! 2. checks the backup (`backup_check`): the newest stopped backup, or the one named,
//!    holds a byte-identical copy of every file the cutover keeps or deletes, and its own
//!    files still match its manifest. The dry run ends here with the plan and its SHA-256
//!    (`plan_sha256`); a confirmed run goes on only with that SHA-256, so it does what the
//!    owner read;
//! 3. writes a plain copy of each file of a vault store of an account that opens with the
//!    store's key (`teams/<id>.db.plain`, and `.plain` of a `.pre-v*` copy) with
//!    `sqlcipher_export`, and checks each against its source (version, schema objects, and
//!    a hash of the rows of each table). For `relay.db` it copies the keyed file
//!    (`relay.db.work`), deletes there the teams of other kinds, the team codes, the free
//!    Connect keys, and the OAuth state, empties every `team.file_key`, adds one audit row
//!    `connect_cutover`, and vacuums it, all still under the master key; only then is the
//!    result exported to `relay.db.plain` and checked against the keyed `relay.db`. No team
//!    key is ever written to the disk in plain;
//! 4. writes `cutover.json` (`"state": "committing"`, the plan and the hashes before),
//!    keeps the keyed `relay.db` as `relay.db.keyed` (the bytes of the inventory), and
//!    renames `relay.db.plain` over `relay.db`: the commit point;
//! 5. checks the backup again and the keyed copy against the inventory, renames each plain
//!    copy over its file, deletes every other team file (its database, its `.pre-v*`
//!    copies, its snapshot folder), the old team files, the files of a stopped migration,
//!    and the audit archives, each a file of the inventory, and checks that only
//!    `relay.db` and the files of the account stores are left;
//! 6. writes `cutover.json` again (`"state": "done"`, the counts and hashes after, the
//!    files deleted) and deletes `relay.db.keyed`, the last file with the team keys.
//!
//! It never deletes a file whose team id is a vault store of an account: it replaces the
//! store's database and its keyed copies by their checked plain copies, and leaves its
//! snapshots and any file that does not open with its key as they are.
//!
//! **Safe to interrupt.** Before the commit point the keyed `relay.db` is whole and the
//! plain copies are side files: an error removes them at once, and after a kill the next
//! run removes them and starts again. After it, the plain `relay.db` names the stores to
//! keep, `cutover.json` holds the plan, and `relay.db.keyed` still holds the keys: a second
//! run finishes steps 5 and 6 (a file whose plain copy is missing is exported again with
//! the key from `relay.db.keyed`). Neither mode of the relay starts on a cutover that is
//! not finished (`check_start`). At any point the stopped backup of step 2 restores the
//! relay as it was.
//!
//! `--dry-run` (the default) does steps 1 and 2 and answers the plan; it opens every file
//! read-only and writes nothing, not even `cutover.json`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::params;
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api::TeamKind;
use crate::config::{
    ADMIN_SOCKET, DIRECTORY_FILE, LEGACY_BACKUP_FILE, LEGACY_VAULT_FILE, RelayConfig, TEAMS_DIR,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::secret::SecretString;
use crate::server::audit::Audit;
use crate::server::directory::{self, DIRECTORY_VERSION, OPERATOR_ACTOR, TeamRow, TeamState};
use crate::server::store::{self, SCHEMA_VERSION, Store, db};

/// The record and journal of the cutover, in the data directory.
pub const CUTOVER_FILE: &str = "cutover.json";
/// The keyed `relay.db`, kept from the commit point until the end of the cutover.
pub const KEYED_DIRECTORY_FILE: &str = "relay.db.keyed";
/// The plain copy of `relay.db` before the commit point.
pub const PLAIN_DIRECTORY_FILE: &str = "relay.db.plain";
/// The keyed working copy of `relay.db`: edited and vacuumed under the master key, then
/// exported to `relay.db.plain` and deleted, before the commit point.
pub const WORK_DIRECTORY_FILE: &str = "relay.db.work";
/// The suffix of the plain copy of a store's file before it replaces the file.
const PLAIN_SUFFIX: &str = ".plain";
/// The folder of the archived audits of swept Connect teams (`Hub::archive_swept_team`).
const AUDIT_ARCHIVE_DIR: &str = "audit-archive";
/// Files at the root of the data directory that the relay keeps only from its past (the
/// old single team and a migration that stopped, `Relay::migrate`). The cutover deletes
/// them, so the inventory and the backup hold them.
const OLD_FILES: [&str; 5] = [
    LEGACY_VAULT_FILE,
    LEGACY_BACKUP_FILE,
    "team.db-journal",
    "relay.db.migrating",
    "relay.db.migrating-journal",
];
/// The version of the form of `cutover.json`.
const RECORD_VERSION: u32 = 1;
/// The tables of the plain `relay.db` that the cutover empties: they belong to the teams
/// that go (team codes, free Connect keys) or to the MCP flow of a node (OAuth).
const CLEARED_TABLES: [&str; 5] = [
    "team_code",
    "connect_key",
    "oauth_refresh",
    "connect_request",
    "oauth_client",
];
/// The start of the error of a test stop (`Options::interrupt`): a kill, so nothing is
/// cleaned up.
const TEST_STOP: &str = "The cutover stopped for a test";

/// One file of the data directory or of a backup: its name relative to the folder, its
/// size, and the hex SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Where a test stops a cutover, to prove that a second run finishes it. Not an option of
/// the command.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interrupt {
    /// After the plain copies of the first vault store.
    StagedOneStore,
    /// After the plain copy of `relay.db` is written.
    ExportedDirectory,
    /// After every plain copy and `cutover.json` "committing", before the commit point.
    Staged,
    /// After `relay.db.keyed` is in place, before the plain `relay.db` replaces the keyed one.
    KeptKeyed,
    /// Right after the commit point (the plain `relay.db` in place).
    Committed,
    /// After the first store's plain copies replaced its files.
    MovedOneStore,
    /// After the files of the first other team were deleted.
    DeletedOneTeam,
    /// After `cutover.json` "done", before `relay.db.keyed` is deleted.
    Recorded,
}

/// The options of `connect-cutover`.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `--confirm-delete-teams <plan>`: change the files, if `<plan>` is the `plan_sha256`
    /// of the plan as it is now (of a committed cutover: as `cutover.json` records it).
    /// Without it the run is a dry run.
    pub confirm: Option<String>,
    /// `--backup <dir>`: the stopped backup to check; else the newest one in the backup
    /// folder.
    pub backup: Option<PathBuf>,
    /// For the tests only: stop at this point as a kill would (nothing is cleaned up).
    #[doc(hidden)]
    pub interrupt: Option<Interrupt>,
    /// For the tests only: fail at this point with an ordinary error.
    #[doc(hidden)]
    pub fail: Option<Interrupt>,
}

/// The backup that the cutover checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCheck {
    pub dir: String,
    pub created_at: u64,
    pub files: usize,
    /// The check that passed, in words (docs/operations/connect.md, "The backup check").
    pub check: String,
    /// The SHA-256 of the backup's `MANIFEST.json`.
    pub manifest_sha256: String,
}

/// A vault store of an account that the cutover keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptStore {
    pub team_id: TeamId,
    pub account_id: String,
    pub vault_id: String,
    pub state: TeamState,
}

/// A team that the cutover deletes, with its files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedTeam {
    pub team_id: TeamId,
    pub kind: TeamKind,
    pub state: TeamState,
}

/// Counts of teams and files at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub teams: usize,
    pub operator: usize,
    pub connect: usize,
    pub account: usize,
    pub files: usize,
    pub bytes: u64,
}

/// What the cutover did, or would do: the answer of the command and the content of
/// `cutover.json`. Ids, counts, sizes, and hashes only; no name, key, or token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub version: u32,
    /// `dry_run`, `committing` (committed and not finished; a second run finishes), or
    /// `done`.
    pub state: String,
    /// The relay version that ran it.
    pub relay_version: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub backup: BackupCheck,
    pub kept: Vec<KeptStore>,
    pub deleted: Vec<DeletedTeam>,
    pub before: Tally,
    pub after: Option<Tally>,
    /// Rows the plain `relay.db` lost, by table (`team` and `CLEARED_TABLES`).
    pub rows_deleted: BTreeMap<String, u64>,
    pub files_before: Vec<FileEntry>,
    pub files_after: Option<Vec<FileEntry>>,
    /// The files that were deleted, relative to the data directory: the files of
    /// `files_before` that are gone, so also those of an earlier run.
    pub files_deleted: Vec<String>,
    /// Entries of the data directory that the cutover does not know and left as they are,
    /// and files of a kept store that do not open with its key.
    pub left: Vec<String>,
    /// In a dry run or a pending run: what a real run still does, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<String>,
    /// The SHA-256 of the plan, which `--confirm-delete-teams` takes.
    pub plan_sha256: String,
    /// The files of the kept stores that become plain: each store's database and each
    /// keyed copy of it.
    pub converted: Vec<String>,
    /// In a dry run: side files of a run that stopped before its commit point, which the
    /// confirmed run removes first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_files: Vec<String>,
    /// True when this run changed a file (never written to `cutover.json`).
    #[serde(skip)]
    pub changed: bool,
}

/// The line that `apassy-relay connect-cutover` writes to stderr after the JSON: what the
/// run did, from the state it answers.
pub fn summary(report: &Report) -> String {
    match report.state.as_str() {
        "dry_run" => {
            let mut line = format!(
                "a dry run, nothing changed: {} vault stores would stay ({} files made plain), {} teams would be deleted. The backup check passed ({}). To do it, run `apassy-relay connect-cutover --confirm-delete-teams {}`.",
                report.kept.len(),
                report.converted.len(),
                report.deleted.len(),
                report.backup.dir,
                report.plan_sha256
            );
            if !report.side_files.is_empty() {
                line.push_str(" Side files of a run that stopped before its commit point remain; the confirmed run removes them first.");
            }
            line
        }
        "done" if report.changed => format!(
            "the cutover is done: {} vault stores kept as plain files, {} teams deleted, {} files deleted. Start the relay with APASSY_RELAY_MODE=connect and without APASSY_RELAY_KEY_FILE.",
            report.kept.len(),
            report.deleted.len(),
            report.files_deleted.len()
        ),
        "done" => format!(
            "the cutover was done at {}; nothing changed.",
            report.finished_at.unwrap_or_default()
        ),
        _ => format!(
            "the cutover is committed and not finished: relay.db is plain and relay.db.keyed still holds the team keys; this run changed nothing. The backup check passed ({}). To finish it, run `apassy-relay connect-cutover --confirm-delete-teams {}`.",
            report.backup.dir, report.plan_sha256
        ),
    }
}

fn io_error(what: &str) -> RelayError {
    RelayError::internal(format!("The cutover cannot {what}."))
}

fn interrupt(options: &Options, at: Interrupt) -> RelayResult<()> {
    if options.interrupt == Some(at) {
        return Err(RelayError::internal(format!("{TEST_STOP} at {at:?}.")));
    }
    if options.fail == Some(at) {
        return Err(RelayError::internal(format!(
            "The cutover failed for a test at {at:?}."
        )));
    }
    Ok(())
}

/// The lock of the data directory, with the answer of a running relay.
fn lock(config: &RelayConfig, what: &str) -> RelayResult<fs::File> {
    crate::server::hub::lock_data_dir(config).map_err(|error| {
        if error.code == codes::CONFLICT {
            RelayError::new(
                codes::CONFLICT,
                format!(
                    "The relay runs (relay.lock is held): stop it first (`docker compose stop relay`). {what} runs only with the relay stopped."
                ),
            )
        } else {
            error
        }
    })
}

/// SHA-256 and size of a file, read in pieces.
fn hash_file(path: &Path) -> RelayResult<(u64, String)> {
    let mut file = fs::File::open(path).map_err(|_| io_error("read a file to hash it"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut bytes = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| io_error("read a file to hash it"))?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((bytes, crate::sync_head::hex(&hasher.finalize())))
}

fn sync_dir(path: &Path) -> RelayResult<()> {
    fs::File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| io_error("sync a folder"))
}

/// `sync_dir` of a folder that may not exist (a relay without `teams/`).
fn sync_dir_if_there(path: &Path) -> RelayResult<()> {
    if exists(path) { sync_dir(path) } else { Ok(()) }
}

fn remove_if_there(path: &Path) -> RelayResult<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(io_error("delete a file")),
    }
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// True when the file starts with the header of a plain SQLite file (`SQLite format 3\0`).
/// SQLCipher encrypts the whole first page (its first 16 bytes are the salt), so a keyed
/// file never does. Unlike an open, it reads no page and is not stopped by a write journal
/// that a read-only connection cannot roll back (a crash of a plain relay mid-write).
pub(crate) fn plain_header(path: &Path) -> bool {
    let mut header = [0u8; 16];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_ok()
        && &header == b"SQLite format 3\0"
}

/// A name that the cutover itself writes in `teams/` and that is not data of the relay.
fn is_artifact(name: &str) -> bool {
    name.ends_with(PLAIN_SUFFIX) || name.ends_with(".plain-journal")
}

/// The team id at the start of a name in `teams/` (`<id>.db`, `<id>.db.pre-v6`,
/// `<id>.sync`).
fn team_prefix(name: &str) -> Option<TeamId> {
    name.split('.').next().and_then(TeamId::parse)
}

/// The team id of a name relative to the data directory (`teams/<id>…`).
fn owner_of(name: &str) -> Option<TeamId> {
    name.strip_prefix(&format!("{TEAMS_DIR}/"))
        .and_then(team_prefix)
}

/// Every file of the relay in its data directory, by name, sorted, without the cutover's
/// own side files: `relay.db`, the old files (`OLD_FILES`), each file under `teams/` (one
/// folder deep, for the snapshots), and each file of `audit-archive/`. A symbolic link or
/// a deeper folder is refused: a data directory of the relay has none.
fn data_files(config: &RelayConfig) -> RelayResult<Vec<String>> {
    let unexpected = |name: &str| {
        RelayError::internal(format!(
            "The data directory has an unexpected entry: {name}."
        ))
    };
    let mut names = Vec::new();
    for name in std::iter::once(DIRECTORY_FILE).chain(OLD_FILES) {
        match fs::symlink_metadata(config.data_dir.join(name)) {
            Ok(meta) if meta.is_file() => names.push(name.to_string()),
            Ok(_) => return Err(unexpected(name)),
            Err(_) => {}
        }
    }
    for folder in [TEAMS_DIR, AUDIT_ARCHIVE_DIR] {
        let path = config.data_dir.join(folder);
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Err(io_error("read a folder of the data directory")),
        };
        for entry in entries {
            let entry = entry.map_err(|_| io_error("read a folder of the data directory"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = format!("{folder}/{name}");
            let meta = fs::symlink_metadata(entry.path()).map_err(|_| unexpected(&relative))?;
            if meta.is_file() {
                if !is_artifact(&name) {
                    names.push(relative);
                }
            } else if meta.is_dir() && folder == TEAMS_DIR {
                for inner in fs::read_dir(entry.path()).map_err(|_| unexpected(&relative))? {
                    let inner = inner.map_err(|_| unexpected(&relative))?;
                    let inner_name = format!("{relative}/{}", inner.file_name().to_string_lossy());
                    let inner_meta =
                        fs::symlink_metadata(inner.path()).map_err(|_| unexpected(&inner_name))?;
                    if !inner_meta.is_file() {
                        return Err(unexpected(&inner_name));
                    }
                    names.push(inner_name);
                }
            } else {
                return Err(unexpected(&relative));
            }
        }
    }
    names.sort();
    Ok(names)
}

/// `data_files` with the size and hash of each.
fn inventory(config: &RelayConfig) -> RelayResult<Vec<FileEntry>> {
    data_files(config)?
        .into_iter()
        .map(|name| {
            let (bytes, sha256) = hash_file(&config.data_dir.join(&name))?;
            Ok(FileEntry {
                name,
                bytes,
                sha256,
            })
        })
        .collect()
}

/// Refuses while a write journal of the relay remains: a copy of the file without it would
/// lose or tear the write. The relay rolls a journal back when it opens the file.
fn refuse_journals(config: &RelayConfig) -> RelayResult<()> {
    let mut found = Vec::new();
    for name in [
        format!("{DIRECTORY_FILE}-journal"),
        format!("{LEGACY_VAULT_FILE}-journal"),
    ] {
        if exists(&config.data_dir.join(&name)) {
            found.push(name);
        }
    }
    if let Ok(entries) = fs::read_dir(config.teams_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with("-journal") && !is_artifact(&name) {
                found.push(format!("{TEAMS_DIR}/{name}"));
            }
        }
    }
    if let Some(first) = found.first() {
        return Err(RelayError::internal(format!(
            "A write journal remains ({first}): start the relay once and stop it (it rolls the write back), then make a new stopped backup."
        )));
    }
    Ok(())
}

/// The UTC time as the name of a backup folder, as `admin backup` names it.
fn backup_name(now: u64) -> String {
    crate::cli::commands::fmt_time(now)
        .replace(' ', "T")
        .replace(':', "-")
}

/// `apassy-relay backup`: a byte-for-byte copy of the data directory of the stopped relay
/// in a new folder `<backup dir>/<UTC time>` (mode 0700, files 0600), with `MANIFEST.json`
/// (`"stopped": true`). Refuses while the relay runs, while a write journal remains, or
/// on a committed cutover (`relay.db` plain and `relay.db.keyed` beside it: run the
/// cutover again to finish it). A `relay.db.keyed` beside a keyed `relay.db` is a side file
/// of a cutover that stopped before its commit point: it is not data, and the backup leaves
/// it out. Works in both modes: the files are copied as they are, keyed or plain. Answers
/// the manifest.
pub fn stopped_backup(config: &RelayConfig, now: u64) -> RelayResult<serde_json::Value> {
    let _lock = lock(config, "`apassy-relay backup`")?;
    if !exists(&config.directory_path()) {
        return Err(RelayError::internal(
            "There is no relay.db in the data directory.",
        ));
    }
    if exists(&config.data_dir.join(KEYED_DIRECTORY_FILE)) && plain_header(&config.directory_path())
    {
        return Err(RelayError::new(
            codes::CONFLICT,
            "A cutover is committed and not finished (relay.db is plain and relay.db.keyed holds the team keys): run `apassy-relay connect-cutover` again to finish it.",
        ));
    }
    refuse_journals(config)?;
    // The folder is a relay of this version, and the number of its teams.
    let teams = {
        let directory =
            Store::open_read_only_for(config, &config.directory_path(), &config.master_key)?;
        if directory.user_version()? != DIRECTORY_VERSION {
            return Err(RelayError::internal(format!(
                "relay.db is not a directory of version {DIRECTORY_VERSION}: start this version of the relay once first."
            )));
        }
        directory.with(directory::read_teams)?.len()
    };
    let before = inventory(config)?;
    let name = backup_name(now);
    let published = config.backup_dir.join(&name);
    if exists(&published) {
        return Err(RelayError::new(
            codes::CONFLICT,
            "A backup of this second exists. Try again.",
        ));
    }
    let partial = config.backup_dir.join(format!(".{name}.partial"));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&config.backup_dir)
        .map_err(|_| RelayError::internal("The backup folder cannot be created."))?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&partial)
        .map_err(|_| RelayError::internal("The backup folder cannot be created."))?;
    let copied = (|| {
        let mut folders = BTreeSet::new();
        for entry in &before {
            let target = partial.join(&entry.name);
            if let Some(parent) = target.parent()
                && parent != partial
                && folders.insert(parent.to_path_buf())
            {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|_| RelayError::internal("The backup folder cannot be created."))?;
            }
            store::copy_private(&config.data_dir.join(&entry.name), &target)?;
            if hash_file(&target)? != (entry.bytes, entry.sha256.clone()) {
                return Err(RelayError::internal(format!(
                    "The copy of {} does not match its source.",
                    entry.name
                )));
            }
        }
        // Nothing changed while the files were copied (the lock is held; this proves it).
        if inventory(config)? != before {
            return Err(RelayError::internal(
                "The data directory changed during the backup.",
            ));
        }
        let manifest = json!({
            "dir": published.to_string_lossy(),
            "created_at": now,
            "stopped": true,
            "mode": if config.connect.plain_files() { "connect" } else { "relay" },
            "directory_version": DIRECTORY_VERSION,
            "teams": teams,
            "files": before,
        });
        let text = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| RelayError::internal("The manifest cannot be written."))?;
        write_new(&partial.join("MANIFEST.json"), &text)?;
        for folder in folders.iter().rev() {
            sync_dir(folder)?;
        }
        sync_dir(&partial)?;
        Ok(manifest)
    })();
    let manifest = match copied {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = fs::remove_dir_all(&partial);
            return Err(error);
        }
    };
    fs::rename(&partial, &published)
        .map_err(|_| RelayError::internal("The backup cannot be published."))?;
    sync_dir(&config.backup_dir)?;
    Ok(manifest)
}

/// Writes `bytes` to a new file of mode 0600 and syncs it.
fn write_new(path: &Path, bytes: &[u8]) -> RelayResult<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io_error("write a file"))?;
    std::io::Write::write_all(&mut file, bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| io_error("write a file"))
}

/// The manifest of a backup, as far as the check reads it.
#[derive(Deserialize)]
struct Manifest {
    created_at: u64,
    #[serde(default)]
    stopped: bool,
    files: Vec<FileEntry>,
}

/// The first file of `listed` whose copy in the backup `dir` does not have its size and
/// hash.
fn damaged_entry(dir: &Path, listed: &[FileEntry]) -> Option<String> {
    listed
        .iter()
        .find(|entry| {
            hash_file(&dir.join(&entry.name)).ok() != Some((entry.bytes, entry.sha256.clone()))
        })
        .map(|entry| entry.name.clone())
}

/// The backup check (docs/operations/connect.md, "The backup check"): the stopped backup
/// `chosen`, or else the newest folder of the backup folder whose `MANIFEST.json` says
/// `"stopped": true`, lists exactly the files of `current` with the same sizes and hashes,
/// and every file of the backup still has the size and hash of its manifest.
fn backup_check(
    config: &RelayConfig,
    chosen: Option<&Path>,
    current: &[FileEntry],
) -> RelayResult<BackupCheck> {
    let read = |dir: &Path| -> Option<(Vec<u8>, Manifest)> {
        let bytes = fs::read(dir.join("MANIFEST.json")).ok()?;
        let manifest = serde_json::from_slice::<Manifest>(&bytes).ok()?;
        Some((bytes, manifest))
    };
    let (dir, bytes, manifest) = match chosen {
        Some(dir) => {
            let (bytes, manifest) = read(dir).ok_or_else(|| {
                RelayError::internal(format!("{} has no readable MANIFEST.json.", dir.display()))
            })?;
            if !manifest.stopped {
                return Err(RelayError::internal(
                    "The backup named was made while the relay ran (`admin backup`): make one with the relay stopped (`apassy-relay backup`).",
                ));
            }
            (dir.to_path_buf(), bytes, manifest)
        }
        None => {
            let mut names: Vec<String> = fs::read_dir(&config.backup_dir)
                .map_err(|_| {
                    RelayError::internal(
                        "There is no backup folder: make a backup with the relay stopped (`apassy-relay backup`).",
                    )
                })?
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| !name.starts_with('.'))
                .collect();
            names.sort();
            names
                .iter()
                .rev()
                .find_map(|name| {
                    let dir = config.backup_dir.join(name);
                    read(&dir)
                        .filter(|(_, manifest)| manifest.stopped)
                        .map(|(bytes, manifest)| (dir, bytes, manifest))
                })
                .ok_or_else(|| {
                    RelayError::internal(
                        "No backup of the stopped relay: stop the relay and run `apassy-relay backup` first.",
                    )
                })?
        }
    };
    let mut listed = manifest.files.clone();
    listed.sort();
    if listed != current {
        let names = |entries: &[FileEntry]| -> BTreeSet<String> {
            entries.iter().map(|entry| entry.name.clone()).collect()
        };
        let (now, then) = (names(current), names(&listed));
        let differs = current
            .iter()
            .find(|entry| !listed.contains(entry))
            .map(|entry| entry.name.clone())
            .or_else(|| then.difference(&now).next().cloned())
            .unwrap_or_default();
        return Err(RelayError::internal(format!(
            "The backup {} is not a copy of the data directory as it is now ({differs} differs): make a new backup with the relay stopped (`apassy-relay backup`).",
            dir.display()
        )));
    }
    if let Some(name) = damaged_entry(&dir, &listed) {
        return Err(RelayError::internal(format!(
            "The backup {} is damaged: {name} does not match its manifest.",
            dir.display()
        )));
    }
    Ok(BackupCheck {
        dir: dir.to_string_lossy().into_owned(),
        created_at: manifest.created_at,
        files: listed.len(),
        check: "a backup of the stopped relay holds a byte-identical copy (size and SHA-256) of every file that the cutover keeps or deletes, and its own files match its MANIFEST.json".to_string(),
        manifest_sha256: crate::sync_head::hex(&Sha256::digest(&bytes)),
    })
}

/// The backup check again, against the record (F5 of the review of C5): before any step
/// that deletes, the backup that the plan checked still has the same `MANIFEST.json`, it
/// lists exactly `files_before`, and each of its files still matches.
fn recheck_backup(report: &Report) -> RelayResult<()> {
    let dir = Path::new(&report.backup.dir);
    let failed = |why: String| {
        RelayError::internal(format!(
            "The backup that the cutover checked ({}) {why}: this run deleted nothing. Put that backup back as it was (the copy kept off the host, docs/operations/connect.md section 9.3, step 5) and run the cutover again.",
            dir.display()
        ))
    };
    let bytes = fs::read(dir.join("MANIFEST.json")).map_err(|_| failed("is gone".to_string()))?;
    if crate::sync_head::hex(&Sha256::digest(&bytes)) != report.backup.manifest_sha256 {
        return Err(failed("has another MANIFEST.json".to_string()));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|_| failed("has a MANIFEST.json that cannot be read".to_string()))?;
    let mut listed = manifest.files;
    listed.sort();
    if listed != report.files_before {
        return Err(failed(
            "does not list the files of cutover.json".to_string(),
        ));
    }
    if let Some(name) = damaged_entry(dir, &listed) {
        return Err(failed(format!(
            "changed: {name} does not match its manifest"
        )));
    }
    Ok(())
}

/// The teams of the keyed directory, split into the stores that stay and the teams that go.
fn split(rows: Vec<TeamRow>) -> (Vec<TeamRow>, Vec<TeamRow>) {
    rows.into_iter()
        .partition(|row| row.kind == TeamKind::Account)
}

fn tally(rows: &[TeamRow], files: &[FileEntry]) -> Tally {
    let count = |kind: TeamKind| rows.iter().filter(|row| row.kind == kind).count();
    Tally {
        teams: rows.len(),
        operator: count(TeamKind::Operator),
        connect: count(TeamKind::Connect),
        account: count(TeamKind::Account),
        files: files.len(),
        bytes: files.iter().map(|entry| entry.bytes).sum(),
    }
}

/// The state of the data directory for the cutover, from its files.
enum Stage {
    /// `relay.db` is keyed: nothing is committed.
    Keyed,
    /// `relay.db` is plain and `relay.db.keyed` exists: committed, not finished.
    Committed,
    /// `relay.db` is plain and `relay.db.keyed` is gone: finished (or a Connect relay
    /// that never had keys).
    Plain,
}

fn stage(config: &RelayConfig) -> RelayResult<Stage> {
    let directory = config.directory_path();
    if !exists(&directory) {
        return Err(RelayError::internal(
            "There is no relay.db in the data directory.",
        ));
    }
    if !plain_header(&directory) {
        return Ok(Stage::Keyed);
    }
    if exists(&config.data_dir.join(KEYED_DIRECTORY_FILE)) {
        Ok(Stage::Committed)
    } else {
        Ok(Stage::Plain)
    }
}

/// At the start of the relay, in either mode, before it opens or sweeps a file
/// (`Hub::open`): refuses a data directory whose cutover is not finished. A committed
/// cutover (`relay.db` plain, `relay.db.keyed` beside it) starts in no mode. `connect`
/// mode also refuses an encrypted `relay.db` (not cut over, or stopped before the commit
/// point) and a `cutover.json` whose state is not `done`. A `relay.db.keyed` beside a keyed
/// `relay.db` (a run that stopped before its commit point) does not stop `relay` mode:
/// `relay.db` is whole, and the next cutover removes the copy.
pub fn check_start(config: &RelayConfig) -> RelayResult<()> {
    let again = "Run `apassy-relay connect-cutover` again with the configuration before the cutover (the master key, APASSY_RELAY_MODE unset): its dry run says what is left and the plan to confirm (docs/operations/connect.md, section 9.5).";
    let keyed_copy = exists(&config.data_dir.join(KEYED_DIRECTORY_FILE));
    let plain = || plain_header(&config.directory_path());
    if keyed_copy && plain() {
        return Err(RelayError::internal(format!(
            "The cutover to Apassy Connect is committed and not finished (relay.db is plain and relay.db.keyed holds the team keys): the relay does not start on it, in either mode. {again}"
        )));
    }
    if !config.connect.plain_files() {
        return Ok(());
    }
    if !plain() {
        return Err(RelayError::internal(format!(
            "relay.db is encrypted: this data directory is not cut over to Apassy Connect, so APASSY_RELAY_MODE=connect does not start on it and changes nothing. {again}"
        )));
    }
    match fs::read(config.data_dir.join(CUTOVER_FILE)) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RelayError::internal(format!(
            "cutover.json cannot be read: the relay does not start. {again}"
        ))),
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(record) if record["state"] == "done" => Ok(()),
            Ok(record) => Err(RelayError::internal(format!(
                "cutover.json records a cutover that is not finished (state {}): the relay does not start on it. {again}",
                record["state"]
            ))),
            Err(_) => Err(RelayError::internal(format!(
                "cutover.json cannot be read: the relay does not start. {again}"
            ))),
        },
    }
}

/// The advice of the log line of a team file that cannot be opened at start. In `connect`
/// mode a file is never deleted on this advice: a vault store that does not open is
/// restored, and an encrypted one was not converted by the cutover.
pub(crate) fn open_failure_advice(connect_mode: bool, file_is_keyed: bool) -> &'static str {
    match (connect_mode, file_is_keyed) {
        (false, _) => "Suspend or delete it with `apassy-relay admin`.",
        (true, true) => {
            "Its file is encrypted: the cutover did not convert it. Nothing was changed; keep the file, and restore the data directory from a backup (docs/operations/connect.md, sections 8 and 10)."
        }
        (true, false) => {
            "Nothing was changed; keep the file, and restore it from a backup of this relay (docs/operations/connect.md, section 8)."
        }
    }
}

/// `apassy-relay connect-cutover` (module docs). Without `options.confirm` it changes
/// nothing and answers the plan. Run it with the configuration before the cutover (the
/// master key); in `connect` mode it only answers the record of a finished cutover.
pub fn run(config: &RelayConfig, options: &Options, now: u64) -> RelayResult<Report> {
    let _lock = lock(config, "`apassy-relay connect-cutover`")?;
    match stage(config)? {
        Stage::Plain => finished(config),
        _ if config.connect.plain_files() => Err(RelayError::invalid(
            "Run `apassy-relay connect-cutover` with the configuration before the cutover: APASSY_RELAY_KEY_FILE set and APASSY_RELAY_MODE unset.",
        )),
        Stage::Keyed => begin(config, options, now),
        Stage::Committed => {
            let report = read_record(config)?;
            finish(config, options, report, now)
        }
    }
}

/// The record of a finished cutover; an error for a plain relay without one.
fn finished(config: &RelayConfig) -> RelayResult<Report> {
    let report = read_record(config).map_err(|_| {
        RelayError::invalid(
            "relay.db is plain and there is no cutover.json: this relay is in the Connect form already, with nothing to cut over.",
        )
    })?;
    if report.state != "done" {
        return Err(RelayError::internal(
            "cutover.json does not record a finished cutover, but relay.db.keyed is gone: restore the backup named in cutover.json.",
        ));
    }
    Ok(report)
}

fn read_record(config: &RelayConfig) -> RelayResult<Report> {
    let bytes = fs::read(config.data_dir.join(CUTOVER_FILE)).map_err(|_| {
        RelayError::internal(
            "cutover.json is missing: the cutover cannot be finished from its files. Restore the backup it checked.",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| RelayError::internal("cutover.json cannot be read."))
}

/// Writes `cutover.json` in place of the old one: a new file, synced, then renamed.
fn write_record(config: &RelayConfig, report: &Report) -> RelayResult<()> {
    let path = config.data_dir.join(CUTOVER_FILE);
    let temp = config.data_dir.join(format!("{CUTOVER_FILE}.tmp"));
    remove_if_there(&temp)?;
    let text = serde_json::to_vec_pretty(report)
        .map_err(|_| RelayError::internal("cutover.json cannot be written."))?;
    write_new(&temp, &text)?;
    fs::rename(&temp, &path).map_err(|_| io_error("move cutover.json into place"))?;
    sync_dir(&config.data_dir)
}

/// The SHA-256 of what the plan keeps, converts, and deletes, and of the backup it checked:
/// the same data directory and backup give the same value.
fn plan_hash(report: &Report) -> String {
    let plan = json!({
        "version": report.version,
        "backup": {"dir": report.backup.dir, "manifest_sha256": report.backup.manifest_sha256},
        "kept": report.kept,
        "deleted": report.deleted,
        "converted": report.converted,
        "files_before": report.files_before,
        "left": report.left,
    });
    let bytes = serde_json::to_vec(&plan).unwrap_or_default();
    crate::sync_head::hex(&Sha256::digest(&bytes))
}

/// A confirmed run goes on only with the plan of its dry run.
fn confirm_plan(given: &str, plan: &str) -> RelayResult<()> {
    if plan.is_empty() || given != plan {
        return Err(RelayError::new(
            codes::CONFLICT,
            "The plan confirmed is not the plan of the data directory and the backup as they are now: nothing was changed. Run the dry run again, read its plan, and give its plan_sha256 to --confirm-delete-teams.",
        ));
    }
    Ok(())
}

/// The files at the top of `teams/` of the kept store `id` other than its database:
/// `.pre-v*` copies and other files of that store (no folder, no side file).
fn store_copies(config: &RelayConfig, id: &TeamId) -> RelayResult<Vec<String>> {
    let entries = match fs::read_dir(config.teams_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(io_error("read the teams folder")),
    };
    let database = format!("{id}.db");
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != database
            && !is_artifact(&name)
            && team_prefix(&name).as_ref() == Some(id)
            && fs::symlink_metadata(entry.path()).is_ok_and(|meta| meta.is_file())
        {
            names.push(format!("{TEAMS_DIR}/{name}"));
        }
    }
    names.sort();
    Ok(names)
}

/// A keyed SQLite file that opens with `key` and passes `integrity_check`.
fn opens_with(path: &Path, key: &SecretString) -> bool {
    Store::open_read_only(path, key)
        .and_then(|store| store.with(integrity_ok))
        .unwrap_or(false)
}

/// The side files of an earlier run that are there now, relative to the data directory.
fn side_files(config: &RelayConfig) -> Vec<String> {
    let mut found: Vec<String> = root_side_files()
        .into_iter()
        .filter(|name| exists(&config.data_dir.join(name)))
        .collect();
    if let Ok(entries) = fs::read_dir(config.teams_dir()) {
        found.extend(
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| is_artifact(name))
                .map(|name| format!("{TEAMS_DIR}/{name}")),
        );
    }
    found.sort();
    found
}

fn root_side_files() -> Vec<String> {
    vec![
        WORK_DIRECTORY_FILE.to_string(),
        format!("{WORK_DIRECTORY_FILE}-journal"),
        PLAIN_DIRECTORY_FILE.to_string(),
        format!("{PLAIN_DIRECTORY_FILE}-journal"),
        KEYED_DIRECTORY_FILE.to_string(),
        format!("{KEYED_DIRECTORY_FILE}.tmp"),
        CUTOVER_FILE.to_string(),
        format!("{CUTOVER_FILE}.tmp"),
    ]
}

/// Removes the side files of a run before its commit point: the copies (keyed and plain),
/// the keyed copy of `relay.db`, and the record. Only while `relay.db` is keyed and whole;
/// after the commit point it removes nothing (the next run finishes from them).
fn remove_side_files(config: &RelayConfig) -> RelayResult<()> {
    if plain_header(&config.directory_path()) {
        return Ok(());
    }
    for name in side_files(config) {
        remove_if_there(&config.data_dir.join(name))?;
    }
    sync_dir_if_there(&config.teams_dir())?;
    sync_dir(&config.data_dir)
}

/// The plan of a keyed relay: the checks of steps 1 and 2, read-only.
fn plan(config: &RelayConfig, options: &Options, now: u64) -> RelayResult<Report> {
    refuse_journals(config)?;
    let rows = {
        let directory = Store::open_read_only(&config.directory_path(), &config.master_key)?;
        if directory.user_version()? != DIRECTORY_VERSION {
            return Err(RelayError::internal(format!(
                "relay.db is not a directory of version {DIRECTORY_VERSION}: start this version of the relay once first, then stop it."
            )));
        }
        directory.with(directory::read_teams)?
    };
    let (kept, deleted) = split(rows.iter().map(clone_row).collect());
    let mut converted = Vec::new();
    let mut unconverted = Vec::new();
    for row in &kept {
        let path = config.team_path(&row.id);
        let store = Store::open_read_only(&path, &row.file_key).map_err(|_| {
            RelayError::internal(format!(
                "The vault store {} cannot be opened: restore it or delete it (`admin delete`) before the cutover.",
                row.id
            ))
        })?;
        if store.user_version()? != SCHEMA_VERSION {
            return Err(RelayError::internal(format!(
                "The vault store {} is not at team schema {SCHEMA_VERSION}: start this version of the relay once first.",
                row.id
            )));
        }
        converted.push(format!("{TEAMS_DIR}/{}.db", row.id));
        // A keyed copy of the store (`.pre-v*`) becomes plain too: its key goes. A file of
        // the store that does not open with its key is left as it is.
        for name in store_copies(config, &row.id)? {
            if opens_with(&config.data_dir.join(&name), &row.file_key) {
                converted.push(name);
            } else {
                unconverted.push(name);
            }
        }
    }
    converted.sort();
    let files = inventory(config)?;
    let backup = backup_check(config, options.backup.as_deref(), &files)?;
    let mut left = left_entries(config)?;
    left.extend(unconverted);
    left.sort();
    let mut report = Report {
        version: RECORD_VERSION,
        state: "dry_run".to_string(),
        relay_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: now,
        finished_at: None,
        backup,
        kept: kept.iter().map(kept_store).collect(),
        deleted: deleted
            .iter()
            .map(|row| DeletedTeam {
                team_id: row.id.clone(),
                kind: row.kind,
                state: row.state,
            })
            .collect(),
        before: tally(&rows, &files),
        after: None,
        rows_deleted: BTreeMap::new(),
        files_before: files,
        files_after: None,
        files_deleted: Vec::new(),
        left,
        pending: Some(
            "Run with --confirm-delete-teams <plan_sha256> to keep the vault stores as plain files and delete every other team with its files and keys."
                .to_string(),
        ),
        plan_sha256: String::new(),
        converted,
        side_files: side_files(config),
        changed: false,
    };
    report.plan_sha256 = plan_hash(&report);
    Ok(report)
}

fn clone_row(row: &TeamRow) -> TeamRow {
    TeamRow {
        id: row.id.clone(),
        name: row.name.clone(),
        file_key: row.file_key.clone(),
        state: row.state,
        legacy: row.legacy,
        created_at: row.created_at,
        suspended_at: row.suspended_at,
        limits: row.limits,
        kind: row.kind,
        suspend_reason: row.suspend_reason.clone(),
        account_id: row.account_id.clone(),
        vault_id: row.vault_id.clone(),
    }
}

fn kept_store(row: &TeamRow) -> KeptStore {
    KeptStore {
        team_id: row.id.clone(),
        account_id: row.account_id.clone().unwrap_or_default(),
        vault_id: row.vault_id.clone().unwrap_or_default(),
        state: row.state,
    }
}

/// Entries of the data directory root that are neither the relay's files nor the
/// cutover's: they are left as they are and named in the record.
fn left_entries(config: &RelayConfig) -> RelayResult<Vec<String>> {
    let side = root_side_files();
    let mut known: Vec<&str> = vec![
        DIRECTORY_FILE,
        TEAMS_DIR,
        AUDIT_ARCHIVE_DIR,
        ADMIN_SOCKET,
        crate::config::LOCK_FILE,
    ];
    known.extend(OLD_FILES);
    known.extend(side.iter().map(String::as_str));
    let mut left: Vec<String> = fs::read_dir(&config.data_dir)
        .map_err(|_| io_error("read the data directory"))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !known.contains(&name.as_str()))
        .collect();
    // An entry of `teams/` without a team id is no team's: it stays, and is named.
    if let Ok(entries) = fs::read_dir(config.teams_dir()) {
        left.extend(
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| team_prefix(name).is_none() && !is_artifact(name))
                .map(|name| format!("{TEAMS_DIR}/{name}")),
        );
    }
    left.sort();
    Ok(left)
}

/// Steps 1 to 4 on a keyed relay, then `finish`.
fn begin(config: &RelayConfig, options: &Options, now: u64) -> RelayResult<Report> {
    let mut report = plan(config, options, now)?;
    let Some(given) = options.confirm.as_deref() else {
        return Ok(report);
    };
    confirm_plan(given, &report.plan_sha256)?;
    // Side files of a run that stopped before its commit point: `relay.db` is keyed and
    // whole, so they are only copies.
    remove_side_files(config)?;
    report.side_files = Vec::new();
    if let Err(error) = stage_copies(config, options, &mut report, now) {
        // An error before the commit point removes what it wrote; a kill (the test stop)
        // leaves it for the next run.
        if !error.message.starts_with(TEST_STOP) {
            let _ = remove_side_files(config);
        }
        return Err(error);
    }
    interrupt(options, Interrupt::Committed)?;
    finish(config, options, report, now)
}

/// Steps 3 and 4: the checked plain copies, the record, the keyed copy, and the commit
/// point (the plain `relay.db` renamed over the keyed one).
fn stage_copies(
    config: &RelayConfig,
    options: &Options,
    report: &mut Report,
    now: u64,
) -> RelayResult<()> {
    let keyed_rows = {
        let directory = Store::open_read_only(&config.directory_path(), &config.master_key)?;
        directory.with(directory::read_teams)?
    };
    let (kept, _) = split(keyed_rows);
    if kept.iter().map(kept_store).collect::<Vec<_>>() != report.kept {
        return Err(RelayError::internal(
            "The vault stores changed during the cutover.",
        ));
    }
    // Step 3: the plain copies of the files of the stores.
    for (index, row) in kept.iter().enumerate() {
        for name in converted_of(report, &row.id) {
            let path = config.data_dir.join(&name);
            let source = Store::open_at(&path, &row.file_key)?;
            source.export_plain(&plain_path(&path))?;
            check_copy(&source, &plain_path(&path))?;
        }
        if index == 0 {
            interrupt(options, Interrupt::StagedOneStore)?;
        }
    }
    // `relay.db`: a keyed working copy of the bytes of the inventory, edited and vacuumed
    // under the master key. Only the result is exported, so no team key and no deleted row
    // is written to the disk in plain.
    let inventoried = directory_entry(report)?;
    let work = config.data_dir.join(WORK_DIRECTORY_FILE);
    store::copy_private(&config.directory_path(), &work)?;
    if hash_file(&work)? != inventoried {
        return Err(RelayError::internal(
            "relay.db changed since the plan: run the dry run again.",
        ));
    }
    let plain_directory = config.data_dir.join(PLAIN_DIRECTORY_FILE);
    {
        let working = Store::open_at(&work, &config.master_key)?;
        report.rows_deleted = edit_directory(&working, report.kept.len(), now)?;
        working.export_plain(&plain_directory)?;
        interrupt(options, Interrupt::ExportedDirectory)?;
        check_copy(&working, &plain_directory)?;
        let original = Store::open_read_only(&config.directory_path(), &config.master_key)?;
        check_plain_directory(&plain_directory, &original, report)?;
    }
    remove_if_there(&work)?;
    remove_if_there(
        &config
            .data_dir
            .join(format!("{WORK_DIRECTORY_FILE}-journal")),
    )?;
    sync_dir_if_there(&config.teams_dir())?;
    sync_dir(&config.data_dir)?;
    // Step 4: the record, the keyed copy, and the commit point.
    report.state = "committing".to_string();
    report.pending = Some(
        "The plain copies are ready. Run again with --confirm-delete-teams <plan_sha256> to finish."
            .to_string(),
    );
    write_record(config, report)?;
    interrupt(options, Interrupt::Staged)?;
    let keyed_temp = config.data_dir.join(format!("{KEYED_DIRECTORY_FILE}.tmp"));
    store::copy_private(&config.directory_path(), &keyed_temp)?;
    if hash_file(&keyed_temp)? != inventoried {
        return Err(RelayError::internal(
            "relay.db changed since the plan: nothing is committed. Run the dry run again.",
        ));
    }
    fs::rename(&keyed_temp, config.data_dir.join(KEYED_DIRECTORY_FILE))
        .map_err(|_| io_error("keep the keyed relay.db"))?;
    sync_dir(&config.data_dir)?;
    interrupt(options, Interrupt::KeptKeyed)?;
    if exists(&config.data_dir.join(format!("{DIRECTORY_FILE}-journal"))) {
        return Err(RelayError::internal(
            "relay.db has a write journal at the commit point: nothing is committed. Run the cutover again.",
        ));
    }
    fs::rename(&plain_directory, config.directory_path())
        .map_err(|_| io_error("move the plain relay.db into place"))?;
    sync_dir(&config.data_dir)
}

/// The size and hash of `relay.db` in the inventory of the record.
fn directory_entry(report: &Report) -> RelayResult<(u64, String)> {
    report
        .files_before
        .iter()
        .find(|entry| entry.name == DIRECTORY_FILE)
        .map(|entry| (entry.bytes, entry.sha256.clone()))
        .ok_or_else(|| RelayError::internal("cutover.json lists no relay.db."))
}

/// The files of the kept store `id` that the plan converts.
fn converted_of(report: &Report, id: &TeamId) -> Vec<String> {
    report
        .converted
        .iter()
        .filter(|name| owner_of(name).as_ref() == Some(id))
        .cloned()
        .collect()
}

fn plain_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(PLAIN_SUFFIX);
    PathBuf::from(name)
}

/// The quoted name of a table for SQL.
fn quoted(table: &str) -> String {
    format!("\"{}\"", table.replace('"', "\"\""))
}

/// The tables of a file, SQLite's own included (`sqlite_sequence`), by name.
fn table_names(conn: &rusqlite::Connection) -> RelayResult<Vec<String>> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .map_err(db)?
        .query_map([], |row| row.get(0))
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)
}

/// The schema objects of a file: the type, name, table, and SQL of each (tables, indexes,
/// views, triggers), without their root pages.
type SchemaObject = (String, String, String, Option<String>);

fn schema_objects(conn: &rusqlite::Connection) -> RelayResult<Vec<SchemaObject>> {
    conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .map_err(db)?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)
}

/// The rows of `table` (with `filter`, a `WHERE` clause or empty) and the SHA-256 of their
/// content in a fixed order (`ORDER BY` every column): each value with its type. The
/// column `blank`, when given, counts as the empty text (the file keys that the plain
/// `relay.db` no longer has).
fn table_hash(
    conn: &rusqlite::Connection,
    table: &str,
    filter: &str,
    blank: Option<&str>,
) -> RelayResult<(u64, String)> {
    let name = quoted(table);
    let (columns, blank_at) = {
        let probe = conn
            .prepare(&format!("SELECT * FROM {name} LIMIT 0"))
            .map_err(db)?;
        let blank_at =
            blank.and_then(|blank| probe.column_names().position(|column| column == blank));
        (probe.column_count(), blank_at)
    };
    let order = (1..=columns.max(1))
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = conn
        .prepare(&format!("SELECT * FROM {name} {filter} ORDER BY {order}"))
        .map_err(db)?;
    let mut rows = statement.query([]).map_err(db)?;
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    while let Some(row) = rows.next().map_err(db)? {
        count += 1;
        for index in 0..columns {
            let value = if Some(index) == blank_at {
                ValueRef::Text(b"")
            } else {
                row.get_ref(index).map_err(db)?
            };
            match value {
                ValueRef::Null => hasher.update([0u8]),
                ValueRef::Integer(number) => {
                    hasher.update([1u8]);
                    hasher.update(number.to_be_bytes());
                }
                ValueRef::Real(number) => {
                    hasher.update([2u8]);
                    hasher.update(number.to_bits().to_be_bytes());
                }
                ValueRef::Text(bytes) => {
                    hasher.update([3u8]);
                    hasher.update((bytes.len() as u64).to_be_bytes());
                    hasher.update(bytes);
                }
                ValueRef::Blob(bytes) => {
                    hasher.update([4u8]);
                    hasher.update((bytes.len() as u64).to_be_bytes());
                    hasher.update(bytes);
                }
            }
        }
        hasher.update([0xffu8]);
    }
    Ok((count, crate::sync_head::hex(&hasher.finalize())))
}

/// The rows and content hash of every table of a file.
fn table_hashes(conn: &rusqlite::Connection) -> RelayResult<BTreeMap<String, (u64, String)>> {
    table_names(conn)?
        .into_iter()
        .map(|table| {
            let hash = table_hash(conn, &table, "", None)?;
            Ok((table, hash))
        })
        .collect()
}

fn integrity_ok(conn: &rusqlite::Connection) -> RelayResult<bool> {
    let answer: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(db)?;
    Ok(answer == "ok")
}

/// The plain copy at `copy` has the version, the schema objects, and the rows (by a
/// content hash of each table) of `source`, and passes `integrity_check`.
fn check_copy(source: &Store, copy: &Path) -> RelayResult<()> {
    let plain = Store::open_plain_unchecked(copy)?;
    let failed = |what: &str| {
        RelayError::internal(format!(
            "The plain copy {} does not match its source: {what}.",
            copy.display()
        ))
    };
    if plain.user_version()? != source.user_version()? {
        return Err(failed("its version"));
    }
    if source.with(schema_objects)? != plain.with(schema_objects)? {
        return Err(failed("its schema"));
    }
    if source.with(table_hashes)? != plain.with(table_hashes)? {
        return Err(failed("its rows"));
    }
    if !plain.with(integrity_ok)? {
        return Err(failed("integrity_check"));
    }
    Ok(())
}

/// The edits of `relay.db` (step 3) on the keyed working copy, in one transaction, then
/// `VACUUM` (still keyed). Answers the rows deleted by table.
fn edit_directory(working: &Store, kept: usize, now: u64) -> RelayResult<BTreeMap<String, u64>> {
    let deleted = working.tx(|tx| {
        let mut deleted = BTreeMap::new();
        let teams = tx
            .execute("DELETE FROM team WHERE kind <> 'account'", [])
            .map_err(db)?;
        deleted.insert("team".to_string(), teams as u64);
        for table in CLEARED_TABLES {
            let rows = tx
                .execute(&format!("DELETE FROM {table}"), [])
                .map_err(db)?;
            deleted.insert(table.to_string(), rows as u64);
        }
        tx.execute(
            "DELETE FROM account_store_device WHERE team_id NOT IN (SELECT id FROM team)",
            [],
        )
        .map_err(db)?;
        // No file has a key any more: the stores are plain.
        tx.execute("UPDATE team SET file_key = ''", [])
            .map_err(db)?;
        Audit::new().write_on(
            tx,
            now,
            OPERATOR_ACTOR,
            "connect_cutover",
            None,
            &json!({"kept": kept, "deleted": teams}),
        )?;
        Ok(deleted)
    })?;
    // Rebuild the file, still keyed: the export copies rows, never a free page.
    working.with(|conn| conn.execute_batch("VACUUM").map_err(db))?;
    Ok(deleted)
}

/// The plain `relay.db` against the keyed `original`: the same version and schema
/// objects; exactly the kept stores, with every row as it was but an empty key; the
/// cleared tables empty; the device maps of the kept stores as they were; the audit as it
/// was with one row `connect_cutover` more; every other table as it was (by a content hash
/// of each); and `integrity_check`.
fn check_plain_directory(path: &Path, original: &Store, report: &Report) -> RelayResult<()> {
    let failed = |why: &str| RelayError::internal(format!("The plain relay.db is wrong: {why}"));
    let directory = Store::open_plain_unchecked(path)?;
    if directory.user_version()? != DIRECTORY_VERSION
        || original.user_version()? != DIRECTORY_VERSION
    {
        return Err(failed("its version"));
    }
    let rows = directory.with(directory::read_teams)?;
    let ids: BTreeSet<&TeamId> = rows.iter().map(|row| &row.id).collect();
    let kept: BTreeSet<&TeamId> = report.kept.iter().map(|store| &store.team_id).collect();
    if ids != kept || rows.iter().any(|row| row.kind != TeamKind::Account) {
        return Err(failed("its teams"));
    }
    if rows.iter().any(|row| !row.file_key.is_empty()) {
        return Err(failed("a file key"));
    }
    if directory.with(schema_objects)? != original.with(schema_objects)? {
        return Err(failed("its schema"));
    }
    let max_audit: i64 = original.with(|conn| {
        conn.query_row("SELECT coalesce(max(id), 0) FROM audit", [], |row| {
            row.get(0)
        })
        .map_err(db)
    })?;
    for table in original.with(table_names)? {
        let plain = |filter: &str| directory.with(|conn| table_hash(conn, &table, filter, None));
        let right = match table.as_str() {
            "team" => {
                plain("")?
                    == original.with(|conn| {
                        table_hash(conn, "team", "WHERE kind = 'account'", Some("file_key"))
                    })?
            }
            name if CLEARED_TABLES.contains(&name) => plain("")?.0 == 0,
            "account_store_device" => {
                plain("")?
                    == original.with(|conn| {
                        table_hash(
                            conn,
                            "account_store_device",
                            "WHERE team_id IN (SELECT id FROM team WHERE kind = 'account')",
                            None,
                        )
                    })?
            }
            "audit" => {
                let before = original.with(|conn| table_hash(conn, "audit", "", None))?;
                let added: String = directory.with(|conn| {
                    conn.query_row(
                        "SELECT coalesce(group_concat(action), '') FROM audit WHERE id > ?1",
                        params![max_audit],
                        |row| row.get(0),
                    )
                    .map_err(db)
                })?;
                plain(&format!("WHERE id <= {max_audit}"))? == before && added == "connect_cutover"
            }
            _ => plain("")? == original.with(|conn| table_hash(conn, &table, "", None))?,
        };
        if !right {
            return Err(failed(&format!("the rows of {table}")));
        }
    }
    if !directory.with(integrity_ok)? {
        return Err(failed("integrity_check"));
    }
    Ok(())
}

/// `relay.db.keyed` is the `relay.db` of the inventory, byte for byte (so the backup holds
/// it): only then is it the copy that the commit point kept, and may it be deleted.
fn check_keyed_copy(config: &RelayConfig, report: &Report) -> RelayResult<()> {
    let keyed = config.data_dir.join(KEYED_DIRECTORY_FILE);
    if hash_file(&keyed)? != directory_entry(report)? {
        return Err(RelayError::internal(format!(
            "{KEYED_DIRECTORY_FILE} is not the relay.db of the inventory in cutover.json (its size or SHA-256 differs): it is kept, and this run deleted nothing more. Compare it with relay.db of the backup named in cutover.json."
        )));
    }
    Ok(())
}

/// The file keys of the kept stores, from `relay.db.keyed`.
fn kept_keys(config: &RelayConfig, kept: &[TeamId]) -> RelayResult<BTreeMap<TeamId, SecretString>> {
    let keyed = Store::open_read_only(
        &config.data_dir.join(KEYED_DIRECTORY_FILE),
        &config.master_key,
    )?;
    kept.iter()
        .map(|id| {
            let row = keyed
                .with(|conn| directory::team_by_id(conn, id))?
                .ok_or_else(|| {
                    RelayError::internal(format!(
                        "The vault store {id} is not in relay.db.keyed: restore the backup named in cutover.json."
                    ))
                })?;
            Ok((id.clone(), row.file_key))
        })
        .collect()
}

/// The derived list of `files_deleted`: the files of the inventory before that are gone.
fn deleted_files(before: &[FileEntry], now: &[FileEntry]) -> Vec<String> {
    let there: BTreeSet<&str> = now.iter().map(|entry| entry.name.as_str()).collect();
    before
        .iter()
        .filter(|entry| !there.contains(entry.name.as_str()))
        .map(|entry| entry.name.clone())
        .collect()
}

/// True for a file (relative to the data directory) that step 5 deletes.
fn goes(name: &str, kept: &BTreeSet<TeamId>) -> bool {
    match owner_of(name) {
        Some(id) => !kept.contains(&id),
        None => OLD_FILES.contains(&name) || name.starts_with(&format!("{AUDIT_ARCHIVE_DIR}/")),
    }
}

/// Steps 5 and 6 on a committed relay: the stores move to their plain files, every other
/// team file goes, the record is written, and `relay.db.keyed` goes last. Without
/// `options.confirm` it changes nothing and answers the pending record.
fn finish(
    config: &RelayConfig,
    options: &Options,
    mut report: Report,
    now: u64,
) -> RelayResult<Report> {
    let Some(given) = options.confirm.as_deref() else {
        // A dry run of a committed cutover: the read-only checks of a confirmed run, and
        // what is left.
        recheck_backup(&report)?;
        report.files_deleted = deleted_files(&report.files_before, &inventory(config)?);
        report.state = "committing".to_string();
        report.pending = Some(
            "The cutover is committed and not finished: relay.db is plain and relay.db.keyed still holds the team keys. Run again with --confirm-delete-teams <plan_sha256> to finish it."
                .to_string(),
        );
        return Ok(report);
    };
    confirm_plan(given, &report.plan_sha256)?;
    // The committed truth: the plain `relay.db`, and it agrees with the record.
    let kept: Vec<TeamId> = {
        let directory = Store::open_plain_unchecked(&config.directory_path())?;
        if directory.user_version()? != DIRECTORY_VERSION {
            return Err(RelayError::internal(
                "The plain relay.db has another version.",
            ));
        }
        let rows = directory.with(directory::read_teams)?;
        if rows.iter().any(|row| row.kind != TeamKind::Account) {
            return Err(RelayError::internal(
                "The plain relay.db names a team that is not a vault store.",
            ));
        }
        rows.into_iter().map(|row| row.id).collect()
    };
    let recorded: BTreeSet<&TeamId> = report.kept.iter().map(|store| &store.team_id).collect();
    if kept.iter().collect::<BTreeSet<_>>() != recorded {
        return Err(RelayError::internal(
            "cutover.json and the plain relay.db name other vault stores: restore the backup named in cutover.json.",
        ));
    }
    let kept_set: BTreeSet<TeamId> = kept.iter().cloned().collect();
    // Before any step that deletes: the backup is still the one that the plan checked, the
    // keyed copy is the relay.db of the inventory, and every file that goes is a file of
    // the inventory, byte for byte (so the backup holds it).
    recheck_backup(&report)?;
    check_keyed_copy(config, &report)?;
    let present = inventory(config)?;
    if let Some(entry) = present
        .iter()
        .find(|entry| goes(&entry.name, &kept_set) && !report.files_before.contains(entry))
    {
        return Err(RelayError::internal(format!(
            "{} is not in the backup that the cutover checked (it is new or changed since): this run deleted nothing. Restore the backup named in cutover.json (docs/operations/connect.md, section 10).",
            entry.name
        )));
    }
    let keys = kept_keys(config, &kept)?;
    // Step 5a: each converted file's plain copy replaces it.
    for (index, id) in kept.iter().enumerate() {
        let key = &keys[id];
        for name in converted_of(&report, id) {
            let is_database = name == format!("{TEAMS_DIR}/{id}.db");
            move_plain(config, &name, key, is_database)?;
        }
        if index == 0 {
            interrupt(options, Interrupt::MovedOneStore)?;
        }
    }
    sync_dir_if_there(&config.teams_dir())?;
    // Step 5b: every other team's files, by team id; never a file of a kept store.
    remove_other_teams(config, &kept_set, options)?;
    // The old single-team files, the files of a stopped migration, the audit archives
    // (they open only with the master key), and a socket that a stopped relay left.
    for name in OLD_FILES {
        remove_if_there(&config.data_dir.join(name))?;
    }
    let archive = config.data_dir.join(AUDIT_ARCHIVE_DIR);
    if let Ok(entries) = fs::read_dir(&archive) {
        for entry in entries.flatten() {
            if fs::symlink_metadata(entry.path()).is_ok_and(|meta| meta.is_file()) {
                fs::remove_file(entry.path()).map_err(|_| io_error("delete an audit archive"))?;
            }
        }
        let _ = fs::remove_dir(&archive);
    }
    let socket = config.data_dir.join(ADMIN_SOCKET);
    if fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        remove_if_there(&socket)?;
    }
    sync_dir(&config.data_dir)?;
    // The check of the result: only `relay.db` and the files of the kept stores, the
    // converted ones plain, every other one the bytes it was.
    let after = inventory(config)?;
    check_after(config, &kept_set, &report, &after)?;
    report.files_deleted = deleted_files(&report.files_before, &after);
    report.after = Some(Tally {
        teams: kept.len(),
        operator: 0,
        connect: 0,
        account: kept.len(),
        files: after.len(),
        bytes: after.iter().map(|entry| entry.bytes).sum(),
    });
    report.files_after = Some(after);
    let mut left = left_entries(config)?;
    left.extend(
        report
            .left
            .iter()
            .filter(|name| owner_of(name).is_some() && exists(&config.data_dir.join(name)))
            .cloned(),
    );
    left.sort();
    left.dedup();
    report.left = left;
    // Step 6: the record, and last the file with the keys of the team files, once it is
    // proven to be the relay.db that the backup holds.
    check_keyed_copy(config, &report)?;
    report.state = "done".to_string();
    report.finished_at = Some(now);
    report.pending = None;
    write_record(config, &report)?;
    interrupt(options, Interrupt::Recorded)?;
    remove_if_there(&config.data_dir.join(KEYED_DIRECTORY_FILE))?;
    sync_dir(&config.data_dir)?;
    report.changed = true;
    Ok(report)
}

/// Replaces the kept file `name` by its checked plain copy. A file that is plain already
/// (a run before moved it) is checked and left; a keyed file whose copy is missing is
/// exported again with `key` (from `relay.db.keyed`). The copy is checked against its
/// keyed source again right before the rename.
fn move_plain(
    config: &RelayConfig,
    name: &str,
    key: &SecretString,
    is_database: bool,
) -> RelayResult<()> {
    let path = config.data_dir.join(name);
    let plain = plain_path(&path);
    if store::is_plain_file(&path) {
        remove_if_there(&plain)?;
        return check_plain_file(&path, is_database);
    }
    {
        let source = Store::open_at(&path, key)?;
        if !exists(&plain) {
            source.export_plain(&plain)?;
        }
        check_copy(&source, &plain)?;
    }
    check_plain_file(&plain, is_database)?;
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    if exists(Path::new(&journal)) {
        return Err(RelayError::internal(format!(
            "{name} has a write journal: restore the backup named in cutover.json."
        )));
    }
    fs::rename(&plain, &path).map_err(|_| io_error("move a plain vault store into place"))
}

/// A plain file that passes `integrity_check`; a store's database is also of the current
/// team schema.
fn check_plain_file(path: &Path, is_database: bool) -> RelayResult<()> {
    let store = Store::open_plain_unchecked(path)?;
    if (is_database && store.user_version()? != SCHEMA_VERSION) || !store.with(integrity_ok)? {
        return Err(RelayError::internal(format!(
            "The plain file {} is not whole.",
            path.display()
        )));
    }
    Ok(())
}

/// Deletes every entry of `teams/` whose name starts with a team id that is not in `kept`:
/// the team's database, its journal, its `.pre-v*` copies, its snapshot folder `<id>.sync`,
/// and any other entry of that team. An entry without a team id is left (`left_entries`
/// names it).
fn remove_other_teams(
    config: &RelayConfig,
    kept: &BTreeSet<TeamId>,
    options: &Options,
) -> RelayResult<()> {
    let entries = match fs::read_dir(config.teams_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io_error("read the teams folder")),
    };
    let mut by_team: BTreeMap<TeamId, Vec<String>> = BTreeMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = team_prefix(&name)
            && !kept.contains(&id)
        {
            by_team.entry(id).or_default().push(name);
        }
    }
    for (index, mut names) in by_team.into_values().enumerate() {
        names.sort();
        for name in names {
            let path = config.teams_dir().join(&name);
            let meta = fs::symlink_metadata(&path).map_err(|_| io_error("read a team file"))?;
            if meta.is_dir() {
                // The snapshot folder `<id>.sync`, or any other folder of that team.
                fs::remove_dir_all(&path).map_err(|_| io_error("delete a team folder"))?;
            } else {
                fs::remove_file(&path).map_err(|_| io_error("delete a team file"))?;
            }
        }
        if index == 0 {
            sync_dir(&config.teams_dir())?;
            interrupt(options, Interrupt::DeletedOneTeam)?;
        }
    }
    sync_dir_if_there(&config.teams_dir())
}

/// After the cutover the data directory holds `relay.db`, plain, and for each kept store
/// its converted files, plain, and every other file of it (its snapshots) as the bytes
/// they were.
fn check_after(
    config: &RelayConfig,
    kept: &BTreeSet<TeamId>,
    report: &Report,
    after: &[FileEntry],
) -> RelayResult<()> {
    let failed = |why: String| {
        RelayError::internal(format!(
            "The data directory after the cutover is wrong: {why}"
        ))
    };
    if !store::is_plain_file(&config.directory_path()) {
        return Err(failed("relay.db is not plain".to_string()));
    }
    let converted: BTreeSet<&str> = report.converted.iter().map(String::as_str).collect();
    for entry in after {
        let owner = owner_of(&entry.name);
        // `relay.db`, a file of a kept store, or a file of `teams/` with no team id (left).
        let allowed = entry.name == DIRECTORY_FILE
            || match &owner {
                Some(id) => kept.contains(id),
                None => entry.name.starts_with(&format!("{TEAMS_DIR}/")),
            };
        if !allowed {
            return Err(failed(format!("{} is left", entry.name)));
        }
        // A file that is not converted (a snapshot, or a file of no key) is unchanged.
        if entry.name != DIRECTORY_FILE
            && !converted.contains(entry.name.as_str())
            && !report.files_before.contains(entry)
        {
            return Err(failed(format!("{} changed", entry.name)));
        }
    }
    for name in &report.converted {
        if !after.iter().any(|entry| &entry.name == name) {
            return Err(failed(format!("{name} is gone")));
        }
        let is_database = owner_of(name).is_some_and(|id| *name == format!("{TEAMS_DIR}/{id}.db"));
        check_plain_file(&config.data_dir.join(name), is_database)?;
    }
    for id in kept {
        if !report.converted.contains(&format!("{TEAMS_DIR}/{id}.db")) {
            return Err(failed(format!("the vault store {id} has no file")));
        }
    }
    // Every other file of a kept store (its snapshots) is still there, the same bytes.
    for old in &report.files_before {
        if owner_of(&old.name).is_some_and(|id| kept.contains(&id))
            && !converted.contains(old.name.as_str())
            && !after.contains(old)
        {
            return Err(failed(format!("{} is gone or changed", old.name)));
        }
    }
    Ok(())
}

/// The row of `id` in the keyed `relay.db.keyed`, for the tests of a crash.
#[doc(hidden)]
pub fn keyed_row_exists(config: &RelayConfig, id: &TeamId) -> RelayResult<bool> {
    let keyed = Store::open_read_only(
        &config.data_dir.join(KEYED_DIRECTORY_FILE),
        &config.master_key,
    )?;
    keyed.with(|conn| {
        conn.query_row(
            "SELECT count(*) FROM team WHERE id = ?1",
            params![id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count == 1)
        .map_err(db)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_is_checked_by_its_schema_and_its_content() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretString::new("k".repeat(64));
        let store = Store::create_at(
            &dir.path().join("t.db"),
            &key,
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL); \
             CREATE TABLE w (a TEXT, b BLOB) ; \
             INSERT INTO t (v) VALUES ('one'), ('two'); \
             INSERT INTO w VALUES ('x', x'78'), (NULL, NULL); \
             PRAGMA user_version = 8;",
        )
        .unwrap();
        let copy = dir.path().join("t.db.plain");
        store.export_plain(&copy).unwrap();
        check_copy(&store, &copy).unwrap();
        let edit = |sql: &str| {
            let conn = rusqlite::Connection::open(&copy).unwrap();
            conn.execute_batch(sql).unwrap();
        };
        // The same rows with another value: the counts agree, the content does not.
        edit("UPDATE t SET v = 'owe' WHERE v = 'one'");
        assert!(check_copy(&store, &copy).is_err());
        edit("UPDATE t SET v = 'one' WHERE v = 'owe'");
        check_copy(&store, &copy).unwrap();
        // A value of another type with the same text: refused.
        edit("UPDATE w SET b = 'x' WHERE a = 'x'");
        assert!(check_copy(&store, &copy).is_err());
        edit("UPDATE w SET b = x'78' WHERE a = 'x'");
        check_copy(&store, &copy).unwrap();
        // Another schema object: refused.
        edit("CREATE INDEX t_v ON t(v)");
        assert!(check_copy(&store, &copy).is_err());
    }

    #[test]
    fn the_header_tells_a_plain_file_from_a_keyed_one_without_opening_it() {
        let dir = tempfile::tempdir().unwrap();
        let keyed = dir.path().join("keyed.db");
        drop(
            Store::create_at(
                &keyed,
                &SecretString::new("k".repeat(64)),
                "CREATE TABLE t (v TEXT);",
            )
            .unwrap(),
        );
        let plain = dir.path().join("plain.db");
        rusqlite::Connection::open(&plain)
            .unwrap()
            .execute_batch("CREATE TABLE t (v TEXT);")
            .unwrap();
        assert!(plain_header(&plain));
        assert!(!plain_header(&keyed));
        // A write journal beside the plain file changes nothing: the header is not a page.
        fs::write(dir.path().join("plain.db-journal"), [0u8; 512]).unwrap();
        assert!(plain_header(&plain));
        let short = dir.path().join("short.db");
        fs::write(&short, b"SQLite").unwrap();
        assert!(!plain_header(&short));
        assert!(!plain_header(&dir.path().join("missing.db")));
    }

    #[test]
    fn the_advice_for_a_store_that_does_not_open_never_says_delete_in_connect_mode() {
        for keyed in [true, false] {
            let advice = open_failure_advice(true, keyed);
            assert!(!advice.contains("delete"), "{advice}");
            assert!(advice.contains("backup"), "{advice}");
        }
        assert!(open_failure_advice(true, true).contains("encrypted"));
        assert!(open_failure_advice(false, false).contains("Suspend or delete"));
    }

    #[test]
    fn team_prefixes_and_artifacts() {
        let id = "t_abcdefgh23";
        for name in [
            format!("{id}.db"),
            format!("{id}.db-journal"),
            format!("{id}.db.pre-v6"),
            format!("{id}.db.pre-v8.tmp"),
            format!("{id}.sync"),
        ] {
            assert_eq!(team_prefix(&name).unwrap().as_str(), id, "{name}");
        }
        for name in [
            "notes.txt",
            "t_short.db",
            "T_ABCDEFGH23.db",
            ".t_abcdefgh23.db",
        ] {
            assert!(team_prefix(name).is_none(), "{name}");
        }
        assert!(is_artifact("t_abcdefgh23.db.plain"));
        assert!(is_artifact("t_abcdefgh23.db.plain-journal"));
        assert!(!is_artifact("t_abcdefgh23.db"));
        assert!(!is_artifact("t_abcdefgh23.db.pre-v6"));
    }
}
