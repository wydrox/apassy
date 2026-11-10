//! The backup of a stopped relay (`apassy-relay backup`) and the cutover from the hosted
//! relay to Apassy Connect (`apassy-relay connect-cutover`), docs/SPEC.md section 37 and
//! docs/operations/connect.md. Both run with the relay stopped: they take `relay.lock`.
//!
//! **The backup of a stopped relay** copies every file that the relay keeps in its data
//! directory, byte for byte: `relay.db`, every file under `teams/` (the team files, their
//! `.pre-v*` copies, and the snapshot folders), the old `team.db` and `team.db.pre-teams`,
//! and `audit-archive/`. Each copy is hashed again against its source. `MANIFEST.json`
//! names each file with its size and SHA-256 and says `"stopped": true`. The relay is
//! stopped, so nothing changes between the copies: the backup is the data directory as it
//! is. The master key is never in it.
//!
//! **The cutover** is one way and destroys data by design. With the master key of the
//! relay (the configuration before the cutover) it:
//!
//! 1. refuses while the relay runs (`relay.lock`) and while a write journal remains;
//! 2. checks the backup (`backup_check`): the newest stopped backup, or the one named,
//!    holds a byte-identical copy of every file the cutover keeps or deletes, and its own
//!    files still match its manifest;
//! 3. writes a plain copy of each vault store of an account (`teams/<id>.db.plain`) and of
//!    `relay.db` (`relay.db.plain`) with `sqlcipher_export`, and checks each copy against
//!    its source (version, tables, rows, `integrity_check`). In the plain `relay.db` the
//!    teams of other kinds, the team codes, the free Connect keys, and the OAuth state are
//!    deleted, every `team.file_key` is emptied, and one audit row `connect_cutover` is
//!    added; then it is vacuumed, so no deleted value stays in a free page;
//! 4. writes `cutover.json` (`"state": "committing"`, the plan and the hashes before),
//!    keeps the keyed `relay.db` as `relay.db.keyed`, and renames `relay.db.plain` over
//!    `relay.db`: the commit point;
//! 5. renames each plain store copy over its file, deletes every other team file (its
//!    database, its `.pre-v*` copies, its snapshot folder) and the old team files and
//!    audit archives, checks that only `relay.db` and the account stores are left, plain;
//! 6. writes `cutover.json` again (`"state": "done"`, the counts and hashes after) and
//!    deletes `relay.db.keyed`, the last file with the team keys.
//!
//! It never deletes a file whose team id is a vault store of an account: it only replaces
//! the store's database by its checked plain copy, and leaves its snapshots untouched.
//!
//! **Safe to interrupt.** Before the commit point the keyed `relay.db` is whole and the
//! plain copies are side files: a second run removes them and starts again. After it, the
//! plain `relay.db` names the stores to keep, `cutover.json` holds the plan, and
//! `relay.db.keyed` still holds the keys: a second run finishes steps 5 and 6 (a store
//! whose plain copy is missing is exported again with the key from `relay.db.keyed`). At
//! any point the stopped backup of step 2 restores the relay as it was.
//!
//! `--dry-run` (the default) does steps 1 and 2 and answers the plan; it opens every file
//! read-only and writes nothing, not even `cutover.json`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api::TeamKind;
use crate::config::{
    ADMIN_SOCKET, DIRECTORY_FILE, LEGACY_BACKUP_FILE, LEGACY_VAULT_FILE, RelayConfig, TEAMS_DIR,
};
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::server::audit::Audit;
use crate::server::directory::{self, DIRECTORY_VERSION, OPERATOR_ACTOR, TeamRow, TeamState};
use crate::server::store::{self, SCHEMA_VERSION, Store, db, to_u};

/// The record and journal of the cutover, in the data directory.
pub const CUTOVER_FILE: &str = "cutover.json";
/// The keyed `relay.db`, kept from the commit point until the end of the cutover.
pub const KEYED_DIRECTORY_FILE: &str = "relay.db.keyed";
/// The plain copy of `relay.db` before the commit point.
pub const PLAIN_DIRECTORY_FILE: &str = "relay.db.plain";
/// The suffix of the plain copy of a store before it replaces the store's file.
const PLAIN_SUFFIX: &str = ".plain";
/// The folder of the archived audits of swept Connect teams (`Hub::archive_swept_team`).
const AUDIT_ARCHIVE_DIR: &str = "audit-archive";
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
    /// After the plain copy of the first vault store.
    StagedOneStore,
    /// After every plain copy and `cutover.json` "committing", before the commit point.
    Staged,
    /// Right after the commit point (the plain `relay.db` in place).
    Committed,
    /// After the first store's plain copy replaced its file.
    MovedOneStore,
    /// After the files of the first other team were deleted.
    DeletedOneTeam,
    /// After `cutover.json` "done", before `relay.db.keyed` is deleted.
    Recorded,
}

/// The options of `connect-cutover`.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `--confirm-delete-teams`: change the files. Without it the run is a dry run.
    pub confirm: bool,
    /// `--backup <dir>`: the stopped backup to check; else the newest one in the backup
    /// folder.
    pub backup: Option<PathBuf>,
    /// For the tests only: stop at this point with an error.
    #[doc(hidden)]
    pub interrupt: Option<Interrupt>,
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
    /// `dry_run`, `committing` (the plain copies are ready; a second run finishes), or
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
    /// The files and folders that were deleted, relative to the data directory.
    pub files_deleted: Vec<String>,
    /// Entries of the data directory that the cutover does not know and left as they are.
    pub left: Vec<String>,
    /// In a dry run or a pending run: what a real run still does, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<String>,
}

fn io_error(what: &str) -> RelayError {
    RelayError::internal(format!("The cutover cannot {what}."))
}

fn interrupt(options: &Options, at: Interrupt) -> RelayResult<()> {
    if options.interrupt == Some(at) {
        return Err(RelayError::internal(format!(
            "The cutover stopped for a test at {at:?}."
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

/// A name that the cutover itself writes and that is not data of the relay.
fn is_artifact(name: &str) -> bool {
    name.ends_with(PLAIN_SUFFIX) || name.ends_with(".plain-journal")
}

/// The team id at the start of a name in `teams/` (`<id>.db`, `<id>.db.pre-v6`,
/// `<id>.sync`).
fn team_prefix(name: &str) -> Option<TeamId> {
    name.split('.').next().and_then(TeamId::parse)
}

/// Every file of the relay in its data directory, by name, sorted, without the cutover's
/// own side files: `relay.db`, `team.db`, `team.db.pre-teams`, each file under `teams/`
/// (one folder deep, for the snapshots), and each file of `audit-archive/`. A symbolic
/// link or a deeper folder is refused: a data directory of the relay has none.
fn data_files(config: &RelayConfig) -> RelayResult<Vec<String>> {
    let unexpected = |name: &str| {
        RelayError::internal(format!(
            "The data directory has an unexpected entry: {name}."
        ))
    };
    let mut names = Vec::new();
    for name in [DIRECTORY_FILE, LEGACY_VAULT_FILE, LEGACY_BACKUP_FILE] {
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
/// during a cutover (`relay.db.keyed` exists: run the cutover again to finish it). Works in
/// both modes: the files are copied as they are, keyed or plain. Answers the manifest.
pub fn stopped_backup(config: &RelayConfig, now: u64) -> RelayResult<serde_json::Value> {
    let _lock = lock(config, "`apassy-relay backup`")?;
    if !exists(&config.directory_path()) {
        return Err(RelayError::internal(
            "There is no relay.db in the data directory.",
        ));
    }
    if exists(&config.data_dir.join(KEYED_DIRECTORY_FILE)) {
        return Err(RelayError::new(
            codes::CONFLICT,
            "A cutover is in progress (relay.db.keyed exists): run `apassy-relay connect-cutover --confirm-delete-teams` again to finish it.",
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
    for entry in &listed {
        let path = dir.join(&entry.name);
        if hash_file(&path).ok() != Some((entry.bytes, entry.sha256.clone())) {
            return Err(RelayError::internal(format!(
                "The backup {} is damaged: {} does not match its manifest.",
                dir.display(),
                entry.name
            )));
        }
    }
    Ok(BackupCheck {
        dir: dir.to_string_lossy().into_owned(),
        created_at: manifest.created_at,
        files: listed.len(),
        check: "a backup of the stopped relay holds a byte-identical copy (size and SHA-256) of every file that the cutover keeps or deletes, and its own files match its MANIFEST.json".to_string(),
        manifest_sha256: crate::sync_head::hex(&Sha256::digest(&bytes)),
    })
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
    if !store::is_plain_file(&directory) {
        return Ok(Stage::Keyed);
    }
    if exists(&config.data_dir.join(KEYED_DIRECTORY_FILE)) {
        Ok(Stage::Committed)
    } else {
        Ok(Stage::Plain)
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
    }
    let files = inventory(config)?;
    let backup = backup_check(config, options.backup.as_deref(), &files)?;
    let left = left_entries(config)?;
    Ok(Report {
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
            "Run with --confirm-delete-teams to keep the vault stores as plain files and delete every other team with its files and keys."
                .to_string(),
        ),
    })
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
    let known = [
        DIRECTORY_FILE,
        LEGACY_VAULT_FILE,
        LEGACY_BACKUP_FILE,
        TEAMS_DIR,
        AUDIT_ARCHIVE_DIR,
        ADMIN_SOCKET,
        crate::config::LOCK_FILE,
        CUTOVER_FILE,
        KEYED_DIRECTORY_FILE,
        PLAIN_DIRECTORY_FILE,
    ];
    let mut left: Vec<String> = fs::read_dir(&config.data_dir)
        .map_err(|_| io_error("read the data directory"))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !known.contains(&name.as_str()))
        .filter(|name| !name.starts_with(&format!("{CUTOVER_FILE}.")))
        .filter(|name| !name.starts_with(&format!("{KEYED_DIRECTORY_FILE}.")))
        .filter(|name| !name.starts_with(&format!("{PLAIN_DIRECTORY_FILE}-")))
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
    if !options.confirm {
        return Ok(report);
    }
    // Side files of an interrupted run before its commit point: `relay.db` is keyed and
    // whole, so they are only copies.
    for name in [
        PLAIN_DIRECTORY_FILE,
        "relay.db.plain-journal",
        KEYED_DIRECTORY_FILE,
        "relay.db.keyed.tmp",
        CUTOVER_FILE,
    ] {
        remove_if_there(&config.data_dir.join(name))?;
    }
    if let Ok(entries) = fs::read_dir(config.teams_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_artifact(&name) {
                remove_if_there(&entry.path())?;
            }
        }
    }
    // Step 3: the plain copies of the stores.
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
    for (index, row) in kept.iter().enumerate() {
        let path = config.team_path(&row.id);
        let plain = plain_path(&path);
        {
            let source = Store::open_at(&path, &row.file_key)?;
            source.export_plain(&plain)?;
            check_copy(&source, &plain)?;
        }
        if index == 0 {
            interrupt(options, Interrupt::StagedOneStore)?;
        }
    }
    // The plain copy of `relay.db`, its edits, and its checks.
    let plain_directory = config.data_dir.join(PLAIN_DIRECTORY_FILE);
    let source_counts = {
        let source = Store::open_at(&config.directory_path(), &config.master_key)?;
        source.export_plain(&plain_directory)?;
        check_copy(&source, &plain_directory)?;
        source.with(table_counts)?
    };
    report.rows_deleted = edit_plain_directory(&plain_directory, report.kept.len(), now)?;
    check_plain_directory(&plain_directory, &report, &source_counts)?;
    sync_dir(&config.teams_dir())?;
    sync_dir(&config.data_dir)?;
    // Step 4: the record, the keyed copy, and the commit point.
    report.state = "committing".to_string();
    report.pending = Some(
        "The plain copies are ready. Run again with --confirm-delete-teams to finish.".to_string(),
    );
    write_record(config, &report)?;
    interrupt(options, Interrupt::Staged)?;
    let keyed_temp = config.data_dir.join("relay.db.keyed.tmp");
    store::copy_private(&config.directory_path(), &keyed_temp)?;
    fs::rename(&keyed_temp, config.data_dir.join(KEYED_DIRECTORY_FILE))
        .map_err(|_| io_error("keep the keyed relay.db"))?;
    sync_dir(&config.data_dir)?;
    if exists(&config.data_dir.join(format!("{DIRECTORY_FILE}-journal"))) {
        return Err(RelayError::internal(
            "relay.db has a write journal at the commit point: nothing is committed. Run the cutover again.",
        ));
    }
    fs::rename(&plain_directory, config.directory_path())
        .map_err(|_| io_error("move the plain relay.db into place"))?;
    sync_dir(&config.data_dir)?;
    interrupt(options, Interrupt::Committed)?;
    finish(config, options, report, now)
}

fn plain_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(PLAIN_SUFFIX);
    PathBuf::from(name)
}

/// The tables of a file (without SQLite's own) and their row counts.
fn table_counts(conn: &rusqlite::Connection) -> RelayResult<BTreeMap<String, u64>> {
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(db)?
        .query_map([], |row| row.get(0))
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)?;
    let mut counts = BTreeMap::new();
    for name in names {
        let count: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
                [],
                |row| row.get(0),
            )
            .map_err(db)?;
        counts.insert(name, to_u(count));
    }
    Ok(counts)
}

fn integrity_ok(conn: &rusqlite::Connection) -> RelayResult<bool> {
    let answer: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(db)?;
    Ok(answer == "ok")
}

/// The plain copy at `copy` has the version, the tables, and the rows of `source`, and
/// passes `integrity_check`.
fn check_copy(source: &Store, copy: &Path) -> RelayResult<()> {
    let plain = Store::open_plain_unchecked(copy)?;
    let failed = || {
        RelayError::internal(format!(
            "The plain copy {} does not match its source.",
            copy.display()
        ))
    };
    if plain.user_version()? != source.user_version()? {
        return Err(failed());
    }
    if source.with(table_counts)? != plain.with(table_counts)? {
        return Err(failed());
    }
    if !plain.with(integrity_ok)? {
        return Err(failed());
    }
    Ok(())
}

/// The edits of the plain `relay.db` (step 3), in one transaction, then `VACUUM`.
/// Answers the rows deleted by table.
fn edit_plain_directory(path: &Path, kept: usize, now: u64) -> RelayResult<BTreeMap<String, u64>> {
    let directory = Store::open_plain_unchecked(path)?;
    let deleted = directory.tx(|tx| {
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
    // Rebuild the file: no deleted row or key stays in a free page.
    directory.with(|conn| conn.execute_batch("VACUUM").map_err(db))?;
    drop(directory);
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error("sync the plain relay.db"))?;
    Ok(deleted)
}

/// The plain `relay.db` holds exactly the kept stores, no key, the other tables as the
/// source (one audit row more), version `DIRECTORY_VERSION`, and passes `integrity_check`.
fn check_plain_directory(
    path: &Path,
    report: &Report,
    source: &BTreeMap<String, u64>,
) -> RelayResult<()> {
    let failed = |why: &str| RelayError::internal(format!("The plain relay.db is wrong: {why}"));
    let directory = Store::open_plain_unchecked(path)?;
    if directory.user_version()? != DIRECTORY_VERSION {
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
    let counts = directory.with(table_counts)?;
    for (table, count) in &counts {
        let before = source.get(table).copied().unwrap_or(u64::MAX);
        let right = match table.as_str() {
            "team" => *count == kept.len() as u64,
            "audit" => *count == before.saturating_add(1),
            // Rows of stores that go (none in a consistent relay.db) may go too.
            "account_store_device" => *count <= before,
            name if CLEARED_TABLES.contains(&name) => *count == 0,
            _ => *count == before,
        };
        if !right {
            return Err(failed(&format!("the rows of {table}")));
        }
    }
    if counts.len() != source.len() {
        return Err(failed("its tables"));
    }
    if !directory.with(integrity_ok)? {
        return Err(failed("integrity_check"));
    }
    Ok(())
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
    if !options.confirm {
        report.pending = Some(
            "The cutover is committed and not finished. Run again with --confirm-delete-teams to finish it."
                .to_string(),
        );
        return Ok(report);
    }
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
    // Step 5a: each store's plain copy replaces its file.
    for (index, id) in kept.iter().enumerate() {
        move_store(config, id)?;
        if index == 0 {
            interrupt(options, Interrupt::MovedOneStore)?;
        }
    }
    sync_dir(&config.teams_dir())?;
    // Step 5b: every other team's files, by team id; never a file of a kept store.
    let mut deleted = remove_other_teams(config, &kept_set, options)?;
    // The old single-team files, the audit archives (they open only with the master key),
    // and a socket that a stopped relay left.
    for name in [
        LEGACY_VAULT_FILE,
        LEGACY_BACKUP_FILE,
        "team.db-journal",
        "relay.db.migrating",
        "relay.db.migrating-journal",
    ] {
        if remove_if_there(&config.data_dir.join(name))? {
            deleted.push(name.to_string());
        }
    }
    let archive = config.data_dir.join(AUDIT_ARCHIVE_DIR);
    if let Ok(entries) = fs::read_dir(&archive) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let path = archive.join(&name);
            if fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) {
                fs::remove_file(&path).map_err(|_| io_error("delete an audit archive"))?;
                deleted.push(format!("{AUDIT_ARCHIVE_DIR}/{name}"));
            }
        }
        if fs::remove_dir(&archive).is_ok() {
            deleted.push(format!("{AUDIT_ARCHIVE_DIR}/"));
        }
    }
    let socket = config.data_dir.join(ADMIN_SOCKET);
    if fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        remove_if_there(&socket)?;
    }
    sync_dir(&config.data_dir)?;
    // The check of the result: only `relay.db` and the kept stores, plain, their
    // snapshots unchanged.
    let after = inventory(config)?;
    check_after(config, &kept_set, &report.files_before, &after)?;
    let mut files_deleted = report.files_deleted.clone();
    files_deleted.extend(deleted);
    files_deleted.sort();
    files_deleted.dedup();
    report.files_deleted = files_deleted;
    report.after = Some(Tally {
        teams: kept.len(),
        operator: 0,
        connect: 0,
        account: kept.len(),
        files: after.len(),
        bytes: after.iter().map(|entry| entry.bytes).sum(),
    });
    report.files_after = Some(after);
    report.left = left_entries(config)?;
    report.state = "done".to_string();
    report.finished_at = Some(now);
    report.pending = None;
    write_record(config, &report)?;
    interrupt(options, Interrupt::Recorded)?;
    // Step 6: the last file with the keys of the team files.
    remove_if_there(&config.data_dir.join(KEYED_DIRECTORY_FILE))?;
    sync_dir(&config.data_dir)?;
    Ok(report)
}

/// Replaces the file of the kept store `id` by its checked plain copy. A store that is
/// plain already is left as it is; a keyed store without a copy is exported again with its
/// key from `relay.db.keyed`.
fn move_store(config: &RelayConfig, id: &TeamId) -> RelayResult<()> {
    let path = config.team_path(id);
    let plain = plain_path(&path);
    if !exists(&plain) {
        if store::is_plain_file(&path) {
            return check_store_file(&path);
        }
        // Keyed, and its copy is gone: make it again from the keyed directory.
        let keyed = Store::open_read_only(
            &config.data_dir.join(KEYED_DIRECTORY_FILE),
            &config.master_key,
        )?;
        let row = keyed
            .with(|conn| directory::team_by_id(conn, id))?
            .ok_or_else(|| {
                RelayError::internal(format!(
                    "The vault store {id} is not in relay.db.keyed: restore the backup named in cutover.json."
                ))
            })?;
        drop(keyed);
        let source = Store::open_at(&path, &row.file_key)?;
        source.export_plain(&plain)?;
        check_copy(&source, &plain)?;
    }
    check_store_file(&plain)?;
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    if exists(Path::new(&journal)) {
        return Err(RelayError::internal(format!(
            "The vault store {id} has a write journal: restore the backup named in cutover.json."
        )));
    }
    fs::rename(&plain, &path).map_err(|_| io_error("move a plain vault store into place"))
}

/// A plain store file of the current team schema that passes `integrity_check`.
fn check_store_file(path: &Path) -> RelayResult<()> {
    let store = Store::open_plain_unchecked(path)?;
    if store.user_version()? != SCHEMA_VERSION || !store.with(integrity_ok)? {
        return Err(RelayError::internal(format!(
            "The plain vault store {} is not whole.",
            path.display()
        )));
    }
    Ok(())
}

/// Deletes every entry of `teams/` whose name starts with a team id that is not in `kept`:
/// the team's database, its journal, its `.pre-v*` copies, its snapshot folder `<id>.sync`,
/// and any other entry of that team. An entry without a team id is left (`left_entries`
/// names it). Answers the names deleted, relative to the data directory.
fn remove_other_teams(
    config: &RelayConfig,
    kept: &BTreeSet<TeamId>,
    options: &Options,
) -> RelayResult<Vec<String>> {
    let entries = match fs::read_dir(config.teams_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
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
    let mut deleted = Vec::new();
    for (index, mut names) in by_team.into_values().enumerate() {
        names.sort();
        for name in names {
            let path = config.teams_dir().join(&name);
            let meta = fs::symlink_metadata(&path).map_err(|_| io_error("read a team file"))?;
            if meta.is_dir() {
                // The snapshot folder `<id>.sync`, or any other folder of that team.
                fs::remove_dir_all(&path).map_err(|_| io_error("delete a team folder"))?;
                deleted.push(format!("{TEAMS_DIR}/{name}/"));
            } else {
                fs::remove_file(&path).map_err(|_| io_error("delete a team file"))?;
                deleted.push(format!("{TEAMS_DIR}/{name}"));
            }
        }
        if index == 0 {
            sync_dir(&config.teams_dir())?;
            interrupt(options, Interrupt::DeletedOneTeam)?;
        }
    }
    sync_dir(&config.teams_dir())?;
    Ok(deleted)
}

/// After the cutover the data directory holds `relay.db`, plain, and for each kept store
/// its plain file and its snapshots, which are the bytes they were before.
fn check_after(
    config: &RelayConfig,
    kept: &BTreeSet<TeamId>,
    before: &[FileEntry],
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
    for entry in after {
        let owner = entry
            .name
            .strip_prefix(&format!("{TEAMS_DIR}/"))
            .and_then(team_prefix);
        // `relay.db`, a file of a kept store, or a file of `teams/` with no team id (left).
        let allowed = entry.name == DIRECTORY_FILE
            || match &owner {
                Some(id) => kept.contains(id),
                None => entry.name.starts_with(&format!("{TEAMS_DIR}/")),
            };
        if !allowed {
            return Err(failed(format!("{} is left", entry.name)));
        }
        // A snapshot (or any other file of a store but its database) is unchanged.
        let is_database = owner
            .as_ref()
            .is_some_and(|id| entry.name == format!("{TEAMS_DIR}/{id}.db"));
        if entry.name != DIRECTORY_FILE && !is_database && !before.iter().any(|old| old == entry) {
            return Err(failed(format!("{} changed", entry.name)));
        }
    }
    for id in kept {
        let path = config.team_path(id);
        if !after
            .iter()
            .any(|entry| entry.name == format!("{TEAMS_DIR}/{id}.db"))
        {
            return Err(failed(format!("the vault store {id} has no file")));
        }
        check_store_file(&path)?;
    }
    // Every snapshot of a kept store is still there.
    for old in before {
        let owner = old
            .name
            .strip_prefix(&format!("{TEAMS_DIR}/"))
            .and_then(team_prefix);
        if owner.is_some_and(|id| kept.contains(&id))
            && old.name.contains(".sync/")
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
