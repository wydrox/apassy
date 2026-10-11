//! iCloud transports closed encrypted snapshots. Swift owns file coordination and
//! bookmarks; this module never opens a provider URL. A prepare merges locally, but
//! only a completion after coordinated publication can report a completed sync.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;

use apassy::vault::{SyncScope, Vault, VaultErrorKind};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::config::{PhoneList, VaultEntry, valid_id};
use super::sync::{Memory, Merged, StatusAnswer, VaultAnswer};
use super::wire::{Secret, ok, params};
use super::{Core, CoreError, CoreResult, guard, now};

/// Bound disk use and provider input before SQLCipher opens it.
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct Pending {
    token: String,
    vault_id: String,
    closes: u64,
    epoch: [u8; 32],
    content: [u8; 32],
    pushed: bool,
    merged: Merged,
}

#[derive(Deserialize)]
struct Import {
    input_path: PathBuf,
    name: String,
    passphrase: Secret,
}

#[derive(Deserialize)]
struct Prepare {
    vault_id: String,
    input_path: PathBuf,
    output_path: PathBuf,
    #[serde(default)]
    passphrase: Option<Secret>,
}

#[derive(Serialize)]
struct Prepared {
    token: String,
    input_sha256: String,
    output_sha256: Option<String>,
    write_required: bool,
    rekeyed: bool,
}

#[derive(Deserialize)]
struct Complete {
    vault_id: String,
    token: String,
}

/// Private temporary files disappear on every return, including an error.
struct WorkDir(PathBuf);

impl WorkDir {
    fn new(root: &Path) -> CoreResult<Self> {
        let path = root.join(format!(".core-{}", random_token()?));
        fs::create_dir(&path).map_err(|_| CoreError::io())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| CoreError::io())?;
        Ok(Self(path))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Only a newly created vault may be removed after a failed registry commit.
struct NewVaultFile(Option<PathBuf>);

impl Drop for NewVaultFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.as_ref() {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(super::sidecar(path));
        }
    }
}

/// Durable proof that this import owns one exact file. Recovery never removes a
/// registered vault or another file that later takes the same name.
#[derive(Serialize, Deserialize)]
struct ImportRecord {
    id: String,
    device: u64,
    inode: u64,
}

struct ImportMarker {
    path: PathBuf,
    _lock: File,
}

impl ImportMarker {
    fn new(data_dir: &Path, id: &str, staging: &Path) -> CoreResult<Self> {
        let path = data_dir
            .join("sync")
            .join(format!("icloud-import-{id}.json"));
        let temporary = staging.with_extension("import-marker");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| CoreError::io())?;
        file.try_lock().map_err(|_| CoreError::io())?;
        let meta = fs::metadata(staging).map_err(|_| CoreError::io())?;
        let record = ImportRecord {
            id: id.to_owned(),
            device: meta.dev(),
            inode: meta.ino(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| CoreError::io())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| CoreError::io())?;
        // Publish a complete marker while its inode is already locked. Startup
        // never sees an incomplete or temporarily unlocked active marker.
        fs::hard_link(&temporary, &path).map_err(|_| {
            CoreError::new("busy", "An import of this vault needs to finish first.")
        })?;
        let marker = Self { path, _lock: file };
        fs::remove_file(&temporary).map_err(|_| CoreError::io())?;
        File::open(data_dir.join("sync"))
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CoreError::io())?;
        Ok(marker)
    }
}

impl Drop for ImportMarker {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn random_token() -> CoreResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| CoreError::io())?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[usize::from(byte >> 4)] as char);
        value.push(DIGITS[usize::from(byte & 15)] as char);
    }
    value
}

fn too_large() -> CoreError {
    CoreError::new("too_large", "The vault file is larger than 64 MiB.")
}

fn changed_selection() -> CoreError {
    CoreError::new(
        "cancelled",
        "The vault selection or lock state changed. Try again.",
    )
}

impl Core {
    pub(super) fn clear_unfinished_icloud_imports(&self) {
        let sync = self.paths.data_dir.join("sync");
        let Ok(entries) = fs::read_dir(&sync) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name
                .strip_prefix("icloud-import-")
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            if !valid_id(id) || !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            let Ok(mut marker) = OpenOptions::new().read(true).write(true).open(entry.path())
            else {
                continue;
            };
            if marker.try_lock().is_err() {
                continue;
            }
            let mut bytes = Vec::new();
            if (&mut marker).take(4097).read_to_end(&mut bytes).is_err() || bytes.len() > 4096 {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            let Ok(record) = serde_json::from_slice::<ImportRecord>(&bytes) else {
                let _ = fs::remove_file(entry.path());
                continue;
            };
            if record.id != id {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            // Read after taking the marker lock. An import can commit its registry
            // while this new Core waits for the marker.
            let Ok(list) = PhoneList::load(&self.paths.data_dir) else {
                continue;
            };
            if list.get(id).is_none() {
                let path = self.paths.vault_file(id);
                if fs::symlink_metadata(&path).is_ok_and(|meta| {
                    meta.is_file()
                        && !meta.file_type().is_symlink()
                        && meta.dev() == record.device
                        && meta.ino() == record.inode
                }) {
                    let _ = fs::remove_file(&path);
                    let _ = fs::remove_file(super::sidecar(&path));
                }
            }
            let _ = fs::remove_file(entry.path());
        }
    }

    pub(super) fn icloud_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "icloud_import" => {
                let input: Import = params(request)?;
                let entry = self.icloud_import(input)?;
                Ok(ok(&VaultAnswer { vault: &entry }))
            }
            "icloud_sync_prepare" => {
                let input: Prepare = params(request)?;
                self.icloud_prepare(input).map(|answer| ok(&answer))
            }
            "icloud_sync_complete" => {
                let input: Complete = params(request)?;
                self.icloud_complete(input)?;
                Ok(ok(&StatusAnswer {
                    status: self.status(),
                }))
            }
            _ => Err(CoreError::invalid("This iCloud call is not known.")),
        }
    }

    fn transfer_root(&self) -> CoreResult<PathBuf> {
        let path = self.paths.data_dir.join("icloud-transfer");
        let meta = fs::symlink_metadata(&path).map_err(|_| CoreError::io())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(CoreError::invalid(
                "The transfer folder must be a private folder.",
            ));
        }
        fs::canonicalize(path).map_err(|_| CoreError::io())
    }

    /// A path can use the configured data directory or its canonical form. Every
    /// component below the transfer root must be literal and free of symlinks.
    fn transfer_path(&self, path: &Path, input: bool) -> CoreResult<PathBuf> {
        let root = self.transfer_root()?;
        let configured = self.paths.data_dir.join("icloud-transfer");
        let relative = path
            .strip_prefix(&root)
            .or_else(|_| path.strip_prefix(&configured))
            .map_err(|_| CoreError::invalid("Use a file in the private transfer folder."))?;
        if !path.is_absolute()
            || relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(CoreError::invalid("The transfer path is not valid."));
        }
        let parts: Vec<_> = relative.components().collect();
        let mut checked = root;
        for (index, part) in parts.iter().enumerate() {
            checked.push(part.as_os_str());
            let final_part = index + 1 == parts.len();
            match fs::symlink_metadata(&checked) {
                Ok(meta) if !final_part && meta.is_dir() && !meta.file_type().is_symlink() => {}
                Ok(meta)
                    if final_part
                        && input
                        && meta.is_file()
                        && !meta.file_type().is_symlink()
                        && meta.nlink() == 1 =>
                {
                    if meta.len() > MAX_SNAPSHOT_BYTES {
                        return Err(too_large());
                    }
                }
                Err(error)
                    if final_part && !input && error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(CoreError::invalid(
                        "The input must be a regular private file. The output must be a new file.",
                    ));
                }
            }
        }
        Ok(checked)
    }

    /// Copy the caller's snapshot to a core-owned file. Hash the actual bytes used by
    /// SQLCipher. Reject SQLite companions instead of silently losing WAL content.
    fn take_snapshot(&self, input: &Path, target: &Path) -> CoreResult<String> {
        let checked = self.transfer_path(input, true)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut companion = checked.as_os_str().to_os_string();
            companion.push(suffix);
            match fs::symlink_metadata(PathBuf::from(companion)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(CoreError::invalid("Use a closed encrypted vault snapshot.")),
            }
        }
        let before = fs::symlink_metadata(&checked).map_err(|_| CoreError::io())?;
        let mut source = File::open(&checked).map_err(|_| CoreError::io())?;
        let opened = source.metadata().map_err(|_| CoreError::io())?;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.nlink() != 1
            || !opened.is_file()
        {
            return Err(CoreError::invalid("The transfer file changed. Try again."));
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
            .map_err(|_| CoreError::io())?;
        let mut hash = Context::new(&SHA256);
        let mut bytes = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = source.read(&mut bytes).map_err(|_| CoreError::io())?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > MAX_SNAPSHOT_BYTES {
                return Err(too_large());
            }
            output
                .write_all(&bytes[..count])
                .map_err(|_| CoreError::io())?;
            hash.update(&bytes[..count]);
        }
        output.sync_all().map_err(|_| CoreError::io())?;
        Ok(hex(hash.finish().as_ref()))
    }

    fn icloud_import(&self, input: Import) -> CoreResult<VaultEntry> {
        let name = input.name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(CoreError::invalid("Type a name of 1 to 64 bytes."));
        }
        // Capture the session under its lock, before expensive key derivations. The
        // existing selected vault stays unchanged on every validation failure.
        let closes = {
            let _slot = guard(&self.vault);
            self.closes.load(Ordering::SeqCst)
        };
        let work = WorkDir::new(&self.transfer_root()?)?;
        let snapshot = work.0.join("input.apassy");
        self.take_snapshot(&input.input_path, &snapshot)?;
        let identity = Vault::inspect_sync_copy(&snapshot, input.passphrase.expose())?;
        let id = identity.vault_id;
        if !valid_id(&id) {
            return Err(CoreError::new(
                "damaged",
                "The copy has an invalid vault ID.",
            ));
        }
        if guard(&self.list).get(&id).is_some() {
            return Err(CoreError::invalid("This vault is on this iPhone already."));
        }

        // A generation-zero raw Mac vault is accepted by inspect_sync_copy. Adopt
        // only after a private export strips ALL local tables, not only device keys.
        let staging = work.0.join("raw.apassy");
        let (mut raw, _) = Vault::adopt_sync_copy(&snapshot, &staging, input.passphrase.expose())?;
        raw.unlock(input.passphrase.expose())?;
        let stripped = work.0.join("stripped.apassy");
        raw.write_sync_copy(&stripped, &self.device_name)?;
        drop(raw);

        // The marker records the staged file's inode before an exclusive link
        // publishes the final name. No rename may replace an existing vault.
        let staged_file = work.0.join("phone.apassy");
        let staged_cleanup = NewVaultFile(Some(staged_file.clone()));
        let (staged_vault, _) =
            Vault::adopt_sync_copy(&stripped, &staged_file, input.passphrase.expose())?;
        drop(staged_vault);
        let marker = ImportMarker::new(&self.paths.data_dir, &id, &staged_file)?;
        let file = self.paths.vault_file(&id);
        fs::hard_link(&staged_file, &file).map_err(|_| CoreError::io())?;
        let mut cleanup = NewVaultFile(Some(file.clone()));
        fs::remove_file(&staged_file).map_err(|_| CoreError::io())?;
        drop(staged_cleanup);
        // Drop the vault before removing its files if any later step fails.
        File::open(self.paths.data_dir.join("vaults"))
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CoreError::io())?;
        let mut vault = Vault::open(&file)?;
        let result = (|| {
            vault.unlock(input.passphrase.expose())?;
            let mut slot = guard(&self.vault);
            if self.closes.load(Ordering::SeqCst) != closes {
                return Err(changed_selection());
            }
            let entry = VaultEntry {
                id,
                name: name.to_owned(),
                sync_source: Some("icloud".to_owned()),
                relay_url: None,
                team_id: None,
                device_id: None,
                added_at: now() as i64,
            };
            let mut list = guard(&self.list);
            if list.get(&entry.id).is_some() {
                return Err(CoreError::invalid("This vault is on this iPhone already."));
            }
            let mut next = list.clone();
            next.put(entry.clone());
            next.save(&self.paths.data_dir)?;
            *list = next;
            drop(list);
            if let Some(mut previous) = slot.take() {
                let _ = previous.lock();
            }
            self.closes.fetch_add(1, Ordering::SeqCst);
            *guard(&self.kept) = None;
            *guard(&self.icloud_pending) = None;
            if let Some(relay) = guard(&self.relay).take() {
                relay.forget();
            }
            *guard(&self.status) = Memory::default();
            // Move the unlocked local vault into the core only after registry commit.
            Ok((entry, slot))
        })();
        match result {
            Ok((entry, mut slot)) => {
                *slot = Some(vault);
                cleanup.0 = None;
                drop(marker);
                Ok(entry)
            }
            Err(error) => {
                drop(vault);
                Err(error)
            }
        }
    }

    fn icloud_prepare(&self, input: Prepare) -> CoreResult<Prepared> {
        let closes = self.with_vault(|vault| {
            let entry = self.selected()?;
            if entry.id != input.vault_id
                || !entry.is_icloud()
                || vault.sync_identity()?.vault_id != input.vault_id
            {
                return Err(CoreError::invalid("Select this iCloud vault before sync."));
            }
            *guard(&self.icloud_pending) = None;
            Ok(self.closes.load(Ordering::SeqCst))
        })?;
        let work = WorkDir::new(&self.transfer_root()?)?;
        let snapshot = work.0.join("input.apassy");
        let input_sha256 = self.take_snapshot(&input.input_path, &snapshot)?;
        let output = self.transfer_path(&input.output_path, false)?;
        let mut rekeyed = false;
        let result = self.with_vault_mut(|vault| {
            if self.closes.load(Ordering::SeqCst) != closes {
                return Err(changed_selection());
            }
            let entry = self.selected()?;
            if entry.id != input.vault_id || !entry.is_icloud()
                || vault.sync_identity()?.vault_id != input.vault_id
            {
                return Err(CoreError::invalid("Select this iCloud vault before sync."));
            }
            // A new attempt makes every earlier prepare token invalid.
            *guard(&self.icloud_pending) = None;
            if let Some(passphrase) = input.passphrase.as_ref() {
                let changed = vault.take_passphrase_of_copy_report(&snapshot, passphrase.expose());
                rekeyed = changed.as_ref().map_or_else(|failure| failure.rekeyed, |()| true);
                if rekeyed {
                    let mut kept = guard(&self.kept);
                    if kept.is_some() {
                        *kept = Some(Zeroizing::new(passphrase.expose().to_owned()));
                    }
                }
                changed.map_err(|failure| CoreError::from(failure.error))?;
            }
            let scope = SyncScope::vault();
            let merge = vault.merge_from(&snapshot, &scope).map_err(|error| {
                if error.kind() == VaultErrorKind::WrongKeyOrCorrupt {
                    CoreError::new("needs_passphrase", "The iCloud copy needs its passphrase. Check the file and type the passphrase.")
                } else { error.into() }
            })?;
            if merge.changed_local() {
                let mut memory = guard(&self.status);
                memory.version = memory.version.saturating_add(1);
            }
            let mut content = vault.sync_content(&scope)?;
            // A snapshot of an earlier schema gets a copy of the current schema, also
            // with the same content. The input snapshot itself never changes.
            let write_required = content != merge.remote_content || merge.remote_outdated();
            let output_sha256 = if write_required {
                // Recheck the absent destination after the merge and key derivation.
                self.transfer_path(&input.output_path, false)?;
                let copy = vault.write_sync_copy(&output, &self.device_name)?;
                if fs::metadata(&output).map_err(|_| CoreError::io())?.len() > MAX_SNAPSHOT_BYTES {
                    let _ = fs::remove_file(&output);
                    return Err(too_large());
                }
                content = copy.content;
                Some(hex(&copy.sha256))
            } else { None };
            let token = random_token()?;
            *guard(&self.icloud_pending) = Some(Pending {
                token: token.clone(),
                vault_id: input.vault_id,
                closes: self.closes.load(Ordering::SeqCst),
                epoch: vault.epoch(),
                content,
                pushed: write_required,
                merged: Merged {
                    inserted: merge.inserted,
                    updated: merge.updated,
                    deleted: merge.deleted,
                    conflicts: merge.conflicts.len(),
                },
            });
            let mut memory = guard(&self.status);
            memory.state = Some("pending");
            memory.message = Some("The iCloud Drive file still needs a check.".to_owned());
            memory.pushed = false;
            Ok(Prepared { token, input_sha256, output_sha256, write_required, rekeyed })
        });
        result.map_err(|mut error| {
            error.rekeyed = rekeyed;
            error
        })
    }

    fn icloud_complete(&self, input: Complete) -> CoreResult<()> {
        self.with_vault(|vault| {
            let mut pending = guard(&self.icloud_pending);
            let Some(prepared) = pending.as_ref() else {
                return Err(changed_selection());
            };
            if prepared.token != input.token || prepared.vault_id != input.vault_id {
                return Err(CoreError::invalid("This sync token is not valid."));
            }
            let prepared = pending.take().expect("pending checked");
            let entry = self.selected()?;
            if entry.id != prepared.vault_id
                || !entry.is_icloud()
                || self.closes.load(Ordering::SeqCst) != prepared.closes
                || vault.epoch() != prepared.epoch
            {
                return Err(changed_selection());
            }
            let current = vault.sync_content(&SyncScope::vault())?;
            let unchanged = current == prepared.content;
            let mut memory = guard(&self.status);
            memory.state = Some(if unchanged { "ok" } else { "pending" });
            memory.message = Some(
                if unchanged {
                    "The iCloud Drive file is up to date."
                } else {
                    "New changes on this iPhone still need sync."
                }
                .to_owned(),
            );
            memory.last_sync_at = Some(now());
            memory.pushed = prepared.pushed;
            memory.merged = Some(prepared.merged);
            Ok(())
        })
    }
}
