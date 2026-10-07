//! The core of one process (the app or the AutoFill extension): the vault list, the
//! selected vault, its relay sync, and a join that waits for a Mac. Every call goes
//! through [`Core::call`] (contract section 5).
//!
//! The vault holds an exclusive lock on its `.lock` file while it is open, and iOS
//! ends a suspended app that holds a file lock in an App Group container. So the core
//! opens the vault only while it is unlocked: `lock` and `suspend` close it, and the
//! AutoFill extension can open it while the app is in the background.

mod autofill;
mod config;
mod errors;
mod generate;
mod items;
mod join;
mod otp;
mod sync;
mod watchtower;
mod wire;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use apassy::sync::{RelayConfig, RelaySync};
use apassy::vault::Vault;

use config::{Paths, PhoneList, VaultEntry};
pub use errors::{CoreError, CoreResult};
use wire::{Empty, Secret, ok, params};

/// The vault schema of this core. A copy of another schema is refused.
pub const SCHEMA: i64 = apassy::vault::SCHEMA_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    App,
    Autofill,
}

#[derive(Deserialize)]
struct ConfigWire {
    data_dir: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    role: Option<Role>,
}

/// The vault core of one process.
pub struct Core {
    paths: Paths,
    device_name: String,
    role: Role,
    list: Mutex<PhoneList>,
    /// The selected vault while it is unlocked; None while it is locked.
    vault: Mutex<Option<Vault>>,
    /// The passphrase of the unlocked vault when the app asked to keep it (`unlock`
    /// with `keep`), for `resume` after `suspend`. `lock` erases it.
    kept: Mutex<Option<Zeroizing<String>>>,
    /// Counts each close of the vault, under the vault mutex. An unlock derives the key
    /// without the mutex and stores the vault only when no close came in between: a
    /// `lock`, `suspend`, or `select` during the key derivation wins.
    closes: AtomicU64,
    /// The relay sync of the selected vault, when it syncs through the relay.
    relay: Mutex<Option<RelaySync>>,
    join: Mutex<Option<join::Joining>>,
    /// Counts each start, cancel, and end of a join. A poll that ran while the join was
    /// replaced or cancelled gives its join up instead of putting it back.
    joins: AtomicU64,
    status: Mutex<sync::Memory>,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct Op {
    op: String,
}

#[derive(Deserialize)]
struct VaultId {
    vault_id: String,
}

#[derive(Deserialize)]
struct Passphrase {
    passphrase: Secret,
    #[serde(default)]
    keep: bool,
}

#[derive(Deserialize)]
struct ItemId {
    id: u64,
}

#[derive(Deserialize)]
struct FieldRef {
    id: u64,
    field: String,
}

#[derive(Serialize)]
struct Info<'a> {
    vaults: &'a [VaultEntry],
    selected: Option<&'a str>,
    unlocked: bool,
    join: Option<join::JoinOut>,
    schema: i64,
    version: &'static str,
}

#[derive(Serialize)]
struct Checked {
    ok: bool,
}

#[derive(Serialize)]
struct Resumed {
    unlocked: bool,
}

#[derive(Serialize)]
struct Revealed<'a> {
    value: &'a str,
}

#[derive(Serialize)]
struct Totp {
    code: String,
    period: u64,
    remaining: u64,
    digits: u32,
}

#[derive(Serialize)]
struct Saved {
    id: u64,
    revision: u64,
}

#[derive(Serialize)]
struct List<T: Serialize> {
    items: Vec<T>,
}

#[derive(Serialize)]
struct Events {
    events: Vec<items::Event>,
}

#[derive(Serialize)]
struct Identities {
    identities: Vec<autofill::Identity>,
}

#[derive(Serialize)]
struct Credential<'a> {
    username: &'a str,
    password: &'a str,
}

impl Core {
    /// Start a core from its JSON config (contract section 3).
    pub fn new(config: &str) -> CoreResult<Self> {
        let config: ConfigWire = params(config)?;
        let paths = Paths::new(PathBuf::from(config.data_dir))?;
        let device_name = config
            .device_name
            .map(|name| {
                name.trim()
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .collect::<String>()
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "iPhone".to_owned());
        let device_name = truncate(&device_name, 64);
        // The name of this iPhone in the sync record and in a conflict copy.
        apassy::sync::set_device_name(&device_name);
        let list = PhoneList::load(&paths.data_dir)?;
        let core = Self {
            paths,
            device_name,
            role: config.role.unwrap_or(Role::App),
            list: Mutex::new(list),
            vault: Mutex::new(None),
            kept: Mutex::new(None),
            closes: AtomicU64::new(0),
            relay: Mutex::new(None),
            join: Mutex::new(None),
            joins: AtomicU64::new(0),
            status: Mutex::new(sync::Memory::default()),
        };
        if core.role == Role::App {
            core.clear_unfinished_joins();
        }
        core.select_relay()?;
        Ok(core)
    }

    /// One call (contract section 4): the answer as JSON.
    pub fn call(&self, request: &str) -> String {
        match self.dispatch(request) {
            Ok(answer) => answer,
            Err(error) => wire::error(&error),
        }
    }

    /// Lock, end the relay calls, and cancel a join: the process ends.
    pub fn shutdown(&self) {
        self.close(true);
        let joining = guard(&self.join).take();
        if let Some(joining) = joining {
            joining.abandon();
        }
    }

    fn require_app(&self) -> CoreResult<()> {
        if self.role == Role::App {
            Ok(())
        } else {
            Err(CoreError::not_allowed())
        }
    }

    fn dispatch(&self, request: &str) -> CoreResult<String> {
        let Op { op } = params(request)?;
        match op.as_str() {
            // 5.1
            "info" => self.info(),
            "select" => {
                let VaultId { vault_id } = params(request)?;
                self.select(&vault_id)?;
                Ok(ok(&Empty {}))
            }
            "unlock" => {
                let Passphrase { passphrase, keep } = params(request)?;
                self.unlock(passphrase.expose(), keep && self.role == Role::App)?;
                Ok(ok(&Empty {}))
            }
            "lock" => {
                self.close(true);
                Ok(ok(&Empty {}))
            }
            "suspend" => {
                self.require_app()?;
                self.close(false);
                Ok(ok(&Empty {}))
            }
            "resume" => {
                self.require_app()?;
                Ok(ok(&Resumed {
                    unlocked: self.resume()?,
                }))
            }
            "check_passphrase" => {
                let Passphrase { passphrase, .. } = params(request)?;
                let entry = self.selected()?;
                let ok_now = match Vault::verify_passphrase_at(
                    &self.paths.vault_file(&entry.id),
                    passphrase.expose(),
                ) {
                    Ok(()) => true,
                    Err(error)
                        if error.kind() == apassy::vault::VaultErrorKind::WrongKeyOrCorrupt =>
                    {
                        false
                    }
                    Err(error) if error.kind() == apassy::vault::VaultErrorKind::InvalidInput => {
                        false
                    }
                    Err(error) => return Err(error.into()),
                };
                Ok(ok(&Checked { ok: ok_now }))
            }
            "create_local_vault" => {
                self.require_app()?;
                #[derive(Deserialize)]
                struct Create {
                    name: String,
                    passphrase: Secret,
                }
                let Create { name, passphrase } = params(request)?;
                let entry = self.create_local_vault(&name, passphrase.expose())?;
                Ok(ok(&sync::VaultAnswer { vault: &entry }))
            }
            "remove_vault" => {
                self.require_app()?;
                #[derive(Deserialize)]
                struct Remove {
                    vault_id: String,
                    #[serde(default)]
                    force: bool,
                }
                let Remove { vault_id, force } = params(request)?;
                self.remove_vault(&vault_id, force)
            }
            // 5.2
            "join_start" | "join_poll" | "join_cancel" | "join_finish" => {
                self.require_app()?;
                self.join_call(&op, request)
            }
            // 5.3
            "items" => {
                #[derive(Deserialize)]
                struct Filter {
                    #[serde(default)]
                    archived: items::Archived,
                }
                let Filter { archived } = params(request)?;
                self.with_vault(|vault| {
                    Ok(ok(&List {
                        items: items::rows(vault, archived)?,
                    }))
                })
            }
            "item" => {
                let ItemId { id } = params(request)?;
                self.with_vault(|vault| Ok(ok(&items::detail(vault, id)?)))
            }
            "reveal" => {
                let FieldRef { id, field } = params(request)?;
                self.with_vault_mut(|vault| {
                    let value = vault.reveal(id, &field)?;
                    vault.record_reveal(id)?;
                    Ok(ok(&Revealed {
                        value: value.expose(),
                    }))
                })
            }
            "totp" => {
                let FieldRef { id, field } = params(request)?;
                self.with_vault(|vault| {
                    let value = vault.reveal(id, &field)?;
                    let totp = otp::Totp::parse(value.expose())?;
                    let (code, remaining) = totp.code_at(now());
                    Ok(ok(&Totp {
                        code,
                        period: totp.period,
                        remaining,
                        digits: totp.digits,
                    }))
                })
            }
            "history" => {
                self.require_app()?;
                let ItemId { id } = params(request)?;
                self.with_vault(|vault| {
                    Ok(ok(&Events {
                        events: items::history(vault, id)?,
                    }))
                })
            }
            "save" => {
                self.require_app()?;
                #[derive(Deserialize)]
                struct Save {
                    id: Option<u64>,
                    revision: Option<u64>,
                    item: items::DraftIn,
                }
                let Save { id, revision, item } = params(request)?;
                self.with_vault_mut(|vault| {
                    let draft = items::build_draft(vault, id, item)?;
                    let summary = match (id, revision) {
                        (Some(id), Some(revision)) => vault.update(id, revision, draft)?,
                        (Some(_), None) => {
                            return Err(CoreError::invalid(
                                "An edit needs the revision of the item.",
                            ));
                        }
                        (None, _) => vault.add(draft)?,
                    };
                    Ok(ok(&Saved {
                        id: summary.id,
                        revision: summary.revision,
                    }))
                })
            }
            "archive" => {
                self.require_app()?;
                #[derive(Deserialize)]
                struct Archive {
                    id: u64,
                    archived: bool,
                }
                let Archive { id, archived } = params(request)?;
                self.with_vault_mut(|vault| {
                    vault.set_archived(id, archived)?;
                    Ok(ok(&Empty {}))
                })
            }
            "delete" => {
                self.require_app()?;
                #[derive(Deserialize)]
                struct Delete {
                    id: u64,
                    revision: u64,
                }
                let Delete { id, revision } = params(request)?;
                self.with_vault_mut(|vault| {
                    vault.delete(id, revision)?;
                    Ok(ok(&Empty {}))
                })
            }
            // 5.4
            "generate" => {
                self.require_app()?;
                let options: generate::Options = params(request)?;
                Ok(ok(&generate::generate(&options)?))
            }
            "strength" => {
                self.require_app()?;
                #[derive(Deserialize)]
                struct Value {
                    value: Secret,
                }
                let Value { value } = params(request)?;
                Ok(ok(&generate::strength(value.expose())))
            }
            "watchtower" => {
                self.require_app()?;
                self.with_vault(|vault| Ok(ok(&watchtower::report(vault, now())?)))
            }
            // 5.5
            "sync" | "sync_wait" | "take_new_passphrase" | "use_relay_copy" | "devices" => {
                self.require_app()?;
                self.sync_call(&op, request)
            }
            "sync_status" => Ok(ok(&sync::StatusAnswer {
                status: self.status(),
            })),
            // 5.7
            "autofill_list" => {
                #[derive(Deserialize)]
                struct Domains {
                    domains: Vec<String>,
                }
                let Domains { domains } = params(request)?;
                self.with_vault(|vault| Ok(ok(&autofill::list(vault, &domains)?)))
            }
            "autofill_credential" => {
                let ItemId { id } = params(request)?;
                self.with_vault_mut(|vault| {
                    let details = vault.details(id)?;
                    if items::kind_str(details.summary.kind) != "login" {
                        return Err(CoreError::invalid("AutoFill fills logins only."));
                    }
                    let username = vault.reveal(id, "username")?;
                    let password = vault.reveal(id, "password")?;
                    vault.record_reveal(id)?;
                    Ok(ok(&Credential {
                        username: username.expose(),
                        password: password.expose(),
                    }))
                })
            }
            "credential_identities" => self.with_vault(|vault| {
                Ok(ok(&Identities {
                    identities: autofill::identities(vault)?,
                }))
            }),
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    // ---- The vault list and the lock. ----

    fn info(&self) -> CoreResult<String> {
        // The app may have changed the list since this process read it.
        if self.role == Role::Autofill {
            *guard(&self.list) = PhoneList::load(&self.paths.data_dir)?;
        }
        // Lock order: the vault and the join before the list, as everywhere.
        let unlocked = guard(&self.vault)
            .as_ref()
            .is_some_and(|vault| !vault.is_locked());
        let join = guard(&self.join).as_ref().map(join::Joining::view);
        let list = guard(&self.list);
        Ok(ok(&Info {
            vaults: &list.vaults,
            selected: list.selected.as_deref(),
            unlocked,
            join,
            schema: SCHEMA,
            version: env!("CARGO_PKG_VERSION"),
        }))
    }

    fn selected(&self) -> CoreResult<VaultEntry> {
        guard(&self.list)
            .selected_entry()
            .cloned()
            .ok_or_else(CoreError::no_vault)
    }

    /// The relay sync of the selected vault, made again after a selection.
    fn select_relay(&self) -> CoreResult<()> {
        let entry = guard(&self.list).selected_entry().cloned();
        let relay = entry.and_then(|entry| {
            entry.relay_url.as_ref().map(|url| {
                RelaySync::new(RelayConfig::in_data_dir(
                    &self.paths.data_dir,
                    &self.paths.vault_file(&entry.id),
                    url,
                    &entry.id,
                ))
            })
        });
        *guard(&self.relay) = relay;
        *guard(&self.status) = sync::Memory::default();
        Ok(())
    }

    fn select(&self, id: &str) -> CoreResult<()> {
        {
            let list = guard(&self.list);
            if list.get(id).is_none() {
                return Err(CoreError::new(
                    "no_vault",
                    "This vault is not on this iPhone.",
                ));
            }
        }
        self.close(true);
        {
            let mut list = guard(&self.list);
            list.selected = Some(id.to_owned());
            // The extension never writes the list.
            if self.role == Role::App {
                list.save(&self.paths.data_dir)?;
            }
        }
        self.select_relay()
    }

    fn unlock(&self, passphrase: &str, keep: bool) -> CoreResult<()> {
        let entry = self.selected()?;
        self.close(true);
        let closes = self.closes.load(Ordering::SeqCst);
        let mut vault = Vault::open(&self.paths.vault_file(&entry.id))?;
        vault.unlock(passphrase)?;
        let mut slot = guard(&self.vault);
        if self.closes.load(Ordering::SeqCst) != closes {
            // A lock, a suspend, or a selection came during the key derivation.
            drop(slot);
            let _ = vault.lock();
            return Err(CoreError::locked());
        }
        *slot = Some(vault);
        if keep {
            *guard(&self.kept) = Some(Zeroizing::new(passphrase.to_owned()));
        }
        Ok(())
    }

    /// Close the vault and end the relay calls. `forget` also erases the kept
    /// passphrase (a lock); without it the app can `resume` (a suspend).
    fn close(&self, forget: bool) {
        if let Some(relay) = guard(&self.relay).as_ref() {
            relay.forget();
        }
        // Lock order: the vault, then the kept passphrase, as in `unlock`.
        let mut slot = guard(&self.vault);
        self.closes.fetch_add(1, Ordering::SeqCst);
        if let Some(mut vault) = slot.take() {
            let _ = vault.lock();
        }
        if forget {
            *guard(&self.kept) = None;
        }
    }

    /// Open the vault again with the kept passphrase after `suspend`.
    fn resume(&self) -> CoreResult<bool> {
        if guard(&self.vault).is_some() {
            return Ok(true);
        }
        let kept = guard(&self.kept).clone();
        let Some(passphrase) = kept else {
            return Ok(false);
        };
        match self.unlock(&passphrase, true) {
            Ok(()) => Ok(true),
            Err(error) if error.code == "wrong_passphrase" => {
                *guard(&self.kept) = None;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn with_vault<T>(&self, run: impl FnOnce(&Vault) -> CoreResult<T>) -> CoreResult<T> {
        let slot = guard(&self.vault);
        match slot.as_ref() {
            Some(vault) if !vault.is_locked() => run(vault),
            _ if guard(&self.list).selected.is_none() => Err(CoreError::no_vault()),
            _ => Err(CoreError::locked()),
        }
    }

    fn with_vault_mut<T>(&self, run: impl FnOnce(&mut Vault) -> CoreResult<T>) -> CoreResult<T> {
        let mut slot = guard(&self.vault);
        match slot.as_mut() {
            Some(vault) if !vault.is_locked() => run(vault),
            _ if guard(&self.list).selected.is_none() => Err(CoreError::no_vault()),
            _ => Err(CoreError::locked()),
        }
    }

    /// A vault on this iPhone only, without the relay (Simulator builds and tests).
    fn create_local_vault(&self, name: &str, passphrase: &str) -> CoreResult<VaultEntry> {
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(CoreError::invalid("Type a name of 1 to 64 bytes."));
        }
        if passphrase.len() < apassy::vault::MIN_PASSPHRASE_BYTES {
            return Err(CoreError::invalid(format!(
                "The passphrase needs at least {} characters.",
                apassy::vault::MIN_PASSPHRASE_BYTES
            )));
        }
        self.close(true);
        let temp = self.paths.new_vault_file(&format!("{}", now()));
        let vault = Vault::create(&temp, passphrase)?;
        let mut vault = vault;
        vault.unlock(passphrase)?;
        let id = vault.sync_identity()?.vault_id;
        drop(vault);
        let file = self.paths.vault_file(&id);
        std::fs::rename(&temp, &file).map_err(|_| CoreError::io())?;
        let _ = std::fs::remove_file(sidecar(&temp));
        let entry = VaultEntry {
            id,
            name: name.to_owned(),
            relay_url: None,
            team_id: None,
            device_id: None,
            added_at: now() as i64,
        };
        {
            let mut list = guard(&self.list);
            list.put(entry.clone());
            list.save(&self.paths.data_dir)?;
        }
        self.select_relay()?;
        self.unlock(passphrase, false)?;
        Ok(entry)
    }
}

impl Core {
    /// Remove the files of a join that a crash ended between the adoption and the
    /// rename: `vaults/.new-*` and `sync/new-*.json`. The app process only, at start.
    fn clear_unfinished_joins(&self) {
        let dirs = [
            (self.paths.data_dir.join("vaults"), ".new-"),
            (self.paths.data_dir.join("sync"), "new-"),
        ];
        for (dir, prefix) in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_str().is_some_and(|name| name.starts_with(prefix))
                    && entry.file_type().is_ok_and(|kind| kind.is_file())
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// The lock file next to a vault file.
pub(crate) fn sidecar(vault_file: &std::path::Path) -> PathBuf {
    let mut name = vault_file.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn truncate(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// An error answer (contract section 4).
pub fn error_answer(code: &'static str, message: &str) -> String {
    wire::error(&CoreError::new(code, message))
}
