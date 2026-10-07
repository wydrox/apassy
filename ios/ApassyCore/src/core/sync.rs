//! Relay sync of the selected vault (contract section 5.5) and removing a vault from
//! this iPhone (section 5.6). The engine is the Mac's (`apassy::sync::RelaySync`): the
//! same merge, the same signed heads, the same checks of the chain.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use apassy::sync::{KeySource, RelayRefusal, RelaySync, SyncError, SyncOutcome};
use apassy::vault::{Vault, VaultErrorKind};

use super::config::VaultEntry;
use super::errors::{CoreError, CoreResult};
use super::wire::{Secret, ok, params};
use super::{Core, guard, now};

/// What the last sync of this process did.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    state: Option<&'static str>,
    message: Option<String>,
    last_sync_at: Option<u64>,
    pushed: bool,
    merged: Option<Merged>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Merged {
    inserted: usize,
    updated: usize,
    deleted: usize,
    conflicts: usize,
}

#[derive(Debug, Serialize)]
pub struct Status {
    enabled: bool,
    state: &'static str,
    message: String,
    version: u64,
    last_sync_at: Option<u64>,
    pushed: bool,
    merged: Option<Merged>,
}

#[derive(Serialize)]
pub struct StatusAnswer {
    pub status: Status,
}

#[derive(Serialize)]
pub struct VaultAnswer<'a> {
    pub vault: &'a VaultEntry,
}

#[derive(Serialize)]
struct Device {
    id: u64,
    name: String,
    this: bool,
    last_seen_at: Option<u64>,
}

#[derive(Serialize)]
struct Devices {
    devices: Vec<Device>,
}

#[derive(Serialize)]
struct Taken {
    status: Status,
    rekeyed: bool,
}

#[derive(Serialize)]
struct Waited {
    changed: bool,
}

#[derive(Serialize)]
struct Removed {
    left_relay: bool,
}

/// The state code of a sync error, for the status.
fn state_of(error: &CoreError) -> &'static str {
    match error.code {
        "relay_unreachable" | "rate_limited" => "offline",
        "needs_passphrase" => "needs_passphrase",
        "removed" => "removed",
        "damaged" => "damaged",
        "stale_copy" => "stale_copy",
        "forked_copy" => "forked_copy",
        "busy" => "busy",
        _ => "error",
    }
}

impl Core {
    fn relay(&self) -> Option<RelaySync> {
        guard(&self.relay).clone()
    }

    /// The canonical path of the selected vault, to tell that the vault in the slot is
    /// still the one of this sync.
    fn selected_path(&self) -> CoreResult<PathBuf> {
        let entry = self.selected()?;
        fs::canonicalize(self.paths.vault_file(&entry.id)).map_err(|_| CoreError::io())
    }

    pub(super) fn status(&self) -> Status {
        let selected = guard(&self.list).selected_entry().cloned();
        let Some(relay) = self.relay() else {
            return Status {
                enabled: false,
                state: "off",
                message: if selected.is_some() {
                    "This vault is only on this iPhone.".to_owned()
                } else {
                    String::new()
                },
                version: 0,
                last_sync_at: None,
                pushed: false,
                merged: None,
            };
        };
        let stored = relay.state().ok().flatten();
        let memory = guard(&self.status).clone();
        let mut state = memory.state.unwrap_or("never");
        if relay.is_removed() {
            state = "removed";
        }
        let message = memory.message.clone().unwrap_or_else(|| match state {
            "never" => "Apassy syncs this vault when it is unlocked.".to_owned(),
            "removed" => {
                "A Mac removed this iPhone from the vault. The vault on this iPhone stays as it is."
                    .to_owned()
            }
            _ => String::new(),
        });
        Status {
            enabled: true,
            state,
            message,
            version: stored
                .as_ref()
                .map_or(0, |stored| stored.last_remote_version),
            last_sync_at: memory
                .last_sync_at
                .or(stored.and_then(|stored| stored.last_sync_at)),
            pushed: memory.pushed,
            merged: memory.merged,
        }
    }

    /// Keep what a sync did, for the status. A locked vault is an error of the call.
    fn record(&self, result: Result<SyncOutcome, SyncError>) -> CoreResult<StatusAnswer> {
        match result {
            Ok(outcome) => {
                let mut memory = guard(&self.status);
                memory.state = Some("ok");
                memory.last_sync_at = Some(now());
                memory.pushed = outcome.pushed;
                if let Some(merge) = outcome.merge.filter(|merge| merge.changed_local()) {
                    memory.merged = Some(Merged {
                        inserted: merge.inserted,
                        updated: merge.updated,
                        deleted: merge.deleted,
                        conflicts: merge.conflicts.len(),
                    });
                }
                memory.message = Some(if outcome.pushed {
                    "Saved to the relay.".to_owned()
                } else {
                    "Up to date.".to_owned()
                });
            }
            Err(SyncError::Vault(VaultErrorKind::Locked)) => return Err(CoreError::locked()),
            Err(error) => {
                let error = CoreError::from(error);
                let mut memory = guard(&self.status);
                memory.state = Some(state_of(&error));
                memory.message = Some(error.message);
            }
        }
        Ok(StatusAnswer {
            status: self.status(),
        })
    }

    pub(super) fn sync_call(&self, op: &str, request: &str) -> CoreResult<String> {
        let Some(relay) = self.relay() else {
            return match op {
                "sync" | "use_relay_copy" => Ok(ok(&StatusAnswer {
                    status: self.status(),
                })),
                "sync_wait" => Ok(ok(&Waited { changed: false })),
                "devices" => Ok(ok(&Devices {
                    devices: Vec::new(),
                })),
                _ => Err(CoreError::invalid("This vault does not sync.")),
            };
        };
        let path = self.selected_path()?;
        let accept = |vault: &Vault| vault.path() == path;
        match op {
            "sync" => Ok(ok(&self.record(relay.sync_shared(&self.vault, accept))?)),
            "use_relay_copy" => Ok(ok(
                &self.record(relay.use_relay_copy_shared(&self.vault, accept))?
            )),
            "take_new_passphrase" => {
                #[derive(Deserialize)]
                struct Take {
                    passphrase: Secret,
                }
                let Take { passphrase } = params(request)?;
                // Without an anchor the typed passphrase only opens the copy for the merge,
                // and the vault keeps its own (ADR 0022, "Use the relay copy").
                let rekeyed = !relay.keeps_passphrase();
                let inner =
                    relay.take_new_passphrase_shared(&self.vault, accept, passphrase.expose())?;
                if rekeyed {
                    // The vault opens with the new passphrase now.
                    let mut kept = guard(&self.kept);
                    if kept.is_some() {
                        *kept = Some(passphrase.into_inner());
                    }
                }
                let StatusAnswer { status } = self.record(inner)?;
                Ok(ok(&Taken { status, rekeyed }))
            }
            "sync_wait" => {
                #[derive(Deserialize)]
                struct Wait {
                    timeout: u64,
                }
                let Wait { timeout } = params(request)?;
                let timeout = Duration::from_secs(timeout.clamp(1, 25));
                match relay.wait_for_change(timeout) {
                    Ok(changed) => Ok(ok(&Waited { changed })),
                    Err(error) => Err(error.into()),
                }
            }
            "devices" => {
                // The key comes from the vault into memory without a network call; the
                // call itself runs without the vault mutex.
                self.with_vault(|vault| Ok(relay.relay_transport(vault).map(|_| ())?))?;
                let devices = relay.devices(KeySource::Memory)?;
                let this = self.selected()?.device_id;
                Ok(ok(&Devices {
                    devices: devices
                        .into_iter()
                        .map(|device| Device {
                            this: device.current || Some(device.id) == this,
                            id: device.id,
                            name: device.name,
                            last_seen_at: device.last_seen_at,
                        })
                        .collect(),
                }))
            }
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    /// Remove a vault from this iPhone (contract section 5.6).
    pub(super) fn remove_vault(&self, id: &str, force: bool) -> CoreResult<String> {
        let entry = guard(&self.list)
            .get(id)
            .cloned()
            .ok_or_else(|| CoreError::new("no_vault", "This vault is not on this iPhone."))?;
        let selected = guard(&self.list).selected.as_deref() == Some(id);
        let mut left_relay = entry.relay_url.is_none();
        if let (Some(device), true) = (entry.device_id, entry.relay_url.is_some()) {
            enum Leave {
                Left,
                /// `409`: the relay keeps the last device of a team, and the copy stays.
                Last,
                Failed(CoreError),
            }
            let relay = if selected { self.relay() } else { None };
            let leave = match relay {
                // The key comes into memory under the vault mutex; the call runs
                // without it.
                Some(relay) => {
                    match self.with_vault(|vault| Ok(relay.relay_transport(vault).map(|_| ())?)) {
                        Ok(()) => match relay.remove_device(KeySource::Memory, device) {
                            // Another device removed this one already.
                            Ok(()) | Err(SyncError::RemovedFromRelay) => Leave::Left,
                            Err(SyncError::Relay(RelayRefusal::Conflict)) => Leave::Last,
                            Err(error) => Leave::Failed(error.into()),
                        },
                        Err(error) => Leave::Failed(error),
                    }
                }
                None => Leave::Failed(CoreError::locked()),
            };
            match leave {
                Leave::Left => left_relay = true,
                Leave::Last => {}
                Leave::Failed(_) if force => {}
                Leave::Failed(error) => return Err(error),
            }
        }
        if selected {
            self.close(true);
        }
        let file = self.paths.vault_file(id);
        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(super::sidecar(&file));
        let sync_dir = self.paths.data_dir.join("sync");
        let _ = fs::remove_file(sync_dir.join(format!("{id}.json")));
        // The work files of this vault only (`.<state name>.relay.<purpose>`): another
        // vault may sync, or a join may hold its download.
        if let Ok(entries) = fs::read_dir(&sync_dir) {
            let prefix = format!(".{id}.relay.");
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&prefix))
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        {
            let mut list = guard(&self.list);
            list.remove(id);
            list.save(&self.paths.data_dir)?;
        }
        if selected {
            self.select_relay()?;
        }
        Ok(ok(&Removed { left_relay }))
    }
}
