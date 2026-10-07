//! Joining a vault from a Mac (contract section 5.2, relay-sync-v1 section 7.2). The
//! iPhone is a new device of the vault's relay team, as a second Mac is: it sends the
//! device link with its key, both show the same two safety words, the owner confirms
//! on the Mac with Touch ID, the iPhone downloads the copy, and the owner types the
//! passphrase.

use std::fs;

use serde::{Deserialize, Serialize};

use apassy::sync::{
    DEFAULT_RELAY_URL, JoinedDevice, PendingJoin, RelayConfig, RelayDownload, RelaySync,
    link_code_team,
};

use super::config::VaultEntry;
use super::errors::{CoreError, CoreResult};
use super::wire::{Empty, Secret, ok, params};
use super::{Core, guard, now};

/// A join in progress. Its device key is in memory only until a vault holds it.
pub struct Joining {
    pending: Option<PendingJoin>,
    joined: Option<JoinedDevice>,
    download: Option<RelayDownload>,
    relay_url: String,
    team_id: String,
    team: String,
    words: Vec<String>,
    expires_at: u64,
}

/// A join as the app shows it.
#[derive(Debug, Serialize)]
pub struct JoinOut {
    pub state: &'static str,
    pub team: String,
    pub words: Vec<String>,
    pub expires_at: u64,
}

impl Joining {
    pub fn view(&self) -> JoinOut {
        JoinOut {
            state: if self.download.is_some() {
                "ready"
            } else {
                "waiting"
            },
            team: self.team.clone(),
            words: self.words.clone(),
            expires_at: self.expires_at,
        }
    }

    /// Give the join up: cancel the link, or remove the device after a confirmation.
    /// Best effort; the relay ends a link after 10 minutes.
    pub fn abandon(mut self) {
        self.download = None;
        if let Some(pending) = self.pending.take() {
            let _ = pending.cancel();
        }
        if let Some(joined) = self.joined.take() {
            joined.cancel();
        }
    }
}

#[derive(Deserialize)]
struct Start {
    link: Secret,
    #[serde(default)]
    device_name: Option<String>,
}

#[derive(Deserialize)]
struct Finish {
    passphrase: Secret,
}

/// An error of a join, as the iPhone that joins reads it: before the Mac confirms,
/// a refusal of the relay is about the link, not about a device that was removed.
fn join_error(error: CoreError) -> CoreError {
    match error.code {
        "removed" | "not_found" => CoreError::new(
            "link_invalid",
            "This link does not work: it was used, it expired, or it is not valid. Make a new link on the Mac.",
        ),
        _ => error,
    }
}

impl Core {
    pub(super) fn join_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "join_start" => {
                let Start { link, device_name } = params(request)?;
                let name = device_name
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| self.device_name.clone());
                Ok(ok(&self.join_start(link.expose(), &name)?))
            }
            "join_poll" => Ok(ok(&self.join_poll()?)),
            "join_cancel" => {
                if let Some(joining) = guard(&self.join).take() {
                    joining.abandon();
                }
                Ok(ok(&Empty {}))
            }
            "join_finish" => {
                let Finish { passphrase } = params(request)?;
                let entry = self.join_finish(passphrase.expose())?;
                Ok(ok(&super::sync::VaultAnswer { vault: &entry }))
            }
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    fn join_start(&self, link: &str, device_name: &str) -> CoreResult<JoinOut> {
        if let Some(joining) = guard(&self.join).take() {
            joining.abandon();
        }
        let (url, code) = PendingJoin::parse_link(link, DEFAULT_RELAY_URL)?;
        let team_id = link_code_team(&code).unwrap_or_default().to_owned();
        let pending = PendingJoin::request(link, DEFAULT_RELAY_URL, device_name)
            .map_err(|error| join_error(error.into()))?;
        let joining = Joining {
            relay_url: url.as_str().to_owned(),
            team_id,
            team: pending.team.clone(),
            words: pending
                .safety
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            expires_at: pending.expires_at,
            pending: Some(pending),
            joined: None,
            download: None,
        };
        let view = joining.view();
        *guard(&self.join) = Some(joining);
        Ok(view)
    }

    fn join_poll(&self) -> CoreResult<JoinOut> {
        // The relay calls run with the join taken out, so `join_cancel` and `info` do
        // not wait for them; a cancel in between finds no join and the device is
        // given up below.
        let mut joining = guard(&self.join)
            .take()
            .ok_or_else(|| CoreError::invalid("No join waits. Scan the code of the Mac again."))?;
        let result = (|| -> CoreResult<()> {
            if joining.download.is_some() {
                return Ok(());
            }
            if joining.joined.is_none() {
                let pending = joining
                    .pending
                    .as_ref()
                    .ok_or_else(|| CoreError::internal("The join has no link."))?;
                match pending.poll().map_err(|error| join_error(error.into()))? {
                    None => return Ok(()),
                    Some(joined) => {
                        joining.pending = None;
                        joining.joined = Some(joined);
                    }
                }
            }
            if let Some(joined) = &joining.joined {
                let work = self.paths.data_dir.join("sync");
                joining.download = Some(joined.download(&work)?);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                let view = joining.view();
                *guard(&self.join) = Some(joining);
                Ok(view)
            }
            // The Mac refused, or the link expired: the join ends.
            Err(error) if error.code == "join_refused" || error.code == "link_invalid" => {
                joining.abandon();
                Err(error)
            }
            Err(error) => {
                *guard(&self.join) = Some(joining);
                Err(error)
            }
        }
    }

    fn join_finish(&self, passphrase: &str) -> CoreResult<VaultEntry> {
        let mut slot = guard(&self.join);
        let joining = slot
            .as_mut()
            .ok_or_else(|| CoreError::invalid("No join waits."))?;
        let (Some(joined), Some(download)) = (&joining.joined, &joining.download) else {
            return Err(CoreError::invalid(
                "The Mac did not confirm this iPhone yet.",
            ));
        };
        // The vault ID is known after the adoption: adopt into a temporary file, then
        // name it after the vault.
        let token = format!("{}-{}", now(), joining.team_id);
        let temp_file = self.paths.new_vault_file(&token);
        let temp_state = format!("new-{token}");
        let relay = RelaySync::new(RelayConfig::in_data_dir(
            &self.paths.data_dir,
            &temp_file,
            &joining.relay_url,
            &temp_state,
        ));
        let (vault, report) = relay.adopt(joined, download, passphrase)?;
        relay.forget();
        let id = report.identity.vault_id.clone();
        drop(vault);
        if !super::config::valid_id(&id) {
            let _ = fs::remove_file(&temp_file);
            return Err(CoreError::new(
                "damaged",
                "The copy has a vault ID that Apassy does not take.",
            ));
        }
        if guard(&self.list).get(&id).is_some() {
            let _ = fs::remove_file(&temp_file);
            let _ = fs::remove_file(super::sidecar(&temp_file));
            let _ = fs::remove_file(
                self.paths
                    .data_dir
                    .join("sync")
                    .join(format!("{temp_state}.json")),
            );
            return Err(CoreError::invalid("This vault is on this iPhone already."));
        }
        self.close(true);
        let file = self.paths.vault_file(&id);
        let sync_dir = self.paths.data_dir.join("sync");
        fs::rename(&temp_file, &file).map_err(|_| CoreError::io())?;
        let _ = fs::remove_file(super::sidecar(&temp_file));
        fs::rename(
            sync_dir.join(format!("{temp_state}.json")),
            sync_dir.join(format!("{id}.json")),
        )
        .map_err(|_| CoreError::io())?;
        let entry = VaultEntry {
            id,
            name: joining.team.clone(),
            relay_url: Some(report.link.url.clone()),
            team_id: Some(report.link.team_id.clone()),
            device_id: Some(report.link.device_id),
            added_at: now() as i64,
        };
        // The join is done: its key is in the vault now.
        *slot = None;
        drop(slot);
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
