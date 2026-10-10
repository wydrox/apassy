//! Joining a vault from a Mac (contract section 5.2, relay-sync-v1 section 7.2). The
//! iPhone is a new device of the vault's relay team, as a second Mac is: it sends the
//! device link with its key, both show the same two safety words, the owner confirms
//! on the Mac with Touch ID, the iPhone downloads the copy, and the owner types the
//! passphrase.

use std::fs;
use std::sync::atomic::Ordering;

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
                self.end_join();
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

    /// Give up the join that waits, if any. The relay calls run without the mutex.
    fn end_join(&self) {
        let joining = {
            let mut slot = guard(&self.join);
            self.joins.fetch_add(1, Ordering::SeqCst);
            slot.take()
        };
        if let Some(joining) = joining {
            joining.abandon();
        }
    }

    /// Put a join back after a call that ran without the mutex, unless a start or a
    /// cancel came in between: then the join is given up.
    fn put_back(&self, joining: Joining, joins: u64) {
        let rest = {
            let mut slot = guard(&self.join);
            if self.joins.load(Ordering::SeqCst) == joins && slot.is_none() {
                *slot = Some(joining);
                None
            } else {
                Some(joining)
            }
        };
        if let Some(joining) = rest {
            joining.abandon();
        }
    }

    fn join_start(&self, link: &str, device_name: &str) -> CoreResult<JoinOut> {
        self.end_join();
        let joins = self.joins.load(Ordering::SeqCst);
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
        self.put_back(joining, joins);
        Ok(view)
    }

    fn join_poll(&self) -> CoreResult<JoinOut> {
        // The relay calls run with the join taken out, so `join_cancel` and `info` do
        // not wait for them. A cancel or a new start in between counts in `joins`, and
        // the join of this poll is given up instead of put back.
        let (joining, joins) = {
            let mut slot = guard(&self.join);
            (slot.take(), self.joins.load(Ordering::SeqCst))
        };
        let mut joining = joining
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
                self.put_back(joining, joins);
                Ok(view)
            }
            // The Mac refused, or the link expired: the join ends.
            Err(error) if error.code == "join_refused" || error.code == "link_invalid" => {
                joining.abandon();
                Err(error)
            }
            Err(error) => {
                self.put_back(joining, joins);
                Err(error)
            }
        }
    }

    fn join_finish(&self, passphrase: &str) -> CoreResult<VaultEntry> {
        // The two key derivations run with the join taken out, as a poll does.
        let (joining, joins) = {
            let mut slot = guard(&self.join);
            (slot.take(), self.joins.load(Ordering::SeqCst))
        };
        let joining = joining.ok_or_else(|| CoreError::invalid("No join waits."))?;
        match self.adopt_joined(&joining, passphrase) {
            Ok(entry) => {
                // The join is done: its key is in the vault now.
                self.joins.fetch_add(1, Ordering::SeqCst);
                Ok(entry)
            }
            Err(error) => {
                // A wrong passphrase keeps the download: the owner tries again.
                self.put_back(joining, joins);
                Err(error)
            }
        }
    }

    fn adopt_joined(&self, joining: &Joining, passphrase: &str) -> CoreResult<VaultEntry> {
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
        let sync_dir = self.paths.data_dir.join("sync");
        let temp_state_file = sync_dir.join(format!("{temp_state}.json"));
        let relay = RelaySync::new(RelayConfig::in_data_dir(
            &self.paths.data_dir,
            &temp_file,
            &joining.relay_url,
            &temp_state,
        ));
        let (vault, report) = relay.adopt(joined, download, passphrase)?;
        let id = report.identity.vault_id.clone();
        drop(vault);
        let remove_temp = || {
            let _ = fs::remove_file(&temp_file);
            let _ = fs::remove_file(super::sidecar(&temp_file));
            let _ = fs::remove_file(&temp_state_file);
        };
        if !super::config::valid_id(&id) {
            remove_temp();
            return Err(CoreError::new(
                "damaged",
                "The copy has a vault ID that Apassy does not take.",
            ));
        }
        if guard(&self.list).get(&id).is_some() {
            remove_temp();
            return Err(CoreError::invalid("This vault is on this iPhone already."));
        }
        self.close(true);
        let file = self.paths.vault_file(&id);
        let renamed = fs::rename(&temp_file, &file)
            .and_then(|()| fs::rename(&temp_state_file, sync_dir.join(format!("{id}.json"))));
        if renamed.is_err() {
            let _ = fs::remove_file(&file);
            remove_temp();
            return Err(CoreError::io());
        }
        let _ = fs::remove_file(super::sidecar(&temp_file));
        // The session of the adoption ends only now: until the files have their names, a
        // cancel can still remove the device from the relay.
        relay.forget();
        let entry = VaultEntry {
            id,
            name: joining.team.clone(),
            sync_source: None,
            relay_url: Some(report.link.url.clone()),
            team_id: Some(report.link.team_id.clone()),
            device_id: Some(report.link.device_id),
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
