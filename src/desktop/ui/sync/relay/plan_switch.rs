//! Sync through Apassy on the vault's own membership, for a paid plan (build plan §2b,
//! flow spec Flow B): the Apassy Connect team of the vault gets the purpose `sync` with
//! the key that it has ([`RelaySync::enable_on_membership_shared`]). It never makes a
//! second team.
//!
//! The call runs on its own thread, as "Turn on" does, and its answer goes through the
//! same steps ([`DesktopApp::relay_turned_on`]): the staged state takes the name of the
//! vault, and a folder sync of the vault ends. A relay that did not accept the plan yet
//! (`403 plan_required`, shown as `TeamLimit`) gets its own plain words, and nothing
//! changed: the membership keeps only `questions`, and no state was written.

use super::{DesktopApp, RelayRefusal, RelaySync, SyncError, TurnedOn, same_file};
use crate::desktop::owner_check::{Task, TaskPoll};
use crate::relay::membership::questions_membership;

/// The switch of a vault to Apassy while the relay answers.
pub(crate) struct MembershipSwitch {
    /// The vault (list ID).
    id: String,
    /// The relay sync that turns on, so that a lock ends its relay calls.
    staged: RelaySync,
    task: Task<TurnedOn>,
}

impl MembershipSwitch {
    /// The vault that switches.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

/// The relay did not accept the plan of the team yet.
pub(crate) fn plan_not_accepted(name: &str) -> String {
    format!(
        "Apassy did not accept your plan yet, so “{name}” did not move. Nothing changed: it syncs as before. Try again in a minute."
    )
}

impl DesktopApp {
    /// Whether the open, unlocked vault `id` has a membership of its own on a relay
    /// that the switch can use: its Apassy Connect team.
    pub(crate) fn relay_membership_team(&self, id: &str) -> Option<String> {
        if !self.relay_open(id) {
            return None;
        }
        self.owner_ui
            .session
            .with_vault(|vault| questions_membership(vault).ok().flatten())
            .flatten()
            .map(|membership| membership.team_id)
    }

    /// Turn relay sync on for the open, unlocked vault `id` in the team of its own
    /// membership, on its own thread. An error before the relay call comes back at once.
    pub(crate) fn relay_enable_on_membership(
        &mut self,
        id: &str,
    ) -> Result<MembershipSwitch, String> {
        let entry = self.relay_target(id)?;
        if self.is_relay(id) {
            return Err(format!("“{}” syncs through Apassy already.", entry.name));
        }
        if self.relay_changing(id) {
            return Err(
                "Relay sync of this vault is turning on or off. Try again when it is done."
                    .to_owned(),
            );
        }
        let membership = self
            .owner_ui
            .session
            .with_vault(|vault| questions_membership(vault).ok().flatten())
            .flatten()
            .ok_or_else(|| {
                "This vault has no device list on Apassy yet. Add a device in Settings > Devices first."
                    .to_owned()
            })?;
        let relay = self.relay_staged(&entry, &membership.relay_url);
        let before = entry.sync.clone();
        let slot = self.relay_slot();
        let name = entry.name;
        let team = membership.team_id;
        let staged = relay.clone();
        let job = relay.clone();
        let task = Task::spawn(self.sync.relay.repaint.clone(), move || {
            let result = relay.enable_on_membership_shared(&slot, same_file(&relay), &team, &name);
            TurnedOn {
                relay: job,
                name,
                joined: false,
                before,
                result,
                device: None,
                typed: false,
                rekeyed: false,
            }
        });
        Ok(MembershipSwitch {
            id: id.to_owned(),
            staged,
            task,
        })
    }

    /// Each frame while a switch runs: `None` while the relay answers, else whether the
    /// vault syncs through Apassy now. The result message says what happened. A lock or
    /// another open vault ends the relay calls of the switch at once.
    pub(crate) fn relay_membership_switch_poll(
        &mut self,
        switch: &MembershipSwitch,
    ) -> Option<bool> {
        if !self.relay_open(&switch.id) {
            switch.staged.forget();
        }
        let turned_on = match switch.task.poll() {
            TaskPoll::Waiting => return None,
            TaskPoll::Done(turned_on) => turned_on,
            TaskPoll::Lost => {
                switch.staged.forget();
                self.set_err("The relay call ended without an answer. Nothing changed. Try again.");
                return Some(false);
            }
        };
        if matches!(
            turned_on.result,
            Err(SyncError::Relay(RelayRefusal::TeamLimit))
        ) {
            switch.staged.forget();
            self.set_err(plan_not_accepted(&turned_on.name));
            return Some(false);
        }
        let name = turned_on.name.clone();
        self.relay_turned_on(&switch.id, turned_on);
        let on = self.is_relay(&switch.id);
        if on {
            self.set_ok(format!(
                "“{name}” syncs through Apassy. Changes reach your devices in seconds."
            ));
        }
        Some(on)
    }
}
