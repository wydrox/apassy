//! Protected device setting. ui.json and the synced vault never carry this policy.
use super::{
    DesktopApp,
    owner_check::{Task, TaskPoll},
};
use crate::broker::approvals::{OwnerAction, OwnerFrequency, OwnerProof};
use eframe::egui;

impl DesktopApp {
    pub(crate) fn save_owner_frequency(
        &mut self,
        old: OwnerFrequency,
        new: OwnerFrequency,
        proof: OwnerProof,
    ) {
        let window = self.owner_ui.session.owner_window.clone();
        // The setting action can never spend an existing window.
        let valid = self.owner_ui.session.epoch().is_some_and(|epoch| {
            proof
                .check(&OwnerAction::ChangeOwnerFrequency { old, new }, &epoch)
                .is_ok()
        });
        if !valid || window.policy() != old {
            window.invalidate();
            self.set_err("The owner check changed. Try changing the setting again.");
            return;
        }
        window.configure(OwnerFrequency::EveryTime);
        let Some(helper) = self.owner.helper.clone() else {
            self.set_err(
                "This build cannot save a protected owner-check setting. Every time is active.",
            );
            return;
        };
        self.owner.frequency_write = Some(Task::spawn(None, move || {
            helper
                .owner_policy_write(new)
                .map(|()| new)
                .map_err(|e| e.to_string())
        }));
    }
    pub(crate) fn poll_owner_frequency(&mut self, ctx: &egui::Context) {
        let writing = self.owner.frequency_write.is_some();
        let task = if writing {
            &self.owner.frequency_write
        } else {
            &self.owner.frequency_read
        };
        let Some(task) = task else { return };
        let result = match task.poll() {
            TaskPoll::Waiting => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
                return;
            }
            TaskPoll::Done(r) => r,
            TaskPoll::Lost => Err("The protected setting service stopped.".into()),
        };
        if writing {
            self.owner.frequency_write = None;
        } else {
            self.owner.frequency_read = None;
        }
        match result {
            Ok(policy) => {
                self.owner_ui.session.owner_window.configure(policy);
                self.owner.frequency_note = None;
                if writing {
                    self.set_ok("Saved for this Mac. The next action needs a fresh check.");
                }
            }
            Err(_) => {
                self.owner_ui
                    .session
                    .owner_window
                    .configure(OwnerFrequency::EveryTime);
                let note = "The setting could not be verified or saved. Every time is active. Try again in Apassy.app.".to_owned();
                self.owner.frequency_note = Some(note.clone());
                if writing {
                    self.set_err(note);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::approvals::CheckMethod;
    use std::time::{Duration, Instant};
    #[test]
    fn security_frequency_store_failure_shows_strict_state() {
        let mut app = DesktopApp::new();
        let window = app.owner_ui.session.owner_window.clone();
        window.configure(OwnerFrequency::UntilLock);
        window.observe(true);
        window.seed([1; 32], CheckMethod::TouchId, window.generation());
        app.owner.frequency_read = Some(Task::spawn(None, || {
            Err("synthetic unreadable Keychain policy".into())
        }));
        let ctx = egui::Context::default();
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.owner.frequency_read.is_some() && Instant::now() < deadline {
            app.poll_owner_frequency(&ctx);
            std::thread::yield_now();
        }
        assert!(app.owner.frequency_read.is_none());
        assert_eq!(window.policy(), OwnerFrequency::EveryTime);
        assert!(window.ticket([1; 32]).is_none());
        assert!(
            app.owner
                .frequency_note
                .as_ref()
                .unwrap()
                .contains("Every time is active")
        );
    }
}
