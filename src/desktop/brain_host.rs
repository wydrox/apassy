//! The host and the trainer of the bouncer brain in the desktop app (ADR 0035, plan
//! 0035 unit C2).
//!
//! - [`DesktopApp::sync_bouncer_host`] gives the model server the host of the open
//!   vault: after each new vault session (an unlock, a passphrase change, another vault)
//!   and after a change. At a lock it gives `None`, so the bearer of an own server leaves
//!   memory with the vault. The window calls it from `logic`, so it also runs while the
//!   window is minimized.
//! - [`DesktopApp::change_bouncer_host`] completes `OwnerRequest::ChangeBouncerHosting`
//!   and `OwnerRequest::ChangeBouncerTraining` with the proof of a fresh owner check
//!   (`crate::broker::brain_host::change`). The picker and the consent screen are unit J1
//!   (`brain_hosting_ui.rs`); they only build the request.
//!
//! The choice never comes from `bouncer.json`: that file keeps the start mode, the idle
//! time and a loopback address.

use std::sync::{Arc, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use super::DesktopApp;
use crate::broker::approvals::OwnerProof;
use crate::broker::brain_host;
use crate::broker::http::TlsClient;
use crate::vault::{BouncerHostChange, BouncerHostKind, BouncerHostRole};

/// What the window applied to the model server.
#[derive(Debug, Default)]
pub(crate) struct BouncerHostFlows {
    /// The vault session whose hosting row the model server has. `None`: locked.
    session: Option<[u8; 32]>,
    /// The next call reads the row again, also in the same session (after a change).
    dirty: bool,
    /// Why the chosen host is not in use, for Settings. The bouncer brain then runs on
    /// this Mac.
    pub(crate) problem: Option<String>,
    /// The "Use My Server" sheet as the owner fills it, with its token (unit J1). It
    /// ends with the sheet and with the vault session.
    pub(crate) draft: Option<super::brain_hosting_ui::HostingDraft>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The status line after a change.
fn changed_text(role: BouncerHostRole, change: &BouncerHostChange) -> String {
    let url = change.normalized_url();
    match (role, change.kind) {
        (BouncerHostRole::Hosting, BouncerHostKind::ThisMac) => concat!(
            "The bouncer brain runs on this ",
            crate::computer!(),
            " again."
        )
        .to_owned(),
        (BouncerHostRole::Hosting, BouncerHostKind::OwnServer) => format!(
            concat!(
                "The bouncer brain now runs on your server at {url}. The bouncer gate still decides on this ",
                crate::computer!(),
                "."
            ),
            url = url
        ),
        (BouncerHostRole::Hosting, BouncerHostKind::Connect) => format!(
            concat!(
                "The bouncer brain now runs at Apassy Connect ({url}). The bouncer gate still decides on this ",
                crate::computer!(),
                "."
            ),
            url = url
        ),
        (BouncerHostRole::Training, BouncerHostKind::ThisMac) => concat!(
            "The bouncer brain trains on this ",
            crate::computer!(),
            " again."
        )
        .to_owned(),
        (BouncerHostRole::Training, BouncerHostKind::OwnServer) => {
            format!("The bouncer brain now trains on your server at {url}.")
        }
        (BouncerHostRole::Training, BouncerHostKind::Connect) => {
            format!("The bouncer brain now trains at Apassy Connect ({url}).")
        }
    }
}

impl DesktopApp {
    /// Give the model server the hosting row of the open vault when the vault session
    /// changed or a change was made. Cheap when nothing changed: one look at the epoch.
    pub(crate) fn sync_bouncer_host(&mut self) {
        // A closed sheet or another vault session erases the draft and its token.
        super::brain_hosting_ui::forget_closed_draft(self);
        let Some(server) = self.model_server.clone() else {
            return;
        };
        let shared = self.owner_ui.session.shared_vault();
        let guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let open = guard.as_ref().filter(|vault| !vault.is_locked());
        let session = open.map(crate::vault::Vault::epoch);
        if session == self.bouncer_host.session && !self.bouncer_host.dirty {
            return;
        }
        let result = match open {
            None => Ok(None),
            Some(vault) => TlsClient::platform()
                .map_err(|error| {
                    format!(
                        concat!(
                            "The TLS settings of this ",
                            crate::computer!(),
                            " did not load ({error})."
                        ),
                        error = error
                    )
                })
                .and_then(|tls| brain_host::hosting_client(vault, &Arc::new(tls))),
        };
        drop(guard);
        self.bouncer_host.session = session;
        self.bouncer_host.dirty = false;
        match result {
            Ok(client) => {
                self.bouncer_host.problem = None;
                server.set_remote(client);
            }
            Err(message) => {
                // Never a silent remote fallback: the brain runs on this Mac, and
                // Settings says why the chosen host is not in use.
                tracing::info!(
                    problem = "bouncer_host",
                    "the chosen bouncer brain host is not in use"
                );
                server.set_remote(None);
                self.bouncer_host.problem = Some(message);
            }
        }
    }

    /// Complete a change of the host or the trainer with the proof of the fresh owner
    /// check. A change of the host applies to the model server at once.
    pub(crate) fn change_bouncer_host(
        &mut self,
        role: BouncerHostRole,
        change: BouncerHostChange,
        proof: OwnerProof,
    ) {
        // The head sets go to a new server before the choice is stored
        // (`brain_host::switch`, plan 0035 unit G).
        let shared = self.owner_ui.session.shared_vault();
        let result = TlsClient::platform()
            .map_err(|error| {
                format!(
                    concat!(
                        "Nothing changed. The TLS settings of this ",
                        crate::computer!(),
                        " did not load ({error})."
                    ),
                    error = error
                )
            })
            .and_then(|tls| {
                brain_host::switch(&shared, role, &change, proof, &Arc::new(tls), now())
            });
        match result {
            Ok(()) => {
                if role == BouncerHostRole::Hosting {
                    // The token is in the vault now; the sheet closes after the check.
                    self.bouncer_host.draft = None;
                    self.bouncer_host.dirty = true;
                    self.sync_bouncer_host();
                }
                match self.bouncer_host.problem.clone() {
                    Some(problem) if role == BouncerHostRole::Hosting => self.set_err(format!(
                        concat!(
                            "The choice is saved, but the bouncer brain runs on this ",
                            crate::computer!(),
                            ": {problem}"
                        ),
                        problem = problem
                    )),
                    _ => self.set_ok(changed_text(role, &change)),
                }
            }
            Err(message) => self.set_err(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_line_names_the_choice_and_never_the_bearer() {
        let change = BouncerHostChange {
            kind: BouncerHostKind::OwnServer,
            url: "https://brain.synthetic.ts.net/".to_owned(),
            bearer: Some(crate::vault::SecretValue::new(
                "SYNTH-desktop-bearer-0123456789".to_owned(),
            )),
            consent_version: crate::vault::HOSTING_CONSENT_VERSION,
        };
        let text = changed_text(BouncerHostRole::Hosting, &change);
        assert!(text.contains("https://brain.synthetic.ts.net."), "{text}");
        assert!(
            text.contains(concat!("still decides on this ", crate::computer!())),
            "{text}"
        );
        assert!(!text.contains("SYNTH-desktop-bearer"));
        assert_eq!(
            changed_text(BouncerHostRole::Training, &BouncerHostChange::this_mac()),
            concat!(
                "The bouncer brain trains on this ",
                crate::computer!(),
                " again."
            )
        );
    }
}
