//! The pairing controller: what the Mac app calls to pair an iPhone (contract
//! companion-v1, sections 5.1 and 5.4).
//!
//! The steps, each one a call:
//!
//! 1. [`PairingController::open`] opens a window and gives the link for the QR code and
//!    its expiry.
//! 2. [`PairingController::view`] shows the request that waits: the device name, never
//!    the code. The code is on the phone only.
//! 3. [`PairingController::submit_code`] takes the code that the owner typed. A right
//!    code gives the `OwnerAction::PairCompanion` for the owner check. A wrong code
//!    gives the tries that are left, and the third wrong code closes the window.
//! 4. The app runs `OwnerGate::authorize` for that action (Touch ID or the passphrase).
//! 5. [`PairingController::confirm`] takes the proof and stores the device.
//!
//! [`PairingController::cancel`] closes the window at any step. It needs no check.
//!
//! Lock order: none of these calls may run while the caller holds the vault mutex. `open`
//! and `confirm` take the pairing lock and then the vault mutex.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};

use zeroize::Zeroizing;

use super::hosts;
use super::link::{LinkError, LinkParts, pairing_link, pairing_link_for_development};
use super::pairing::{CodeError, CompleteError, OpenError, PairCandidate, Pairing, PairingView};
use crate::broker::SharedVault;
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::vault::{AddDeviceError, CompanionDevice};

/// A pairing window that the app shows.
pub struct PairingInvite {
    /// The link for the QR code. It has the pairing secret: the app draws it and never
    /// puts it on the pasteboard or in a log. It is erased on drop.
    pub link: Zeroizing<String>,
    /// The end of the window, Unix seconds.
    pub expires_at: u64,
}

impl fmt::Debug for PairingInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingInvite")
            .field("link", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why no window opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenPairingError {
    /// The listener is stopped.
    Stopped,
    /// The vault is locked, or is not the vault of the listener.
    VaultLocked,
    /// The window did not open: another window is open, or there are no random bytes.
    Window(OpenError),
    /// The Mac has no address that the phone can reach: no `.local` name and no IPv4
    /// address on a local network.
    NoHost,
    /// The link cannot be built. This is a bug of the caller.
    Link(LinkError),
}

impl OpenPairingError {
    /// Text for the owner.
    pub fn message(self) -> String {
        match self {
            Self::Stopped => {
                "The iPhone listener is not running. Nothing was paired.".to_owned()
            }
            Self::VaultLocked => "The vault is locked. Nothing was paired.".to_owned(),
            Self::Window(error) => error.message().to_owned(),
            Self::NoHost => "Apassy found no network address for this Mac. Connect the Mac to Wi-Fi or Ethernet. Nothing was paired.".to_owned(),
            Self::Link(_) => {
                "Apassy could not make the pairing link. Nothing was paired.".to_owned()
            }
        }
    }
}

/// Why [`PairingController::confirm`] did not pair.
#[derive(Debug)]
pub enum ConfirmError {
    /// The proof is not for a pairing.
    WrongProof,
    /// No request waits, or the waiting request is another device.
    NotWaiting,
    /// The vault is locked.
    VaultLocked,
    /// The vault refused the device.
    Device(AddDeviceError),
}

impl ConfirmError {
    /// Text for the owner.
    pub fn message(&self) -> String {
        match self {
            Self::WrongProof => {
                "The owner check was for another action. Nothing was paired.".to_owned()
            }
            Self::NotWaiting => {
                "No iPhone waits to pair, or the window ended. Make a new code. Nothing was paired."
                    .to_owned()
            }
            Self::VaultLocked => "The vault is locked. Nothing was paired.".to_owned(),
            Self::Device(error) => error.message(),
        }
    }
}

struct Inner {
    pairing: Arc<Pairing>,
    vault: SharedVault,
    mac_name: String,
    port: u16,
    pin: String,
    epoch: [u8; 32],
    stopped: Arc<AtomicBool>,
    /// Hosts for the link instead of the found ones (the development server).
    hosts: Option<Vec<String>>,
    /// The link may name a loopback host (the development server).
    development: bool,
}

/// The pairing calls of the running listener. It is cheap to clone.
#[derive(Clone)]
pub struct PairingController {
    inner: Arc<Inner>,
}

impl fmt::Debug for PairingController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingController")
            .field("port", &self.inner.port)
            .finish_non_exhaustive()
    }
}

/// What the controller needs from the listener.
pub(super) struct ControllerParts {
    pub pairing: Arc<Pairing>,
    pub vault: SharedVault,
    pub mac_name: String,
    pub port: u16,
    pub pin: String,
    pub epoch: [u8; 32],
    pub stopped: Arc<AtomicBool>,
    pub hosts: Option<Vec<String>>,
    pub development: bool,
}

impl PairingController {
    pub(super) fn new(parts: ControllerParts) -> Self {
        Self {
            inner: Arc::new(Inner {
                pairing: parts.pairing,
                vault: parts.vault,
                mac_name: parts.mac_name,
                port: parts.port,
                pin: parts.pin,
                epoch: parts.epoch,
                stopped: parts.stopped,
                hosts: parts.hosts,
                development: parts.development,
            }),
        }
    }

    fn vault_is_ours(&self) -> bool {
        self.inner
            .vault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|vault| !vault.is_locked() && vault.epoch() == self.inner.epoch)
    }

    /// Open a pairing window for 5 minutes and build its link. The hosts are looked up
    /// now (see [`hosts::link_hosts`]). No window opens when no host is found.
    pub fn open(&self) -> Result<PairingInvite, OpenPairingError> {
        let inner = &self.inner;
        if inner.stopped.load(Ordering::SeqCst) {
            return Err(OpenPairingError::Stopped);
        }
        if !self.vault_is_ours() {
            return Err(OpenPairingError::VaultLocked);
        }
        let found = inner.hosts.clone().unwrap_or_else(hosts::link_hosts);
        if found.is_empty() {
            return Err(OpenPairingError::NoHost);
        }
        let window = inner
            .pairing
            .open(&inner.mac_name)
            .map_err(OpenPairingError::Window)?;
        let parts = LinkParts {
            hosts: &found,
            port: inner.port,
            pin: &inner.pin,
            secret: &window.secret,
            mac_name: &inner.mac_name,
            expires_at: window.expires_at,
        };
        let built = if inner.development {
            pairing_link_for_development(&parts)
        } else {
            pairing_link(&parts)
        };
        match built {
            Ok(link) => Ok(PairingInvite {
                link: Zeroizing::new(link),
                expires_at: window.expires_at,
            }),
            Err(error) => {
                inner.pairing.cancel();
                Err(OpenPairingError::Link(error))
            }
        }
    }

    /// What the pairing window shows now: closed, open, or a device that waits.
    pub fn view(&self) -> PairingView {
        self.inner.pairing.view()
    }

    /// Check the code that the owner typed. A right code gives the owner action for the
    /// owner check. The window then lasts at least two more minutes.
    pub fn submit_code(&self, typed: &str) -> Result<OwnerAction, CodeError> {
        self.inner
            .pairing
            .check_code(typed)
            .map(|candidate| candidate.action())
    }

    /// Store the device that the owner confirmed. `proof` comes from
    /// `OwnerGate::authorize` for the action of [`Self::submit_code`]. The proof is used up.
    pub fn confirm(&self, proof: OwnerProof) -> Result<CompanionDevice, ConfirmError> {
        let OwnerAction::PairCompanion {
            device_id,
            device_name,
            request_key,
            approval_key,
        } = proof.action().clone()
        else {
            return Err(ConfirmError::WrongProof);
        };
        let (Ok(request_key), Ok(approval_key)) = (request_key.try_into(), approval_key.try_into())
        else {
            return Err(ConfirmError::WrongProof);
        };
        let candidate = PairCandidate {
            device_id,
            device_name,
            request_key,
            approval_key,
        };
        let vault = &self.inner.vault;
        let stored = self.inner.pairing.complete(&candidate, || {
            let mut guard = vault.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
                return Err(ConfirmError::VaultLocked);
            };
            vault
                .add_companion_device(
                    proof,
                    &candidate.device_id,
                    &candidate.device_name,
                    &candidate.request_key,
                    &candidate.approval_key,
                )
                .map_err(ConfirmError::Device)
        });
        match stored {
            Ok(device) => Ok(device),
            Err(CompleteError::NotWaiting) => Err(ConfirmError::NotWaiting),
            Err(CompleteError::Store(error)) => Err(error),
        }
    }

    /// Close the window. A device that waits gets the answer `denied`. It needs no
    /// owner check: it only takes authority away.
    pub fn cancel(&self) {
        self.inner.pairing.cancel();
    }
}
