//! The iPhone companion, Mac side (ADR 0020, contract `docs/contracts/companion-v1.md`).
//!
//! The companion lets the owner approve or deny a waiting run from a paired iPhone on
//! the local network. This module holds the parts that need no network:
//!
//! - [`wire`]: the request and response bodies, the error body, and the format checks.
//! - [`crypto`]: SHA-256, HMAC, ECDSA P-256 verification through `ring`, the four
//!   signing strings, the pairing code, and the certificate pin.
//! - [`digest`]: the digest of a waiting run that the phone signs.
//! - [`pairing`]: the pairing window, with an injectable clock.
//! - [`link`]: the pairing link for the QR code.
//!
//! The listener is [`server`]: HTTPS on the local network, in the Mac app process. It
//! has these parts:
//!
//! - [`server`]: the listener, its TLS configuration, and its threads.
//! - [`control`]: the pairing calls for the app (open a window, type the code, confirm).
//! - [`hosts`]: the hosts for the pairing link.
//! - `http`, `limits`, and `handler`: the framing, the limits, and the endpoints.
//!
//! The device store is in the vault (`Vault::add_companion_device` and its neighbors).
//! The owner check for a phone approval is `OwnerCheck::Companion` in
//! `broker::approvals`. Nothing here gives authority by itself: a phone approves through
//! `OwnerGate::authorize`, and a device is added only with an `OwnerProof`.

pub mod control;
pub mod crypto;
pub mod digest;
mod handler;
pub mod hosts;
mod http;
mod limits;
pub mod link;
pub mod pairing;
pub mod server;
pub mod wire;

pub use control::{ConfirmError, OpenPairingError, PairingController, PairingInvite};
pub use server::{CompanionHandle, CompanionOptions, Timeouts, start};
