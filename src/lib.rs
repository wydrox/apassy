//! Apassy contracts and desktop foundation.
//! This crate does not yet provide a secure credential vault or live agent use.
#![forbid(unsafe_code)]

/// Owner-check wording by platform (`owner_check!`, `touch_id!`).
mod wording;

pub mod agent;
/// The browser extension (ADR 0021): wire, site match, and the native messaging host.
pub mod browser;
/// The `apassy` owner command line (ADR 0017).
#[cfg(feature = "desktop")]
pub mod cli;
/// The Apassy Connect account of this Mac (ADR 0037 stage 7, contract
/// connect-account-v1): the account device key in the Keychain, sign-in, device links,
/// recovery, and the entitlement token. It needs the vault.
#[cfg(feature = "vault")]
pub mod connect;
pub mod contracts;
/// CSV framing shared by the owner CLI and the vault import preview.
pub mod csv;
/// The bouncer decision log file for debugging (`apassy decisions log`).
pub mod decision_log;
/// Process hardening: no core dumps, not dumpable on Linux (ADR 0011 stage 6).
pub mod harden;

/// Local agent broker (ADR 0004). It needs the vault.
#[cfg(feature = "vault")]
pub mod broker;

/// The iPhone companion, Mac side (ADR 0020). It needs the vault.
#[cfg(feature = "vault")]
pub mod companion;
/// The TLS front of the node and the tailnet addresses (ADR 0037 D4). The Wi-Fi
/// companion shares its TLS configuration, limits, and pin. It needs the vault
/// (rustls, ring, rcgen).
#[cfg(feature = "vault")]
pub mod net;
/// Sync of a vault through a folder (ADR 0014). It needs the vault.
#[cfg(feature = "vault")]
pub mod sync;

/// Questions of the broker through the relay (ADR 0025 §3e, contract relay-questions-v1).
/// It needs the vault.
#[cfg(feature = "vault")]
pub mod questions;

/// Relay memberships of this Mac for sync and questions (stage 5). It needs the vault.
#[cfg(feature = "vault")]
pub mod relay {
    pub mod connect;
    pub mod membership;
    pub mod pairing;
}

#[cfg(feature = "desktop")]
pub mod desktop;

/// Process isolation outside Seatbelt: the bubblewrap sandbox of Linux (ADR 0011
/// stage 2, ADR 0037 stage 8). It needs no feature, so `apassy-sandbox` uses it.
pub mod isolation;

/// Import from 1Password (1PUX and CSV exports). It needs the vault types.
#[cfg(feature = "vault")]
pub mod import;

/// Short-lived credentials, "way C" (ADR 0037 stage 6, contract private-sharing-v1):
/// the lease providers, AWS SigV4, and the no-secret scan of the tests. It needs the
/// vault (`ring`, the broker's HTTP client, the field types).
#[cfg(feature = "vault")]
pub mod lease;

/// Time-based one-time passwords shared by the desktop and iPhone vaults.
#[cfg(feature = "vault")]
pub mod otp;

pub mod native;
/// The Mac's own node for cloud agents (ADR 0037): the seam to the embedded relay. It
/// needs the vault.
#[cfg(feature = "vault")]
pub mod node;
/// The owner command line channel (ADR 0017): wire and client.
pub mod owner;
pub mod paths;
/// The hidden characters of names that the owner reads (control, format, and tag
/// characters), for the app, the relay, and the iPhone core. It needs no feature.
pub mod text;
/// The list of vaults on this computer (ADR 0013). It needs no feature, so the
/// sandbox launcher reads it.
pub mod vaults;

/// Experimental trusted-process vault APIs.
///
/// With `desktop` and `vault` both enabled, the owner vault and item views call
/// these APIs. The broker also uses them for agents and grants. Rules stay
/// in-memory fixtures. These APIs are not an authenticated owner channel. The
/// broker is the only agent endpoint, and it never returns a secret value.
///
/// Secret-bearing public types do not support automatic serialization.
///
/// ```compile_fail
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<apassy::vault::SecretValue>();
/// ```
///
/// ```compile_fail
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<apassy::vault::Field>();
/// ```
///
/// ```compile_fail
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<apassy::vault::ItemDraft>();
/// ```
///
/// A vault cannot be cloned or serialized. Its connection is private.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<apassy::vault::Vault>();
/// ```
///
/// ```compile_fail
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<apassy::vault::Vault>();
/// ```
///
/// ```compile_fail
/// fn connection(vault: &apassy::vault::Vault) {
///     let _ = &vault.conn;
/// }
/// ```
#[cfg(feature = "vault")]
pub mod vault;
