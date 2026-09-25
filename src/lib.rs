//! Apassy contracts and desktop foundation.
//! This crate does not yet provide a secure credential vault or live agent use.
#![forbid(unsafe_code)]

pub mod agent;
pub mod contracts;

/// Local agent broker (ADR 0004). It needs the vault.
#[cfg(feature = "vault")]
pub mod broker;

#[cfg(feature = "desktop")]
pub mod desktop;

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
