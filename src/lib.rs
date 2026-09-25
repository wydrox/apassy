//! Apassy contracts and desktop foundation.
//! This crate does not yet provide a secure credential vault or live agent use.
#![forbid(unsafe_code)]

pub mod contracts;

#[cfg(feature = "desktop")]
pub mod desktop;

/// Experimental trusted-process vault APIs.
///
/// With `desktop` and `vault` both enabled, the owner vault and item views call
/// these APIs. Rules, agents, and activity stay in-memory fixtures. These APIs
/// are not an authenticated owner channel or an agent endpoint.
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
