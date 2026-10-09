//! The browser extension, app and host side (ADR 0021, `docs/contracts/browser-v1.md`).
//!
//! The extension in `extension/` asks the native messaging host
//! (`apassy-browser-host`) for the logins of the page in the active tab, and for one
//! fill. The host passes each request to the browser socket of the app. The app checks
//! which site may get a login ([`site`]) and asks for the owner check before each fill.
//!
//! Passkeys and one-time codes (contract section 9) add strict packets to the wire
//! ([`wire`]), the client data and relying party checks ([`webauthn`]), and the caller
//! checks of the signed Swift guard ([`caller`]).
//!
//! The module needs no feature, so the host builds without the vault. The public
//! suffix list and SHA-256 of `webauthn::client_data` need the vault feature.

pub mod caller;
pub mod install;
/// New passwords for the browser. It needs the random generator of the vault feature.
#[cfg(feature = "vault")]
pub mod password;
pub mod relay;
pub mod site;
pub mod webauthn;
pub mod wire;
