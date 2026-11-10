//! The owner command line channel (ADR 0017).
//!
//! The desktop app listens on `owner.sock` in the data directory. The `apassy` command
//! line sends one request per connection there. The agent profile denies the data
//! directory and re-allows only the broker socket, so a sandboxed agent cannot connect.
//!
//! The channel gives no authority that the app does not give:
//!
//! - Without a session, it answers only status, lock, show, and login.
//! - `login` asks for the owner check in the app (Touch ID or the passphrase). Then the
//!   app gives a session token. The session ends after 30 idle minutes, after 12 hours,
//!   at a lock, and when the app quits.
//! - An action that needs an owner check in the app (stored-secret reveal is never offered) asks
//!   for the same check here, in the app window, for each action.

pub mod client;
pub mod wire;

/// Interactive terminal prompts shared with headless owner commands.
#[path = "../cli/terminal.rs"]
pub mod terminal;

/// The in-memory demo model and the owner errors of the desktop session. The file stays
/// with the desktop; the headless owner service (`apassy owner serve`) shares it.
#[cfg(any(feature = "vault", feature = "desktop"))]
#[path = "../desktop/model.rs"]
pub mod model;
/// The owner vault session of the desktop window, without a window: the headless owner
/// service (`apassy owner serve`) hosts the same session.
#[cfg(feature = "vault")]
#[path = "../desktop/owner_store.rs"]
pub mod owner_store;
/// `apassy owner serve`: the owner process without a window (ADR 0045).
#[cfg(feature = "vault")]
pub mod serve;
/// The line sockets of the owner process: `owner.sock` and `browser.sock`.
#[cfg(feature = "vault")]
pub(crate) mod socket;
