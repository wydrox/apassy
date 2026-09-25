//! Local broker for the thin agent path (ADR 0004).
//!
//! The broker runs inside the owner process. It shares the open vault with the
//! desktop app. It reads a secret only after every check passes. It returns
//! only the permitted output fields to the agent. Manual grants are temporary.
//! They are not the rule engine from P3.

pub mod decide;
pub mod http;
pub mod profile;
pub mod server;

use std::sync::{Arc, Mutex};

use crate::vault::Vault;

/// The one open vault in this process. The desktop app and the broker share it.
pub type SharedVault = Arc<Mutex<Option<Vault>>>;

pub use server::{BrokerHandle, start, start_with_tls};
