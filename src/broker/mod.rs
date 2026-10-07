//! Local broker for the thin agent path (ADR 0004).
//!
//! The broker runs inside the owner process. It shares the open vault with the
//! desktop app. It reads a secret only after every check passes. It returns
//! only the permitted output fields to the agent. Manual grants are temporary.
//! They are not the rule engine from P3.

pub mod approvals;
pub mod bouncer;
pub mod calibration;
pub mod decide;
pub mod exec;
pub mod finetune;
pub mod http;
pub mod learning;
pub mod model_server;
pub mod packs;
pub mod patterns;
pub mod profile;
pub mod prompts;
pub mod proxy;
pub mod replay;
mod run;
pub mod server;
pub mod shadow;
pub mod shell_risk;

use std::sync::{Arc, Mutex};

use crate::vault::Vault;

/// The one open vault in this process. The desktop app and the broker share it.
pub type SharedVault = Arc<Mutex<Option<Vault>>>;

pub use server::{
    BrokerHandle, BrokerOptions, start, start_with, start_with_model_server, start_with_tls,
};
