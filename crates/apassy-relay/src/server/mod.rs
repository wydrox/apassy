//! Track server: the relay server (docs/SPEC.md).
//!
//! The team vault, the auth of the edge and of tokens, the admin API, the decision
//! per run, the live sessions, the approvals, the audit, and the remote MCP
//! endpoint. The proxy path `/p/` goes to `crate::proxy::Proxy::handle`.
//!
//! The public interface below is fixed by the skeleton: the `apassy-relay`
//! binary and the tests use `Relay::init` and `Relay::start`.

pub mod admin;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod decide;
pub mod env;
pub mod http;
pub mod mcp;
pub mod sessions;
pub mod store;

use std::net::SocketAddr;

use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult};
use crate::secret::SecretString;

/// The relay server.
pub struct Relay;

/// A started relay. Dropping it does not stop it; call `stop`.
pub struct RunningRelay {
    /// The bound address (useful when the config asked for port 0).
    pub addr: SocketAddr,
}

impl RunningRelay {
    /// `http://<addr>`: the plain HTTP origin of the listener.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Blocks until the server stops.
    pub fn wait(self) {}

    /// Stops accepting requests and ends every live session.
    pub fn stop(self) {}
}

impl Relay {
    /// Creates the team vault at `config.vault_path()` with the team and its owner.
    /// Returns the owner token once. Refuses if the vault exists.
    pub fn init(config: &RelayConfig, team: &str, owner: &str) -> RelayResult<SecretString> {
        let _ = (config, team, owner);
        Err(RelayError::internal("The server is not built yet."))
    }

    /// Opens the team vault, binds `config.listen`, and serves in background threads.
    pub fn start(config: RelayConfig) -> RelayResult<RunningRelay> {
        let _ = config;
        Err(RelayError::internal("The server is not built yet."))
    }
}
