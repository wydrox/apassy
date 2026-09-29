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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use apassy::broker::packs::RuleSet;
use rusqlite::params;
use serde_json::json;

use crate::api::Role;
use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult};
use crate::proxy::Proxy;
use crate::secret::{SecretString, TokenKind, new_token, token_hash};
use crate::server::approvals::{LongPolls, Notifier};
use crate::server::audit::{Audit, RELAY_ACTOR};
use crate::server::sessions::SessionTable;
use crate::server::store::{Store, db, load_all_items, to_i, to_u};
use crate::session::SessionSource;

/// The state that every request handler shares.
pub struct Core {
    pub config: RelayConfig,
    pub store: Arc<Store>,
    pub audit: Arc<Audit>,
    pub sessions: Arc<SessionTable>,
    /// The built-in rule packs of the core, loaded once at start.
    pub rules: RuleSet,
    pub notify: Notifier,
    /// The open long polls of each agent.
    pub polls: LongPolls,
    /// The host of the public URL. A command that names it is not a foreign host.
    pub public_host: String,
    stop: Arc<AtomicBool>,
}

impl Core {
    /// True after `RunningRelay::stop`.
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

/// The relay server.
pub struct Relay;

/// A started relay. Dropping it does not stop it; call `stop`.
pub struct RunningRelay {
    /// The bound address (useful when the config asked for port 0).
    pub addr: SocketAddr,
    core: Arc<Core>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RunningRelay {
    /// `http://<addr>`: the plain HTTP origin of the listener.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The live sessions, as the proxy reads them.
    pub fn sessions(&self) -> Arc<dyn SessionSource> {
        self.core.sessions.clone()
    }

    /// Blocks until the server stops.
    pub fn wait(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Stops accepting requests and ends every live session.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.core.notify.notify();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.core.sessions.clear();
    }
}

impl Relay {
    /// Creates the team vault at `config.vault_path()` with the team and its owner.
    /// Returns the owner token once. Refuses if the vault exists.
    pub fn init(config: &RelayConfig, team: &str, owner: &str) -> RelayResult<SecretString> {
        let team = team.trim();
        if team.is_empty()
            || team.len() > crate::api::MAX_NAME_BYTES
            || team.chars().any(char::is_control)
        {
            return Err(RelayError::invalid(
                "The team name is 1 to 64 bytes with no control character.",
            ));
        }
        let owner = admin::checked_member_name(owner)?;
        let token = new_token(TokenKind::Member)?;
        let hash = token_hash(token.expose());
        let now = crate::now_unix();
        let store = Store::create(config)?;
        let audit = Audit::new();
        let made =
            store.tx(|tx| {
                tx.execute(
                    "INSERT INTO team (id, name, created_at) VALUES (1, ?1, ?2)",
                    params![team, to_i(now)],
                )
                .map_err(db)?;
                tx.execute(
                "INSERT INTO member (name, role, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![owner, auth::role_text(Role::Owner), hash.0.as_slice(), to_i(now)],
            )
            .map_err(db)?;
                let owner_id = to_u(tx.last_insert_rowid());
                audit.write_on(
                    tx,
                    now,
                    RELAY_ACTOR,
                    "team_created",
                    None,
                    &json!({"team": team, "owner": owner, "owner_id": owner_id}),
                )?;
                Ok(())
            });
        if let Err(error) = made {
            drop(store);
            let _ = std::fs::remove_file(config.vault_path());
            return Err(error);
        }
        Ok(token)
    }

    /// Opens the team vault, binds `config.listen`, and serves in background threads.
    pub fn start(config: RelayConfig) -> RelayResult<RunningRelay> {
        let store = Arc::new(Store::open(&config)?);
        let audit = Audit::new();
        let now = crate::now_unix();
        store.tx(|tx| {
            for item in load_all_items(tx)? {
                audit.add_value(&item.env_name, &item.value);
            }
            // A restart ends every session.
            let ended: Vec<u64> = {
                let mut statement = tx
                    .prepare("SELECT id FROM run WHERE status = 'ready'")
                    .map_err(db)?;
                statement
                    .query_map([], |row| Ok(to_u(row.get(0)?)))
                    .map_err(db)?
                    .collect::<Result<_, _>>()
                    .map_err(db)?
            };
            for id in ended {
                tx.execute(
                    "UPDATE run SET status = 'ended' WHERE id = ?1",
                    params![to_i(id)],
                )
                .map_err(db)?;
                audit.write_on(
                    tx,
                    now,
                    RELAY_ACTOR,
                    "session_ended",
                    Some(crate::ids::RunId(id)),
                    &json!({"reason": "restart"}),
                )?;
            }
            Ok(())
        })?;
        let sessions = SessionTable::new(store.clone(), audit.clone());
        let rules = RuleSet::builtin().map_err(|_| {
            RelayError::internal("The built-in rule packs of the core cannot be loaded.")
        })?;
        let source: Arc<dyn SessionSource> = sessions.clone();
        let proxy = Arc::new(Proxy::new(&config.upstream, source)?);
        let server = tiny_http::Server::http(config.listen)
            .map_err(|_| RelayError::internal(format!("Cannot listen on {}.", config.listen)))?;
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| RelayError::internal("The listener has no IP address."))?;
        let stop = Arc::new(AtomicBool::new(false));
        let core = Arc::new(Core {
            public_host: decide::public_host(&config.public_url),
            polls: LongPolls::new(config.limits.long_polls_per_agent),
            config,
            store,
            audit,
            sessions,
            rules,
            notify: Notifier::default(),
            stop: stop.clone(),
        });
        let serving = http::Serving {
            core: core.clone(),
            proxy,
            server,
            stop: stop.clone(),
        };
        let handle = std::thread::Builder::new()
            .name("relay-accept".to_string())
            .spawn(move || http::serve(serving))
            .map_err(|_| RelayError::internal("The accept thread cannot start."))?;
        Ok(RunningRelay {
            addr,
            core,
            stop,
            handle: Some(handle),
        })
    }
}
