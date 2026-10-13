//! Track server: the relay server (docs/SPEC.md).
//!
//! The directory of teams and one vault per team (sealed item values only), the auth
//! of the edge and of tokens, the admin API, the decision per run, the one-time keys of
//! pending runs, the endpoints of the owner's host, the live sessions, the audit, the
//! remote MCP endpoint, and the socket of the operator.
//! The proxy path `/p/` goes to `crate::proxy::Proxy::handle`.
//!
//! The public interface below is fixed by the skeleton: the `apassy-relay`
//! binary and the tests use `Relay::init` and `Relay::start`.

pub mod admin;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod decide;
pub mod devices;
pub mod directory;
pub mod env;
pub mod host;
pub mod http;
pub mod hub;
pub mod joins;
pub mod mcp;
pub mod operator;
pub mod push;
pub mod questions;
pub mod runkeys;
pub mod sessions;
pub mod store;
pub mod sync;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::JoinHandle;

use apassy::broker::packs::RuleSet;

use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::TeamId;
use crate::proxy::Proxy;
use crate::secret::{SecretString, new_file_key};
use crate::server::approvals::{LongPolls, Notifier};
use crate::server::audit::Audit;
use crate::server::directory::{Directory, TeamLimits, insert_team};
use crate::server::hub::{Hub, make_team_file, remove_team_file};
use crate::server::runkeys::RunKeys;
use crate::server::sessions::SessionTable;
use crate::server::store::Store;
use crate::session::SessionSource;

/// The state of one team that every request handler of that team shares. A handler
/// gets exactly one `Core`, chosen by the hub from the team id of the request.
pub struct Core {
    /// The team of this state.
    pub team: TeamId,
    /// How the team was made (docs/SPEC.md section 26). Fixed for its life.
    pub kind: crate::api::TeamKind,
    pub config: Arc<RelayConfig>,
    pub store: Arc<Store>,
    pub audit: Arc<Audit>,
    /// Effective limits, changed only through the operator socket.
    pub team_limits: RwLock<TeamLimits>,
    /// Agent-lane requests of this team currently in flight.
    pub agent_requests: AtomicUsize,
    /// Last limit audit row, by kind. Kept separate from authentication refusals.
    pub(crate) last_limit: Mutex<HashMap<&'static str, u64>>,
    pub sessions: Arc<SessionTable>,
    /// The built-in rule packs of the core, loaded once at start, shared by the teams.
    pub rules: Arc<RuleSet>,
    pub notify: Notifier,
    /// The open long polls of each agent.
    pub polls: LongPolls,
    /// The open long polls of the owner's host.
    pub host_polls: LongPolls,
    /// The one-time keys of pending runs. In memory only.
    pub run_keys: RunKeys,
    /// Device nonces and access tokens, in memory only.
    pub device_auth: devices::DeviceAuthState,
    /// The host of the public URL. A command that names it is not a foreign host.
    pub public_host: String,
    /// Snapshot pushes and downloads of this team in flight (`sync_transfers`).
    pub sync_transfers: AtomicUsize,
    /// Snapshot transfers of every team in flight (`Limits::sync_transfers_total`). One
    /// counter for the relay, shared by every `Core`.
    pub relay_sync_transfers: Arc<AtomicUsize>,
    /// The open sync long polls of each device: at most one.
    pub sync_polls: LongPolls,
    /// One commit, delete, or snapshot lookup of this team at a time.
    pub sync_commit: Mutex<()>,
    /// The open question list long polls of each device: at most one.
    pub question_polls: LongPolls,
    /// The open answer long polls of each asking device: at most one.
    pub answer_polls: LongPolls,
    /// Question long polls of this team that hold a thread of the question lane
    /// (`Limits::question_long_polls_per_team`).
    pub question_lane: AtomicUsize,
    /// The push trigger of the relay, shared by every `Core`.
    pub push: Arc<push::Push>,
    stop: Arc<AtomicBool>,
    /// Set when the team is suspended or the relay stops.
    closed: AtomicBool,
}

impl Core {
    pub fn limits(&self) -> TeamLimits {
        *self
            .team_limits
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes at most one audit row per limit kind per ten seconds. Call on the
    /// insertion transaction, and commit the refusal so the audit row stays.
    pub fn limit_error_on(
        &self,
        conn: &rusqlite::Connection,
        now: u64,
        kind: &'static str,
    ) -> RelayResult<RelayError> {
        let mut last = self
            .last_limit
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.get(kind).is_none_or(|at| now >= at.saturating_add(10)) {
            self.audit.write_on(
                conn,
                now,
                crate::server::audit::RELAY_ACTOR,
                "limit_reached",
                None,
                &serde_json::json!({"limit": kind}),
            )?;
            last.insert(kind, now);
        }
        Ok(RelayError::new(
            codes::TEAM_LIMIT,
            format!("The team's {kind} limit is reached."),
        ))
    }

    /// True after `RunningRelay::stop`, or once the team is suspended.
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.closed.load(Ordering::Relaxed)
    }

    /// Ends every session, drops every run key, and wakes the long polls.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify();
        self.sessions.clear();
        self.run_keys.clear();
        self.device_auth.clear();
    }
}

/// The relay server.
pub struct Relay;

/// A started relay. Dropping it does not stop it; call `stop`.
pub struct RunningRelay {
    /// The bound address (useful when the config asked for port 0).
    pub addr: SocketAddr,
    hub: Arc<Hub>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    operator: Option<JoinHandle<()>>,
}

impl RunningRelay {
    /// `http://<addr>`: the plain HTTP origin of the listener.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The live sessions of every team, as the proxy reads them.
    pub fn sessions(&self) -> Arc<dyn SessionSource> {
        self.hub.clone()
    }

    /// The teams of this relay.
    pub fn hub(&self) -> Arc<Hub> {
        self.hub.clone()
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
        for core in self.hub.all() {
            core.notify.notify();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.operator.take() {
            let _ = handle.join();
        }
        self.hub.close_all();
    }
}

/// Removes what a migration that stopped before its commit point left: the staged
/// directory and every `*.migrating` file in `teams/`. Their key was only in the staged
/// directory, so nothing in them can be read any more.
fn remove_staged(config: &RelayConfig, staged_directory: &std::path::Path) -> RelayResult<()> {
    let gone = |path: &std::path::Path| match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RelayError::internal(
            "A file of an earlier migration cannot be removed.",
        )),
    };
    let mut journal = staged_directory.as_os_str().to_owned();
    journal.push("-journal");
    gone(staged_directory)?;
    gone(std::path::Path::new(&journal))?;
    if let Ok(entries) = std::fs::read_dir(config.teams_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".migrating") || name.ends_with(".migrating-journal") {
                gone(&entry.path())?;
            }
        }
    }
    Ok(())
}

/// The data directory has a relay already (a directory or a vault from before teams).
fn refuse_existing(config: &RelayConfig) -> RelayResult<()> {
    if std::fs::symlink_metadata(config.directory_path()).is_ok() {
        return Err(RelayError::new(
            codes::CONFLICT,
            "The relay already exists. Refusing to create it again.",
        ));
    }
    if std::fs::symlink_metadata(config.legacy_vault_path()).is_ok() {
        return Err(RelayError::new(
            codes::CONFLICT,
            "This data directory holds the vault of a relay from before teams. Run `apassy-relay migrate`.",
        ));
    }
    Ok(())
}

impl Relay {
    /// Creates the directory of a new relay with no team. Teams come from team codes
    /// (`apassy-relay admin team-code`). Refuses if the relay exists.
    pub fn init_empty(config: &RelayConfig) -> RelayResult<()> {
        let _lock = hub::lock_data_dir(config)?;
        refuse_existing(config)?;
        Directory::create(config).map(drop)
    }

    /// Creates a new relay with one team and its owner. Returns the owner token once.
    /// Refuses if the relay exists.
    pub fn init(config: &RelayConfig, team: &str, owner: &str) -> RelayResult<SecretString> {
        let _lock = hub::lock_data_dir(config)?;
        refuse_existing(config)?;
        // The names are checked before any file is made.
        hub::checked_team_name(team)?;
        admin::checked_member_name(owner)?;
        let now = crate::now_unix();
        let directory = Directory::create(config)?;
        let made = make_team_file(config, team, owner, now).and_then(|new| {
            let added = directory
                .store
                .tx(|tx| insert_team(tx, &new.id, team.trim(), &new.file_key, false, now));
            match added {
                Ok(()) => Ok(new.owner_token),
                Err(error) => {
                    let _ = remove_team_file(config, &new.id);
                    Err(error)
                }
            }
        });
        if made.is_err() {
            drop(directory);
            let _ = std::fs::remove_file(config.directory_path());
        }
        made
    }

    /// Moves the vault of a relay from before teams into a team (ADR 0019, section 12).
    ///
    /// `team.db` is copied to `teams/<id>.db.migrating`, the copy gets a new random key
    /// (`PRAGMA rekey`), and a new directory with the master key holds that key. The
    /// directory is written as `relay.db.migrating` and renamed to `relay.db` last: that
    /// rename is the commit point. Before it, a failure (or a crash) leaves `team.db` as
    /// it was, and the next `migrate` removes the leftovers. After it, `serve` finishes a
    /// migration that stopped. Old member and agent tokens (no team id) keep working for
    /// this team. The original file stays as `team.db.pre-teams`: it opens with the old
    /// key only. Returns the team id.
    pub fn migrate(config: &RelayConfig, old_key: &SecretString) -> RelayResult<TeamId> {
        let _lock = hub::lock_data_dir(config)?;
        let legacy = config.legacy_vault_path();
        if std::fs::symlink_metadata(config.directory_path()).is_ok() {
            return Err(RelayError::new(
                codes::CONFLICT,
                "The relay has a directory already: there is nothing to migrate.",
            ));
        }
        if std::fs::symlink_metadata(&legacy).is_err() {
            return Err(RelayError::internal(
                "There is no team.db in the data directory to migrate.",
            ));
        }
        let backup = config.data_dir.join(crate::config::LEGACY_BACKUP_FILE);
        if std::fs::symlink_metadata(&backup).is_ok() {
            return Err(RelayError::new(
                codes::CONFLICT,
                "team.db.pre-teams exists. Move it away before a new migration.",
            ));
        }
        if old_key.expose() == config.master_key.expose() {
            return Err(RelayError::invalid(
                "The master key must not be the old vault key: the old key would then open every team. Make a new master key.",
            ));
        }
        let staged_directory = config.data_dir.join("relay.db.migrating");
        remove_staged(config, &staged_directory)?;
        // Check the old file and its key before anything changes.
        // Check the old file and its key without changing it: `open_team` would move it
        // to schema version 3 in place. The copy below is migrated instead.
        let name = {
            let old = Store::open_at(&legacy, old_key)?;
            match old.user_version()? {
                2..=store::SCHEMA_VERSION => {}
                1 => {
                    return Err(RelayError::internal(
                        "This team vault is from the first alpha and holds plaintext item values. Start with a new data volume: there is no migration.",
                    ));
                }
                _ => {
                    return Err(RelayError::internal(
                        "The team vault has an unknown schema version.",
                    ));
                }
            }
            old.with(store::team_name)?
        };
        let id = TeamId::generate()
            .map_err(|_| RelayError::internal("The system has no random source."))?;
        let file_key = new_file_key()?;
        let target = config.team_path(&id);
        let mut staged = target.clone().into_os_string();
        staged.push(".migrating");
        let staged = PathBuf::from(staged);
        let prepared = (|| {
            std::fs::create_dir_all(config.teams_dir())
                .map_err(|_| RelayError::internal("The teams folder cannot be created."))?;
            std::fs::copy(&legacy, &staged)
                .map_err(|_| RelayError::internal("team.db cannot be copied."))?;
            {
                let copy = Store::open_team(&staged, old_key)?;
                copy.rekey(&file_key)?;
            }
            // The copy opens with the new key, and not with the old one.
            Store::open_team(&staged, &file_key)?;
            if Store::open_team(&staged, old_key).is_ok() {
                return Err(RelayError::internal(
                    "The new key of the team file did not take.",
                ));
            }
            let directory = Directory::create_at(&staged_directory, &config.master_key)?;
            directory
                .store
                .tx(|tx| insert_team(tx, &id, &name, &file_key, true, crate::now_unix()))?;
            drop(directory);
            // The commit point.
            std::fs::rename(&staged_directory, config.directory_path())
                .map_err(|_| RelayError::internal("relay.db cannot be moved into place."))
        })();
        if let Err(error) = prepared {
            let _ = remove_staged(config, &staged_directory);
            return Err(error);
        }
        let finish =
            std::fs::rename(&staged, &target).and_then(|()| std::fs::rename(&legacy, &backup));
        if finish.is_err() {
            return Err(RelayError::internal(
                "relay.db is written, but the files could not all be renamed. Start the relay: it finishes the migration.",
            ));
        }
        Ok(id)
    }

    /// The file and key of one team, for tests and for the operator's backup tools.
    pub fn team_vault(config: &RelayConfig, team: &TeamId) -> RelayResult<(PathBuf, SecretString)> {
        let directory = Directory::open(config)?;
        let row = directory
            .team(team)?
            .ok_or_else(|| RelayError::not_found("team"))?;
        Ok((config.team_path(team), row.file_key))
    }

    /// Opens the directory and the active teams, binds `config.listen`, opens the
    /// operator socket, and serves in background threads.
    pub fn start(config: RelayConfig) -> RelayResult<RunningRelay> {
        let stop = Arc::new(AtomicBool::new(false));
        let hub = Hub::open(config, stop.clone())?;
        let source: Arc<dyn SessionSource> = hub.clone();
        let proxy = Arc::new(Proxy::new(&hub.config.upstream, source)?);
        let server = tiny_http::Server::http(hub.config.listen).map_err(|_| {
            RelayError::internal(format!("Cannot listen on {}.", hub.config.listen))
        })?;
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| RelayError::internal("The listener has no IP address."))?;
        let operator = operator::listen(hub.clone(), stop.clone())?;
        let serving = http::Serving {
            hub: hub.clone(),
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
            hub,
            stop,
            handle: Some(handle),
            operator: Some(operator),
        })
    }
}
