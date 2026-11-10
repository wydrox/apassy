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

pub mod account;
pub mod admin;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod billing_store;
pub mod connect;
pub mod decide;
pub mod devices;
pub mod directory;
pub mod entitlement;
pub mod env;
pub mod feed;
pub mod group;
pub mod host;
pub mod http;
pub mod hub;
pub mod ingress;
pub mod joins;
pub mod mcp;
pub mod oauth;
pub mod operator;
pub mod push;
pub mod questions;
pub mod rollback;
pub mod runkeys;
pub mod sessions;
pub mod store;
pub mod stripe;
pub mod sync;
pub mod tunnel;
pub mod tunnel_routes;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    /// (`Limits::question_long_polls_per_team`). Feed polls never count here.
    pub question_lane: AtomicUsize,
    /// The open feed list long polls of each device: at most one (section 27).
    pub feed_polls: LongPolls,
    /// The open action list long polls of each target device: at most one.
    pub feed_action_polls: LongPolls,
    /// The open action status long polls of each sending device: at most one.
    pub feed_status_polls: LongPolls,
    /// The feed long polls of this team that hold a thread of the feed lane
    /// (`Limits::feed_long_polls_per_team`, for a Connect team `connect::TEAM_FEED_POLLS`),
    /// apart from its question seats (docs/SPEC.md section 27.7).
    pub feed_lane: AtomicUsize,
    /// The feed list polls and the action status polls of this team out of `feed_lane`,
    /// at most `feed::kind_seats` of its share each, so they leave seats to the action
    /// polls and to each other.
    pub feed_lists: AtomicUsize,
    pub feed_statuses: AtomicUsize,
    /// The feed polls of each member of this team out of `feed_lane`
    /// (`feed::member_seats`), so one member's devices leave a seat to each other member.
    pub feed_members: Mutex<HashMap<u64, usize>>,
    /// The last `feed_started` or `feed_deleted` row of each device and whether its feed
    /// changed since without a row (`feed::FeedAudit`), so a loop of `PUT` and `DELETE`
    /// writes at most one row per device and hour. In memory only.
    pub feed_audit: Mutex<HashMap<u64, feed::FeedAudit>>,
    /// The feed text that each device read in the current minute (`feed::FeedReads`).
    /// In memory only.
    pub feed_reads: Mutex<HashMap<u64, feed::FeedReads>>,
    /// The time of each device's last accepted feed, so a delete does not lift the 10 s
    /// pace of feeds. In memory only: the feed row keeps it across a restart.
    pub feed_times: Mutex<HashMap<u64, u64>>,
    /// The push trigger of the relay, shared by every `Core`.
    pub push: Arc<push::Push>,
    /// The long polls that all Connect teams hold (`Limits::connect_long_polls`). One
    /// counter for the relay, shared by every `Core`.
    pub connect_polls: Arc<AtomicUsize>,
    /// The feed long polls that all Connect teams hold (`Limits::connect_feed_long_polls`),
    /// apart from `connect_polls`. One counter for the relay, shared by every `Core`.
    pub connect_feed_polls: Arc<AtomicUsize>,
    /// The requests of this team in the current minute (a Connect team only).
    pub request_rate: connect::RequestRate,
    /// The time of the last request that named this team, and of its last maintenance
    /// pass: an idle Connect team is maintained less often (`http::maintain`).
    pub last_request: AtomicU64,
    pub maintained_at: AtomicU64,
    /// The relay's own store and audit (`relay.db`): a Connect team's refusals of callers
    /// that are not its devices go there (`outside_refusal`).
    pub(crate) relay_store: Arc<Store>,
    pub(crate) relay_audit: Arc<Audit>,
    /// The last warning about the file cap of a Connect team (`audit::watch_cap`): the
    /// level logged and when.
    pub(crate) cap_warning: Mutex<(audit::CapLevel, u64)>,
    stop: Arc<AtomicBool>,
    /// Set when the team is suspended or the relay stops.
    closed: Arc<AtomicBool>,
}

impl Core {
    /// A team that anyone may make without the operator: a Connect team, or a vault store
    /// of an account (connect-account-v1). Its outside refusals go to the relay audit, and
    /// its long polls and requests have the Connect bounds.
    pub fn hosted(&self) -> bool {
        matches!(
            self.kind,
            crate::api::TeamKind::Connect | crate::api::TeamKind::Account
        )
    }

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
        self.limit_error_every(conn, now, kind, 10)
    }

    /// `limit_error_on` with at most one row of `kind` per `secs` seconds (the feed limits:
    /// one an hour, docs/SPEC.md section 27.9).
    pub fn limit_error_every(
        &self,
        conn: &rusqlite::Connection,
        now: u64,
        kind: &'static str,
        secs: u64,
    ) -> RelayResult<RelayError> {
        let mut last = self
            .last_limit
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last
            .get(kind)
            .is_none_or(|at| now >= at.saturating_add(secs))
        {
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
        Ok(Self::limit_error(kind))
    }

    /// The last warning about this team's file cap (`audit::watch_cap`): its level and
    /// time, `(Ok, 0)` before any.
    pub fn cap_warning(&self) -> (audit::CapLevel, u64) {
        *self
            .cap_warning
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// 403 `team_limit` for the limit `kind`, without an audit row.
    pub fn limit_error(kind: &str) -> RelayError {
        RelayError::new(
            codes::TEAM_LIMIT,
            format!("The team's {kind} limit is reached."),
        )
    }

    /// A refusal of a call that no device of this team made: a token that is not one of
    /// the team's, a failed sign-in, a used invite, a proxy request over the team's slots
    /// before its session is checked, a join over the member limit. Anyone who knows
    /// the team id (it is in every code of the team) can cause one. An operator team
    /// writes it to its own audit, at most one row per kind and ten seconds, as before.
    /// A Connect team's file has a cap and its audit is never trimmed, so such rows
    /// would let an outsider fill it and block the team: they go to the relay audit
    /// instead, with the team id, at most one row per kind and ten seconds for all
    /// Connect teams together (docs/SPEC.md section 26.7). Call it with no lock of the
    /// team's store held: `relay.db` is locked before a team file, never after.
    pub fn outside_refusal(
        &self,
        now: u64,
        kind: &'static str,
        action: &str,
        detail: &serde_json::Value,
    ) {
        if !self.hosted() {
            self.audit.refusal(&self.store, now, kind, action, detail);
            return;
        }
        let relay_kind = match kind {
            "token" => "connect_token",
            "device_sign_in" => "connect_device_sign_in",
            "invite_reused" => "connect_invite_reused",
            "agent_requests" => "connect_agent_requests",
            "members" => "connect_members",
            _ => "connect_other",
        };
        let mut detail = detail.clone();
        if let Some(fields) = detail.as_object_mut() {
            fields.insert("team_id".to_string(), serde_json::json!(self.team));
        }
        self.relay_audit
            .refusal(&self.relay_store, now, relay_kind, action, &detail);
    }

    /// 403 `team_limit` for a limit that a caller who is not a device of the team
    /// reached: for an operator team with its `limit_reached` row in the team audit
    /// (`limit_error_on`), for a Connect team with that row in the relay audit
    /// (`outside_refusal`). Call it with no lock of the team's store held.
    pub fn outside_limit(&self, now: u64, kind: &'static str) -> RelayError {
        if !self.hosted() {
            return self
                .store
                .with(|conn| self.limit_error_on(conn, now, kind))
                .unwrap_or_else(|error| error);
        }
        self.outside_refusal(
            now,
            kind,
            "limit_reached",
            &serde_json::json!({"limit": kind}),
        );
        Self::limit_error(kind)
    }

    /// A seat for one long poll: always for an operator team; for a Connect team one of
    /// `Limits::connect_long_polls`, or `None` when they are all held (the poll then
    /// answers at once).
    pub fn poll_seat(&self) -> Option<connect::PollSeat<'_>> {
        if !self.hosted() {
            return Some(connect::PollSeat::free());
        }
        connect::PollSeat::take(&self.connect_polls, self.config.limits.connect_long_polls)
    }

    /// A seat for one feed long poll: always for an operator team; for a Connect team one
    /// of `Limits::connect_feed_long_polls`, apart from the seats of `poll_seat`, or
    /// `None` when they are all held (the poll then answers at once).
    pub fn feed_poll_seat(&self) -> Option<connect::PollSeat<'_>> {
        if !self.hosted() {
            return Some(connect::PollSeat::free());
        }
        connect::PollSeat::take(
            &self.connect_feed_polls,
            self.config.limits.connect_feed_long_polls,
        )
    }

    /// Counts one authenticated request of a Connect team: 429 `rate_limited` over
    /// `connect::REQUESTS_PER_MINUTE` for each member its limits allow, with the seconds
    /// to wait, and a `limit_reached` row at most once per ten seconds. An operator team
    /// is not counted.
    pub fn take_request(&self, now: u64) -> Result<(), (RelayError, u64)> {
        self.last_request.store(now, Ordering::Relaxed);
        if !self.hosted() {
            return Ok(());
        }
        let per_minute = connect::REQUESTS_PER_MINUTE.saturating_mul(self.limits().members.max(1));
        self.request_rate.take(per_minute, now).map_err(|wait| {
            let _ = self
                .store
                .with(|conn| self.limit_error_on(conn, now, "requests_per_minute"));
            (connect::requests_limited(), wait)
        })
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
    /// The bound address of the public listener (`RelayConfig::public_listen`).
    pub public_addr: Option<SocketAddr>,
    /// The bound address of the tailnet listener (`RelayConfig::tailnet_listen`): the
    /// target of the node's TLS front.
    pub tailnet_addr: Option<SocketAddr>,
    /// The bound address of the local route listener: the same routes as the tailnet
    /// listener, on a free port of the same loopback address, for the Mac's own clients
    /// (the local route of the node origin). The TLS front never forwards to it, so the
    /// failed authentications of tailnet peers never limit it (N8-1).
    pub tailnet_local_addr: Option<SocketAddr>,
    hub: Arc<Hub>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<RelayResult<()>>>,
    public_handle: Option<JoinHandle<RelayResult<()>>>,
    tailnet_handle: Option<JoinHandle<RelayResult<()>>>,
    tailnet_local_handle: Option<JoinHandle<RelayResult<()>>>,
    operator: Option<JoinHandle<()>>,
    /// The Connect tunnel (with the account routes only): the broker, the ingress, and
    /// the usage writer.
    tunnel: Option<tunnel_routes::TunnelRuntime>,
}

impl RunningRelay {
    /// `http://<addr>`: the plain HTTP origin of the listener.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// `http://<public addr>`: the plain HTTP origin of the public listener, if any.
    pub fn public_listener_url(&self) -> Option<String> {
        self.public_addr.map(|addr| format!("http://{addr}"))
    }

    /// `http://<tailnet addr>`: the plain HTTP origin of the tailnet listener, if any.
    pub fn tailnet_listener_url(&self) -> Option<String> {
        self.tailnet_addr.map(|addr| format!("http://{addr}"))
    }

    /// The live sessions of every team, as the proxy reads them.
    pub fn sessions(&self) -> Arc<dyn SessionSource> {
        self.hub.clone()
    }

    /// The bound address of the tunnel's SNI ingress (`APASSY_CONNECT_INGRESS_LISTEN`).
    pub fn tunnel_ingress_addr(&self) -> Option<SocketAddr> {
        self.tunnel
            .as_ref()
            .and_then(|tunnel| tunnel.ingress_addr())
    }

    /// The bound address of the tunnel's ACME listener (`APASSY_CONNECT_ACME_LISTEN`).
    pub fn tunnel_acme_addr(&self) -> Option<SocketAddr> {
        self.tunnel.as_ref().and_then(|tunnel| tunnel.acme_addr())
    }

    /// The teams of this relay.
    pub fn hub(&self) -> Arc<Hub> {
        self.hub.clone()
    }

    /// Blocks until the server stops. An error when the listener died (`http::serve`):
    /// the caller exits non-zero.
    pub fn wait(mut self) -> RelayResult<()> {
        match self.handle.take() {
            Some(handle) => handle
                .join()
                .unwrap_or_else(|_| Err(RelayError::internal("The accept loop panicked."))),
            None => Ok(()),
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
        if let Some(handle) = self.public_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.tailnet_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.tailnet_local_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.operator.take() {
            let _ = handle.join();
        }
        // The usage of the month reaches `relay.db` before the data directory unlocks.
        if let Some(tunnel) = self.tunnel.take() {
            tunnel.stop();
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

    /// Opens the directory and the active teams, binds `config.listen` (and
    /// `config.public_listen` and `config.tailnet_listen`), opens the operator socket when
    /// `config.operator_socket` is on (never on a Mac's own node), and serves in
    /// background threads. A relay without the edge must listen on the loopback only
    /// (`RelayConfig::check_listeners`).
    pub fn start(config: RelayConfig) -> RelayResult<RunningRelay> {
        config.check_listeners()?;
        let stop = Arc::new(AtomicBool::new(false));
        let hub = Hub::open(config, stop.clone())?;
        // Connect billing: the price cache is filled at start, on a thread of its own, so
        // a Stripe outage never delays or stops the start (`GET /v1/plans` asks again).
        if let Some(billing) = hub.billing().cloned() {
            let warm = std::thread::Builder::new()
                .name("relay-stripe-prices".to_string())
                .spawn(move || {
                    if billing.prices(crate::now_unix()).is_err() {
                        eprintln!("apassy-relay: the Stripe prices could not be read at start");
                    }
                });
            if warm.is_err() {
                eprintln!("apassy-relay: the Stripe price thread cannot start");
            }
        }
        let source: Arc<dyn SessionSource> = hub.clone();
        let proxy = Arc::new(Proxy::new(&hub.config.upstream, source)?);
        let bind = |listen: SocketAddr| {
            let server = tiny_http::Server::http_with_deadlines(
                listen,
                std::time::Duration::from_secs(10),
                hub.config.request_read_timeout,
                hub.config.request_handle_timeout,
            )
            .map_err(|_| RelayError::internal(format!("Cannot listen on {listen}.")))?;
            let addr = server
                .server_addr()
                .to_ip()
                .ok_or_else(|| RelayError::internal("The listener has no IP address."))?;
            Ok::<_, RelayError>((server, addr))
        };
        let (server, addr) = bind(hub.config.listen)?;
        let public = hub.config.public_listen.map(bind).transpose()?;
        let tailnet = hub.config.tailnet_listen.map(bind).transpose()?;
        let tailnet_local = hub
            .config
            .tailnet_listen
            .map(|listen| bind(SocketAddr::new(listen.ip(), 0)))
            .transpose()?;
        let operator = if hub.config.operator_socket {
            Some(operator::listen(hub.clone(), stop.clone())?)
        } else {
            // A socket that an older version left answers nothing: remove it.
            let _ = operator::remove_stale(&hub.config.admin_socket_path());
            None
        };
        // The tunnel exists only with the account routes; dropped on any error below, it
        // stops again.
        let tunnel = match tunnel_routes::start(&hub) {
            Ok(tunnel) => tunnel,
            Err(error) => {
                stop.store(true, Ordering::Relaxed);
                if let Some(operator) = operator {
                    let _ = operator.join();
                }
                hub.close_all();
                return Err(error);
            }
        };
        let serving = http::Serving {
            hub: hub.clone(),
            proxy: proxy.clone(),
            server,
            stop: stop.clone(),
            scope: http::Scope::Node,
            limits: hub.config.limits,
            local_route: false,
        };
        let spawned = std::thread::Builder::new()
            .name("relay-accept".to_string())
            .spawn(move || http::serve(serving));
        let handle = match spawned {
            Ok(handle) => handle,
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                if let Some(operator) = operator {
                    let _ = operator.join();
                }
                hub.close_all();
                return Err(RelayError::internal("The accept thread cannot start."));
            }
        };
        let mut public_addr = None;
        let mut public_handle = None;
        if let Some((server, addr)) = public {
            // Agents only, and a lane of its own: the public listener never takes the
            // threads of the loopback listener of the app.
            let serving = http::Serving {
                hub: hub.clone(),
                proxy: proxy.clone(),
                server,
                stop: stop.clone(),
                scope: http::Scope::Public,
                limits: crate::config::Limits {
                    max_active: crate::config::PUBLIC_MAX_ACTIVE,
                    member_reserve: 0,
                    ..hub.config.limits
                },
                local_route: false,
            };
            let spawned = std::thread::Builder::new()
                .name("relay-public-accept".to_string())
                .spawn(move || http::serve(serving));
            match spawned {
                Ok(spawned) => {
                    public_addr = Some(addr);
                    public_handle = Some(spawned);
                }
                Err(_) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = handle.join();
                    if let Some(operator) = operator {
                        let _ = operator.join();
                    }
                    hub.close_all();
                    return Err(RelayError::internal(
                        "The accept thread of the public listener cannot start.",
                    ));
                }
            }
        }
        let mut tailnet_addr = None;
        let mut tailnet_handle = None;
        let mut tailnet_local_addr = None;
        let mut tailnet_local_handle = None;
        // The devices of the tailnet (and on the Linux node, its team clients), with the
        // lanes and limits of the node listener but threads of their own. Then the local
        // route of the Mac's own clients: the same routes on a listener of its own.
        for (bound, local_route) in [(tailnet, false), (tailnet_local, true)] {
            let Some((server, addr)) = bound else {
                continue;
            };
            let serving = http::Serving {
                hub: hub.clone(),
                proxy: proxy.clone(),
                server,
                stop: stop.clone(),
                scope: http::Scope::Tailnet {
                    agents: hub.config.tailnet_agents,
                },
                limits: hub.config.limits,
                local_route,
            };
            let name = if local_route {
                "relay-local-accept"
            } else {
                "relay-tailnet-accept"
            };
            let spawned = std::thread::Builder::new()
                .name(name.to_string())
                .spawn(move || http::serve(serving));
            match spawned {
                Ok(spawned) if local_route => {
                    tailnet_local_addr = Some(addr);
                    tailnet_local_handle = Some(spawned);
                }
                Ok(spawned) => {
                    tailnet_addr = Some(addr);
                    tailnet_handle = Some(spawned);
                }
                Err(_) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = handle.join();
                    for other in [public_handle, tailnet_handle].into_iter().flatten() {
                        let _ = other.join();
                    }
                    if let Some(operator) = operator {
                        let _ = operator.join();
                    }
                    hub.close_all();
                    return Err(RelayError::internal(
                        "The accept thread of the tailnet listener cannot start.",
                    ));
                }
            }
        }
        Ok(RunningRelay {
            addr,
            public_addr,
            tailnet_addr,
            tailnet_local_addr,
            hub,
            stop,
            handle: Some(handle),
            public_handle,
            tailnet_handle,
            tailnet_local_handle,
            operator,
            tunnel,
        })
    }
}
