//! The teams of one relay (ADR 0019, docs/SPEC.md "Teams").
//!
//! Each active team is one `Core`: its own file, audit, sessions, run keys, and long
//! polls. The hub finds the team of a request from the team id in its credential
//! before it opens anything, and gives the handler that one team. No map spans teams,
//! so ids that repeat between teams (run 5, member 1) never meet.

use std::collections::HashMap;
use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};

use apassy::broker::packs::RuleSet;
use rusqlite::params;
use serde::Serialize;
use serde_json::json;

use crate::api::{ConnectCreate, Role, TeamCreate, TeamKind};
use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{DeviceId, MemberId, TeamId};
use crate::secret::{SecretString, TokenKind, new_file_key, new_token, parse_token, token_hash};
use crate::server::approvals::{LongPolls, Notifier};
use crate::server::audit::{Audit, RELAY_ACTOR};
use crate::server::directory::{
    self, Directory, OPERATOR_ACTOR, TeamLimits, TeamLimitsUpdate, TeamRow, TeamState,
};
use crate::server::runkeys::RunKeys;
use crate::server::sessions::SessionTable;
use crate::server::store::{Store, db, to_i, to_u};
use crate::server::{Core, admin, auth, connect};
use crate::session::{LiveSession, ProxyEvent, SessionSource};

/// A team that was just made, with its owner.
pub struct NewTeam {
    pub id: TeamId,
    pub file_key: SecretString,
    pub owner_id: MemberId,
    pub owner_token: SecretString,
    pub store: Store,
}

/// Checks a team name: 1 to 64 bytes with no control character.
pub fn checked_team_name(name: &str) -> RelayResult<&str> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > crate::api::MAX_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(RelayError::invalid(
            "The team name is 1 to 64 bytes with no control character.",
        ));
    }
    Ok(name)
}

/// Makes the file of a new team, with its team row, its owner, and the first audit
/// row. On a failure the file is removed. The caller adds the team to the directory.
pub fn make_team_file(
    config: &RelayConfig,
    name: &str,
    owner: &str,
    now: u64,
) -> RelayResult<NewTeam> {
    make_team_file_with_device(config, name, owner, now, None)
}

fn make_team_file_with_device(
    config: &RelayConfig,
    name: &str,
    owner: &str,
    now: u64,
    device: Option<(&str, &[u8])>,
) -> RelayResult<NewTeam> {
    let name = checked_team_name(name)?;
    let owner = admin::checked_member_name(owner)?;
    let mut id =
        TeamId::generate().map_err(|_| RelayError::internal("The system has no random source."))?;
    for _ in 0..8 {
        if std::fs::symlink_metadata(config.team_path(&id)).is_err() {
            break;
        }
        id = TeamId::generate()
            .map_err(|_| RelayError::internal("The system has no random source."))?;
    }
    let path = config.team_path(&id);
    let file_key = new_file_key()?;
    let store = Store::create_team(&path, &file_key)?;
    let owner_token = new_token(TokenKind::Member, &id)?;
    let hash = token_hash(owner_token.expose());
    let audit = Audit::new();
    let made = store.tx(|tx| {
        tx.execute(
            "INSERT INTO team (id, name, created_at, member_tokens_until) VALUES (1, ?1, ?2, ?3)",
            params![name, to_i(now), to_i(now.saturating_add(14 * 86400))],
        )
        .map_err(db)?;
        tx.execute(
            "INSERT INTO member (name, role, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                owner,
                auth::role_text(Role::Owner),
                device.is_none().then_some(hash.0.as_slice()),
                to_i(now)
            ],
        )
        .map_err(db)?;
        let owner_id = to_u(tx.last_insert_rowid());
        if let Some((device_name, public_key)) = device {
            crate::server::devices::end_host_bootstrap_on(tx, &audit, now)?;
            tx.execute(
                "INSERT INTO device (member_id, name, public_key, key_holder, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                params![to_i(owner_id), device_name, public_key, to_i(now)],
            ).map_err(db)?;
            let device_id = to_u(tx.last_insert_rowid());
            audit.write_on(tx, now, RELAY_ACTOR, "device_added", None,
                &json!({"member_id": owner_id, "device_id": device_id, "name": device_name}))?;
        }
        audit.write_on(
            tx,
            now,
            RELAY_ACTOR,
            "team_created",
            None,
            &json!({"team": name, "team_id": id, "owner": owner, "owner_id": owner_id}),
        )?;
        Ok(MemberId(owner_id))
    });
    match made {
        Ok(owner_id) => Ok(NewTeam {
            id,
            file_key,
            owner_id,
            owner_token,
            store,
        }),
        Err(error) => {
            drop(store);
            let _ = std::fs::remove_file(&path);
            Err(error)
        }
    }
}

/// Deletes the file of a team, its journal and schema backups, and its snapshots. A file that is not there is
/// not an error; any other failure is.
pub fn remove_team_file(config: &RelayConfig, id: &TeamId) -> RelayResult<()> {
    let path = config.team_path(id);
    let with = |suffix: &str| {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        name
    };
    let extra = [
        with("-journal"),
        with(".pre-v3"),
        with(".pre-v3.tmp"),
        with(".pre-v4"),
        with(".pre-v4.tmp"),
        with(".pre-v5"),
        with(".pre-v5.tmp"),
    ];
    for file in std::iter::once(path.clone().into_os_string()).chain(extra) {
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(RelayError::internal("The team file cannot be deleted.")),
        }
    }
    // The vault snapshots of the team (docs/SPEC.md section 24).
    match std::fs::remove_dir_all(config.sync_dir(id)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RelayError::internal(
            "The snapshots of the team cannot be deleted.",
        )),
    }
}

/// Takes the lock of the data directory (`relay.lock`), so that one relay process at
/// a time uses it. `serve`, `init`, and `migrate` hold it; `admin` does not.
pub fn lock_data_dir(config: &RelayConfig) -> RelayResult<File> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|_| RelayError::internal("The data directory cannot be created."))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(config.data_dir.join(crate::config::LOCK_FILE))
        .map_err(|_| {
            RelayError::internal("The lock file of the data directory cannot be opened.")
        })?;
    file.try_lock().map_err(|_| {
        RelayError::new(
            codes::CONFLICT,
            "Another relay process uses this data directory. Stop it first.",
        )
    })?;
    Ok(file)
}

/// Finishes a migration that stopped after `relay.db` was written (the commit point of
/// `Relay::migrate`): moves `teams/<id>.db.migrating` into place, and renames the old
/// `team.db` of the migrated team to `team.db.pre-teams`.
fn finish_migration(config: &RelayConfig, rows: &[TeamRow]) {
    for row in rows {
        let path = config.team_path(&row.id);
        let mut staged = path.clone().into_os_string();
        staged.push(".migrating");
        if std::fs::symlink_metadata(&path).is_err()
            && std::fs::symlink_metadata(&staged).is_ok()
            && std::fs::rename(&staged, &path).is_ok()
        {
            eprintln!("apassy-relay: finished the migration of team {}", row.id);
        }
    }
    let legacy = config.legacy_vault_path();
    let backup = config.data_dir.join(crate::config::LEGACY_BACKUP_FILE);
    if rows.iter().any(|row| row.legacy)
        && std::fs::symlink_metadata(&legacy).is_ok()
        && std::fs::symlink_metadata(&backup).is_err()
        && std::fs::rename(&legacy, &backup).is_ok()
    {
        eprintln!("apassy-relay: renamed the migrated team.db to team.db.pre-teams");
    }
}

/// The threads that open the team files at start, at most.
const OPEN_THREADS: usize = 8;

/// The member name of the owner of a Connect team.
pub const CONNECT_OWNER: &str = "owner";

/// The longest `idle_days` and `delete_days` of `connect-sweep`.
pub const MAX_SWEEP_DAYS: u64 = 3650;

/// What `admin connect-sweep` did, or would do (`dry_run`).
#[derive(Debug, Serialize)]
pub struct SweepReport {
    pub dry_run: bool,
    /// Idle Connect teams suspended with the reason `idle`.
    pub suspended: Vec<TeamId>,
    /// Connect teams deleted after their idle suspension.
    pub deleted: Vec<TeamId>,
    /// `{team, error}` of each team the sweep could not suspend or delete.
    pub failed: Vec<serde_json::Value>,
}

/// What the operator sees of one team. No member, item, run, or audit row.
#[derive(Debug, Serialize)]
pub struct TeamInfo {
    pub id: TeamId,
    pub name: String,
    pub state: TeamState,
    pub legacy: bool,
    pub created_at: u64,
    pub suspended_at: Option<u64>,
    /// `operator` or `connect` (docs/SPEC.md section 26).
    pub kind: TeamKind,
    /// `idle` when `connect-sweep` suspended the team.
    pub suspend_reason: Option<String>,
    pub limits: TeamLimits,
    /// True while the team is served. An active team that is not open failed to open
    /// at start: suspend or delete it.
    pub open: bool,
    /// Counts and the time of the last audit row. `None` while the team is not open.
    pub members: Option<u64>,
    pub items: Option<u64>,
    pub agents: Option<u64>,
    pub last_activity: Option<u64>,
    /// The current vault sync version (0: no snapshot) and the size of its snapshot.
    /// `None` while the team is not open.
    pub sync_version: Option<u64>,
    pub sync_size: Option<u64>,
    /// Open questions and push tokens (counts). `None` while the team is not open.
    pub open_questions: Option<u64>,
    pub push_tokens: Option<u64>,
}

/// The teams of the relay.
pub struct Hub {
    pub config: Arc<RelayConfig>,
    pub directory: Directory,
    teams: RwLock<HashMap<TeamId, Arc<Core>>>,
    legacy: RwLock<Option<TeamId>>,
    rules: Arc<RuleSet>,
    public_host: String,
    stop: Arc<AtomicBool>,
    /// Suspended teams whose requests may still run. Delete waits for them.
    draining: Mutex<HashMap<TeamId, Weak<Core>>>,
    /// The lock of the data directory, held until the relay stops.
    lock: Mutex<Option<File>>,
    /// Snapshot transfers of every team in flight.
    sync_transfers: Arc<AtomicUsize>,
    /// The push trigger, shared by every team.
    push: Arc<crate::server::push::Push>,
    /// The Connect teams of each client prefix today, in memory only (section 26).
    connect_prefixes: connect::PrefixLimiter,
    /// The long polls that Connect teams hold, all of them together.
    connect_polls: Arc<AtomicUsize>,
}

impl Hub {
    /// Opens the directory and every active team.
    pub fn open(config: RelayConfig, stop: Arc<AtomicBool>) -> RelayResult<Arc<Self>> {
        let lock = lock_data_dir(&config)?;
        if std::fs::symlink_metadata(config.directory_path()).is_err() {
            if std::fs::symlink_metadata(config.legacy_vault_path()).is_ok() {
                return Err(RelayError::internal(
                    "This data directory holds the vault of a relay from before teams. Run `apassy-relay migrate` first.",
                ));
            }
            return Err(RelayError::internal(
                "There is no relay in the data directory. Run `apassy-relay init` first.",
            ));
        }
        let directory = Directory::open(&config)?;
        let rules = RuleSet::builtin().map_err(|_| {
            RelayError::internal("The built-in rule packs of the core cannot be loaded.")
        })?;
        let push = crate::server::push::Push::start(config.push.clone(), stop.clone())?;
        let hub = Arc::new(Self {
            public_host: crate::decision::public_host(&config.public_url),
            config: Arc::new(config),
            directory,
            teams: RwLock::new(HashMap::new()),
            legacy: RwLock::new(None),
            rules: Arc::new(rules),
            stop,
            draining: Mutex::new(HashMap::new()),
            lock: Mutex::new(Some(lock)),
            sync_transfers: Arc::new(AtomicUsize::new(0)),
            push,
            connect_prefixes: connect::PrefixLimiter::default(),
            connect_polls: Arc::new(AtomicUsize::new(0)),
        });
        let rows = hub.directory.teams()?;
        finish_migration(&hub.config, &rows);
        for row in &rows {
            if row.legacy {
                *hub.legacy.write().unwrap_or_else(PoisonError::into_inner) = Some(row.id.clone());
            }
        }
        // Each open derives the key of its file (PBKDF2, 256 000 rounds, about 0.1 s of
        // one core): with many Connect teams, open them on several threads.
        let active: Vec<&TeamRow> = rows
            .iter()
            .filter(|row| row.state == TeamState::Active)
            .collect();
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .clamp(1, OPEN_THREADS);
        let chunk = active.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            for part in active.chunks(chunk) {
                let hub = &hub;
                scope.spawn(move || {
                    for row in part {
                        // One team that cannot be opened does not stop the others. It
                        // stays out of service until the operator suspends or deletes it.
                        if let Err(error) = hub.open_team(row) {
                            eprintln!(
                                "apassy-relay: team {} cannot be opened and is out of service: {} Suspend or delete it with `apassy-relay admin`.",
                                row.id, error.message
                            );
                        }
                    }
                });
            }
        });
        Ok(hub)
    }

    /// Opens the file of a team and adds it to the hub. A restart ends every session:
    /// a run that was `ready` becomes `ended`.
    fn open_team(&self, row: &TeamRow) -> RelayResult<Arc<Core>> {
        let store = Store::open_team(&self.config.team_path(&row.id), &row.file_key)?;
        Ok(self.register(row.id.clone(), store, row.limits, row.kind))
    }

    fn register(
        &self,
        id: TeamId,
        store: Store,
        team_limits: TeamLimits,
        kind: TeamKind,
    ) -> Arc<Core> {
        let store = Arc::new(store);
        // A Connect team's file has a cap (`TeamLimits::file_bytes`), so one anonymous
        // team cannot fill the disk.
        if store.set_max_bytes(team_limits.file_bytes(kind)).is_err() {
            eprintln!("apassy-relay: the file cap of team {id} could not be set");
        }
        let audit = Audit::new();
        if end_ready_runs(&store, &audit, crate::now_unix()).is_err() {
            eprintln!(
                "apassy-relay: the sessions of team {id} from before the start could not be ended"
            );
        }
        let limits = self.config.limits;
        let core = Arc::new(Core {
            sessions: SessionTable::new(id.clone(), store.clone(), audit.clone()),
            team: id.clone(),
            kind,
            config: self.config.clone(),
            store,
            audit,
            rules: self.rules.clone(),
            notify: Notifier::default(),
            polls: LongPolls::new(limits.long_polls_per_agent),
            host_polls: LongPolls::new(limits.host_long_polls),
            run_keys: RunKeys::default(),
            device_auth: crate::server::devices::DeviceAuthState::default(),
            public_host: self.public_host.clone(),
            sync_transfers: AtomicUsize::new(0),
            relay_sync_transfers: self.sync_transfers.clone(),
            sync_polls: LongPolls::new(1),
            sync_commit: Mutex::new(()),
            question_polls: LongPolls::new(1),
            answer_polls: LongPolls::new(1),
            question_lane: AtomicUsize::new(0),
            push: self.push.clone(),
            connect_polls: self.connect_polls.clone(),
            request_rate: connect::RequestRate::default(),
            last_request: AtomicU64::new(0),
            maintained_at: AtomicU64::new(0),
            stop: self.stop.clone(),
            closed: AtomicBool::new(false),
            team_limits: RwLock::new(team_limits),
            agent_requests: AtomicUsize::new(0),
            last_limit: Mutex::new(HashMap::new()),
        });
        self.teams
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, core.clone());
        core
    }

    /// An active team.
    pub fn team(&self, id: &TeamId) -> Option<Arc<Core>> {
        self.teams
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// The team of a credential: the team id in it, or for a member or agent token of
    /// the first alpha (no team id), the migrated team. `None` for anything else.
    pub fn for_token(&self, token: &str) -> Option<Arc<Core>> {
        let parsed = parse_token(token)?;
        match parsed.team {
            Some(team) => self.team(&team),
            None if matches!(parsed.kind, TokenKind::Member | TokenKind::Agent) => {
                let legacy = self
                    .legacy
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()?;
                self.team(&legacy)
            }
            None => None,
        }
    }

    /// Every active team.
    pub fn all(&self) -> Vec<Arc<Core>> {
        self.teams
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// `POST /v1/teams`: a one-time team code makes a team and its owner.
    pub fn create_team(
        &self,
        request: &TeamCreate,
        now: u64,
    ) -> RelayResult<(TeamId, MemberId, DeviceId)> {
        // The names are checked before the code, so a typo does not use the code up.
        checked_team_name(&request.team)?;
        admin::checked_member_name(&request.owner)?;
        let update = || {
            RelayError::invalid(format!(
                "This apassy-team is too old: update it (curl -fsSL {}/install.sh ...)",
                self.config.public_url.trim_end_matches('/')
            ))
        };
        let device_name = admin::checked_label(
            request.device_name.as_deref().ok_or_else(update)?,
            "device name",
        )?;
        let public_key =
            crate::device::decode_public_key(request.public_key.as_deref().ok_or_else(update)?)
                .map_err(|_| RelayError::invalid("The device public key is not valid."))?;
        let mut made: Option<TeamId> = None;
        let new = self.directory.store.tx(|tx| {
            // The code is checked before any work for the team.
            let code_id = directory::find_team_code(tx, request.code.expose(), now)?;
            let new = make_team_file_with_device(
                &self.config,
                &request.team,
                &request.owner,
                now,
                Some((&device_name, &public_key)),
            )?;
            made = Some(new.id.clone());
            let added = directory::mark_team_code_used(tx, code_id, &new.id, now)
                .and_then(|()| {
                    directory::insert_team(
                        tx,
                        &new.id,
                        request.team.trim(),
                        &new.file_key,
                        false,
                        now,
                    )
                })
                .and_then(|()| {
                    self.directory.audit.write_on(
                        tx,
                        now,
                        RELAY_ACTOR,
                        "team_created",
                        None,
                        &json!({"team_id": new.id, "code_id": code_id}),
                    )
                });
            added.map(|_| new)
        });
        let new = match new {
            Ok(new) => new,
            Err(error) => {
                // The team row did not commit: its file, if made, has no key anywhere.
                if let Some(id) = made {
                    let _ = remove_team_file(&self.config, &id);
                }
                return Err(error);
            }
        };
        let NewTeam {
            id,
            owner_id,
            store,
            ..
        } = new;
        let device_id = store.with(|conn| {
            conn.query_row(
                "SELECT id FROM device WHERE member_id = ?1 AND revoked_at IS NULL",
                params![to_i(owner_id.0)],
                |row| row.get::<_, i64>(0),
            )
            .map(|id| DeviceId(to_u(id)))
            .map_err(db)
        })?;
        self.register(id.clone(), store, TeamLimits::default(), TeamKind::Operator);
        Ok((id, owner_id, device_id))
    }

    /// `POST /v1/connect` (docs/SPEC.md section 26): a Connect team without a code. An
    /// ordinary team (one file, the member `owner`, its device as the key holder) with
    /// the `connect` limits. The request proves its key with a signature. One public key
    /// makes at most one Connect team, ever; one client `prefix` (the Worker's
    /// `X-Apassy-Client-Prefix`) makes at most `connect::per_prefix` of them in a UTC
    /// day; the relay makes at most `connect_teams_per_day` of them in 24 hours and
    /// holds at most `connect_teams_max`.
    ///
    /// The team file and its key (PBKDF2) are made outside the lock of `relay.db`: the
    /// checks run once before and again in the transaction that adds the team, and a
    /// team that loses the race has its file removed.
    pub fn create_connect_team(
        &self,
        request: &ConnectCreate,
        prefix: &str,
        now: u64,
    ) -> RelayResult<(TeamId, MemberId, DeviceId)> {
        if request.v != 1 {
            return Err(RelayError::invalid("The version `v` must be 1."));
        }
        let name = checked_team_name(&request.team)?.to_string();
        let device_name = admin::checked_label(&request.device_name, "device name")?;
        let public_key = crate::device::decode_public_key(&request.public_key)
            .map_err(|_| RelayError::invalid("The device public key is not valid."))?;
        let signature =
            crate::hostkeys::decode_b64(&request.signature, crate::device::MAX_SIGNATURE_BYTES)
                .map_err(|_| RelayError::invalid("The signature is not valid."))?;
        let message = crate::device::connect_message(&self.config.public_url, &request.public_key);
        if !crate::device::verify(&public_key, &message, &signature) {
            return Err(RelayError::invalid(
                "The signature is not one of the device key over the connect message.",
            ));
        }
        let key_hash = directory::connect_key_hash(&public_key);
        let per_day = self.config.connect_teams_per_day;
        let max = self.config.connect_teams_max;
        // In memory only: the count of this client prefix today.
        let ticket = self
            .connect_prefixes
            .reserve(prefix, per_day, now)
            .inspect_err(|error| self.connect_refused(now, error, "prefix"))?;
        let check = |conn: &rusqlite::Connection| -> Result<(), (RelayError, &'static str)> {
            directory::check_connect_key(conn, &key_hash, per_day, now).map_err(|e| (e, "busy"))?;
            directory::check_connect_room(conn, max).map_err(|e| (e, "full"))
        };
        // Before any work for the team.
        if let Err((error, reason)) = self.directory.store.with(|conn| Ok(check(conn)))? {
            self.connect_refused(now, &error, reason);
            return Err(error);
        }
        let new = make_team_file_with_device(
            &self.config,
            &name,
            CONNECT_OWNER,
            now,
            Some((&device_name, &public_key)),
        )?;
        let mut refused: Option<&'static str> = None;
        let added = self.directory.store.tx(|tx| {
            // Again, under the lock: another request may have used the key or the room.
            check(tx).map_err(|(error, reason)| {
                refused = Some(reason);
                error
            })?;
            directory::insert_connect_team(tx, &new.id, &name, &new.file_key, now)?;
            directory::insert_connect_key(tx, &key_hash, &new.id, now)?;
            self.directory.audit.write_on(
                tx,
                now,
                RELAY_ACTOR,
                "team_created",
                None,
                &json!({"team_id": new.id, "kind": TeamKind::Connect}),
            )?;
            Ok(())
        });
        if let Err(error) = added {
            // The team row did not commit: its file has no key anywhere.
            let id = new.id.clone();
            drop(new);
            let _ = remove_team_file(&self.config, &id);
            if let Some(reason) = refused {
                self.connect_refused(now, &error, reason);
            }
            return Err(error);
        }
        ticket.keep();
        let NewTeam {
            id,
            owner_id,
            store,
            ..
        } = new;
        let device_id = store.with(|conn| {
            conn.query_row(
                "SELECT id FROM device WHERE member_id = ?1 AND revoked_at IS NULL",
                params![to_i(owner_id.0)],
                |row| row.get::<_, i64>(0),
            )
            .map(|id| DeviceId(to_u(id)))
            .map_err(db)
        })?;
        self.register(id.clone(), store, TeamLimits::connect(), TeamKind::Connect);
        Ok((id, owner_id, device_id))
    }

    /// A `connect_refused` row in the relay audit for a refusal of the relay's own caps
    /// (503 `busy`, 429 `rate_limited`), at most one per reason and ten seconds. It names
    /// no key, no team, and nothing of the client.
    fn connect_refused(&self, now: u64, error: &RelayError, reason: &'static str) {
        let reason = match (error.code, reason) {
            (codes::RATE_LIMITED, _) => "rate_limited",
            (codes::BUSY, "prefix") => "prefixes_full",
            (codes::BUSY, "full") => "full",
            (codes::BUSY, _) => "busy",
            _ => return,
        };
        let kind = match reason {
            "rate_limited" => "connect_rate_limited",
            "prefixes_full" => "connect_prefixes_full",
            "full" => "connect_full",
            _ => "connect_busy",
        };
        self.refusal(now, kind, "connect_refused", &json!({"reason": reason}));
    }

    /// Suspends a team: its tokens stop at the next request, its sessions and waiting
    /// runs end, and its file is closed. The file and its key stay.
    pub fn suspend(&self, id: &TeamId, now: u64) -> RelayResult<()> {
        self.suspend_with(id, None, now)
    }

    /// `suspend` with a reason kept in the directory and the audits (`IDLE_REASON`).
    fn suspend_with(&self, id: &TeamId, reason: Option<&str>, now: u64) -> RelayResult<()> {
        let row = self
            .directory
            .team(id)?
            .ok_or_else(|| RelayError::not_found("team"))?;
        if row.state == TeamState::Suspended {
            return Err(RelayError::new(
                codes::CONFLICT,
                "The team is suspended already.",
            ));
        }
        self.directory
            .set_state(id, TeamState::Suspended, reason, now)?;
        let core = self
            .teams
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if let Some(core) = core {
            let detail = match reason {
                Some(reason) => json!({"reason": reason}),
                None => json!({}),
            };
            let _ = core.audit.write(
                &core.store,
                now,
                OPERATOR_ACTOR,
                "team_suspended",
                None,
                &detail,
            );
            core.close();
            self.draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id.clone(), Arc::downgrade(&core));
        }
        Ok(())
    }

    /// Opens a suspended team again.
    pub fn resume(&self, id: &TeamId, now: u64) -> RelayResult<()> {
        let row = self
            .directory
            .team(id)?
            .ok_or_else(|| RelayError::not_found("team"))?;
        if row.state == TeamState::Active {
            return Err(RelayError::new(
                codes::CONFLICT,
                "The team is active already.",
            ));
        }
        let core = self.open_team(&row)?;
        self.draining
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if let Err(error) = self.directory.set_state(id, TeamState::Active, None, now) {
            self.teams
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(id);
            core.close();
            return Err(error);
        }
        let _ = core.audit.write(
            &core.store,
            now,
            OPERATOR_ACTOR,
            "team_resumed",
            None,
            &json!({}),
        );
        Ok(())
    }

    /// Deletes a suspended team: its row and file key in the directory, then its file.
    /// There is no undo.
    pub fn delete(&self, id: &TeamId, now: u64) -> RelayResult<()> {
        let row = self
            .directory
            .team(id)?
            .ok_or_else(|| RelayError::not_found("team"))?;
        if row.state != TeamState::Suspended || self.team(id).is_some() {
            return Err(RelayError::new(
                codes::CONFLICT,
                "Suspend the team first. Only a suspended team can be deleted.",
            ));
        }
        // Requests that started before the suspension hold the team's state, and with
        // it the open file. Wait a moment for them to end.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let busy = self
                .draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(id)
                .is_some_and(|weak| weak.strong_count() > 0);
            if !busy {
                break;
            }
            if std::time::Instant::now() > deadline {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "Requests of this team still run. Try again in a moment.",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        self.directory.remove(id, now)?;
        self.draining
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        remove_team_file(&self.config, id)?;
        let mut legacy = self.legacy.write().unwrap_or_else(PoisonError::into_inner);
        if legacy.as_ref() == Some(id) {
            *legacy = None;
        }
        Ok(())
    }

    /// The teams as the operator sees them.
    pub fn team_infos(&self) -> RelayResult<Vec<TeamInfo>> {
        let mut infos = Vec::new();
        let now = crate::now_unix();
        for row in self.directory.teams()? {
            let counts = self.team(&row.id).and_then(|core| {
                core.store
                    .with(|conn| {
                        let count = |sql: &str| -> RelayResult<u64> {
                            conn.query_row(sql, [], |r| r.get::<_, i64>(0))
                                .map(to_u)
                                .map_err(db)
                        };
                        let last: Option<i64> = conn
                            .query_row("SELECT max(at) FROM audit", [], |r| r.get(0))
                            .map_err(db)?;
                        let (sync_version, sync_size): (i64, i64) = conn
                            .query_row(
                                "SELECT coalesce(max(version), 0), coalesce((SELECT size FROM sync_head ORDER BY version DESC LIMIT 1), 0) FROM sync_head",
                                [],
                                |r| Ok((r.get(0)?, r.get(1)?)),
                            )
                            .map_err(db)?;
                        let questions = crate::server::questions::counts(conn, now)?;
                        Ok((
                            count("SELECT count(*) FROM member WHERE revoked_at IS NULL")?,
                            count("SELECT count(*) FROM item WHERE archived_at IS NULL")?,
                            conn.query_row(
                                "SELECT count(*) FROM agent a JOIN member m ON m.id = a.member_id \
                                 WHERE a.revoked_at IS NULL AND a.expires_at > ?1 AND m.revoked_at IS NULL",
                                [to_i(now)],
                                |r| r.get::<_, i64>(0),
                            )
                            .map(to_u)
                            .map_err(db)?,
                            last.map(to_u),
                            to_u(sync_version),
                            to_u(sync_size),
                            questions,
                        ))
                    })
                    .ok()
            });
            infos.push(TeamInfo {
                open: self.team(&row.id).is_some(),
                id: row.id,
                name: row.name,
                state: row.state,
                legacy: row.legacy,
                created_at: row.created_at,
                suspended_at: row.suspended_at,
                kind: row.kind,
                suspend_reason: row.suspend_reason,
                limits: row.limits,
                members: counts.map(|c| c.0),
                items: counts.map(|c| c.1),
                agents: counts.map(|c| c.2),
                last_activity: counts.and_then(|c| c.3),
                sync_version: counts.map(|c| c.4),
                sync_size: counts.map(|c| c.5),
                open_questions: counts.map(|c| c.6.0),
                push_tokens: counts.map(|c| c.6.1),
            });
        }
        Ok(infos)
    }

    /// `admin connect-sweep` (docs/SPEC.md section 26.5): suspends each active Connect
    /// team whose newest sign-in of any live device (or, without one, the newest device's
    /// creation) is `idle_days` old, with the reason `idle`, however many devices it has;
    /// deletes each Connect team that a sweep suspended `delete_days` ago or earlier. A
    /// team whose limits are not `TeamLimits::connect()` (a plan lifted them) or that
    /// has a vault sync head is never swept. A team that the operator suspended, or that
    /// a sweep suspended and the operator resumed, is never deleted here. A team
    /// suspended in this run is deleted in a later one. `dry_run` changes nothing and
    /// names the same teams.
    pub fn connect_sweep(
        &self,
        idle_days: u64,
        delete_days: u64,
        dry_run: bool,
        now: u64,
    ) -> RelayResult<SweepReport> {
        for (name, days) in [("idle_days", idle_days), ("delete_days", delete_days)] {
            if !(1..=MAX_SWEEP_DAYS).contains(&days) {
                return Err(RelayError::invalid(format!(
                    "{name} must be 1 to {MAX_SWEEP_DAYS}."
                )));
            }
        }
        let idle_before = now.saturating_sub(idle_days.saturating_mul(86_400));
        let delete_before = now.saturating_sub(delete_days.saturating_mul(86_400));
        let mut report = SweepReport {
            dry_run,
            suspended: Vec::new(),
            deleted: Vec::new(),
            failed: Vec::new(),
        };
        for row in self.directory.teams()? {
            // A plan's team (lifted limits) is the operator's, not the sweep's.
            if row.kind != TeamKind::Connect || row.limits != TeamLimits::connect() {
                continue;
            }
            let done = match row.state {
                TeamState::Suspended => {
                    let due = row.suspend_reason.as_deref() == Some(directory::IDLE_REASON)
                        && row.suspended_at.is_some_and(|at| at <= delete_before);
                    if !due {
                        continue;
                    }
                    (if dry_run {
                        Ok(())
                    } else {
                        self.delete(&row.id, now)
                    })
                    .map(|()| report.deleted.push(row.id.clone()))
                }
                TeamState::Active => {
                    // A team that did not open is the operator's to look at.
                    let Some(core) = self.team(&row.id) else {
                        continue;
                    };
                    let idle = core.store.with(|conn| {
                        let (last, heads): (Option<i64>, i64) = conn
                            .query_row(
                                "SELECT (SELECT max(coalesce(d.last_seen_at, d.created_at)) \
                                 FROM device d JOIN member m ON m.id = d.member_id \
                                 WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL), \
                                 (SELECT count(*) FROM sync_head)",
                                [],
                                |r| Ok((r.get(0)?, r.get(1)?)),
                            )
                            .map_err(db)?;
                        Ok(heads == 0 && last.map_or(row.created_at, to_u) <= idle_before)
                    });
                    match idle {
                        Ok(false) => continue,
                        Ok(true) => (if dry_run {
                            Ok(())
                        } else {
                            self.suspend_with(&row.id, Some(directory::IDLE_REASON), now)
                        })
                        .map(|()| report.suspended.push(row.id.clone())),
                        Err(error) => Err(error),
                    }
                }
            };
            if let Err(error) = done {
                report
                    .failed
                    .push(json!({"team": row.id, "error": error.message}));
            }
        }
        Ok(report)
    }

    /// Reads or changes the effective limits of a team.
    pub fn limits(
        &self,
        id: &TeamId,
        set: Option<TeamLimitsUpdate>,
        now: u64,
    ) -> RelayResult<TeamLimits> {
        let Some(update) = set else {
            return self
                .directory
                .team(id)?
                .map(|row| row.limits)
                .ok_or_else(|| RelayError::not_found("team"));
        };
        // A suspended team can still have requests that hold its open file.
        let core = self.team(id).or_else(|| {
            self.draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(id)
                .and_then(Weak::upgrade)
        });
        let limits = self.directory.store.tx(|tx| {
            let row =
                directory::team_by_id(tx, id)?.ok_or_else(|| RelayError::not_found("team"))?;
            let limits = row.limits.apply(update)?;
            let (store, audit) = match &core {
                Some(core) => (core.store.clone(), core.audit.clone()),
                None => (
                    Arc::new(Store::open_team(&self.config.team_path(id), &row.file_key)?),
                    Audit::new(),
                ),
            };
            let detail = json!({"team_id": id, "limits": limits});
            // Question limits at their default stay out of the column, so the image
            // before questions can read it after a rollback.
            let text = limits.stored_json()?;
            tx.execute(
                "UPDATE team SET limits = ?1 WHERE id = ?2",
                params![text, id.as_str()],
            )
            .map_err(db)?;
            self.directory.audit.write_on(
                tx,
                now,
                OPERATOR_ACTOR,
                "limits_changed",
                None,
                &detail,
            )?;
            audit.write(&store, now, OPERATOR_ACTOR, "limits_changed", None, &detail)?;
            Ok(limits)
        })?;
        if let Some(core) = core {
            *core
                .team_limits
                .write()
                .unwrap_or_else(PoisonError::into_inner) = limits;
            // The file cap follows the limits (a plan that lifts them lifts it).
            core.store.set_max_bytes(limits.file_bytes(core.kind))?;
        }
        Ok(limits)
    }

    /// `admin backup`: a consistent copy of `relay.db` and of every team file in a new
    /// folder `<backup dir>/<UTC time>` (mode 0700, files 0600), with `MANIFEST.json`.
    /// Each file is copied while its connection is locked. The vault snapshots of a team
    /// go to `teams/<id>.sync/`. The files stay encrypted: the master key is not in the
    /// backup.
    pub fn backup(&self, now: u64) -> RelayResult<serde_json::Value> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::DirBuilderExt;
        let name = crate::cli::commands::fmt_time(now)
            .replace(' ', "T")
            .replace(':', "-");
        let dir = self.config.backup_dir.join(&name);
        let teams_dir = dir.join(crate::config::TEAMS_DIR);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.config.backup_dir)
            .map_err(|_| RelayError::internal("The backup folder cannot be created."))?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|error| {
                if error.kind() == ErrorKind::AlreadyExists {
                    RelayError::new(
                        codes::CONFLICT,
                        "A backup of this second exists. Try again.",
                    )
                } else {
                    RelayError::internal("The backup folder cannot be created.")
                }
            })?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&teams_dir)
            .map_err(|_| RelayError::internal("The backup folder cannot be created."))?;
        let mut copied: Vec<(String, std::path::PathBuf, u64)> = Vec::new();
        let target = dir.join(crate::config::DIRECTORY_FILE);
        let bytes = self
            .directory
            .store
            .copy_to(&self.config.directory_path(), &target)?;
        copied.push((crate::config::DIRECTORY_FILE.to_string(), target, bytes));
        let rows = self.directory.teams()?;
        for row in &rows {
            let source = self.config.team_path(&row.id);
            let file = format!("{}/{}.db", crate::config::TEAMS_DIR, row.id);
            let target = dir.join(&file);
            let bytes = match self.team(&row.id) {
                Some(core) => core.store.copy_to(&source, &target)?,
                // A suspended team (or one that did not open) has no open connection.
                None if std::fs::symlink_metadata(&source).is_ok() => {
                    crate::server::store::copy_private(&source, &target)?
                }
                None => continue,
            };
            copied.push((file, target, bytes));
            copied.extend(self.copy_snapshots(&row.id, &dir)?);
        }
        let mut files = Vec::new();
        for (file, path, bytes) in &copied {
            // Read back in pieces: a snapshot can be large.
            let read_back = || RelayError::internal("A backup file cannot be read back.");
            let mut source = std::fs::File::open(path).map_err(|_| read_back())?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let read =
                    std::io::Read::read(&mut source, &mut buffer).map_err(|_| read_back())?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let hex = crate::sync_head::hex(&hasher.finalize());
            files.push(json!({"name": file, "bytes": bytes, "sha256": hex}));
        }
        let manifest = json!({
            "dir": dir.to_string_lossy(),
            "created_at": now,
            "teams": rows.len(),
            "files": files,
        });
        let text = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| RelayError::internal("The manifest cannot be written."))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("MANIFEST.json"))
            .map_err(|_| RelayError::internal("The manifest cannot be written."))?;
        std::io::Write::write_all(&mut file, &text)
            .and_then(|()| file.sync_all())
            .map_err(|_| RelayError::internal("The manifest cannot be written."))?;
        let _ = self.directory.audit.write(
            &self.directory.store,
            now,
            OPERATOR_ACTOR,
            "backup_made",
            None,
            &json!({"name": name, "teams": rows.len()}),
        );
        Ok(manifest)
    }

    /// Copies the vault snapshots of one team (`teams/<id>.sync/<version>.bin`) into a
    /// backup folder, while no push or delete of that team can commit. Returns the names
    /// relative to the folder, the paths, and the sizes.
    fn copy_snapshots(
        &self,
        id: &TeamId,
        dir: &std::path::Path,
    ) -> RelayResult<Vec<(String, std::path::PathBuf, u64)>> {
        use std::os::unix::fs::DirBuilderExt;
        let source = self.config.sync_dir(id);
        let core = self.team(id);
        let _commit = core.as_ref().map(|core| {
            core.sync_commit
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        });
        let entries = match std::fs::read_dir(&source) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(RelayError::internal(
                    "The snapshots of a team cannot be read.",
                ));
            }
        };
        let mut names: Vec<String> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| crate::server::sync::is_snapshot_name(name))
            .collect();
        names.sort();
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let folder = format!("{}/{id}.sync", crate::config::TEAMS_DIR);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join(&folder))
            .map_err(|_| RelayError::internal("The backup folder cannot be created."))?;
        let mut copied = Vec::new();
        for name in names {
            let file = format!("{folder}/{name}");
            let target = dir.join(&file);
            let bytes = crate::server::store::copy_private(&source.join(&name), &target)?;
            copied.push((file, target, bytes));
        }
        Ok(copied)
    }

    /// Ends every session and drops every run key of every team, and releases the lock
    /// of the data directory (at stop).
    pub fn close_all(&self) {
        for core in self.all() {
            core.close();
        }
        if let Some(lock) = self
            .lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = lock.unlock();
        }
    }

    /// Writes a refused request that names no known team to the audit of the relay.
    /// At most one row per 10 seconds for each kind.
    pub fn refusal(&self, now: u64, kind: &'static str, action: &str, detail: &serde_json::Value) {
        self.directory
            .audit
            .refusal(&self.directory.store, now, kind, action, detail);
    }
}

/// Ends the sessions that a stop ended: each `ready` run becomes `ended`.
fn end_ready_runs(store: &Store, audit: &Audit, now: u64) -> RelayResult<()> {
    store.tx(|tx| {
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
    })
}

impl SessionSource for Hub {
    fn find(&self, session_key: &str, now: u64) -> Option<Arc<LiveSession>> {
        let parsed = parse_token(session_key)?;
        if parsed.kind != TokenKind::Session {
            return None;
        }
        self.team(parsed.team.as_ref()?)?
            .sessions
            .find(session_key, now)
    }

    fn record(&self, event: ProxyEvent) {
        if let Some(core) = event.team.as_ref().and_then(|team| self.team(team)) {
            core.sessions.record(event);
            return;
        }
        // No session was found: the request names no live session of any team.
        self.refusal(
            event.at,
            "proxy",
            "proxy_refused",
            &json!({"code": event.code, "status": event.status}),
        );
    }
}
