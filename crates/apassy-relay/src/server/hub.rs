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
use rusqlite::{OptionalExtension, params};
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

fn sweep_idle(conn: &rusqlite::Connection, created_at: u64, before: u64) -> RelayResult<bool> {
    let (last, heads): (Option<i64>, i64) = conn
        .query_row(
            "SELECT (SELECT max(coalesce(d.last_seen_at, d.created_at)) FROM device d \
         JOIN member m ON m.id = d.member_id WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL), \
         (SELECT count(*) FROM sync_head)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(db)?;
    Ok(heads == 0 && last.map_or(created_at, to_u) <= before)
}

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
        with(".pre-v6"),
        with(".pre-v6.tmp"),
        with(".pre-v7"),
        with(".pre-v7.tmp"),
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

/// Removes, at start, every team file that no row of `relay.db` names: a team whose
/// creation stopped between its file and the commit of its row (a crash, a kill). The key
/// of such a file was only in the row that never committed, so nothing can open it. Only
/// `teams/<team id>.db` of a well-formed id counts, with its journal, its `.pre-v*`
/// copies, and its snapshots (`remove_team_file`); other names stay. Each removal is
/// logged.
fn sweep_orphans(config: &RelayConfig, rows: &[TeamRow]) {
    let Ok(entries) = std::fs::read_dir(config.teams_dir()) else {
        return;
    };
    let known: std::collections::HashSet<&TeamId> = rows.iter().map(|row| &row.id).collect();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".db"))
            .and_then(TeamId::parse)
        else {
            continue;
        };
        if known.contains(&id) {
            continue;
        }
        match remove_team_file(config, &id) {
            Ok(()) => eprintln!(
                "apassy-relay: removed the file of team {id}: relay.db has no row for it (its creation stopped before the commit), so no key opens it"
            ),
            Err(_) => eprintln!(
                "apassy-relay: the file of team {id} has no row in relay.db and could not be removed"
            ),
        }
    }
}

/// The threads that open the team files at start, at most.
const OPEN_THREADS: usize = 8;

/// The member name of the owner of a Connect team.
pub const CONNECT_OWNER: &str = "owner";
/// The member name of the owner of an embedded node's personal team.
pub const PERSONAL_OWNER: &str = "owner";

/// The longest `idle_days` and `delete_days` of `connect-sweep`.
pub const MAX_SWEEP_DAYS: u64 = 3650;
/// Suspensions and deletions together, including failed attempts, in one sweep.
pub const MAX_SWEEP_ACTIONS: usize = 10;

/// What `admin connect-sweep` did, or would do (`dry_run`).
#[derive(Debug, Serialize)]
pub struct SweepReport {
    pub dry_run: bool,
    pub action_limit: usize,
    pub capped: bool,
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
    /// The bytes of the team file in use. `None` while the team is not open.
    pub file_bytes: Option<u64>,
    /// The cap of the team file in bytes (a Connect team, docs/SPEC.md section 26.4);
    /// `None` without a cap (an operator team) or while the team is not open.
    pub file_cap: Option<u64>,
    /// How full a capped file is: `ok`, `near` (about 90 %), or `full` (about 100 %: its
    /// writes are refused with 403 `team_limit`, nothing is deleted). `None` without a
    /// cap or while the team is not open.
    pub file_level: Option<crate::server::audit::CapLevel>,
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
    connect_recovery: Mutex<HashMap<String, ([u8; 32], u64)>>,
    connect_recovery_rate: connect::RequestRate,
    /// The long polls that Connect teams hold, all of them together.
    connect_polls: Arc<AtomicUsize>,
    /// The feed long polls that Connect teams hold, all of them together.
    connect_feed_polls: Arc<AtomicUsize>,
    /// The bad codes and refresh tokens of each OAuth client of an embedded node, in
    /// memory only (docs/SPEC.md section 31.5).
    pub(crate) oauth_failures: crate::server::oauth::ClientFailures,
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
            connect_recovery: Mutex::new(HashMap::new()),
            connect_recovery_rate: connect::RequestRate::default(),
            connect_polls: Arc::new(AtomicUsize::new(0)),
            connect_feed_polls: Arc::new(AtomicUsize::new(0)),
            oauth_failures: crate::server::oauth::ClientFailures::default(),
        });
        let rows = hub.directory.teams()?;
        finish_migration(&hub.config, &rows);
        sweep_orphans(&hub.config, &rows);
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
        self.register(row.id.clone(), store, row.limits, row.kind)
    }

    /// Serves an open team file. A Connect team's file gets its cap
    /// (`TeamLimits::file_bytes`), so one anonymous team cannot fill the disk, and a small
    /// page cache (`connect::CACHE_KIB`), so a hundred of them fit the container. A cap
    /// that cannot be set after a second try refuses the team: it is not served without
    /// one. An operator team has no cap; a failure to lift one is only logged, as before.
    fn register(
        &self,
        id: TeamId,
        store: Store,
        team_limits: TeamLimits,
        kind: TeamKind,
    ) -> RelayResult<Arc<Core>> {
        let store = Arc::new(store);
        let cap = team_limits.file_bytes(kind);
        if store
            .set_max_bytes(cap)
            .or_else(|_| store.set_max_bytes(cap))
            .is_err()
        {
            if cap.is_some() {
                eprintln!(
                    "apassy-relay: the file cap of team {id} could not be set: the team is not served"
                );
                return Err(RelayError::internal(
                    "The file cap of the team could not be set.",
                ));
            }
            eprintln!("apassy-relay: the file cap of team {id} could not be lifted");
        }
        if kind == TeamKind::Connect && store.set_cache_kib(connect::CACHE_KIB).is_err() {
            eprintln!("apassy-relay: the page cache of team {id} could not be bounded");
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
            feed_polls: LongPolls::new(1),
            feed_action_polls: LongPolls::new(1),
            feed_status_polls: LongPolls::new(1),
            feed_lane: AtomicUsize::new(0),
            feed_lists: AtomicUsize::new(0),
            feed_statuses: AtomicUsize::new(0),
            feed_members: Mutex::new(HashMap::new()),
            feed_times: Mutex::new(HashMap::new()),
            feed_audit: Mutex::new(HashMap::new()),
            feed_reads: Mutex::new(HashMap::new()),
            push: self.push.clone(),
            connect_polls: self.connect_polls.clone(),
            connect_feed_polls: self.connect_feed_polls.clone(),
            request_rate: connect::RequestRate::default(),
            last_request: AtomicU64::new(0),
            maintained_at: AtomicU64::new(0),
            relay_store: self.directory.store.clone(),
            relay_audit: self.directory.audit.clone(),
            cap_warning: Mutex::new((crate::server::audit::CapLevel::Ok, 0)),
            stop: self.stop.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            team_limits: RwLock::new(team_limits),
            agent_requests: AtomicUsize::new(0),
            last_limit: Mutex::new(HashMap::new()),
        });
        self.teams
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, core.clone());
        crate::server::questions::recover_push(&core, crate::now_unix())?;
        Ok(core)
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
        self.register(id.clone(), store, TeamLimits::default(), TeamKind::Operator)?;
        Ok((id, owner_id, device_id))
    }

    /// The personal team of an embedded node (docs/SPEC.md section 30.2): a team file
    /// with its owner member, without a team code. The owner token is made, hashed into
    /// the member row, and dropped here: nobody holds it, and the node acts for the owner
    /// in process. The team has no member-token deadline (`team.member_tokens_until` is
    /// `NULL`), so the owner member stays usable in process, and the limits of
    /// `TeamLimits::personal`. A restart opens it again from `relay.db` as any team.
    pub fn create_personal_team(&self, name: &str, now: u64) -> RelayResult<TeamId> {
        let name = checked_team_name(name)?.to_string();
        let new = make_team_file(&self.config, &name, PERSONAL_OWNER, now)?;
        let limits = TeamLimits::personal();
        let added = new
            .store
            .tx(|tx| {
                tx.execute(
                    "UPDATE team SET member_tokens_until = NULL WHERE id = 1",
                    [],
                )
                .map_err(db)?;
                Ok(())
            })
            .and_then(|()| limits.stored_json(TeamKind::Operator))
            .and_then(|text| {
                self.directory.store.tx(|tx| {
                    directory::insert_team(tx, &new.id, &name, &new.file_key, false, now)?;
                    tx.execute(
                        "UPDATE team SET limits = ?1 WHERE id = ?2",
                        params![text, new.id.as_str()],
                    )
                    .map_err(db)?;
                    self.directory.audit.write_on(
                        tx,
                        now,
                        RELAY_ACTOR,
                        "team_created",
                        None,
                        &json!({"team_id": new.id, "kind": "personal"}),
                    )?;
                    Ok(())
                })
            });
        if let Err(error) = added {
            // The team row did not commit: its file has no key anywhere.
            let id = new.id.clone();
            drop(new);
            let _ = remove_team_file(&self.config, &id);
            return Err(error);
        }
        let NewTeam {
            id,
            store,
            owner_token,
            ..
        } = new;
        drop(owner_token);
        self.register(id.clone(), store, limits, TeamKind::Operator)?;
        Ok(id)
    }

    /// An existence-independent, bounded recovery challenge for a device key.
    pub fn connect_challenge(&self, public_key: &str, now: u64) -> RelayResult<serde_json::Value> {
        let public = crate::device::decode_public_key(public_key)
            .map_err(|_| RelayError::invalid("The device public key is not valid."))?;
        // Count issued challenges too: consuming a nonce must not let a flood churn
        // through the bounded table indefinitely. Independent of key existence.
        self.connect_recovery_rate
            .take(1000, now)
            .map_err(|_| connect::requests_limited())?;
        let mut challenges = self
            .connect_recovery
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        challenges.retain(|_, (_, expiry)| *expiry > now);
        if challenges.len() >= 1000 {
            return Err(directory::connect_busy());
        }
        let nonce = crate::device::new_nonce()
            .map_err(|_| RelayError::internal("The system has no random source."))?;
        let expires_at = now.saturating_add(60);
        challenges.insert(
            nonce.clone(),
            (directory::connect_key_hash(&public), expires_at),
        );
        Ok(json!({"nonce": nonce, "expires_at": expires_at, "origin": self.config.public_url}))
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
        let key_hash = directory::connect_key_hash(&public_key);
        let message = if let Some(nonce) = &request.recovery_nonce {
            // Consume before validation, including invalid signatures; restart forgets nonces.
            let challenge = self
                .connect_recovery
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(nonce);
            if !challenge.is_some_and(|(key, expiry)| key == key_hash && expiry > now) {
                return Err(RelayError::unauthenticated());
            }
            crate::device::connect_recovery_message(
                &self.config.public_url,
                &request.public_key,
                nonce,
            )
        } else {
            crate::device::connect_message(&self.config.public_url, &request.public_key)
        };
        if !crate::device::verify(&public_key, &message, &signature) {
            return Err(RelayError::invalid(
                "The signature is not one of the device key over the connect message.",
            ));
        }
        if request.recovery_nonce.is_some() {
            // Hold the directory lock while checking state and the live device. Recovery
            // never changes state, limits, names, or the key tombstone.
            return self.directory.store.with(|conn| {
                let id: Option<String> = conn.query_row(
                    "SELECT t.id FROM connect_key k JOIN team t ON t.id = k.team_id \
                     WHERE k.key_hash = ?1 AND t.state = 'active' AND t.kind = 'connect'",
                    params![key_hash.as_slice()], |r| r.get(0),
                ).optional().map_err(db)?;
                let id = id.and_then(|id| TeamId::parse(&id)).ok_or_else(directory::connect_key_used)?;
                let core = self.team(&id).ok_or_else(|| RelayError::internal("The team database is unavailable. Contact the relay operator."))?;
                core.take_request(now).map_err(|(error, _)| error)?;
                let (member, device) = core.store.with(|conn| {
                    conn.query_row(
                        "SELECT d.member_id, d.id FROM device d JOIN member m ON m.id = d.member_id \
                         WHERE d.public_key = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
                        params![public_key], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                    ).optional().map_err(db)?.ok_or_else(directory::connect_key_used)
                })?;
                Ok((id, MemberId(to_u(member)), DeviceId(to_u(device))))
            });
        }
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
        // A team that cannot be served (its cap) stays in `relay.db`, out of service like
        // a team that fails to open at start: the call answers 500.
        self.register(id.clone(), store, TeamLimits::connect(), TeamKind::Connect)?;
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
    /// There is no undo. With `free_connect_key` (a Connect team only, 400 otherwise) the
    /// device key that made the team may make a new one (docs/SPEC.md section 27.10).
    /// Returns whether a connect key was freed.
    pub fn delete(&self, id: &TeamId, free_connect_key: bool, now: u64) -> RelayResult<bool> {
        let row = self
            .directory
            .team(id)?
            .ok_or_else(|| RelayError::not_found("team"))?;
        if free_connect_key && row.kind != TeamKind::Connect {
            return Err(RelayError::invalid(
                "Only a Connect team has a connect key to free.",
            ));
        }
        if row.state != TeamState::Suspended || self.team(id).is_some() {
            return Err(RelayError::new(
                codes::CONFLICT,
                "Suspend the team first. Only a suspended team can be deleted.",
            ));
        }
        self.wait_for_drained(id)?;
        let freed = self.directory.remove(id, free_connect_key, now)?;
        self.draining
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        remove_team_file(&self.config, id)?;
        let mut legacy = self.legacy.write().unwrap_or_else(PoisonError::into_inner);
        if legacy.as_ref() == Some(id) {
            *legacy = None;
        }
        Ok(freed)
    }

    /// Freeze every possible writer before archiving or deleting a suspended team.
    fn wait_for_drained(&self, id: &TeamId) -> RelayResult<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let busy = self
                .draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(id)
                .is_some_and(|weak| weak.strong_count() > 0);
            if !busy && !self.push.has_team_jobs(id) {
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
        Ok(())
    }

    /// Private operator readiness. No corresponding public HTTP endpoint exists.
    pub fn readiness(&self) -> RelayResult<serde_json::Value> {
        let mut teams = Vec::new();
        let mut ready = true;
        let rows = self.directory.teams()?;
        let held = rows
            .iter()
            .filter(|row| row.kind == TeamKind::Connect)
            .count();
        for row in &rows {
            if row.state != TeamState::Active {
                continue;
            }
            let readable = self.team(&row.id).is_some_and(|core| {
                core.store
                    .with(|conn| {
                        let check: String = conn
                            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
                            .map_err(db)?;
                        conn.query_row("SELECT count(*) FROM team", [], |r| r.get::<_, i64>(0))
                            .map_err(db)?;
                        Ok(check == "ok")
                    })
                    .unwrap_or(false)
            });
            let full = self.team(&row.id).is_some_and(|core| {
                crate::server::audit::file_use(&core)
                    .is_ok_and(|(_, _, level)| level == Some(crate::server::audit::CapLevel::Full))
            });
            ready &= readable && !full;
            teams.push(json!({"id": row.id, "readable": readable, "file_full": full}));
        }
        Ok(
            json!({"ready": ready, "teams": teams, "push": self.push.status(),
            "connect": {"held": held, "capacity": self.config.connect_teams_max,
                "high_water": (held as u64).saturating_mul(10) >= self.config.connect_teams_max.saturating_mul(8)}}),
        )
    }

    /// Preserve the complete append-only team audit before automatic reclamation.
    /// The immutable encrypted snapshot uses the relay master key, so deleting the
    /// directory's team key cannot make the history unreadable. Archives are never pruned.
    fn archive_swept_team(&self, row: &TeamRow, idle_before: u64, now: u64) -> RelayResult<()> {
        use std::os::unix::fs::DirBuilderExt;
        self.wait_for_drained(&row.id)?;
        let directory = self.config.data_dir.join("audit-archive");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .map_err(|_| RelayError::internal("The audit archive folder cannot be created."))?;
        let archive = directory.join(format!("{}-{now}.db", row.id));
        let store = Store::open_read_only(&self.config.team_path(&row.id), &row.file_key)?;
        if !store.with(|conn| sweep_idle(conn, row.created_at, idle_before))? {
            return Err(RelayError::new(
                codes::CONFLICT,
                "The team has recent activity or a sync head; it was not deleted.",
            ));
        }
        store.with(|conn| Store::snapshot_on(conn, &archive, &self.config.master_key))?;
        // Verify readability and the audit count with the archive key before deletion.
        let archived = Store::open_read_only(&archive, &self.config.master_key)?;
        let count = |store: &Store| {
            store.with(|conn| {
                conn.query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, i64>(0))
                    .map_err(db)
            })
        };
        if count(&store)? != count(&archived)? {
            return Err(RelayError::internal("The archived audit is incomplete."));
        }
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| RelayError::internal("The audit archive folder cannot be synced."))?;
        self.directory.audit.write(&self.directory.store, now, OPERATOR_ACTOR, "team_archived", None,
            &json!({"team_id": row.id, "archive": archive.file_name().and_then(|name| name.to_str())}))?;
        Ok(())
    }

    /// The teams as the operator sees them.
    pub fn team_infos(&self) -> RelayResult<Vec<TeamInfo>> {
        let mut infos = Vec::new();
        let now = crate::now_unix();
        for row in self.directory.teams()? {
            let file = self
                .team(&row.id)
                .and_then(|core| crate::server::audit::file_use(&core).ok());
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
                file_bytes: file.map(|f| f.0),
                file_cap: file.and_then(|f| f.1),
                file_level: file.and_then(|f| f.2),
            });
        }
        Ok(infos)
    }

    /// Recheck directory limits and device activity with both stores locked, then
    /// close admission before releasing the activity lock. A fresh sign-in/use wins.
    fn suspend_idle(&self, id: &TeamId, before: u64, dry_run: bool, now: u64) -> RelayResult<bool> {
        let Some(core) = self.team(id) else {
            return Ok(false);
        };
        let changed = self.directory.store.tx(|tx| {
            let Some(row) = directory::team_by_id(tx, id)? else { return Ok(false); };
            if row.state != TeamState::Active || row.kind != TeamKind::Connect
                || row.limits != TeamLimits::connect() { return Ok(false); }
            core.store.with(|conn| {
                if !sweep_idle(conn, row.created_at, before)? { return Ok(false); }
                if !dry_run {
                    tx.execute("UPDATE team SET state = 'suspended', suspended_at = ?2, suspend_reason = 'idle' WHERE id = ?1",
                        params![id.as_str(), to_i(now)]).map_err(db)?;
                    self.directory.audit.write_on(tx, now, OPERATOR_ACTOR, "team_suspended", None,
                        &json!({"team_id": id, "reason": directory::IDLE_REASON}))?;
                    core.close();
                }
                Ok(true)
            })
        })?;
        if changed && !dry_run {
            self.teams
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(id);
            let _ = core.audit.write(
                &core.store,
                now,
                OPERATOR_ACTOR,
                "team_suspended",
                None,
                &json!({"reason": directory::IDLE_REASON}),
            );
            self.draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id.clone(), Arc::downgrade(&core));
        }
        Ok(changed)
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
            action_limit: MAX_SWEEP_ACTIONS,
            capped: false,
            suspended: Vec::new(),
            deleted: Vec::new(),
            failed: Vec::new(),
        };
        for row in self.directory.teams()? {
            if report.suspended.len() + report.deleted.len() + report.failed.len()
                >= MAX_SWEEP_ACTIONS
            {
                report.capped = true;
                break;
            }
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
                        self.archive_swept_team(&row, idle_before, now)
                            .and_then(|()| self.delete(&row.id, false, now).map(drop))
                    })
                    .map(|()| report.deleted.push(row.id.clone()))
                }
                TeamState::Active => match self.suspend_idle(&row.id, idle_before, dry_run, now) {
                    Ok(false) => continue,
                    Ok(true) => {
                        report.suspended.push(row.id.clone());
                        Ok(())
                    }
                    Err(error) => Err(error),
                },
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
            // Question limits at their default, and feed limits at the preset of the
            // team's kind, stay out of the column, so the images before them can read it
            // after a rollback.
            let text = limits.stored_json(row.kind)?;
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
    /// SQLite snapshots and the frozen directory list retain the same file keys.
    /// Each team's DB and vault snapshots are copied under its commit lock, verified,
    /// then published together. The master key is never included.
    pub fn backup(&self, now: u64) -> RelayResult<serde_json::Value> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::DirBuilderExt;
        let name = crate::cli::commands::fmt_time(now)
            .replace(' ', "T")
            .replace(':', "-");
        let published = self.config.backup_dir.join(&name);
        if published.exists() {
            return Err(RelayError::new(
                codes::CONFLICT,
                "A backup of this second exists. Try again.",
            ));
        }
        let dir = self.config.backup_dir.join(format!(".{name}.partial"));
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
        // Freeze directory membership and keys until every referenced team is copied.
        // Lock order: directory -> sync_commit -> team store (the sync commit order).
        let rows = self.directory.store.with(|conn| {
            let target = dir.join(crate::config::DIRECTORY_FILE);
            let bytes = Store::snapshot_on(conn, &target, &self.config.master_key)?;
            copied.push((crate::config::DIRECTORY_FILE.to_string(), target, bytes));
            let rows = directory::read_teams(conn)?;
            for row in &rows {
                let core = self.team(&row.id).or_else(|| {
                    self.draining
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get(&row.id)
                        .and_then(Weak::upgrade)
                });
                let _commit = core.as_ref().map(|core| {
                    core.sync_commit
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                });
                let file = format!("{}/{}.db", crate::config::TEAMS_DIR, row.id);
                let target = dir.join(&file);
                let bytes = if let Some(core) = &core {
                    core.store
                        .with(|conn| Store::snapshot_on(conn, &target, &row.file_key))?
                } else {
                    // Includes suspended and failed-open teams. Missing/unreadable is
                    // an explicit backup failure, never a successful partial manifest.
                    let store =
                        Store::open_read_only(&self.config.team_path(&row.id), &row.file_key)?;
                    store.with(|conn| Store::snapshot_on(conn, &target, &row.file_key))?
                };
                copied.push((file, target.clone(), bytes));
                copied.extend(self.copy_snapshots(&row.id, &dir)?);
                let saved = Store::open_read_only(&target, &row.file_key)?;
                saved.with(|conn| {
                    crate::server::sync::verify_snapshots(
                        conn,
                        &dir.join(format!("teams/{}.sync", row.id)),
                    )
                })?;
            }
            Ok(rows)
        })?;
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
            "dir": published.to_string_lossy(),
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
        for folder in [&teams_dir, &dir] {
            File::open(folder)
                .and_then(|file| file.sync_all())
                .map_err(|_| RelayError::internal("The backup directory cannot be synced."))?;
        }
        // A partial directory is never advertised as a completed backup.
        std::fs::rename(&dir, &published)
            .map_err(|_| RelayError::internal("The backup cannot be published."))?;
        File::open(&self.config.backup_dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| RelayError::internal("The backup directory cannot be synced."))?;
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
        File::open(dir.join(&folder))
            .and_then(|file| file.sync_all())
            .map_err(|_| RelayError::internal("The snapshot backup directory cannot be synced."))?;
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

/// Ends runs whose session or one-time release key was lost at restart.
fn end_ready_runs(store: &Store, audit: &Audit, now: u64) -> RelayResult<()> {
    store.tx(|tx| {
        let interrupted: Vec<u64> = {
            let mut statement = tx.prepare("SELECT id FROM run WHERE status = 'pending'").map_err(db)?;
            statement.query_map([], |row| Ok(to_u(row.get(0)?))).map_err(db)?
                .collect::<Result<_, _>>().map_err(db)?
        };
        for id in interrupted {
            tx.execute("UPDATE run SET status = 'ended', code = ?2, decided_by = 'revocation', decided_at = ?3, note = ?4 WHERE id = ?1",
                params![to_i(id), codes::RUN_INTERRUPTED, to_i(now),
                    "The relay restarted and discarded this run's one-time key. Request a new run when you are ready; the command was not rerun."])
                .map_err(db)?;
            audit.write_on(tx, now, RELAY_ACTOR, "run_interrupted", Some(crate::ids::RunId(id)),
                &json!({"reason": "restart"}))?;
        }

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
