//! The teams of one relay (ADR 0019, docs/SPEC.md "Teams").
//!
//! Each active team is one `Core`: its own file, audit, sessions, run keys, and long
//! polls. The hub finds the team of a request from the team id in its credential
//! before it opens anything, and gives the handler that one team. No map spans teams,
//! so ids that repeat between teams (run 5, member 1) never meet.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, PoisonError, RwLock};

use apassy::broker::packs::RuleSet;
use rusqlite::params;
use serde::Serialize;
use serde_json::json;

use crate::api::{Role, TeamCreate};
use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{MemberId, TeamId};
use crate::secret::{SecretString, TokenKind, new_file_key, new_token, parse_token, token_hash};
use crate::server::approvals::{LongPolls, Notifier};
use crate::server::audit::{Audit, RELAY_ACTOR};
use crate::server::directory::{self, Directory, OPERATOR_ACTOR, TeamRow, TeamState};
use crate::server::runkeys::RunKeys;
use crate::server::sessions::SessionTable;
use crate::server::store::{Store, db, to_i, to_u};
use crate::server::{Core, admin, auth};
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
            "INSERT INTO team (id, name, created_at) VALUES (1, ?1, ?2)",
            params![name, to_i(now)],
        )
        .map_err(db)?;
        tx.execute(
            "INSERT INTO member (name, role, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                owner,
                auth::role_text(Role::Owner),
                hash.0.as_slice(),
                to_i(now)
            ],
        )
        .map_err(db)?;
        let owner_id = to_u(tx.last_insert_rowid());
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

/// Deletes the file of a team and its journal, if any.
pub fn remove_team_file(config: &RelayConfig, id: &TeamId) {
    let path = config.team_path(id);
    let _ = std::fs::remove_file(&path);
    let mut journal = path.into_os_string();
    journal.push("-journal");
    let _ = std::fs::remove_file(journal);
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
    /// Counts and the time of the last audit row. `None` while the team is suspended.
    pub members: Option<u64>,
    pub items: Option<u64>,
    pub agents: Option<u64>,
    pub last_activity: Option<u64>,
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
}

impl Hub {
    /// Opens the directory and every active team.
    pub fn open(config: RelayConfig, stop: Arc<AtomicBool>) -> RelayResult<Arc<Self>> {
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
        let hub = Arc::new(Self {
            public_host: crate::decision::public_host(&config.public_url),
            config: Arc::new(config),
            directory,
            teams: RwLock::new(HashMap::new()),
            legacy: RwLock::new(None),
            rules: Arc::new(rules),
            stop,
        });
        for row in hub.directory.teams()? {
            if row.legacy {
                *hub.legacy.write().unwrap_or_else(PoisonError::into_inner) = Some(row.id.clone());
            }
            if row.state == TeamState::Active {
                hub.open_team(&row)?;
            }
        }
        Ok(hub)
    }

    /// Opens the file of a team and adds it to the hub. A restart ends every session:
    /// a run that was `ready` becomes `ended`.
    fn open_team(&self, row: &TeamRow) -> RelayResult<Arc<Core>> {
        let store = Store::open_team(&self.config.team_path(&row.id), &row.file_key)?;
        Ok(self.register(row.id.clone(), store))
    }

    fn register(&self, id: TeamId, store: Store) -> Arc<Core> {
        let store = Arc::new(store);
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
            config: self.config.clone(),
            store,
            audit,
            rules: self.rules.clone(),
            notify: Notifier::default(),
            polls: LongPolls::new(limits.long_polls_per_agent),
            host_polls: LongPolls::new(limits.host_long_polls),
            run_keys: RunKeys::default(),
            public_host: self.public_host.clone(),
            stop: self.stop.clone(),
            closed: AtomicBool::new(false),
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
    ) -> RelayResult<(TeamId, MemberId, SecretString)> {
        // The names are checked before the code, so a typo does not use the code up.
        checked_team_name(&request.team)?;
        admin::checked_member_name(&request.owner)?;
        let new = self.directory.store.tx(|tx| {
            // The code is checked before any work for the team.
            let code_id = directory::find_team_code(tx, request.code.expose(), now)?;
            let new = make_team_file(&self.config, &request.team, &request.owner, now)?;
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
            match added {
                Ok(_) => Ok(new),
                Err(error) => {
                    let id = new.id.clone();
                    drop(new);
                    remove_team_file(&self.config, &id);
                    Err(error)
                }
            }
        })?;
        let NewTeam {
            id,
            owner_id,
            owner_token,
            store,
            ..
        } = new;
        self.register(id.clone(), store);
        Ok((id, owner_id, owner_token))
    }

    /// Suspends a team: its tokens stop at the next request, its sessions and waiting
    /// runs end, and its file is closed. The file and its key stay.
    pub fn suspend(&self, id: &TeamId, now: u64) -> RelayResult<()> {
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
        self.directory.set_state(id, TeamState::Suspended, now)?;
        let core = self
            .teams
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if let Some(core) = core {
            let _ = core.audit.write(
                &core.store,
                now,
                OPERATOR_ACTOR,
                "team_suspended",
                None,
                &json!({}),
            );
            core.close();
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
        if let Err(error) = self.directory.set_state(id, TeamState::Active, now) {
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
        self.directory.remove(id, now)?;
        remove_team_file(&self.config, id);
        let mut legacy = self.legacy.write().unwrap_or_else(PoisonError::into_inner);
        if legacy.as_ref() == Some(id) {
            *legacy = None;
        }
        Ok(())
    }

    /// The teams as the operator sees them.
    pub fn team_infos(&self) -> RelayResult<Vec<TeamInfo>> {
        let mut infos = Vec::new();
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
                        Ok((
                            count("SELECT count(*) FROM member WHERE revoked_at IS NULL")?,
                            count("SELECT count(*) FROM item WHERE archived_at IS NULL")?,
                            count("SELECT count(*) FROM agent WHERE revoked_at IS NULL")?,
                            last.map(to_u),
                        ))
                    })
                    .ok()
            });
            infos.push(TeamInfo {
                id: row.id,
                name: row.name,
                state: row.state,
                legacy: row.legacy,
                created_at: row.created_at,
                suspended_at: row.suspended_at,
                members: counts.map(|c| c.0),
                items: counts.map(|c| c.1),
                agents: counts.map(|c| c.2),
                last_activity: counts.and_then(|c| c.3),
            });
        }
        Ok(infos)
    }

    /// Ends every session and drops every run key of every team (at stop).
    pub fn close_all(&self) {
        for core in self.all() {
            core.close();
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
