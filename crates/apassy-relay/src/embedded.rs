//! The embedded node (docs/SPEC.md section 30): the relay inside the Mac app, behind
//! the traits of `apassy::node::backend`.
//!
//! The node is an ordinary relay with `RelayConfig::embedded`: no edge, every listener
//! on the loopback, a public listener for `POST /mcp` and `/p/` that Tailscale Funnel
//! reaches. Each vault has one personal team (`Hub::create_personal_team`) with one
//! collection, `CATALOG_COLLECTION`, whose items hold metadata only
//! (`hostkeys::VALUE_ON_HOST`). The app is the host, in the same process: it acts as the
//! team's owner member without a token, and it releases a run with the values from the
//! vault (`host::release_values`). Nothing secret is written to the node's directory.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy::node::backend::{
    self as node, AuditRow, CatalogItem, CreatedAgent, NewCloudAgent, NodeAgentId, NodeBackend,
    NodeConfig, NodeError, NodeRunId, NodeSecret, NodeTeamId, PendingItem, PendingRun, RunState,
    RunningNode, SyncReport,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::api::{
    AgentCreate, CollectionCreate, DecisionRequest, GrantCreate, NewItem, Policy, PolicyMode, Role,
    RunStatus, Suggestion,
};
use crate::config::{EmbeddedOptions, RelayConfig, UpstreamOptions};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys;
use crate::ids::{AgentId, CollectionId, ItemId, MemberId, RunId, TeamId};
use crate::now_unix;
use crate::secret::SecretString;
use crate::server::approvals::{self, Denier, RunRow};
use crate::server::auth::MemberAuth;
use crate::server::host::{self, EmbeddedRequest};
use crate::server::hub::Hub;
use crate::server::store::{ItemRow, db, load_item, load_live_items, to_i, to_u};
use crate::server::{Core, Relay, RunningRelay, admin};

/// The collection of the catalog mirror in a personal team. Its policy asks for every
/// run, and the owner member has its grant.
pub const CATALOG_COLLECTION: &str = "cloud";

/// The longest wait of `RunningNode::wait_pending`.
const MAX_PENDING_WAIT: Duration = Duration::from_secs(3600);

/// Starts embedded nodes (`apassy::node::backend::NodeBackend`).
#[derive(Debug, Clone, Default)]
pub struct EmbeddedRelay {
    /// How the proxy reaches upstream hosts. The default (system roots, DNS) is the
    /// product's; tests add a root and fixed addresses.
    pub upstream: UpstreamOptions,
}

fn node_error(error: RelayError) -> NodeError {
    NodeError::new(error.code, error.message)
}

impl NodeBackend for EmbeddedRelay {
    fn start(&self, config: NodeConfig) -> Result<Box<dyn RunningNode>, NodeError> {
        let NodeConfig {
            data_dir,
            master_key,
            public_url,
            public_listen,
        } = config;
        let mut relay = RelayConfig::embedded(EmbeddedOptions {
            data_dir,
            master_key: SecretString::new(master_key.expose().to_owned()),
            public_url,
            public_listen,
        })
        .map_err(node_error)?;
        relay.upstream = self.upstream.clone();
        let node = EmbeddedNode::start(relay).map_err(node_error)?;
        Ok(Box::new(node))
    }
}

/// A running embedded node.
pub struct EmbeddedNode {
    running: RunningRelay,
    hub: Arc<Hub>,
}

impl EmbeddedNode {
    /// Starts a node with `config` (normally `RelayConfig::embedded`). The first start
    /// makes the directory `relay.db` with no team.
    pub fn start(config: RelayConfig) -> RelayResult<Self> {
        // Before anything is made in the data directory.
        config.check_listeners()?;
        if std::fs::symlink_metadata(config.directory_path()).is_err() {
            Relay::init_empty(&config)?;
        }
        let running = Relay::start(config)?;
        let hub = running.hub();
        Ok(Self { running, hub })
    }

    /// The teams of the node.
    pub fn hub(&self) -> Arc<Hub> {
        self.hub.clone()
    }

    /// The relay of the node: its listeners and their URLs.
    pub fn running(&self) -> &RunningRelay {
        &self.running
    }

    fn core(&self, team: &NodeTeamId) -> RelayResult<Arc<Core>> {
        TeamId::parse(&team.0)
            .and_then(|id| self.hub.team(&id))
            .ok_or_else(|| RelayError::not_found("team"))
    }
}

/// The owner member of a personal team, as the in-process host acts for it.
fn owner(core: &Core) -> RelayResult<MemberAuth> {
    core.store.with(|conn| {
        conn.query_row(
            "SELECT id, name FROM member WHERE role = 'owner' AND revoked_at IS NULL \
             ORDER BY id LIMIT 1",
            [],
            |row| {
                Ok(MemberAuth {
                    id: MemberId(to_u(row.get(0)?)),
                    name: row.get(1)?,
                    role: Role::Owner,
                    device: None,
                })
            },
        )
        .optional()
        .map_err(db)?
        .ok_or_else(|| RelayError::not_found("owner"))
    })
}

/// The catalog collection of a personal team, made with its grant when it is not there.
fn ensure_catalog(core: &Core, owner: &MemberAuth, now: u64) -> RelayResult<CollectionId> {
    let found: Option<i64> = core.store.with(|conn| {
        conn.query_row(
            "SELECT id FROM collection WHERE name = ?1",
            params![CATALOG_COLLECTION],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)
    })?;
    if let Some(id) = found {
        return Ok(CollectionId(to_u(id)));
    }
    let created = admin::collection_create(
        core,
        owner,
        CollectionCreate {
            name: CATALOG_COLLECTION.to_string(),
            policy: Policy {
                mode: PolicyMode::Ask,
                ..Policy::default()
            },
        },
        now,
    )?;
    let id = created["id"]
        .as_u64()
        .map(CollectionId)
        .ok_or_else(|| RelayError::internal("The catalog collection has no id."))?;
    admin::grant_create(
        core,
        owner,
        &GrantCreate {
            collection_id: id,
            member_id: owner.id,
        },
        now,
    )?;
    Ok(id)
}

/// The item with this uid, live or archived.
fn item_by_uid(conn: &Connection, uid: &str) -> RelayResult<Option<ItemRow>> {
    let id: Option<i64> = conn
        .query_row("SELECT id FROM item WHERE uid = ?1", params![uid], |row| {
            row.get(0)
        })
        .optional()
        .map_err(db)?;
    match id {
        Some(id) => load_item(conn, ItemId(to_u(id))),
        None => Ok(None),
    }
}

/// The ids of the live catalog items with these uids, in their order.
fn live_ids(core: &Core, collection: CollectionId, uids: &[String]) -> RelayResult<Vec<ItemId>> {
    core.store.with(|conn| {
        uids.iter()
            .map(|uid| match item_by_uid(conn, uid)? {
                Some(item) if !item.archived && item.collection_id == collection => Ok(item.id),
                _ => Err(RelayError::invalid(
                    "An item of the agent's list is not in the catalog.",
                )),
            })
            .collect()
    })
}

/// The request of `POST /v1/items` for a catalog item: `admin::checked_item` checks it.
fn new_item(collection: CollectionId, item: &CatalogItem) -> NewItem {
    NewItem {
        collection_id: collection,
        name: item.name.clone(),
        env_name: item.env_name.clone(),
        uid: item.uid.clone(),
        sealed: String::new(),
        provider: item.provider.clone(),
        hosts: item.hosts.clone(),
        environment: item.environment.clone(),
        risk: item.risk.clone(),
        scope: item.scope.clone(),
        reversibility: item.reversibility.clone(),
        allow_broad_host: item.allow_broad_host,
    }
}

fn pending_run(request: EmbeddedRequest) -> PendingRun {
    let EmbeddedRequest {
        run,
        agent,
        items,
        suggestion,
    } = request;
    PendingRun {
        run_id: NodeRunId(run.id.0),
        agent_id: NodeAgentId(run.agent_id.0),
        agent,
        items: items
            .into_iter()
            .map(|item| PendingItem {
                uid: item.uid,
                name: item.name,
                env_name: item.env_name,
            })
            .collect(),
        command: run.command,
        purpose: run.purpose,
        user_request: run.user_request,
        cwd: run.cwd,
        ttl_secs: run.ttl_secs,
        flags: run.flags,
        note: run.note,
        suggestion: match suggestion {
            Suggestion::Allow => node::Suggestion::Allow,
            Suggestion::Ask => node::Suggestion::Ask,
        },
        created_at: run.created_at,
        expires_at: run.expires_at.unwrap_or(0),
    }
}

fn state_of(run: RunRow) -> RunState {
    RunState {
        run_id: NodeRunId(run.id.0),
        status: match run.status {
            RunStatus::Pending => node::RunStatus::Pending,
            RunStatus::Ready => node::RunStatus::Ready,
            RunStatus::Denied => node::RunStatus::Denied,
            RunStatus::TimedOut => node::RunStatus::TimedOut,
            RunStatus::Ended => node::RunStatus::Ended,
        },
        code: run.code,
        note: run.note,
        decided_at: run.decided_at,
        session_expires_at: run.session_expires_at,
    }
}

impl EmbeddedNode {
    fn sync(&self, team: &NodeTeamId, items: &[CatalogItem]) -> RelayResult<SyncReport> {
        let now = now_unix();
        let core = self.core(team)?;
        let owner = owner(&core)?;
        let collection = ensure_catalog(&core, &owner, now)?;
        // Every item is checked before anything changes: a bad item changes nothing.
        let wanted = items
            .iter()
            .map(|item| {
                admin::checked_item(&new_item(collection, item), || {
                    Ok(hostkeys::VALUE_ON_HOST.to_vec())
                })
            })
            .collect::<RelayResult<Vec<_>>>()?;
        let uids: HashSet<&str> = wanted.iter().map(|item| item.uid.as_str()).collect();
        if uids.len() != wanted.len() {
            return Err(RelayError::invalid("Two catalog items have the same uid."));
        }
        let mut report = SyncReport::default();
        // Archive first, so a variable that moves to another item is free again.
        let live = core
            .store
            .with(|conn| load_live_items(conn, Some(collection)))?;
        for row in &live {
            if !uids.contains(row.uid.as_str()) {
                admin::item_archive(&core, &owner, row.id, now)?;
                report.archived += 1;
            }
        }
        for item in &wanted {
            match core.store.with(|conn| item_by_uid(conn, &item.uid))? {
                Some(row) if row.collection_id != collection => {
                    return Err(RelayError::new(
                        codes::CONFLICT,
                        "An item with this uid exists.",
                    ));
                }
                Some(row) if admin::item_matches(&core, &row, item) => report.unchanged += 1,
                Some(row) => {
                    admin::item_update(&core, &owner, row.id, item, now)?;
                    report.changed += 1;
                }
                None => {
                    admin::insert_item(&core, &owner, collection, item, now)?;
                    report.added += 1;
                }
            }
        }
        Ok(report)
    }

    fn audit(
        &self,
        team: &NodeTeamId,
        run: Option<NodeRunId>,
        limit: u32,
    ) -> RelayResult<Vec<AuditRow>> {
        if !(1..=500).contains(&limit) {
            return Err(RelayError::invalid("The limit is from 1 to 500."));
        }
        let core = self.core(team)?;
        core.store.with(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT id, at, actor, action, run_id, detail FROM audit \
                     WHERE (?1 IS NULL OR run_id = ?1) ORDER BY id DESC LIMIT ?2",
                )
                .map_err(db)?;
            let rows = statement
                .query_map(
                    params![run.map(|run| to_i(run.0)), i64::from(limit)],
                    |row| {
                        Ok(AuditRow {
                            id: to_u(row.get(0)?),
                            at: to_u(row.get(1)?),
                            actor: row.get(2)?,
                            action: row.get(3)?,
                            run_id: row.get::<_, Option<i64>>(4)?.map(|id| NodeRunId(to_u(id))),
                            detail: row.get(5)?,
                        })
                    },
                )
                .map_err(db)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db)
        })
    }
}

impl RunningNode for EmbeddedNode {
    fn node_addr(&self) -> SocketAddr {
        self.running.addr
    }

    fn public_addr(&self) -> Option<SocketAddr> {
        self.running.public_addr
    }

    fn create_team(&self, name: &str) -> Result<NodeTeamId, NodeError> {
        (|| -> RelayResult<NodeTeamId> {
            let now = now_unix();
            let id = self.hub.create_personal_team(name, now)?;
            let core = self
                .hub
                .team(&id)
                .ok_or_else(|| RelayError::not_found("team"))?;
            ensure_catalog(&core, &owner(&core)?, now)?;
            Ok(NodeTeamId(id.as_str().to_string()))
        })()
        .map_err(node_error)
    }

    fn has_team(&self, team: &NodeTeamId) -> bool {
        self.core(team).is_ok()
    }

    fn check_value(&self, value: &NodeSecret) -> Result<(), NodeError> {
        hostkeys::check_value(value.expose())
            .map_err(|problem| NodeError::new(codes::INVALID_REQUEST, problem.message()))
    }

    fn sync_items(
        &self,
        team: &NodeTeamId,
        items: &[CatalogItem],
    ) -> Result<SyncReport, NodeError> {
        self.sync(team, items).map_err(node_error)
    }

    fn create_agent(
        &self,
        team: &NodeTeamId,
        agent: &NewCloudAgent,
    ) -> Result<CreatedAgent, NodeError> {
        (|| -> RelayResult<CreatedAgent> {
            let now = now_unix();
            let core = self.core(team)?;
            let owner = owner(&core)?;
            let collection = ensure_catalog(&core, &owner, now)?;
            let items = live_ids(&core, collection, &agent.items)?;
            let request = AgentCreate {
                name: agent.name.clone(),
                days: Some(agent.lifetime_days),
            };
            let made = admin::insert_agent(&core, &owner, &request, Some(&items), now)?;
            Ok(CreatedAgent {
                agent_id: NodeAgentId(made.id.0),
                token: NodeSecret::new(made.token.expose().to_owned()),
                expires_at: made.expires_at,
            })
        })()
        .map_err(node_error)
    }

    fn set_agent_items(
        &self,
        team: &NodeTeamId,
        agent: NodeAgentId,
        items: &[String],
    ) -> Result<(), NodeError> {
        (|| -> RelayResult<()> {
            let now = now_unix();
            let core = self.core(team)?;
            let owner = owner(&core)?;
            let collection = ensure_catalog(&core, &owner, now)?;
            let items = live_ids(&core, collection, items)?;
            admin::agent_set_items(&core, &owner, AgentId(agent.0), Some(&items), now)
        })()
        .map_err(node_error)
    }

    fn revoke_agent(&self, team: &NodeTeamId, agent: NodeAgentId) -> Result<(), NodeError> {
        (|| -> RelayResult<()> {
            let core = self.core(team)?;
            let owner = owner(&core)?;
            admin::agent_revoke(&core, &owner, AgentId(agent.0), now_unix()).map(drop)
        })()
        .map_err(node_error)
    }

    fn wait_pending(
        &self,
        team: &NodeTeamId,
        timeout: Duration,
    ) -> Result<Vec<PendingRun>, NodeError> {
        let core = self.core(team).map_err(node_error)?;
        let deadline = Instant::now() + timeout.min(MAX_PENDING_WAIT);
        loop {
            let seen = core.notify.current();
            let list = host::embedded_requests(&core, now_unix()).map_err(node_error)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !list.is_empty() || remaining.is_zero() || core.stopping() {
                return Ok(list.into_iter().map(pending_run).collect());
            }
            core.notify
                .wait_from(seen, remaining.min(Duration::from_millis(500)));
        }
    }

    fn release(
        &self,
        team: &NodeTeamId,
        run: NodeRunId,
        values: Vec<NodeSecret>,
        reason: Option<&str>,
    ) -> Result<RunState, NodeError> {
        (|| -> RelayResult<RunState> {
            let core = self.core(team)?;
            let values: Vec<SecretString> = values
                .iter()
                .map(|value| SecretString::new(value.expose().to_owned()))
                .collect();
            host::release_values(&core, RunId(run.0), values, reason, now_unix())?;
            host::embedded_run(&core, RunId(run.0), now_unix()).map(state_of)
        })()
        .map_err(node_error)
    }

    fn deny(&self, team: &NodeTeamId, run: NodeRunId, reason: &str) -> Result<RunState, NodeError> {
        (|| -> RelayResult<RunState> {
            let core = self.core(team)?;
            let request = DecisionRequest {
                reason: Some(reason.to_string()),
            };
            approvals::deny(&core, Denier::Embedded, RunId(run.0), &request, now_unix())?;
            host::embedded_run(&core, RunId(run.0), now_unix()).map(state_of)
        })()
        .map_err(node_error)
    }

    fn run_state(&self, team: &NodeTeamId, run: NodeRunId) -> Result<RunState, NodeError> {
        (|| -> RelayResult<RunState> {
            let core = self.core(team)?;
            host::embedded_run(&core, RunId(run.0), now_unix()).map(state_of)
        })()
        .map_err(node_error)
    }

    fn recent_audit(
        &self,
        team: &NodeTeamId,
        run: Option<NodeRunId>,
        limit: u32,
    ) -> Result<Vec<AuditRow>, NodeError> {
        self.audit(team, run, limit).map_err(node_error)
    }

    fn stop(self: Box<Self>) {
        let node = *self;
        node.running.stop();
    }
}
