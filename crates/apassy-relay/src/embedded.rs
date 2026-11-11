//! The embedded node (docs/SPEC.md section 30): the relay inside the Mac app, behind
//! the traits of `apassy::node::backend`.
//!
//! The node is an ordinary relay with `RelayConfig::embedded`: no edge, every listener
//! on the loopback, a public listener for `POST /mcp`, `/p/`, and the MCP authorization
//! flow (`server::oauth`, docs/SPEC.md section 31) that Tailscale Funnel reaches. Each
//! vault has one personal team (`Hub::create_personal_team`) with one collection,
//! `CATALOG_COLLECTION`, whose items hold metadata only
//! (`hostkeys::VALUE_ON_HOST`). The app is the host, in the same process: it acts as the
//! team's owner member without a token, and it releases a run with the values from the
//! vault (`host::release_values`). Nothing secret is written to the node's directory.
//!
//! On the tailnet (`NodeBackend::start_on_tailnet`, docs/SPEC.md section 32), the node
//! also has a tailnet listener for its TLS front, accepts sign-ins with its node origin,
//! pushes through the push gateway, and hosts teams of devices: made in process
//! (`create_device_team`) or with a node pairing code (`make_node_code`).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy::node::backend::{
    self as node, AgentAccess, AuditRow, CatalogItem, ConnectDecision, CreatedAgent, NewCloudAgent,
    NodeAgentId, NodeBackend, NodeCode, NodeConfig, NodeDevice, NodeError, NodeRunId, NodeSecret,
    NodeTailnet, NodeTeamId, PendingConnect, PendingItem, PendingRun, RunState, RunningNode,
    SyncReport, TokenIssue,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::api::{
    AgentCreate, CollectionCreate, DecisionRequest, GrantCreate, NewItem, Policy, PolicyMode, Role,
    RunStatus, Suggestion,
};
use crate::config::{EmbeddedOptions, RelayConfig, UpstreamOptions};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys;
use crate::ids::{AgentId, CollectionId, DeviceId, ItemId, MemberId, RunId, TeamId};
use crate::now_unix;
use crate::secret::SecretString;
use crate::server::approvals::{self, Denier, RunRow};
use crate::server::auth::MemberAuth;
use crate::server::host::{self, EmbeddedRequest};
use crate::server::hub::Hub;
use crate::server::store::{ItemRow, db, load_item, load_live_items, to_i, to_u};
use crate::server::{Core, Relay, RunningRelay, admin, oauth};

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
        self.start_on_tailnet(config, None)
    }

    fn start_on_tailnet(
        &self,
        config: NodeConfig,
        tailnet: Option<NodeTailnet>,
    ) -> Result<Box<dyn RunningNode>, NodeError> {
        let NodeConfig {
            data_dir,
            master_key,
            public_url,
            public_origins,
            public_listen,
        } = config;
        let (node_origin, tailnet_listen, tailnet_agents, push_gateway) = match tailnet {
            Some(tailnet) => (
                Some(tailnet.node_origin),
                Some(tailnet.tailnet_listen),
                tailnet.tailnet_agents,
                tailnet.push_gateway,
            ),
            None => (None, None, false, None),
        };
        let mut relay = RelayConfig::embedded(EmbeddedOptions {
            data_dir,
            master_key: SecretString::new(master_key.expose().to_owned()),
            public_url,
            public_listen,
            node_origin,
            tailnet_listen,
            tailnet_agents,
            push_gateway,
        })
        .and_then(|relay| relay.with_public_origins(&public_origins))
        .map_err(node_error)?;
        relay.upstream = self.upstream.clone();
        // The connect page keeps `EMBEDDED_MAC_NAME` ("your Mac"): it is public, so it
        // never shows the computer name. Only the owner's own prompts name the Mac.
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

/// The public origin of the session of `run`: the origin of its agent's connection of the
/// MCP authorization flow (`oauth::agent_origin`), else `public_url`, the first.
fn session_origin(hub: &Hub, core: &Core, run: RunId) -> RelayResult<String> {
    let first = || core.config.public_url.clone();
    if hub.config.public_origins().len() < 2 {
        return Ok(first());
    }
    let agent: Option<i64> = core.store.with(|conn| {
        conn.query_row(
            "SELECT agent_id FROM run WHERE id = ?1",
            params![to_i(run.0)],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)
    })?;
    let Some(agent) = agent else {
        return Ok(first());
    };
    Ok(oauth::agent_origin(hub, &core.team, AgentId(to_u(agent)))?
        .map_or_else(first, str::to_string))
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

/// The owner of a team of devices, as its own device (the key holder first): the member
/// that the node acts for when the app revokes a device. A team of devices has no
/// member token, so `owner` (no device) cannot act in it.
fn owner_device(core: &Core) -> RelayResult<MemberAuth> {
    core.store.with(|conn| {
        let id: i64 = conn
            .query_row(
                "SELECT d.id FROM device d JOIN member m ON m.id = d.member_id \
                 WHERE m.role = 'owner' AND d.revoked_at IS NULL AND m.revoked_at IS NULL \
                 ORDER BY d.key_holder DESC, d.id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| RelayError::not_found("owner device"))?;
        crate::server::auth::device_member(conn, DeviceId(to_u(id)))
    })
}

/// The live devices of a team, oldest first.
fn team_devices(core: &Core) -> RelayResult<Vec<NodeDevice>> {
    core.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT d.id, d.name, m.id, m.name, m.role, d.key_holder, d.created_at, \
                 d.last_seen_at, EXISTS(SELECT 1 FROM push_handle h \
                 WHERE h.device_id = d.id AND h.failed_at IS NULL) \
                 FROM device d JOIN member m ON m.id = d.member_id \
                 WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL ORDER BY d.id",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok(NodeDevice {
                    id: to_u(row.get(0)?),
                    name: row.get(1)?,
                    member_id: to_u(row.get(2)?),
                    member_name: row.get(3)?,
                    role: row.get(4)?,
                    key_holder: row.get(5)?,
                    created_at: to_u(row.get(6)?),
                    last_seen_at: row.get::<_, Option<i64>>(7)?.map(to_u),
                    push: row.get(8)?,
                })
            })
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
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

    fn tailnet_addr(&self) -> Option<SocketAddr> {
        self.running.tailnet_addr
    }

    fn local_route_addr(&self) -> Option<SocketAddr> {
        self.running.tailnet_local_addr
    }

    fn create_device_team(
        &self,
        name: &str,
        device_name: &str,
        public_key_b64u: &str,
    ) -> Result<(NodeTeamId, u64), NodeError> {
        self.hub
            .create_device_team(name, device_name, public_key_b64u, now_unix())
            .map(|(team, device)| (NodeTeamId(team.as_str().to_string()), device.0))
            .map_err(node_error)
    }

    fn devices(&self, team: &NodeTeamId) -> Result<Vec<NodeDevice>, NodeError> {
        self.core(team)
            .and_then(|core| team_devices(&core))
            .map_err(node_error)
    }

    fn revoke_device(&self, team: &NodeTeamId, device: u64) -> Result<(), NodeError> {
        (|| -> RelayResult<()> {
            let core = self.core(team)?;
            let owner = owner_device(&core)?;
            crate::server::devices::revoke(&core, &owner, DeviceId(device), now_unix()).map(drop)
        })()
        .map_err(node_error)
    }

    fn make_node_code(&self, minutes: u32) -> Result<NodeCode, NodeError> {
        (|| -> RelayResult<NodeCode> {
            if !self.hub.config.is_node() {
                return Err(RelayError::new(
                    codes::NOT_SUPPORTED,
                    "A node pairing code needs the tailnet route of the node.",
                ));
            }
            let (code, expires_at) = self
                .hub
                .directory
                .new_node_code(u64::from(minutes), now_unix())?;
            Ok(NodeCode {
                code: NodeSecret::new(code.expose().to_owned()),
                expires_at,
            })
        })()
        .map_err(node_error)
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
            let days = match agent.token {
                TokenIssue::Now { lifetime_days } => lifetime_days,
                // The token of the row is dropped below, before anyone sees it.
                TokenIssue::Later => 1,
            };
            let request = AgentCreate {
                name: agent.name.clone(),
                days: Some(days),
            };
            let made = admin::insert_agent(&core, &owner, &request, Some(&items), now)?;
            match agent.token {
                TokenIssue::Now { .. } => Ok(CreatedAgent {
                    agent_id: NodeAgentId(made.id.0),
                    token: Some(NodeSecret::new(made.token.expose().to_owned())),
                    expires_at: made.expires_at,
                }),
                TokenIssue::Later => {
                    drop(made.token);
                    oauth::drop_access(&core, made.id, "token_later", now)?;
                    Ok(CreatedAgent {
                        agent_id: NodeAgentId(made.id.0),
                        token: None,
                        expires_at: now,
                    })
                }
            }
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
            let now = now_unix();
            let core = self.core(team)?;
            let owner = owner(&core)?;
            admin::agent_revoke(&core, &owner, AgentId(agent.0), now)?;
            // Its refresh families and the open requests of its clients go too.
            oauth::forget_agent(&self.hub, &core.team, AgentId(agent.0), now)
        })()
        .map_err(node_error)
    }

    fn pending_connects(&self) -> Result<Vec<PendingConnect>, NodeError> {
        let list = oauth::pending(&self.hub, now_unix()).map_err(node_error)?;
        Ok(list
            .into_iter()
            .map(|request| PendingConnect {
                id: request.id,
                client_id: request.client_id,
                client_name: request.client_name,
                code: request.match_code,
                created_at: request.created_at,
                expires_at: request.expires_at,
                redirect_host: request.redirect_host,
            })
            .collect())
    }

    fn decide_connect(&self, id: &str, decision: ConnectDecision) -> Result<(), NodeError> {
        (|| -> RelayResult<()> {
            let allow = match decision {
                ConnectDecision::Allow { team, agent } => {
                    let core = self.core(&team)?;
                    Some((core.team.clone(), AgentId(agent.0)))
                }
                ConnectDecision::Deny => None,
            };
            oauth::decide(&self.hub, id, allow, now_unix())
        })()
        .map_err(node_error)
    }

    fn agent_access(
        &self,
        team: &NodeTeamId,
        agent: NodeAgentId,
    ) -> Result<AgentAccess, NodeError> {
        (|| -> RelayResult<AgentAccess> {
            let now = now_unix();
            let core = self.core(team)?;
            let row: Option<(i64, Option<i64>)> = core.store.with(|conn| {
                conn.query_row(
                    "SELECT expires_at, revoked_at FROM agent WHERE id = ?1",
                    params![to_i(agent.0)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db)
            })?;
            let (expires_at, revoked_at) = row.ok_or_else(|| RelayError::not_found("agent"))?;
            let revoked = revoked_at.is_some();
            let connection = if revoked {
                oauth::AgentConnection::default()
            } else {
                oauth::connection_of(&self.hub, &core.team, AgentId(agent.0), now)?
            };
            Ok(AgentAccess {
                revoked,
                token_expires_at: (!revoked && to_u(expires_at) > now).then(|| to_u(expires_at)),
                client_id: connection.client_id,
                connected_at: connection.connected_at,
                refresh_expires_at: connection.refresh_expires_at,
            })
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
        // The host loop also looks at the connect requests after each return.
        let connects = oauth::pending_mark(&self.hub, now_unix()).map_err(node_error)?;
        loop {
            let seen = core.notify.current();
            let list = host::embedded_requests(&core, now_unix()).map_err(node_error)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let changed =
                oauth::pending_mark(&self.hub, now_unix()).map_err(node_error)? != connects;
            if !list.is_empty() || changed || remaining.is_zero() || core.stopping() {
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
            // The session is for the origin that the run's agent uses (`oauth::agent_origin`),
            // read before the release takes the team file.
            let origin = session_origin(&self.hub, &core, RunId(run.0))?;
            host::release_values_at(&core, RunId(run.0), values, reason, &origin, now_unix())?;
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
