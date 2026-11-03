//! Cloud agents and the node settings of this vault (schema 26, ADR 0037 cloud slice,
//! decision 3). The tables are in `schema26.rs`; the OAuth link of an agent and the
//! cloud runs (`cloud_run`) are in `schema27.rs`.
//!
//! A cloud agent is a vault agent with `kind = 'cloud'`. It starts with `see_all = 0`
//! and "only these items" with the items that the owner picked, so ADR 0012 visibility,
//! "Not for this agent", and the activity log apply to it as to a local agent. Its token
//! belongs to the node (`crate::node`); the vault keeps the node's agent id and the
//! expiry, never the token. Revocation is in two steps: the vault revokes the agent at
//! once ([`Vault::revoke_agent`]), and the row in `cloud_agent` stays until the node
//! revoked its agent too ([`Vault::forget_cloud_agent`]), so a revocation while the node
//! is stopped reaches the node at its next start.

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::agents::{
    AgentSummary, MAX_AGENT_NAME_BYTES, checked_text, from_sql_time, now_unix, require_item,
    to_sql_time,
};
use super::exceptions::restrict_in;
use super::schema18::ONLY_MARKER_ITEM;
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, fresh_epoch, to_public_id, to_sql_id};

/// The ports of the public listener: the dynamic range, so no service of the system
/// has it by convention.
pub const CLOUD_PORT_MIN: u16 = 49152;
pub const CLOUD_PORT_MAX: u16 = 65535;
/// The token lifetimes that the owner can pick, in days.
pub const CLOUD_TOKEN_DAYS: [u32; 3] = [30, 90, 365];
/// The default token lifetime, in days.
pub const DEFAULT_CLOUD_TOKEN_DAYS: u32 = 90;
/// A cloud agent has at most this many items (the limit of the node's item list).
pub const MAX_CLOUD_AGENT_ITEMS: usize = 500;
/// The length of a node team id, such as `t_7k2m5q4x3c`, is at most this.
const MAX_TEAM_ID_BYTES: usize = 64;

/// One cloud agent, without its token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudAgent {
    /// The vault agent.
    pub agent_id: u64,
    pub name: String,
    /// The id of the agent in the node.
    pub relay_agent_id: u64,
    pub created_at: u64,
    /// When the node token stops working.
    pub token_expires_at: u64,
    /// The last run that the owner or the broker decided for it.
    pub last_used_at: Option<u64>,
    /// The items that it may use now: its "only these items" list without the items
    /// that a "Not for this agent" exception hides, by id.
    pub items: Vec<u64>,
}

/// The node settings of this vault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudNodeSetting {
    /// The personal team of this vault in the node.
    pub team_id: Option<String>,
    /// The loopback port of the public listener, once chosen.
    pub port: Option<u16>,
    /// The public route (Tailscale Funnel) is on.
    pub route_on: bool,
}

/// How a cloud agent connected (schema 27, `cloud_agent.connected_with`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectedWith {
    /// The MCP authorization flow (OAuth 2.1): the agent connected by itself and the
    /// owner allowed it.
    OAuth,
    /// A token that the owner gave it (`apassy agents add-remote`), and every cloud agent
    /// made before schema 27.
    #[default]
    Token,
}

impl ConnectedWith {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::Token => "token",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "oauth" => Some(Self::OAuth),
            "token" => Some(Self::Token),
            _ => None,
        }
    }
}

/// The longest OAuth `client_id` that the vault keeps, in bytes.
pub const MAX_CLIENT_ID_BYTES: usize = 255;

/// A cloud run to store when the node asks about it (schema 27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewCloudRun {
    /// The run id of the node.
    pub relay_run_id: u64,
    /// The decision log row of the broker's decision, when it wrote one.
    pub decision_log_id: Option<u64>,
    /// The vault agent.
    pub agent_id: u64,
    /// When the node asked.
    pub at: u64,
}

/// One stored cloud run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloudRun {
    pub relay_run_id: u64,
    pub decision_log_id: Option<u64>,
    pub agent_id: u64,
    pub at: u64,
    /// When its session ended. `None` while it runs, and for a denied run.
    pub ended_at: Option<u64>,
    /// Requests of its session that the proxy of the node forwarded.
    pub forwarded: u64,
    /// Requests that the proxy refused.
    pub refused: u64,
    /// Requests that failed upstream.
    pub failed: u64,
}

fn storage<E>(_: E) -> super::types::VaultError {
    err(VaultErrorKind::Storage)
}

/// 16 random bytes as 32 lowercase hex characters.
fn fresh_uid() -> VaultResult<String> {
    let bytes = fresh_epoch()?;
    Ok(bytes[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

impl Vault {
    /// Store a new cloud agent for the node agent `relay_agent_id`: a vault agent of kind
    /// `cloud` that sees only `items`. Its vault token is random and never leaves this
    /// call. Returns the vault agent id.
    ///
    /// `InvalidInput`: an empty or long name, no item or more than
    /// [`MAX_CLOUD_AGENT_ITEMS`], an item twice, or a node id of 0. `NotFound`: an item
    /// is not in the vault. `AlreadyExists`: another active cloud agent has this node id.
    pub fn add_cloud_agent(
        &mut self,
        name: &str,
        items: &[u64],
        relay_agent_id: u64,
        token_expires_at: u64,
    ) -> VaultResult<u64> {
        let name = checked_text(name.trim(), MAX_AGENT_NAME_BYTES)?.to_owned();
        let unique: BTreeSet<u64> = items.iter().copied().collect();
        if items.is_empty()
            || items.len() > MAX_CLOUD_AGENT_ITEMS
            || unique.len() != items.len()
            || unique.contains(&ONLY_MARKER_ITEM)
        {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let relay = to_sql_id(relay_agent_id)?;
        let expires = to_sql_time(token_expires_at)?;
        let token = Zeroizing::new(fresh_epoch()?);
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let taken: Option<i64> = tx
            .query_row(
                "SELECT c.agent_id FROM cloud_agent c JOIN agent a ON a.id = c.agent_id
                 WHERE c.relay_agent_id = ?1 AND a.revoked_at IS NULL",
                [relay],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if taken.is_some() {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        for item in items {
            require_item(&tx, to_sql_id(*item)?)?;
        }
        tx.execute(
            "INSERT INTO agent (name, token, created_at, revoked_at, token_issued_at, see_all, kind)
             VALUES (?1, ?2, ?3, NULL, ?3, 0, 'cloud')",
            (name.as_str(), token.as_slice(), at),
        )
        .map_err(storage)?;
        let agent = tx.last_insert_rowid();
        restrict_in(&tx, agent)?;
        for item in items {
            tx.execute(
                "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
                 VALUES (?1, ?2, 'only', ?3)",
                (agent, to_sql_id(*item)?, at),
            )
            .map_err(storage)?;
        }
        tx.execute(
            "INSERT INTO cloud_agent (agent_id, relay_agent_id, token_expires_at, last_used_at)
             VALUES (?1, ?2, ?3, NULL)",
            (agent, relay, expires),
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        to_public_id(agent)
    }

    /// The active cloud agents, oldest first.
    pub fn cloud_agents(&self) -> VaultResult<Vec<CloudAgent>> {
        let rows: Vec<(i64, String, i64, i64, i64, Option<i64>)> = {
            let conn = self.conn_ref()?;
            let mut stmt = conn
                .prepare(
                    "SELECT a.id, a.name, a.created_at, c.relay_agent_id, c.token_expires_at,
                            c.last_used_at
                     FROM agent a JOIN cloud_agent c ON c.agent_id = a.id
                     WHERE a.kind = 'cloud' AND a.revoked_at IS NULL ORDER BY a.id",
                )
                .map_err(storage)?;
            stmt.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?
        };
        let mut agents = Vec::with_capacity(rows.len());
        for (id, name, created_at, relay, expires, used) in rows {
            let agent_id = to_public_id(id)?;
            let view = self.agent_view(agent_id)?;
            agents.push(CloudAgent {
                agent_id,
                name,
                relay_agent_id: to_public_id(relay)?,
                created_at: from_sql_time(created_at)?,
                token_expires_at: from_sql_time(expires)?,
                last_used_at: used.map(from_sql_time).transpose()?,
                items: view
                    .listed
                    .iter()
                    .copied()
                    .filter(|item| view.visible(*item))
                    .collect(),
            });
        }
        Ok(agents)
    }

    /// True when the vault has an active cloud agent.
    pub fn has_cloud_agents(&self) -> VaultResult<bool> {
        self.conn_ref()?
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM agent a JOIN cloud_agent c ON c.agent_id = a.id
                     WHERE a.kind = 'cloud' AND a.revoked_at IS NULL)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(storage)
    }

    /// The active cloud agent `agent_id` as the broker needs it: its name and the expiry
    /// of its node token. `NotFound`: no such agent, a revoked one, or a local agent.
    pub fn cloud_agent_summary(&self, agent_id: u64) -> VaultResult<AgentSummary> {
        let agent = to_sql_id(agent_id)?;
        let row: Option<(String, i64, i64, i64)> = self
            .conn_ref()?
            .query_row(
                "SELECT a.name, a.created_at, a.token_issued_at, c.token_expires_at
                 FROM agent a JOIN cloud_agent c ON c.agent_id = a.id
                 WHERE a.id = ?1 AND a.kind = 'cloud' AND a.revoked_at IS NULL",
                [agent],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage)?;
        let (name, created_at, issued_at, expires) =
            row.ok_or_else(|| err(VaultErrorKind::NotFound))?;
        Ok(AgentSummary {
            id: agent_id,
            name,
            created_at: from_sql_time(created_at)?,
            revoked: false,
            token_issued_at: from_sql_time(issued_at)?,
            token_expires_at: from_sql_time(expires)?,
        })
    }

    /// The active cloud agent with the node id `relay_agent_id`, if any.
    pub fn cloud_agent_for_relay(&self, relay_agent_id: u64) -> VaultResult<Option<u64>> {
        let relay = to_sql_id(relay_agent_id)?;
        let id: Option<i64> = self
            .conn_ref()?
            .query_row(
                "SELECT a.id FROM agent a JOIN cloud_agent c ON c.agent_id = a.id
                 WHERE c.relay_agent_id = ?1 AND a.kind = 'cloud' AND a.revoked_at IS NULL",
                [relay],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        id.map(to_public_id).transpose()
    }

    /// Store the time of the last decided run of a cloud agent.
    pub fn touch_cloud_agent(&mut self, agent_id: u64, at: u64) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let at = to_sql_time(at)?;
        self.conn_mut()?
            .execute(
                "UPDATE cloud_agent SET last_used_at = ?2 WHERE agent_id = ?1",
                (agent, at),
            )
            .map_err(storage)?;
        Ok(())
    }

    /// The revoked cloud agents whose node agent may still be live: (vault agent, node
    /// agent). The node revokes each, then [`Vault::forget_cloud_agent`] removes the row.
    pub fn pending_cloud_revocations(&self) -> VaultResult<Vec<(u64, u64)>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT c.agent_id, c.relay_agent_id FROM cloud_agent c
                 LEFT JOIN agent a ON a.id = c.agent_id
                 WHERE a.id IS NULL OR a.revoked_at IS NOT NULL ORDER BY c.agent_id",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            let (agent, relay) = row.map_err(storage)?;
            out.push((to_public_id(agent)?, to_public_id(relay)?));
        }
        Ok(out)
    }

    /// Remove the node link of a revoked cloud agent, after the node revoked its agent.
    /// An active agent is refused (`InvalidInput`): revoke it first.
    pub fn forget_cloud_agent(&mut self, agent_id: u64) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT id FROM agent WHERE id = ?1 AND revoked_at IS NULL",
                [agent],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if active.is_some() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        tx.execute("DELETE FROM cloud_agent WHERE agent_id = ?1", [agent])
            .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// The uid of each item in the catalog mirror, in the order of `items`. An item
    /// without one gets a new random uid, stored at once. `NotFound`: an item is not in
    /// the vault.
    pub fn cloud_item_uids(&mut self, items: &[u64]) -> VaultResult<Vec<String>> {
        let mut fresh = Vec::new();
        for _ in items {
            fresh.push(fresh_uid()?);
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut uids = Vec::with_capacity(items.len());
        for (item, candidate) in items.iter().zip(fresh) {
            let item = to_sql_id(*item)?;
            require_item(&tx, item)?;
            let stored: Option<String> = tx
                .query_row(
                    "SELECT uid FROM cloud_item WHERE item_id = ?1",
                    [item],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            let uid = match stored {
                Some(uid) => uid,
                None => {
                    tx.execute(
                        "INSERT INTO cloud_item (item_id, uid) VALUES (?1, ?2)",
                        (item, candidate.as_str()),
                    )
                    .map_err(storage)?;
                    candidate
                }
            };
            uids.push(uid);
        }
        tx.commit().map_err(storage)?;
        Ok(uids)
    }

    /// The vault item of a catalog uid, if any.
    pub fn cloud_item_for_uid(&self, uid: &str) -> VaultResult<Option<u64>> {
        let id: Option<i64> = self
            .conn_ref()?
            .query_row(
                "SELECT item_id FROM cloud_item WHERE uid = ?1",
                [uid],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        id.map(to_public_id).transpose()
    }

    /// The node settings. A vault made from a synced copy has no row: the defaults.
    pub fn cloud_node_setting(&self) -> VaultResult<CloudNodeSetting> {
        let row: Option<(Option<String>, Option<i64>, i64)> = self
            .conn_ref()?
            .query_row(
                "SELECT team_id, port, route_on FROM cloud_node WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let Some((team_id, port, route_on)) = row else {
            return Ok(CloudNodeSetting::default());
        };
        Ok(CloudNodeSetting {
            team_id,
            port: port
                .map(|port| u16::try_from(port).map_err(storage))
                .transpose()?,
            route_on: route_on == 1,
        })
    }

    /// Store the node team of this vault, or forget it (`None`).
    pub fn set_cloud_node_team(&mut self, team_id: Option<&str>) -> VaultResult<()> {
        if let Some(team) = team_id {
            let valid = !team.is_empty()
                && team.len() <= MAX_TEAM_ID_BYTES
                && team
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if !valid {
                return Err(err(VaultErrorKind::InvalidInput));
            }
        }
        self.update_cloud_node("team_id", team_id)
    }

    /// Store the loopback port of the public listener: [`CLOUD_PORT_MIN`] to
    /// [`CLOUD_PORT_MAX`] (`InvalidInput` otherwise).
    pub fn set_cloud_node_port(&mut self, port: u16) -> VaultResult<()> {
        if port < CLOUD_PORT_MIN {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        self.update_cloud_node("port", i64::from(port))
    }

    /// Turn the public route on or off.
    pub fn set_cloud_route_on(&mut self, on: bool) -> VaultResult<()> {
        self.update_cloud_node("route_on", i64::from(on))
    }

    /// Start the node of this vault again, empty: after its key was lost, the node is new
    /// and knows none of the agents. Every cloud agent is revoked and loses its node link,
    /// the team is forgotten, and the route is off. The catalog uids stay. Returns how
    /// many agents were revoked.
    pub fn reset_cloud_node(&mut self) -> VaultResult<usize> {
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let agents: Vec<i64> = {
            let mut stmt = tx
                .prepare("SELECT id FROM agent WHERE kind = 'cloud' AND revoked_at IS NULL")
                .map_err(storage)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        for agent in &agents {
            tx.execute(
                "UPDATE agent SET revoked_at = ?1, see_all = 0 WHERE id = ?2",
                (at, *agent),
            )
            .map_err(storage)?;
            super::learning::forget_agent(&tx, *agent)?;
        }
        tx.execute("DELETE FROM cloud_agent", []).map_err(storage)?;
        // A new node numbers its runs again.
        tx.execute("DELETE FROM cloud_run", []).map_err(storage)?;
        tx.execute(
            "INSERT INTO cloud_node (id, team_id, port, route_on) VALUES (1, NULL, NULL, 0)
             ON CONFLICT(id) DO UPDATE SET team_id = NULL, route_on = 0",
            [],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(agents.len())
    }

    /// Set one column of the node row, made with its defaults when it is not there.
    fn update_cloud_node(
        &mut self,
        column: &'static str,
        value: impl rusqlite::ToSql,
    ) -> VaultResult<()> {
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            "INSERT OR IGNORE INTO cloud_node (id, team_id, port, route_on) VALUES (1, NULL, NULL, 0)",
            [],
        )
        .map_err(storage)?;
        tx.execute(
            &format!("UPDATE cloud_node SET {column} = ?1 WHERE id = 1"),
            [value],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
}

/// The OAuth link of the cloud agents and the cloud runs (schema 27).
impl Vault {
    /// Store how the cloud agent `agent_id` connected: the OAuth `client_id` of an agent
    /// that connected by itself ([`ConnectedWith::OAuth`], a client id is required), or
    /// none for a token agent. `InvalidInput`: an empty, long, or unprintable client id,
    /// a client id for a token agent, or no client id for an OAuth agent. `NotFound`: no
    /// active cloud agent `agent_id`.
    pub fn set_cloud_agent_link(
        &mut self,
        agent_id: u64,
        client_id: Option<&str>,
        connected_with: ConnectedWith,
    ) -> VaultResult<()> {
        let valid = match (connected_with, client_id) {
            (ConnectedWith::OAuth, Some(id)) => {
                !id.is_empty()
                    && id.len() <= MAX_CLIENT_ID_BYTES
                    && !id.chars().any(char::is_control)
            }
            (ConnectedWith::Token, None) => true,
            _ => false,
        };
        if !valid {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let agent = to_sql_id(agent_id)?;
        let changed = self
            .conn_mut()?
            .execute(
                "UPDATE cloud_agent SET client_id = ?2, connected_with = ?3
                 WHERE agent_id = ?1 AND agent_id IN (
                     SELECT id FROM agent WHERE kind = 'cloud' AND revoked_at IS NULL)",
                (agent, client_id, connected_with.as_str()),
            )
            .map_err(storage)?;
        if changed == 0 {
            return Err(err(VaultErrorKind::NotFound));
        }
        Ok(())
    }

    /// The OAuth client id and the way of connection of the cloud agent `agent_id`, also
    /// a revoked one whose node link is still here. `None`: no such cloud agent.
    pub fn cloud_agent_link(
        &self,
        agent_id: u64,
    ) -> VaultResult<Option<(Option<String>, ConnectedWith)>> {
        let agent = to_sql_id(agent_id)?;
        let row: Option<(Option<String>, String)> = self
            .conn_ref()?
            .query_row(
                "SELECT client_id, connected_with FROM cloud_agent WHERE agent_id = ?1",
                [agent],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        row.map(|(client, with)| {
            ConnectedWith::parse(&with)
                .map(|with| (client, with))
                .ok_or_else(|| err(VaultErrorKind::Storage))
        })
        .transpose()
    }

    /// The active cloud agent that connected with the OAuth client `client_id`, if any:
    /// the same client connects again to that agent.
    pub fn cloud_agent_for_client(&self, client_id: &str) -> VaultResult<Option<u64>> {
        let id: Option<i64> = self
            .conn_ref()?
            .query_row(
                "SELECT a.id FROM agent a JOIN cloud_agent c ON c.agent_id = a.id
                 WHERE c.client_id = ?1 AND a.kind = 'cloud' AND a.revoked_at IS NULL
                 ORDER BY a.id DESC LIMIT 1",
                [client_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        id.map(to_public_id).transpose()
    }

    /// Store a cloud run when the broker decided it. The same run id again replaces the
    /// row (a node numbers its runs again after a reset of the node).
    pub fn record_cloud_run(&mut self, run: &NewCloudRun) -> VaultResult<()> {
        let relay = to_sql_id(run.relay_run_id)?;
        let log = run.decision_log_id.map(to_sql_id).transpose()?;
        let agent = to_sql_id(run.agent_id)?;
        let at = to_sql_time(run.at)?;
        self.conn_mut()?
            .execute(
                "INSERT OR REPLACE INTO cloud_run
                     (relay_run_id, decision_log_id, agent_id, at, ended_at, forwarded, refused, failed)
                 VALUES (?1, ?2, ?3, ?4, NULL, 0, 0, 0)",
                (relay, log, agent, at),
            )
            .map_err(storage)?;
        Ok(())
    }

    /// Store the end of the session of a cloud run and the counts of its proxied
    /// requests. `NotFound`: no row for `relay_run_id`.
    pub fn end_cloud_run(
        &mut self,
        relay_run_id: u64,
        ended_at: u64,
        forwarded: u64,
        refused: u64,
        failed: u64,
    ) -> VaultResult<()> {
        let count = |n: u64| i64::try_from(n).map_err(|_| err(VaultErrorKind::InvalidInput));
        let changed = self
            .conn_mut()?
            .execute(
                "UPDATE cloud_run SET ended_at = ?2, forwarded = ?3, refused = ?4, failed = ?5
                 WHERE relay_run_id = ?1",
                (
                    to_sql_id(relay_run_id)?,
                    to_sql_time(ended_at)?,
                    count(forwarded)?,
                    count(refused)?,
                    count(failed)?,
                ),
            )
            .map_err(storage)?;
        if changed == 0 {
            return Err(err(VaultErrorKind::NotFound));
        }
        Ok(())
    }

    /// The cloud run `relay_run_id`, if stored.
    pub fn cloud_run(&self, relay_run_id: u64) -> VaultResult<Option<CloudRun>> {
        type Row = (i64, Option<i64>, i64, i64, Option<i64>, i64, i64, i64);
        let row: Option<Row> = self
            .conn_ref()?
            .query_row(
                "SELECT relay_run_id, decision_log_id, agent_id, at, ended_at, forwarded,
                        refused, failed
                 FROM cloud_run WHERE relay_run_id = ?1",
                [to_sql_id(relay_run_id)?],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((relay, log, agent, at, ended, forwarded, refused, failed)) = row else {
            return Ok(None);
        };
        let count = |n: i64| u64::try_from(n).map_err(storage);
        Ok(Some(CloudRun {
            relay_run_id: to_public_id(relay)?,
            decision_log_id: log.map(to_public_id).transpose()?,
            agent_id: to_public_id(agent)?,
            at: from_sql_time(at)?,
            ended_at: ended.map(from_sql_time).transpose()?,
            forwarded: count(forwarded)?,
            refused: count(refused)?,
            failed: count(failed)?,
        }))
    }
}

/// What a restored copy keeps of the node: nothing. Its agents are revoked by
/// `agents::prepare_restored`, its node links and team go, and its route is off, so the
/// restored file never shares a node team with the vault it came from.
pub(super) fn prepare_restored(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute("DELETE FROM cloud_agent", []).map_err(storage)?;
    tx.execute("DELETE FROM cloud_run", []).map_err(storage)?;
    tx.execute(
        "UPDATE cloud_node SET team_id = NULL, route_on = 0 WHERE id = 1",
        [],
    )
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::exceptions::ExceptionKind;
    use crate::vault::{Field, ItemDraft, SecretValue};

    const PASS: &str = "synthetic-cloud-pass";

    fn vault_with_items(dir: &tempfile::TempDir, count: usize) -> (Vault, Vec<u64>) {
        let mut vault = Vault::create(&dir.path().join("cloud.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let items = (0..count)
            .map(|index| {
                vault
                    .add(ItemDraft {
                        title: format!("Synthetic {index}"),
                        kind: CredentialKind::ApiKey,
                        notes: String::new(),
                        tags: Vec::new(),
                        fields: vec![Field {
                            name: "token".to_owned(),
                            value: SecretValue::new(format!("SYNTH-cloud-{index}-0123456789")),
                            secret: true,
                        }],
                    })
                    .unwrap()
                    .id
            })
            .collect();
        (vault, items)
    }

    #[test]
    fn a_cloud_agent_sees_only_its_items_and_never_authenticates_locally() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, items) = vault_with_items(&dir, 3);
        let id = vault
            .add_cloud_agent("Grok Bot", &[items[0], items[2]], 4, 2_000_000_000)
            .unwrap();
        let agents = vault.cloud_agents().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_id, id);
        assert_eq!(agents[0].relay_agent_id, 4);
        assert_eq!(agents[0].token_expires_at, 2_000_000_000);
        assert_eq!(agents[0].items, [items[0], items[2]]);
        let view = vault.agent_view(id).unwrap();
        assert!(view.visible(items[0]) && !view.visible(items[1]) && view.visible(items[2]));
        // "Not for this agent" takes an item away from a cloud agent too.
        vault
            .add_agent_exception(id, items[2], ExceptionKind::Never)
            .unwrap();
        assert_eq!(vault.cloud_agents().unwrap()[0].items, [items[0]]);
        assert!(vault.has_cloud_agents().unwrap());
        assert_eq!(vault.cloud_agent_for_relay(4).unwrap(), Some(id));
        assert_eq!(vault.cloud_agent_summary(id).unwrap().name, "Grok Bot");
        // The vault token of a cloud agent is never shown, and no local token reaches it.
        assert!(vault.rotate_agent_token(id).is_err());
        let (local, _) = vault.register_agent("Local").unwrap();
        assert_eq!(
            vault.cloud_agent_summary(local.id).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        // A second active agent with the same node id is refused.
        assert_eq!(
            vault
                .add_cloud_agent("Other", &[items[1]], 4, 2_000_000_000)
                .unwrap_err()
                .kind(),
            VaultErrorKind::AlreadyExists
        );
        for bad in [&[][..], &[items[0], items[0]][..], &[999][..]] {
            assert!(vault.add_cloud_agent("Bad", bad, 9, 1).is_err());
        }
    }

    #[test]
    fn a_revocation_waits_for_the_node_and_a_reset_revokes_every_cloud_agent() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, items) = vault_with_items(&dir, 2);
        let first = vault.add_cloud_agent("First", &[items[0]], 1, 3).unwrap();
        let second = vault.add_cloud_agent("Second", &[items[1]], 2, 3).unwrap();
        assert!(vault.forget_cloud_agent(first).is_err(), "revoke first");
        vault.revoke_agent(first).unwrap();
        assert_eq!(vault.pending_cloud_revocations().unwrap(), [(first, 1)]);
        assert_eq!(vault.cloud_agents().unwrap().len(), 1);
        assert!(vault.cloud_agent_summary(first).is_err());
        vault.forget_cloud_agent(first).unwrap();
        assert!(vault.pending_cloud_revocations().unwrap().is_empty());

        vault.set_cloud_node_team(Some("t_abcdefgh23")).unwrap();
        vault.set_cloud_node_port(49200).unwrap();
        vault.set_cloud_route_on(true).unwrap();
        assert_eq!(
            vault.cloud_node_setting().unwrap(),
            CloudNodeSetting {
                team_id: Some("t_abcdefgh23".to_owned()),
                port: Some(49200),
                route_on: true,
            }
        );
        assert_eq!(vault.reset_cloud_node().unwrap(), 1);
        assert!(vault.cloud_agent_summary(second).is_err());
        assert!(vault.cloud_agents().unwrap().is_empty());
        let setting = vault.cloud_node_setting().unwrap();
        assert_eq!(
            (setting.team_id, setting.port, setting.route_on),
            (None, Some(49200), false)
        );
        assert!(vault.set_cloud_node_port(1024).is_err());
        assert!(vault.set_cloud_node_team(Some("bad team")).is_err());
    }

    #[test]
    fn catalog_uids_are_stable_and_unique() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, items) = vault_with_items(&dir, 2);
        let first = vault.cloud_item_uids(&items).unwrap();
        assert_eq!(first.len(), 2);
        assert_ne!(first[0], first[1]);
        assert!(first.iter().all(|uid| {
            uid.len() == 32
                && uid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }));
        let again = vault.cloud_item_uids(&[items[1], items[0]]).unwrap();
        assert_eq!(again, [first[1].clone(), first[0].clone()]);
        assert_eq!(vault.cloud_item_for_uid(&first[1]).unwrap(), Some(items[1]));
        assert_eq!(vault.cloud_item_for_uid(&"0".repeat(32)).unwrap(), None);
        assert!(vault.cloud_item_uids(&[999]).is_err());
    }
}
