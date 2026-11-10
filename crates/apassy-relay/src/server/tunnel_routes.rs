//! The Connect tunnel on the account store (ADR 0037 stage 7, unit CW; the wire is
//! docs/contracts/connect-tunnel-v1.md, docs/SPEC.md section 35).
//!
//! [`AccountDirectory`] is the [`TunnelDirectory`] of the broker on `relay.db`: the caller
//! of a token through `account::authenticate` (each request reads the device again, so a
//! revoked device is 401 at once; a relay-sync team token is 403 `account_required`), the
//! nodes of `tunnel_node`, the grants of `tunnel_grant` (valid only while the two accounts
//! share a group, `Groups::share_group`), and the plan of `Plans::plan` (`entitled`) and
//! `Plans::people` (the byte budgets). Nothing of a plan or a group is cached beyond one
//! call.
//!
//! The JSON routes of the contract (sections 3.1 and 6) are [`dispatch`]; the two upgrade
//! routes go to `Broker::serve_node` and `Broker::serve_dial` (`http::respond_tunnel`).
//! [`start`] makes the broker of a relay with the account routes, restores this month's
//! usage from `tunnel_usage`, starts each ingress listener whose address is set, and
//! flushes the usage every [`USAGE_FLUSH_SECS`] and once at stop.
//!
//! The hooks of the other units: [`device_revoked`] and [`account_deleted`] (accounts),
//! [`plan_ended`] (billing), and [`grants_end_between`] (groups).
//!
//! The audit names accounts, devices, nodes, and grants by id, never a token, a pin, or an
//! address.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::api::{
    EmptyRequest, TunnelGrantDeleted, TunnelGrantRequest, TunnelGrantView, TunnelNodeDeleted,
    TunnelNodeRegister, TunnelNodeView,
};
use crate::config::TunnelSettings;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::decode_b64;
use crate::secret::is_connect_id;
use crate::server::account::{self, AccountCaller};
use crate::server::hub::Hub;
use crate::server::ingress::{self, IngressConfig, IngressHandle};
use crate::server::store::{db, to_i, to_u};
use crate::server::tunnel::{
    self, Broker, Caller, Limits, NodeEntry, Refusal, SystemClock, TunnelDirectory, Usage, month_of,
};

/// The node's WebSocket (contract 3.2).
pub const NODE_SOCKET_PATH: &str = "/v1/tunnel/node";
/// The dial of a node (contract 3.3), with the node id after it.
pub const DIAL_PREFIX: &str = "/v1/tunnel/dial/";
/// Seconds between two writes of the usage counters to `tunnel_usage`. A crash loses at
/// most this much of the month's count; a stop writes them at once.
pub const USAGE_FLUSH_SECS: u64 = 60;

// ---- The directory of the broker. ----

/// The broker's view of the account store. It holds the hub weakly: the hub holds the
/// broker.
pub struct AccountDirectory {
    hub: Weak<Hub>,
}

impl AccountDirectory {
    pub fn new(hub: &Arc<Hub>) -> Self {
        Self {
            hub: Arc::downgrade(hub),
        }
    }
}

fn node_entry(conn: &Connection, sql: &str, value: &str) -> RelayResult<Option<NodeEntry>> {
    conn.query_row(sql, params![value], |row| {
        Ok(NodeEntry {
            node_id: row.get(0)?,
            account_id: row.get(1)?,
            device_id: row.get(2)?,
        })
    })
    .optional()
    .map_err(db)
}

fn node_by_id(conn: &Connection, node_id: &str) -> RelayResult<Option<NodeEntry>> {
    node_entry(
        conn,
        "SELECT id, account_id, device_id FROM tunnel_node WHERE id = ?1",
        node_id,
    )
}

fn node_of_device(conn: &Connection, device: &str) -> RelayResult<Option<NodeEntry>> {
    node_entry(
        conn,
        "SELECT id, account_id, device_id FROM tunnel_node WHERE device_id = ?1",
        device,
    )
}

/// Whether the account has a plan with the tunnel now (connect-billing-v1 section 8).
fn entitled(hub: &Hub, account: &str, now: u64) -> RelayResult<bool> {
    Ok(hub
        .accounts
        .plans()
        .plan(&hub.directory.store, account, now)?
        .entitled)
}

/// Whether the two accounts are in one group now.
fn share_group(hub: &Hub, owner: &str, other: &str, now: u64) -> RelayResult<bool> {
    hub.accounts
        .groups()
        .share_group(&hub.directory.store, owner, other, now)
}

/// Whether `grantee` holds a grant to the node that is still valid: the row exists and the
/// node's account and the grantee share a group.
fn grant_valid(hub: &Hub, node_id: &str, grantee: &str, now: u64) -> RelayResult<bool> {
    let owner: Option<String> = hub.directory.store.with(|conn| {
        conn.query_row(
            "SELECT n.account_id FROM tunnel_grant g JOIN tunnel_node n ON n.id = g.node_id \
             WHERE g.node_id = ?1 AND g.account_id = ?2",
            params![node_id, grantee],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)
    })?;
    match owner {
        Some(owner) if owner != grantee => share_group(hub, &owner, grantee, now),
        _ => Ok(false),
    }
}

impl TunnelDirectory for AccountDirectory {
    fn caller(&self, bearer: &str) -> Result<Caller, Refusal> {
        let hub = self.hub.upgrade().ok_or(Refusal::Unauthenticated)?;
        match account::authenticate(&hub, Some(bearer), crate::now_unix()) {
            Ok(caller) => Ok(Caller {
                account_id: caller.account,
                device_id: caller.device,
            }),
            Err(error) if error.code == codes::ACCOUNT_REQUIRED => Err(Refusal::AccountRequired),
            Err(_) => Err(Refusal::Unauthenticated),
        }
    }

    fn device_node(&self, caller: &Caller) -> Option<NodeEntry> {
        let hub = self.hub.upgrade()?;
        hub.directory
            .store
            .with(|conn| node_of_device(conn, &caller.device_id))
            .ok()
            .flatten()
            .filter(|entry| entry.account_id == caller.account_id)
    }

    fn node(&self, node_id: &str) -> Option<NodeEntry> {
        let hub = self.hub.upgrade()?;
        hub.directory
            .store
            .with(|conn| node_by_id(conn, node_id))
            .ok()
            .flatten()
    }

    fn has_grant(&self, node_id: &str, grantee_account: &str) -> bool {
        self.hub.upgrade().is_some_and(|hub| {
            grant_valid(&hub, node_id, grantee_account, crate::now_unix()).unwrap_or(false)
        })
    }

    fn entitled(&self, account_id: &str) -> bool {
        self.hub
            .upgrade()
            .is_some_and(|hub| entitled(&hub, account_id, crate::now_unix()).unwrap_or(false))
    }

    fn budget_units(&self, account_id: &str) -> u64 {
        self.hub.upgrade().map_or(1, |hub| {
            hub.accounts
                .plans()
                .people(&hub.directory.store, account_id, crate::now_unix())
                .unwrap_or(1)
                .max(1)
        })
    }
}

// ---- Routes. ----

/// The tunnel endpoints (contract sections 3 and 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelEndpoint {
    NodeRegister,
    NodeList,
    NodeDelete(String),
    NodeSocket,
    Dial(String),
    GrantCreate,
    GrantList,
    GrantDelete(String),
}

impl TunnelEndpoint {
    /// The two WebSocket routes.
    pub fn is_upgrade(&self) -> bool {
        matches!(self, Self::NodeSocket | Self::Dial(_))
    }
}

/// True for `/v1/tunnel` and every path below it.
pub fn is_tunnel_path(path: &str) -> bool {
    path == "/v1/tunnel" || path.starts_with("/v1/tunnel/")
}

/// `GET /v1/tunnel/node` or `GET /v1/tunnel/dial/{node_id}`: the only routes that take an
/// `Upgrade` (docs/SPEC.md section 35.6).
pub fn is_upgrade_route(method: &str, path: &str) -> bool {
    method == "GET" && route(method, path).is_ok_and(|endpoint| endpoint.is_upgrade())
}

/// The endpoint of a tunnel path. 404 `not_found` for an unknown path, 405 for a known
/// path with another method. An id in the path is checked by its endpoint.
pub fn route(method: &str, path: &str) -> RelayResult<TunnelEndpoint> {
    use TunnelEndpoint::*;
    let not_found = || RelayError::new(codes::NOT_FOUND, "No such path.");
    let pick = |choices: Vec<(&str, TunnelEndpoint)>| {
        choices
            .into_iter()
            .find(|(m, _)| *m == method)
            .map(|(_, endpoint)| endpoint)
            .ok_or_else(|| {
                RelayError::new(
                    codes::METHOD_NOT_ALLOWED,
                    "This path does not allow this method.",
                )
            })
    };
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v1", "tunnel", "nodes"] => pick(vec![("POST", NodeRegister), ("GET", NodeList)]),
        ["v1", "tunnel", "nodes", id] if !id.is_empty() => {
            pick(vec![("DELETE", NodeDelete((*id).to_string()))])
        }
        ["v1", "tunnel", "node"] => pick(vec![("GET", NodeSocket)]),
        ["v1", "tunnel", "dial", id] if !id.is_empty() => {
            pick(vec![("GET", Dial((*id).to_string()))])
        }
        ["v1", "tunnel", "grants"] => pick(vec![("POST", GrantCreate), ("GET", GrantList)]),
        ["v1", "tunnel", "grants", id] if !id.is_empty() => {
            pick(vec![("DELETE", GrantDelete((*id).to_string()))])
        }
        _ => Err(not_found()),
    }
}

// ---- Errors and values. ----

fn node_unknown() -> RelayError {
    RelayError::new(codes::NODE_UNKNOWN, "No such node.")
}

fn grant_unknown() -> RelayError {
    RelayError::new(codes::NOT_FOUND, "No such grant.")
}

fn strict<T: DeserializeOwned>(body: &[u8]) -> RelayResult<T> {
    serde_json::from_slice(body)
        .map_err(|_| RelayError::invalid("The request body does not match the contract."))
}

/// An empty body or `{}`: the DELETE routes.
fn no_body(body: &[u8]) -> RelayResult<()> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    strict::<EmptyRequest>(body).map(drop)
}

fn to_value<T: Serialize>(value: &T) -> RelayResult<Value> {
    serde_json::to_value(value).map_err(|_| RelayError::internal("The answer cannot be written."))
}

/// A new id: `prefix` and 10 random characters of `a-z2-7`.
fn new_id(prefix: &str) -> RelayResult<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 10];
    getrandom::fill(&mut bytes)
        .map_err(|_| RelayError::internal("The system has no random source."))?;
    let mut text = String::with_capacity(prefix.len() + 10);
    text.push_str(prefix);
    for byte in bytes {
        text.push(char::from(ALPHABET[usize::from(byte & 31)]));
    }
    Ok(text)
}

/// A node name: 1 to 64 bytes of UTF-8 without a control character, trimmed.
fn checked_name(text: &str) -> RelayResult<String> {
    let text = text.trim();
    if text.is_empty()
        || text.len() > crate::api::MAX_NAME_BYTES
        || text.chars().any(char::is_control)
    {
        return Err(RelayError::invalid(
            "The node name is 1 to 64 bytes with no control character.",
        ));
    }
    Ok(text.to_string())
}

/// A pin: base64url without padding of 32 bytes (43 characters).
fn valid_pin(text: &str) -> bool {
    text.len() == 43
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && decode_b64(text, 32).is_ok_and(|bytes| bytes.len() == 32)
}

fn actor(account: &str) -> String {
    format!("account:{account}")
}

/// A fresh id of `prefix` that no row of `table` has.
fn free_id(conn: &Connection, table: &str, prefix: &str) -> RelayResult<String> {
    for _ in 0..8 {
        let id = new_id(prefix)?;
        let used: bool = conn
            .query_row(
                &format!("SELECT EXISTS (SELECT 1 FROM {table} WHERE id = ?1)"),
                params![id],
                |row| row.get(0),
            )
            .map_err(db)?;
        if !used {
            return Ok(id);
        }
    }
    Err(RelayError::internal("No free id."))
}

// ---- Dispatch. ----

/// A JSON endpoint with the account token of `caller`. The upgrade endpoints are not here.
pub fn dispatch(
    hub: &Hub,
    broker: &Broker,
    caller: &AccountCaller,
    endpoint: &TunnelEndpoint,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        TunnelEndpoint::NodeRegister => register(hub, broker, caller, &strict(body)?, now),
        TunnelEndpoint::NodeList => node_list(hub, broker, caller, now),
        TunnelEndpoint::NodeDelete(node_id) => {
            no_body(body)?;
            node_delete(hub, broker, caller, node_id, now)
        }
        TunnelEndpoint::GrantCreate => grant_create(hub, caller, &strict(body)?, now),
        TunnelEndpoint::GrantList => grant_list(hub, caller),
        TunnelEndpoint::GrantDelete(grant_id) => {
            no_body(body)?;
            grant_delete(hub, broker, caller, grant_id, now)
        }
        TunnelEndpoint::NodeSocket | TunnelEndpoint::Dial(_) => {
            Err(RelayError::internal("Not a JSON endpoint."))
        }
    }
}

/// A stored node, for the `NodeView`.
struct NodeRow {
    node_id: String,
    account_id: String,
    device_id: String,
    name: String,
    pin: String,
    created_at: u64,
}

const NODE_COLUMNS: &str = "n.id, n.account_id, n.device_id, n.name, n.pin, n.created_at";

fn node_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRow> {
    Ok(NodeRow {
        node_id: row.get(0)?,
        account_id: row.get(1)?,
        device_id: row.get(2)?,
        name: row.get(3)?,
        pin: row.get(4)?,
        created_at: to_u(row.get(5)?),
    })
}

fn node_view(broker: &Broker, row: NodeRow) -> TunnelNodeView {
    TunnelNodeView {
        public_name: tunnel::public_name(&row.node_id, broker.zone()).unwrap_or_default(),
        online: broker.online(&row.node_id),
        node_id: row.node_id,
        account_id: row.account_id,
        device_id: row.device_id,
        name: row.name,
        pin: row.pin,
        created_at: row.created_at,
    }
}

/// `POST /v1/tunnel/nodes`: the node of the calling device, new or with a new name and
/// pin. One stable node for each account device; at most `nodes_per_account` for the
/// account (403 `account_limit`).
fn register(
    hub: &Hub,
    broker: &Broker,
    caller: &AccountCaller,
    request: &TunnelNodeRegister,
    now: u64,
) -> RelayResult<Value> {
    let name = checked_name(&request.name)?;
    if !valid_pin(&request.pin) {
        return Err(RelayError::invalid(
            "The pin is the base64url SHA-256 of the node's certificate (43 characters).",
        ));
    }
    let limit = broker.limits().nodes_per_account;
    let row = hub.directory.store.tx(|tx| {
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM tunnel_node WHERE device_id = ?1",
                params![caller.device],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let (node_id, action) = match existing {
            Some(node_id) => {
                tx.execute(
                    "UPDATE tunnel_node SET name = ?2, pin = ?3 WHERE id = ?1",
                    params![node_id, name, request.pin],
                )
                .map_err(db)?;
                (node_id, "tunnel_node_updated")
            }
            None => {
                let count: i64 = tx
                    .query_row(
                        "SELECT count(*) FROM tunnel_node WHERE account_id = ?1",
                        params![caller.account],
                        |row| row.get(0),
                    )
                    .map_err(db)?;
                if to_u(count) >= limit as u64 {
                    return Err(RelayError::new(
                        codes::ACCOUNT_LIMIT,
                        format!("This account has {limit} nodes."),
                    ));
                }
                let node_id = free_id(tx, "tunnel_node", "node_")?;
                tx.execute(
                    "INSERT INTO tunnel_node (id, account_id, device_id, name, pin, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        node_id,
                        caller.account,
                        caller.device,
                        name,
                        request.pin,
                        to_i(now)
                    ],
                )
                .map_err(db)?;
                (node_id, "tunnel_node_registered")
            }
        };
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            action,
            None,
            &json!({"node_id": node_id, "device_id": caller.device}),
        )?;
        tx.query_row(
            &format!("SELECT {NODE_COLUMNS} FROM tunnel_node n WHERE n.id = ?1"),
            params![node_id],
            node_row,
        )
        .map_err(db)
    })?;
    to_value(&node_view(broker, row))
}

/// `GET /v1/tunnel/nodes`: the nodes of the account, and those of accounts whose grant
/// to it is still valid.
fn node_list(hub: &Hub, broker: &Broker, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let rows: Vec<NodeRow> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {NODE_COLUMNS} FROM tunnel_node n WHERE n.account_id = ?1 \
                 UNION SELECT {NODE_COLUMNS} FROM tunnel_node n \
                 JOIN tunnel_grant g ON g.node_id = n.id WHERE g.account_id = ?1 \
                 ORDER BY 6, 1"
            ))
            .map_err(db)?;
        let rows = statement
            .query_map(params![caller.account], node_row)
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    let mut shared: HashMap<String, bool> = HashMap::new();
    let mut views = Vec::with_capacity(rows.len());
    for row in rows {
        if row.account_id != caller.account {
            let valid = match shared.get(&row.account_id) {
                Some(valid) => *valid,
                None => {
                    let valid = share_group(hub, &row.account_id, &caller.account, now)?;
                    shared.insert(row.account_id.clone(), valid);
                    valid
                }
            };
            if !valid {
                continue;
            }
        }
        views.push(node_view(broker, row));
    }
    to_value(&views)
}

/// `DELETE /v1/tunnel/nodes/{node_id}` from a device of the node's account: the node and
/// its grants go, and its tunnel closes (4003; its streams end with 4001).
fn node_delete(
    hub: &Hub,
    broker: &Broker,
    caller: &AccountCaller,
    node_id: &str,
    now: u64,
) -> RelayResult<Value> {
    if !tunnel::valid_node_id(node_id) {
        return Err(node_unknown());
    }
    hub.directory.store.tx(|tx| {
        let owner = node_by_id(tx, node_id)?.map(|entry| entry.account_id);
        if owner.as_deref() != Some(caller.account.as_str()) {
            return Err(node_unknown());
        }
        tx.execute(
            "DELETE FROM tunnel_grant WHERE node_id = ?1",
            params![node_id],
        )
        .map_err(db)?;
        tx.execute("DELETE FROM tunnel_node WHERE id = ?1", params![node_id])
            .map_err(db)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "tunnel_node_removed",
            None,
            &json!({"node_id": node_id, "by": caller.device}),
        )?;
        Ok(())
    })?;
    broker.remove_node(node_id);
    to_value(&TunnelNodeDeleted {
        node_id: node_id.to_string(),
    })
}

fn grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelGrantView> {
    Ok(TunnelGrantView {
        grant_id: row.get(0)?,
        node_id: row.get(1)?,
        account_id: row.get(2)?,
        created_at: to_u(row.get(3)?),
    })
}

/// `POST /v1/tunnel/grants` from a device of the node's account: the grantee must share a
/// group with the account (403 `not_in_group`). The same grant again answers the existing
/// one.
fn grant_create(
    hub: &Hub,
    caller: &AccountCaller,
    request: &TunnelGrantRequest,
    now: u64,
) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_") {
        return Err(RelayError::invalid(
            "The account id is not one of Apassy Connect.",
        ));
    }
    if !tunnel::valid_node_id(&request.node_id) {
        return Err(node_unknown());
    }
    let owner = hub
        .directory
        .store
        .with(|conn| node_by_id(conn, &request.node_id))?
        .ok_or_else(node_unknown)?
        .account_id;
    if owner != caller.account {
        return Err(RelayError::forbidden(
            "Only a device of the node's account gives access to it.",
        ));
    }
    if request.account_id == caller.account {
        return Err(RelayError::invalid(
            "The devices of the node's own account need no grant.",
        ));
    }
    if !share_group(hub, &caller.account, &request.account_id, now)? {
        return Err(RelayError::new(
            codes::NOT_IN_GROUP,
            "That account is not in your family or team.",
        ));
    }
    let view = hub.directory.store.tx(|tx| {
        // Again under the lock: the node may have gone since.
        if node_by_id(tx, &request.node_id)?.map(|entry| entry.account_id)
            != Some(caller.account.clone())
        {
            return Err(node_unknown());
        }
        let existing = tx
            .query_row(
                "SELECT id, node_id, account_id, created_at FROM tunnel_grant \
                 WHERE node_id = ?1 AND account_id = ?2",
                params![request.node_id, request.account_id],
                grant_row,
            )
            .optional()
            .map_err(db)?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let grant_id = free_id(tx, "tunnel_grant", "tgr_")?;
        tx.execute(
            "INSERT INTO tunnel_grant (id, node_id, account_id, granted_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                grant_id,
                request.node_id,
                request.account_id,
                caller.device,
                to_i(now)
            ],
        )
        .map_err(db)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "tunnel_grant_created",
            None,
            &json!({"grant_id": grant_id, "node_id": request.node_id,
                    "account_id": request.account_id}),
        )?;
        Ok(TunnelGrantView {
            grant_id,
            node_id: request.node_id.clone(),
            account_id: request.account_id.clone(),
            created_at: now,
        })
    })?;
    to_value(&view)
}

/// `GET /v1/tunnel/grants`: the grants this account made and those made to it.
fn grant_list(hub: &Hub, caller: &AccountCaller) -> RelayResult<Value> {
    let grants: Vec<TunnelGrantView> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT g.id, g.node_id, g.account_id, g.created_at FROM tunnel_grant g \
                 JOIN tunnel_node n ON n.id = g.node_id \
                 WHERE n.account_id = ?1 OR g.account_id = ?1 ORDER BY g.created_at, g.id",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![caller.account], grant_row)
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    to_value(&grants)
}

/// `DELETE /v1/tunnel/grants/{grant_id}` from either account: the grant goes, and the
/// grantee's open streams to the node are reset at once (4003).
fn grant_delete(
    hub: &Hub,
    broker: &Broker,
    caller: &AccountCaller,
    grant_id: &str,
    now: u64,
) -> RelayResult<Value> {
    if !is_connect_id(grant_id, "tgr_") {
        return Err(grant_unknown());
    }
    let (node_id, grantee) = hub.directory.store.tx(|tx| {
        let found: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT g.node_id, g.account_id, n.account_id FROM tunnel_grant g \
                 LEFT JOIN tunnel_node n ON n.id = g.node_id WHERE g.id = ?1",
                params![grant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((node_id, grantee, owner)) = found else {
            return Err(grant_unknown());
        };
        if grantee != caller.account && owner.as_deref() != Some(caller.account.as_str()) {
            return Err(grant_unknown());
        }
        tx.execute("DELETE FROM tunnel_grant WHERE id = ?1", params![grant_id])
            .map_err(db)?;
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "tunnel_grant_removed",
            None,
            &json!({"grant_id": grant_id, "node_id": node_id, "account_id": grantee}),
        )?;
        Ok((node_id, grantee))
    })?;
    let closed = broker.revoke_grant(&node_id, &grantee);
    to_value(&TunnelGrantDeleted {
        grant_id: grant_id.to_string(),
        closed_streams: closed as u64,
    })
}

// ---- Hooks of the other units. ----

/// An account device was revoked (`account::revoke`, which deleted its node row and the
/// node's grants): its dials end (4003) and its node's tunnel closes.
pub fn device_revoked(hub: &Hub, device: &str) {
    if let Some(broker) = hub.tunnel() {
        broker.revoke_device(device);
    }
}

/// An account was deleted (`account::delete_account`, which deleted its nodes and the
/// grants both ways): its node WebSockets close (4003) and its devices' dials end.
pub fn account_deleted(hub: &Hub, account: &str) {
    if let Some(broker) = hub.tunnel() {
        broker.end_account(account);
    }
}

/// The plan of `account` ended (billing): the open streams of its nodes end with 4003.
/// New dials and ingress streams are refused by `entitled` at once, so nothing else is
/// needed.
pub fn plan_ended(hub: &Hub, account: &str) {
    if let Some(broker) = hub.tunnel() {
        broker.end_plan(account);
    }
}

/// `account` and each of `others` no longer share a group (groups): the grants between
/// them, both directions, are deleted, and the open streams that they carried are reset
/// at once (4003). Returns how many grants were deleted.
pub fn grants_end_between(
    hub: &Hub,
    account: &str,
    others: &[String],
    now: u64,
) -> RelayResult<usize> {
    let ended: Vec<(String, String)> = hub.directory.store.tx(|tx| {
        let mut ended: Vec<(String, String, String)> = Vec::new();
        {
            let mut statement = tx
                .prepare(
                    "SELECT g.id, g.node_id, g.account_id FROM tunnel_grant g \
                     JOIN tunnel_node n ON n.id = g.node_id \
                     WHERE (n.account_id = ?1 AND g.account_id = ?2) \
                     OR (n.account_id = ?2 AND g.account_id = ?1)",
                )
                .map_err(db)?;
            for other in others.iter().filter(|other| other.as_str() != account) {
                let rows = statement
                    .query_map(params![account, other], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })
                    .map_err(db)?;
                for row in rows {
                    ended.push(row.map_err(db)?);
                }
            }
        }
        for (grant_id, _, _) in &ended {
            tx.execute("DELETE FROM tunnel_grant WHERE id = ?1", params![grant_id])
                .map_err(db)?;
        }
        if !ended.is_empty() {
            hub.directory.audit.write_on(
                tx,
                now,
                &actor(account),
                "tunnel_grants_ended",
                None,
                &json!({"account_id": account, "grants": ended.len()}),
            )?;
        }
        Ok(ended
            .into_iter()
            .map(|(_, node, grantee)| (node, grantee))
            .collect())
    })?;
    if let Some(broker) = hub.tunnel() {
        for (node_id, grantee) in &ended {
            broker.revoke_grant(node_id, grantee);
        }
    }
    Ok(ended.len())
}

// ---- Usage in `relay.db`. ----

/// The counters of this month from `tunnel_usage` into the broker (at start).
pub fn restore_usage(hub: &Hub, broker: &Broker, now: u64) -> RelayResult<usize> {
    let month = month_of(now);
    let rows: Vec<(String, i64, i64, i64)> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare("SELECT account_id, dials, streams, bytes FROM tunnel_usage WHERE month = ?1")
            .map_err(db)?;
        let rows = statement
            .query_map(params![month.to_string()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(db)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db)
    })?;
    for (account, dials, streams, bytes) in &rows {
        broker.restore_usage(
            account,
            &Usage {
                month,
                bytes: to_u(*bytes),
                dials: to_u(*dials),
                streams: to_u(*streams),
                ..Usage::default()
            },
        );
    }
    Ok(rows.len())
}

/// Writes the counters that changed since `written` to `tunnel_usage` (the larger of the
/// stored and the counted value, so a write never lowers a count). Returns how many rows.
pub fn flush_usage(
    hub: &Hub,
    broker: &Broker,
    written: &mut HashMap<String, Usage>,
) -> RelayResult<usize> {
    let changed: Vec<(String, Usage)> = broker
        .usage_all()
        .into_iter()
        .map(|(account, usage)| {
            (
                account,
                Usage {
                    open_streams: 0,
                    tripped: false,
                    ..usage
                },
            )
        })
        .filter(|(account, usage)| {
            (usage.bytes > 0 || usage.dials > 0 || usage.streams > 0)
                && written.get(account) != Some(usage)
        })
        .collect();
    if changed.is_empty() {
        return Ok(0);
    }
    hub.directory.store.tx(|tx| {
        for (account, usage) in &changed {
            tx.execute(
                "INSERT INTO tunnel_usage (account_id, month, dials, streams, bytes) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (account_id, month) DO UPDATE SET \
                 dials = max(dials, excluded.dials), streams = max(streams, excluded.streams), \
                 bytes = max(bytes, excluded.bytes)",
                params![
                    account,
                    usage.month.to_string(),
                    to_i(usage.dials),
                    to_i(usage.streams),
                    to_i(usage.bytes)
                ],
            )
            .map_err(db)?;
        }
        Ok(())
    })?;
    let count = changed.len();
    written.extend(changed);
    Ok(count)
}

// ---- The runtime of a started relay. ----

/// The broker limits of the settings.
pub fn limits_of(settings: &TunnelSettings) -> Limits {
    Limits {
        streams_per_account: settings.streams_per_account,
        nodes_per_account: settings.nodes_per_account,
        dials_per_minute: settings.dials_per_minute,
        bytes_per_month: settings.bytes_per_month,
        ping_interval: settings.ping_interval,
        idle_timeout: settings.idle_timeout,
        stream_idle: settings.stream_idle,
        stream_buffer: settings.stream_buffer,
        ..Limits::default()
    }
}

/// The tunnel of a started relay: the broker (also in the hub), the ingress listeners, and
/// the usage writer. Dropping it stops all of it and writes the usage once more.
pub struct TunnelRuntime {
    broker: Broker,
    sni: Option<IngressHandle>,
    acme: Option<IngressHandle>,
    stop: Arc<AtomicBool>,
    writer: Option<JoinHandle<()>>,
}

impl TunnelRuntime {
    /// The bound address of the SNI ingress, if it runs.
    pub fn ingress_addr(&self) -> Option<SocketAddr> {
        self.sni.as_ref().map(|handle| handle.addr)
    }

    /// The bound address of the ACME listener, if it runs.
    pub fn acme_addr(&self) -> Option<SocketAddr> {
        self.acme.as_ref().map(|handle| handle.addr)
    }

    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    /// Stops the ingress, closes every tunnel WebSocket, and writes the usage.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        if let Some(sni) = self.sni.take() {
            sni.stop();
        }
        if let Some(acme) = self.acme.take() {
            acme.stop();
        }
        self.broker.stop();
        self.stop.store(true, Ordering::SeqCst);
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

fn listen(addr: SocketAddr, what: &str) -> RelayResult<TcpListener> {
    TcpListener::bind(addr)
        .map_err(|_| RelayError::internal(format!("The tunnel {what} cannot listen on {addr}.")))
}

/// Starts the tunnel of a relay with the account routes (else `None`): the broker in the
/// hub with this month's usage from `relay.db`, each ingress listener whose address is
/// set, and the usage writer (every [`USAGE_FLUSH_SECS`], and at stop).
pub fn start(hub: &Arc<Hub>) -> RelayResult<Option<TunnelRuntime>> {
    if !hub.config.connect.accounts {
        return Ok(None);
    }
    let settings = &hub.config.connect.tunnel;
    let broker = Broker::new(
        Arc::new(AccountDirectory::new(hub)),
        limits_of(settings),
        Arc::new(SystemClock),
        &settings.node_zone,
    );
    let mut runtime = TunnelRuntime {
        broker: broker.clone(),
        sni: None,
        acme: None,
        stop: Arc::new(AtomicBool::new(false)),
        writer: None,
    };
    restore_usage(hub, &broker, crate::now_unix())?;
    if let Some(addr) = settings.ingress_listen {
        let listener = listen(addr, "ingress")?;
        runtime.sni = Some(
            ingress::serve_sni(listener, broker.clone(), IngressConfig::default())
                .map_err(|_| RelayError::internal("The tunnel ingress cannot start."))?,
        );
    }
    if let Some(addr) = settings.acme_listen {
        let listener = listen(addr, "ACME listener")?;
        runtime.acme = Some(
            ingress::serve_acme(listener, broker.clone(), IngressConfig::default())
                .map_err(|_| RelayError::internal("The tunnel ACME listener cannot start."))?,
        );
    }
    if hub.tunnel.set(broker.clone()).is_err() {
        return Err(RelayError::internal(
            "The tunnel of this relay runs already.",
        ));
    }
    let (writer_hub, stop) = (hub.clone(), runtime.stop.clone());
    let writer = std::thread::Builder::new()
        .name("tunnel-usage".to_string())
        .spawn(move || {
            let mut written = HashMap::new();
            let mut last = Instant::now();
            loop {
                let stopping = stop.load(Ordering::SeqCst);
                if stopping || last.elapsed() >= Duration::from_secs(USAGE_FLUSH_SECS) {
                    last = Instant::now();
                    if flush_usage(&writer_hub, &broker, &mut written).is_err() {
                        eprintln!("apassy-relay: the tunnel usage cannot be written");
                    }
                }
                if stopping {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        })
        .map_err(|_| RelayError::internal("The tunnel usage thread cannot start."))?;
    runtime.writer = Some(writer);
    Ok(Some(runtime))
}
