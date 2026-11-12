//! Vaults shared between the accounts of one family or team (ADR 0037 stage 7, contract
//! connect-account-v1 section 16, docs/SPEC.md section 33).
//!
//! The account that made a vault store is the only authority for it. What it says of
//! other accounts are entries of its own signed device list (`account_list`), in the
//! chain of its device entries: `store` (a vault store that this account made, appended
//! with the store), `peer` and `unpeer` (the root of another account, pinned after six
//! words), `share` and `unshare` (a store of this account, for another account), `join`
//! and `leave` (a store of another account that this account syncs; a `join` names the
//! list hash of the `share` it answers). Each is signed by a live device of the list over
//! the hash of the entry before (`apassy-connect share-list v1`). Connect keeps and
//! serves the lists; the devices verify them from the roots they pinned and take no
//! signer from Connect's word.
//!
//! Connect checks, before it stores an entry, what the devices check (the signature, the
//! version, the room of the list, the rules of section 16), and the conditions of the
//! service: a `store` and a `share` come from the account that made the store, and a
//! `share` only after the `store` entry, naming an active member of the same group with a
//! plan that allows sharing; a `peer` names the root of that account's list; a `join`
//! names a store that the other account made and the active `share` of it with the
//! caller. An `unshare` removes the other account's devices from the store, and
//! a `leave` the caller's, in the transaction of the entry. A device of another account
//! is added to a store only while the owner's list shares it with that account (a share
//! newer than the last removal of that account from its group, with the root of that
//! account's list now pinned by the owner's `peer`), and both are active members of one
//! group (`account::may_join_store`); it signs in only after its own list joined the store
//! while that share was active (`account::store_device_live`).
//!
//! The ceremony of section 16.2 meets here: `POST /v1/account/peers/link` keeps the hash
//! of a share code for one member (600 s, one use), `POST /v1/account/peers/join` takes
//! the signed answer of a device of that member, and `GET /v1/account/peers/pending`
//! shows it to the device that made the code, with the answering account's device list.
//! Connect never sees the code, so it cannot compute the six words. The ceremony routes
//! and `POST /v1/account/list` count for the calling device (`PeerCalls`: 60 a minute);
//! the reads of other accounts' lists (`GET /v1/account/peers/{account_id}`, `POST
//! /v1/account/peers/lists`) in a budget of their own (`PeerCalls::reads`: 60 a minute).
//! A list is read by an account of the same group, or by an account that takes part in a
//! vault store with it (`may_read`).

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::api::{
    AccountLinkCreated, AccountListAppend, AccountListAppended, EmptyRequest, ListEntry, ListOp,
    PeerDevice, PeerInviter, PeerJoinRequest, PeerJoinView, PeerJoined, PeerLinkRequest,
    PeerListItem, PeerLists, PeerListsRequest, PeerPending, PeerView, PlanView, Platform, TeamKind,
    VoidShare,
};
use crate::device;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::TeamId;
use crate::secret::is_connect_id;
use crate::server::account::{
    AccountCaller, LINK_KEEP_SECS, LINK_SECS, LINKS_PER_DEVICE, MAX_PEERS, MAX_SHARED,
    account_limit, actor, body_hash, conflict, forbidden, list_entries, next_entry, not_in_group,
    plan_required, public_key_of, share_active, signature_of, strict, to_value, valid_link_hash,
};
use crate::server::hub::{Hub, StoreRemoval, queue_store_removal};
use crate::server::store::{db, to_i, to_u};

/// Pending answers to the share codes of one device at most (the 3 codes of a device,
/// `account::LINKS_PER_DEVICE`): a newer answer ends the oldest (`expired`), and `GET
/// /v1/account/peers/pending` gives at most this many.
pub const PENDING_PER_DEVICE: u64 = 3;
/// Requests of one device to the ceremony routes and `POST /v1/account/list` in one
/// minute at most (429 `rate_limited` with `Retry-After`).
pub const PEER_CALLS_PER_MINUTE: u32 = 60;
/// Reads of other accounts' lists by one device in one minute at most (`GET
/// /v1/account/peers/{account_id}` and `POST /v1/account/peers/lists`; 429 `rate_limited`
/// with `Retry-After`), apart from `PEER_CALLS_PER_MINUTE`.
pub const PEER_READS_PER_MINUTE: u32 = 60;
/// Accounts of one `POST /v1/account/peers/lists` at most.
pub const LIST_READ_ACCOUNTS: usize = 64;
/// The bytes of the `device_list`s of one `POST /v1/account/peers/lists` answer together
/// at most (the first list that changed always comes; a list past it is `later`).
pub const LIST_READ_BYTES: usize = 1 << 20;
/// The window of `PEER_CALLS_PER_MINUTE`, in seconds.
pub const PEER_CALL_WINDOW_SECS: u64 = 60;
/// Devices counted at once at most (the live account tokens of the relay are at most
/// `account::MAX_TOKENS`); a new device past it is 503 `busy` until a window ends.
pub const PEER_CALL_DEVICES: usize = 100_000;

/// The requests of each device to a group of routes of section 16 in fixed windows of
/// `PEER_CALL_WINDOW_SECS` that start at its first request: the ceremony and the list
/// entries (`PeerCalls::default`), or the reads of other accounts' lists
/// (`PeerCalls::reads`). In memory only: a restart resets them (and ends every account
/// token).
#[derive(Debug)]
pub struct PeerCalls {
    windows: Mutex<HashMap<String, (u64, u32)>>,
    per_minute: u32,
    refusal: &'static str,
}

impl Default for PeerCalls {
    fn default() -> Self {
        Self {
            windows: Mutex::default(),
            per_minute: PEER_CALLS_PER_MINUTE,
            refusal: "This device asked too often about shared vaults. Try again in a minute.",
        }
    }
}

/// A request that `PeerCalls` refused: the error and the seconds of its `Retry-After`.
#[derive(Debug)]
pub struct PeerCallRefused {
    pub error: RelayError,
    pub retry_after: u64,
}

impl PeerCalls {
    /// The budget of the reads of other accounts' lists (`PEER_READS_PER_MINUTE`).
    pub fn reads() -> Self {
        Self {
            windows: Mutex::default(),
            per_minute: PEER_READS_PER_MINUTE,
            refusal: "This device read the lists of other accounts too often. Try again in a minute.",
        }
    }

    /// Counts one request of `device` at `now`: refused with 429 `rate_limited` over the
    /// requests of a minute of this budget in its window (until the window ends), and with
    /// 503 `busy` for a new device while `PEER_CALL_DEVICES` windows are open.
    pub fn take(&self, device: &str, now: u64) -> Result<(), PeerCallRefused> {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let ended = |start: u64| now >= start.saturating_add(PEER_CALL_WINDOW_SECS);
        if !windows.contains_key(device) && windows.len() >= PEER_CALL_DEVICES {
            windows.retain(|_, (start, _)| !ended(*start));
            if windows.len() >= PEER_CALL_DEVICES {
                return Err(PeerCallRefused {
                    error: crate::server::account::busy(
                        "The relay counts too many devices now. Try again in a minute.",
                    ),
                    retry_after: PEER_CALL_WINDOW_SECS,
                });
            }
        }
        let window = windows.entry(device.to_owned()).or_insert((now, 0));
        if ended(window.0) {
            *window = (now, 0);
        }
        if window.1 >= self.per_minute {
            return Err(PeerCallRefused {
                error: RelayError::new(codes::RATE_LIMITED, self.refusal),
                retry_after: window
                    .0
                    .saturating_add(PEER_CALL_WINDOW_SECS)
                    .saturating_sub(now)
                    .max(1),
            });
        }
        window.1 += 1;
        Ok(())
    }
}

/// The routes of section 16 below `/v1/account`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEndpoint {
    /// `POST /v1/account/list`.
    Append,
    /// `POST /v1/account/peers/link`.
    Link,
    /// `POST /v1/account/peers/join`.
    Join,
    /// `GET /v1/account/peers/pending`.
    Pending,
    /// `GET /v1/account/peers/join/{join_id}`.
    JoinState(u64),
    /// `DELETE /v1/account/peers/join/{join_id}`.
    JoinEnd(u64),
    /// `GET /v1/account/peers/{account_id}`.
    View(String),
    /// `POST /v1/account/peers/lists`.
    Lists,
}

impl PeerEndpoint {
    /// A read of other accounts' lists: it counts in `PeerCalls::reads`, the other routes
    /// in the budget of the ceremony.
    pub fn is_read(&self) -> bool {
        matches!(self, Self::View(_) | Self::Lists)
    }
}

/// The endpoint of `rest`, the segments after `/v1/account`. 404 for an unknown path, 405
/// for a known path with another method.
pub fn route(method: &str, rest: &[&str]) -> RelayResult<PeerEndpoint> {
    let not_found = || RelayError::new(codes::NOT_FOUND, "No such path.");
    let only = |wanted: &str, endpoint: PeerEndpoint| {
        if method == wanted {
            Ok(endpoint)
        } else {
            Err(RelayError::new(
                codes::METHOD_NOT_ALLOWED,
                "This path does not allow this method.",
            ))
        }
    };
    match rest {
        ["list"] => only("POST", PeerEndpoint::Append),
        ["peers", "link"] => only("POST", PeerEndpoint::Link),
        ["peers", "join"] => only("POST", PeerEndpoint::Join),
        ["peers", "pending"] => only("GET", PeerEndpoint::Pending),
        ["peers", "lists"] => only("POST", PeerEndpoint::Lists),
        ["peers", "join", id] => {
            let id = id.parse::<u64>().map_err(|_| not_found())?;
            match method {
                "GET" => Ok(PeerEndpoint::JoinState(id)),
                "DELETE" => Ok(PeerEndpoint::JoinEnd(id)),
                _ => only("GET", PeerEndpoint::JoinState(id)),
            }
        }
        ["peers", account] if is_connect_id(account, "acc_") => {
            only("GET", PeerEndpoint::View((*account).to_string()))
        }
        _ => Err(not_found()),
    }
}

/// An endpoint of section 16 with the account token of `caller`.
pub fn dispatch(
    hub: &Hub,
    caller: &AccountCaller,
    endpoint: &PeerEndpoint,
    body: &[u8],
    now: u64,
) -> RelayResult<Value> {
    match endpoint {
        PeerEndpoint::Append => append(hub, caller, &strict(body)?, now),
        PeerEndpoint::Link => link(hub, caller, &strict(body)?, now),
        PeerEndpoint::Join => join(hub, caller, &strict(body)?, now),
        PeerEndpoint::Pending => pending(hub, caller, now),
        PeerEndpoint::JoinState(id) => join_state(hub, caller, *id, now),
        PeerEndpoint::JoinEnd(id) => {
            strict::<EmptyRequest>(body)?;
            join_end(hub, caller, *id, now)
        }
        PeerEndpoint::View(account) => view(hub, caller, account, now),
        PeerEndpoint::Lists => lists(hub, caller, &strict(body)?, now),
    }
}

/// Deletes share codes (with their answers) a day after they end. Answers how many.
pub(crate) fn prune_links(tx: &Connection, now: u64) -> RelayResult<usize> {
    tx.execute(
        "DELETE FROM account_peer_link WHERE expires_at < ?1",
        params![to_i(now.saturating_sub(LINK_KEEP_SECS))],
    )
    .map_err(db)
}

// ---- What a list says of other accounts. ----

/// The active peers, shares, and joins of a list at its head, and the stores it names in
/// a `store` entry (the rules of section 16). A join keeps the list hash of the share it
/// answers (`None` for a join stored before joins named it).
#[derive(Debug, Default)]
struct ListState {
    peers: Vec<(String, Vec<u8>)>,
    shares: Vec<(String, String)>,
    joins: Vec<(String, String, Option<Vec<u8>>)>,
    stores: Vec<String>,
    /// Every share that a `join` of this list answered (store, account, share hash), also
    /// a join that a `leave` ended: the same share is not joined twice.
    joined: Vec<(String, String, Vec<u8>)>,
}

impl ListState {
    fn is_peer(&self, account: &str) -> bool {
        self.peers.iter().any(|(held, _)| held == account)
    }

    fn names(&self, account: &str) -> bool {
        self.shares.iter().any(|(_, held)| held == account)
            || self.joins.iter().any(|(_, held, _)| held == account)
    }

    fn holds_store(&self, team: &str) -> bool {
        self.stores.iter().any(|held| held == team)
    }

    fn shared(&self, team: &str) -> bool {
        self.shares.iter().any(|(store, _)| store == team)
    }

    /// The active join of `team`, with the account it names and the share it answers.
    fn join_of(&self, team: &str) -> Option<&(String, String, Option<Vec<u8>>)> {
        self.joins.iter().find(|(store, _, _)| store == team)
    }

    /// Apply one stored entry (they were checked when they were written). A `join` of a
    /// pair with an active join replaces it: one active join for each pair.
    fn take(
        &mut self,
        op: ListOp,
        account: Option<String>,
        root: Option<Vec<u8>>,
        team: Option<String>,
    ) {
        match (op, account, team) {
            (ListOp::Peer, Some(account), _) => {
                self.peers.push((account, root.unwrap_or_default()));
            }
            (ListOp::Unpeer, Some(account), _) => self.peers.retain(|(held, _)| *held != account),
            (ListOp::Share, Some(account), Some(team)) => self.shares.push((team, account)),
            (ListOp::Unshare, Some(account), Some(team)) => self
                .shares
                .retain(|(store, held)| (store, held) != (&team, &account)),
            (ListOp::Join, Some(account), Some(team)) => {
                self.joins
                    .retain(|(store, held, _)| (store, held) != (&team, &account));
                if let Some(share) = &root {
                    self.joined
                        .push((team.clone(), account.clone(), share.clone()));
                }
                self.joins.push((team, account, root));
            }
            (ListOp::Leave, Some(account), Some(team)) => self
                .joins
                .retain(|(store, held, _)| (store, held) != (&team, &account)),
            (ListOp::Store, None, Some(team)) => self.stores.push(team),
            _ => {}
        }
    }

    /// Whether the rules of section 16 allow `op` for `account` (`None` for a `store`),
    /// `team`, and `root` (the share that a `join` answers) now: 409 `conflict` when the
    /// list does not allow it at its head, 403 `account_limit` over the counts.
    fn check(
        &self,
        op: ListOp,
        account: Option<&str>,
        team: Option<&str>,
        root: Option<&[u8]>,
    ) -> RelayResult<()> {
        let refused =
            || conflict("The device list does not allow this entry now. Read the account again.");
        let counted = self.shares.len() + self.joins.len();
        let full = || account_limit("This account has 128 shared vaults.");
        match (op, account, team) {
            (ListOp::Peer, Some(account), None) => {
                if self.is_peer(account) {
                    return Err(refused());
                }
                if self.peers.len() as u64 >= MAX_PEERS {
                    return Err(account_limit("This account pins 64 other accounts."));
                }
            }
            (ListOp::Unpeer, Some(account), None) => {
                if !self.is_peer(account) || self.names(account) {
                    return Err(refused());
                }
            }
            (ListOp::Share, Some(account), Some(team)) => {
                let pair = (team.to_owned(), account.to_owned());
                if !self.is_peer(account)
                    || !self.holds_store(team)
                    || self.join_of(team).is_some()
                    || self.shares.contains(&pair)
                {
                    return Err(refused());
                }
                if counted as u64 >= MAX_SHARED {
                    return Err(full());
                }
            }
            (ListOp::Join, Some(account), Some(team)) => {
                let earlier = self.join_of(team);
                let again = root.is_some_and(|root| {
                    self.joined.iter().any(|(store, held, share)| {
                        store == team && held == account && share.as_slice() == root
                    })
                });
                if !self.is_peer(account)
                    || self.shared(team)
                    || self.holds_store(team)
                    || again
                    || earlier.is_some_and(|(_, held, answered)| {
                        held != account || answered.as_deref() == root
                    })
                {
                    return Err(refused());
                }
                // A join that replaces the active join of the pair adds none.
                if earlier.is_none() && counted as u64 >= MAX_SHARED {
                    return Err(full());
                }
            }
            (ListOp::Unshare, Some(account), Some(team)) => {
                if !self.shares.contains(&(team.to_owned(), account.to_owned())) {
                    return Err(refused());
                }
            }
            (ListOp::Leave, Some(account), Some(team)) => {
                if !self
                    .joins
                    .iter()
                    .any(|(store, held, _)| store == team && held == account)
                {
                    return Err(refused());
                }
            }
            (ListOp::Store, None, Some(team)) => {
                if self.holds_store(team) || self.join_of(team).is_some() {
                    return Err(refused());
                }
            }
            _ => {
                return Err(RelayError::invalid(
                    "This entry has fields that its op does not take.",
                ));
            }
        }
        Ok(())
    }
}

/// The state of the list of `account` at its head.
fn list_state(conn: &Connection, account: &str) -> RelayResult<ListState> {
    let mut statement = conn
        .prepare(
            "SELECT op, peer_account, peer_root, team_id FROM account_list \
             WHERE account_id = ?1 AND (peer_account IS NOT NULL OR op = 'store') ORDER BY version",
        )
        .map_err(db)?;
    let rows = statement
        .query_map(params![account], |row| {
            let op: String = row.get(0)?;
            Ok((
                ListOp::parse(&op).ok_or(rusqlite::Error::InvalidQuery)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)?;
    let mut state = ListState::default();
    for (op, peer, root, team) in rows {
        state.take(op, peer, root, team);
    }
    Ok(state)
}

/// The root of `account`: the key of version 1 of its list. 404 for an account that does
/// not exist.
fn root_of(conn: &Connection, account: &str) -> RelayResult<Vec<u8>> {
    conn.query_row(
        "SELECT key FROM account_list WHERE account_id = ?1 AND version = 1",
        params![account],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(db)?
    .ok_or_else(|| RelayError::not_found("account"))
}

/// The account that made the vault store `team`, or 404 for a team that is no vault store.
fn store_owner(conn: &Connection, team: &TeamId) -> RelayResult<String> {
    crate::server::directory::team_by_id(conn, team)?
        .filter(|row| row.kind == TeamKind::Account)
        .and_then(|row| row.account_id)
        .ok_or_else(|| RelayError::not_found("vault store"))
}

/// Whether `plan` allows sharing: an entitled Family or Team plan.
fn allows_sharing(plan: &PlanView) -> bool {
    plan.entitled && matches!(plan.plan.as_deref(), Some("family" | "team"))
}

/// Whether the plan of `account` allows sharing.
fn shares_plan(hub: &Hub, account: &str, now: u64) -> RelayResult<bool> {
    let plan = hub
        .accounts
        .plans()
        .plan(&hub.directory.store, account, now)?;
    Ok(allows_sharing(&plan))
}

/// Whether `a` and `b` are active members of one group.
fn same_group(hub: &Hub, a: &str, b: &str, now: u64) -> RelayResult<bool> {
    hub.accounts
        .groups()
        .share_group(&hub.directory.store, a, b, now)
}

/// The group check again on `tx`, the transaction of the change it guards, when the seam
/// reads on a transaction (`Groups::share_group_on`): a removal from the group that
/// committed after the check before the transaction refuses the change (403
/// `not_in_group`).
fn same_group_on(hub: &Hub, tx: &Connection, a: &str, b: &str, now: u64) -> RelayResult<()> {
    if hub.accounts.groups().share_group_on(tx, a, b, now)? == Some(false) {
        return Err(not_in_group());
    }
    Ok(())
}

/// The plan check of a `share` again on `tx`, when the seam reads on a transaction
/// (`Plans::plan_on`; 403 `plan_required`).
fn shares_plan_on(hub: &Hub, tx: &Connection, accounts: [&str; 2], now: u64) -> RelayResult<()> {
    let plans = hub.accounts.plans();
    for account in accounts {
        if plans
            .plan_on(tx, account, now)?
            .is_some_and(|plan| !allows_sharing(&plan))
        {
            return Err(plan_required());
        }
    }
    Ok(())
}

/// A removal of `member` from its group, or the rollback of its confirmation (in its
/// transaction `tx`): every `share` that names `member`, and every `share` that `member`
/// made, is void at Connect from the head of its owner's list on (`account_share_void`),
/// so after a new admission only a newer `share` gives the other account's devices a store
/// (`account::share_active`). The lists stay as they are: a client sees the share, and
/// Connect counts it for nothing (and names it in the `void` of its views). Answers the
/// marks written.
pub(crate) fn void_shares_naming(tx: &Connection, member: &str, now: u64) -> RelayResult<usize> {
    let head = "(SELECT max(h.version) FROM account_list h WHERE h.account_id = l.account_id)";
    let upsert = "ON CONFLICT(account_id, peer_account) DO UPDATE SET version = excluded.version, \
                  created_at = excluded.created_at";
    let naming = tx
        .execute(
            &format!(
                "INSERT INTO account_share_void (account_id, peer_account, version, created_at) \
                 SELECT l.account_id, ?1, {head}, ?2 \
                 FROM account_list l WHERE l.peer_account = ?1 AND l.op = 'share' GROUP BY l.account_id {upsert}"
            ),
            params![member, to_i(now)],
        )
        .map_err(db)?;
    let made = tx
        .execute(
            &format!(
                "INSERT INTO account_share_void (account_id, peer_account, version, created_at) \
                 SELECT ?1, l.peer_account, {head}, ?2 \
                 FROM account_list l WHERE l.account_id = ?1 AND l.op = 'share' GROUP BY l.peer_account {upsert}"
            ),
            params![member, to_i(now)],
        )
        .map_err(db)?;
    Ok(naming + made)
}

/// The shares of the list of `owner` (of the store `team` only, when given) that are
/// active in the list (the last `share` or `unshare` of the pair is a `share`) and void
/// at Connect (a mark of `account_share_void` at their version or later), in their order.
pub(crate) fn void_shares(
    conn: &Connection,
    owner: &str,
    team: Option<&str>,
) -> RelayResult<Vec<VoidShare>> {
    let mut statement = conn
        .prepare(
            "SELECT l.team_id, l.peer_account FROM account_list l JOIN account_share_void v \
             ON v.account_id = l.account_id AND v.peer_account = l.peer_account \
             WHERE l.account_id = ?1 AND l.op = 'share' AND l.version <= v.version \
             AND (?2 IS NULL OR l.team_id = ?2) \
             AND NOT EXISTS(SELECT 1 FROM account_list u WHERE u.account_id = l.account_id \
               AND u.team_id = l.team_id AND u.peer_account = l.peer_account \
               AND u.op IN ('share', 'unshare') AND u.version > l.version) \
             ORDER BY l.version",
        )
        .map_err(db)?;
    statement
        .query_map(params![owner, team], |row| {
            Ok(VoidShare {
                team_id: row.get(0)?,
                account_id: row.get(1)?,
            })
        })
        .map_err(db)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db)
}

/// The store rows of the devices of `account` in `team`, queued for removal in `tx`.
fn queue_account_removals(
    tx: &Connection,
    team: &TeamId,
    account: &str,
    now: u64,
) -> RelayResult<Vec<StoreRemoval>> {
    let rows: Vec<(String, i64)> = {
        let mut statement = tx
            .prepare(
                "SELECT device_id, store_device FROM account_store_device WHERE team_id = ?1 AND account_id = ?2",
            )
            .map_err(db)?;
        statement
            .query_map(params![team.as_str(), account], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?
    };
    let mut removals = Vec::with_capacity(rows.len());
    for (device, store_device) in rows {
        let removal = StoreRemoval {
            team: team.clone(),
            device,
            store_device: to_u(store_device),
        };
        queue_store_removal(tx, &removal, now)?;
        removals.push(removal);
    }
    Ok(removals)
}

/// One checked entry of section 16 of `caller`'s list: its op, the other account (`None`
/// for a `store`), the root (the pinned root of a `peer`, the list hash of the share that
/// a `join` answers), the store, and the caller's signature over its message.
struct Entry<'a> {
    version: u64,
    op: ListOp,
    peer: Option<&'a str>,
    root: Option<&'a [u8]>,
    team: Option<&'a TeamId>,
    statement: &'a [u8],
}

impl Entry<'_> {
    /// The `apassy-connect share-list v1` message of the entry after the head `previous`.
    fn message(&self, origin: &str, caller: &AccountCaller, previous: &str) -> Vec<u8> {
        let root = self.root.map(encode_b64);
        device::share_list_message(
            origin,
            &caller.account,
            self.version,
            previous,
            self.op.as_str(),
            self.peer.unwrap_or(device::LIST_NONE),
            root.as_deref().unwrap_or(device::LIST_NONE),
            self.team.map_or(device::LIST_NONE, TeamId::as_str),
            &encode_b64(&caller.public_key),
        )
    }

    /// The checks of every entry in the transaction `tx`: `next_entry` (409 for another
    /// version, 403 `account_limit` for the room, 401 for a signer that is not live in the
    /// list) and the signature over its message (400). Answers the message.
    fn signed(
        &self,
        tx: &Connection,
        origin: &str,
        caller: &AccountCaller,
    ) -> RelayResult<Vec<u8>> {
        let previous = next_entry(tx, caller, self.version, self.op, &caller.public_key)?;
        let message = self.message(origin, caller, &previous);
        if !device::verify(&caller.public_key, &message, self.statement) {
            return Err(RelayError::invalid(
                "The statement is not the signature of this device over the next entry of the device list. Nothing changed.",
            ));
        }
        Ok(message)
    }

    /// Writes the entry with the hash of `message`.
    fn write(
        &self,
        tx: &Connection,
        caller: &AccountCaller,
        message: &[u8],
        now: u64,
    ) -> RelayResult<()> {
        tx.execute(
            "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at, peer_account, peer_root, team_id) \
             VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                caller.account,
                to_i(self.version),
                self.op.as_str(),
                caller.public_key,
                self.statement,
                device::account_list_hash(message),
                to_i(now),
                self.peer,
                self.root,
                self.team.map(TeamId::as_str),
            ],
        )
        .map_err(db)
        .map(drop)
    }
}

/// The `store` entry of the new vault store `team` of `caller`, at `version`, signed with
/// `statement`, inside the directory transaction `tx` that inserts the store
/// (`Hub::create_vault_store`): the checks of `Entry::signed`, then the rules of section
/// 16 (409: the list names the store already), then the entry.
pub(crate) fn store_entry(
    tx: &Connection,
    origin: &str,
    caller: &AccountCaller,
    team: &TeamId,
    version: u64,
    statement: &[u8],
    now: u64,
) -> RelayResult<()> {
    let entry = Entry {
        version,
        op: ListOp::Store,
        peer: None,
        root: None,
        team: Some(team),
        statement,
    };
    let message = entry.signed(tx, origin, caller)?;
    list_state(tx, &caller.account)?.check(ListOp::Store, None, Some(team.as_str()), None)?;
    entry.write(tx, caller, &message, now)
}

/// The `share` of `team` with `member` in the list of `owner` that a `join` answers: the
/// last one, while it is active by the share condition (`account::share_active`, with the
/// owner's `store` entry), with its version and its list hash.
fn answered_share(
    tx: &Connection,
    owner: &str,
    team: &TeamId,
    member: &str,
) -> RelayResult<Option<(i64, String)>> {
    if !share_active(tx, owner, team.as_str(), member)? {
        return Ok(None);
    }
    tx.query_row(
        "SELECT version, hash FROM account_list WHERE account_id = ?1 AND team_id = ?2 \
         AND peer_account = ?3 AND op = 'share' ORDER BY version DESC LIMIT 1",
        params![owner, team.as_str(), member],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(db)
}

// ---- `POST /v1/account/list` (section 16.3). ----

/// `POST /v1/account/list`: an entry of section 16, signed by the calling device at the
/// version after the head. In this order: the shape (400), the group and the plan of a
/// `peer`, `share`, or `join` (403 `not_in_group`, 403 `plan_required`; read before the
/// transaction and again in it, where the seams read on a transaction), then in one
/// transaction the version and the room (409, 403 `account_limit`), the signer (401 for a
/// device that is not in the list), the signature (400), for a `share` or a `store` the
/// account that made the store (404 for no store, 403 `forbidden` for another account's),
/// the rules of section 16 (409), and the conditions of each op; then the entry, for a
/// `join` the share it answers (`account_join_share`), and for an `unshare` or a `leave`
/// the removal of the store rows. Nothing is written on a refusal.
fn append(
    hub: &Hub,
    caller: &AccountCaller,
    request: &AccountListAppend,
    now: u64,
) -> RelayResult<Value> {
    let op = request.op;
    if !op.of_section_16() {
        return Err(RelayError::invalid(
            "This route takes the entries of section 16. A device is added by a confirmation and removed by a revoke.",
        ));
    }
    let peer = match (op, request.account_id.as_deref()) {
        (ListOp::Store, None) => None,
        (ListOp::Store, Some(_)) | (_, None) => {
            return Err(RelayError::invalid(
                "A store entry names no account, and every other entry of section 16 names one.",
            ));
        }
        (_, Some(peer)) => {
            if !is_connect_id(peer, "acc_") || peer == caller.account {
                return Err(RelayError::invalid(
                    "The account id is not another account.",
                ));
            }
            Some(peer)
        }
    };
    let root: Option<Vec<u8>> = match (op, request.root.as_deref()) {
        (ListOp::Peer, Some(root)) => Some(public_key_of(root)?.to_vec()),
        (ListOp::Join, Some(hash)) if valid_link_hash(hash) => Some(
            decode_b64(hash, 32)
                .map_err(|_| RelayError::invalid("The share hash is not valid."))?,
        ),
        (ListOp::Peer | ListOp::Join, _) | (_, Some(_)) => {
            return Err(RelayError::invalid(
                "A peer entry names the root it pins, and a join the list hash of the share it answers; no other entry names a root.",
            ));
        }
        (_, None) => None,
    };
    let team = match (op.names_store(), request.team_id.as_deref()) {
        (true, Some(team)) => Some(
            TeamId::parse(team).ok_or_else(|| RelayError::invalid("The store id is not valid."))?,
        ),
        (false, None) => None,
        _ => {
            return Err(RelayError::invalid(
                "Only a share, unshare, join, leave, or store entry names a store, and each must.",
            ));
        }
    };
    let statement = decode_b64(&request.statement, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::invalid("The statement is not valid."))?;
    let entry = Entry {
        version: request.version,
        op,
        peer,
        root: root.as_deref(),
        team: team.as_ref(),
        statement: &statement,
    };
    // The conditions of the service that read the group and the plan seams.
    let other = peer.unwrap_or_default();
    if matches!(op, ListOp::Peer | ListOp::Share | ListOp::Join)
        && !same_group(hub, &caller.account, other, now)?
    {
        return Err(not_in_group());
    }
    if op == ListOp::Share
        && (!shares_plan(hub, &caller.account, now)? || !shares_plan(hub, other, now)?)
    {
        return Err(plan_required());
    }
    let origin = hub.config.public_url.clone();
    let (removals, version) = hub.directory.store.tx(|tx| {
        if matches!(op, ListOp::Peer | ListOp::Share | ListOp::Join) {
            same_group_on(hub, tx, &caller.account, other, now)?;
        }
        if op == ListOp::Share {
            shares_plan_on(hub, tx, [&caller.account, other], now)?;
        }
        let message = entry.signed(tx, &origin, caller)?;
        if let (ListOp::Share | ListOp::Store, Some(team)) = (op, team.as_ref())
            && store_owner(tx, team)? != caller.account
        {
            return Err(forbidden(if op == ListOp::Share {
                "Only the account that made a vault store shares it."
            } else {
                "Only the account that made a vault store names it in its list."
            }));
        }
        let state = list_state(tx, &caller.account)?;
        state.check(op, peer, team.as_ref().map(TeamId::as_str), root.as_deref())?;
        let mut removals = Vec::new();
        let mut answered = None;
        match (op, team.as_ref()) {
            (ListOp::Peer, _) => {
                if Some(root_of(tx, other)?.as_slice()) != root.as_deref() {
                    return Err(conflict(
                        "That root is not the root of the other account's device list. Nothing changed.",
                    ));
                }
            }
            (ListOp::Join, Some(team)) => {
                // The share that this join answers: the owner's last `share` of the store
                // with the caller, active now, named by its list hash.
                let named = root.as_deref().map(encode_b64);
                answered = match answered_share(tx, other, team, &caller.account)? {
                    Some((share_version, hash))
                        if store_owner(tx, team)? == other && Some(&hash) == named.as_ref() =>
                    {
                        Some(share_version)
                    }
                    _ => {
                        return Err(conflict(
                            "That account does not share this vault store with you by that share. Nothing changed.",
                        ));
                    }
                };
            }
            (ListOp::Unshare, Some(team)) => removals = queue_account_removals(tx, team, other, now)?,
            (ListOp::Leave, Some(team)) => removals = queue_account_removals(tx, team, &caller.account, now)?,
            _ => {}
        }
        entry.write(tx, caller, &message, now)?;
        if let (Some(share_version), Some(team)) = (answered, team.as_ref()) {
            // The share that this join answers: the member's devices sign in to the store
            // only while it is the active one (`account::store_device_live`).
            tx.execute(
                "INSERT INTO account_join_share (account_id, team_id, share_version, created_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(account_id, team_id) DO UPDATE SET \
                 share_version = excluded.share_version, created_at = excluded.created_at",
                params![caller.account, team.as_str(), share_version, to_i(now)],
            )
            .map_err(db)?;
        }
        if op == ListOp::Peer {
            // The answer of that account to a share code of this account is confirmed.
            tx.execute(
                "UPDATE account_peer_join SET state = 'confirmed', decided_at = ?3 WHERE state = 'pending' \
                 AND account_id = ?2 AND link_id IN (SELECT id FROM account_peer_link WHERE account_id = ?1)",
                params![caller.account, other, to_i(now)],
            )
            .map_err(db)?;
        }
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_list_peer_entry",
            None,
            &json!({"op": op.as_str(), "account_id": peer, "team_id": team.as_ref().map(TeamId::as_str),
                    "by": caller.device, "list_version": request.version,
                    "removed_from_store": removals.len()}),
        )?;
        Ok((removals, request.version))
    })?;
    hub.apply_removals(&removals, now);
    to_value(&AccountListAppended { version, op })
}

// ---- The ceremony (section 16.2). ----

/// `POST /v1/account/peers/link`: the hash of a share code that the calling device made
/// for the member `account_id` of its group (403 `not_in_group` otherwise, also in the
/// transaction). One use, 600 s, at most 3 codes of one device that have not expired,
/// used or not (403 `account_limit`).
fn link(
    hub: &Hub,
    caller: &AccountCaller,
    request: &PeerLinkRequest,
    now: u64,
) -> RelayResult<Value> {
    if !valid_link_hash(&request.link_hash) {
        return Err(RelayError::invalid("The link hash is b64u of 32 bytes."));
    }
    if !is_connect_id(&request.account_id, "acc_") || request.account_id == caller.account {
        return Err(RelayError::invalid(
            "The account id is not another account.",
        ));
    }
    if !same_group(hub, &caller.account, &request.account_id, now)? {
        return Err(not_in_group());
    }
    let expires_at = now.saturating_add(LINK_SECS);
    let link_id = hub.directory.store.tx(|tx| {
        same_group_on(hub, tx, &caller.account, &request.account_id, now)?;
        // A used code counts until it expires: its answer waits for the confirmation.
        let open: i64 = tx
            .query_row(
                "SELECT count(*) FROM account_peer_link WHERE device_id = ?1 AND expires_at > ?2",
                params![caller.device, to_i(now)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(open) >= LINKS_PER_DEVICE {
            return Err(account_limit(
                "This device made 3 share codes in the last 10 minutes. Wait until one ends.",
            ));
        }
        let taken: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_peer_link WHERE link_hash = ?1)",
                params![request.link_hash],
                |row| row.get(0),
            )
            .map_err(db)?;
        if taken {
            return Err(conflict("This code was made before. Make a new code."));
        }
        tx.execute(
            "INSERT INTO account_peer_link (account_id, device_id, peer_account, link_hash, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![caller.account, caller.device, request.account_id, request.link_hash, to_i(now), to_i(expires_at)],
        )
        .map_err(db)?;
        let link_id = to_u(tx.last_insert_rowid());
        hub.directory.audit.write_on(
            tx,
            now,
            &actor(&caller.account),
            "account_share_code_created",
            None,
            &json!({"link_id": link_id, "device_id": caller.device, "account_id": request.account_id}),
        )?;
        Ok(link_id)
    })?;
    to_value(&AccountLinkCreated {
        link_id,
        expires_at,
    })
}

/// The device that made the share code `link_id`, as the answer names it.
fn inviter(conn: &Connection, link_id: i64) -> RelayResult<PeerInviter> {
    conn.query_row(
        "SELECT l.account_id, d.id, a.name, d.public_key FROM account_peer_link l \
         JOIN account_device d ON d.id = l.device_id JOIN account a ON a.id = l.account_id WHERE l.id = ?1",
        params![link_id],
        |row| {
            let key: Vec<u8> = row.get(3)?;
            Ok(PeerInviter {
                account_id: row.get(0)?,
                device_id: row.get(1)?,
                name: row.get(2)?,
                public_key: encode_b64(&key),
            })
        },
    )
    .map_err(db)
}

/// `POST /v1/account/peers/join`: a device of the member that a share code was made for
/// answers it, with its signature over the `apassy-connect peer-join v1` message of its
/// account, its root, and its key (400 otherwise). An unknown, used, or expired code, or
/// a code for another account, is 403 `forbidden`; the same body again answers the same
/// result. A new answer ends the oldest pending answers to the codes of the same device
/// beyond `PENDING_PER_DEVICE`. The answer names the device that made the code and
/// carries its account's device list, read after the transaction.
fn join(
    hub: &Hub,
    caller: &AccountCaller,
    request: &PeerJoinRequest,
    now: u64,
) -> RelayResult<Value> {
    if !is_connect_id(&request.account_id, "acc_")
        || request.account_id == caller.account
        || !valid_link_hash(&request.link_hash)
    {
        return Err(RelayError::invalid(
            "The account id or the link hash is not valid.",
        ));
    }
    let signature = signature_of(&request.signature)?;
    let root = hub
        .directory
        .store
        .with(|conn| root_of(conn, &caller.account))?;
    let message = device::peer_join_message(
        &hub.config.public_url,
        &request.account_id,
        &request.link_hash,
        &caller.account,
        &encode_b64(&root),
        &encode_b64(&caller.public_key),
    );
    if !device::verify(&caller.public_key, &message, &signature) {
        return Err(RelayError::invalid(
            "The signature is not one of this device over the answer of this Connect.",
        ));
    }
    if !same_group(hub, &caller.account, &request.account_id, now)? {
        return Err(not_in_group());
    }
    let hash = body_hash(request)?;
    let (join_id, inviter, expires_at) = hub.directory.store.tx(|tx| {
        same_group_on(hub, tx, &caller.account, &request.account_id, now)?;
        let earlier: Option<(i64, i64, i64)> = tx
            .query_row(
                "SELECT id, link_id, expires_at FROM account_peer_join WHERE body_hash = ?1 AND device_id = ?2",
                params![hash.as_slice(), caller.device],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        let (join_id, link_id, expires_at) = match earlier {
            Some(earlier) => earlier,
            None => {
                let link: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT l.id, l.expires_at FROM account_peer_link l JOIN account_device d ON d.id = l.device_id \
                         WHERE l.account_id = ?1 AND l.link_hash = ?2 AND l.peer_account = ?3 AND l.used_at IS NULL \
                         AND l.expires_at > ?4 AND d.revoked_at IS NULL",
                        params![request.account_id, request.link_hash, caller.account, to_i(now)],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(db)?;
                let (link_id, expires_at) =
                    link.ok_or_else(|| forbidden("The code is not valid, was used, expired, or is for another account."))?;
                tx.execute(
                    "UPDATE account_peer_link SET used_at = ?2 WHERE id = ?1",
                    params![link_id, to_i(now)],
                )
                .map_err(db)?;
                tx.execute(
                    "INSERT INTO account_peer_join (link_id, account_id, device_id, public_key, signature, body_hash, state, created_at, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8)",
                    params![link_id, caller.account, caller.device, caller.public_key, signature,
                            hash.as_slice(), to_i(now), expires_at],
                )
                .map_err(db)?;
                let join_id = tx.last_insert_rowid();
                // At most `PENDING_PER_DEVICE` pending answers to the codes of the device
                // that made this one: the oldest end first.
                tx.execute(
                    "UPDATE account_peer_join SET state = 'expired', decided_at = ?2 WHERE id IN \
                     (SELECT j.id FROM account_peer_join j JOIN account_peer_link l ON l.id = j.link_id \
                      WHERE l.device_id = (SELECT device_id FROM account_peer_link WHERE id = ?1) \
                      AND j.state = 'pending' AND j.expires_at > ?2 ORDER BY j.id DESC LIMIT -1 OFFSET ?3)",
                    params![link_id, to_i(now), to_i(PENDING_PER_DEVICE)],
                )
                .map_err(db)?;
                hub.directory.audit.write_on(
                    tx,
                    now,
                    &actor(&caller.account),
                    "account_share_code_answered",
                    None,
                    &json!({"join_id": join_id, "link_id": link_id, "device_id": caller.device}),
                )?;
                (join_id, link_id, expires_at)
            }
        };
        Ok((join_id, inviter(tx, link_id)?, expires_at))
    })?;
    let device_list = hub
        .directory
        .store
        .with(|conn| list_entries(conn, &request.account_id))?;
    to_value(&PeerJoined {
        join_id: to_u(join_id),
        inviter,
        expires_at: to_u(expires_at),
        device_list,
    })
}

/// One pending answer as `relay.db` holds it: the answer, the code, the account and its
/// name, the key and its signature, and the times.
type PendingRow = (i64, i64, String, String, Vec<u8>, Vec<u8>, i64, i64);

/// `GET /v1/account/peers/pending`: the pending answers to the share codes that this
/// device made (at most `PENDING_PER_DEVICE`, the newest, in their order), each with the
/// answering account's device list. The lists are read after the answers, each account's
/// once and each in a lock of its own.
fn pending(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let mut rows: Vec<PendingRow> = hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT j.id, j.link_id, j.account_id, a.name, j.public_key, j.signature, j.created_at, j.expires_at \
                 FROM account_peer_join j JOIN account_peer_link l ON l.id = j.link_id JOIN account a ON a.id = j.account_id \
                 WHERE l.device_id = ?1 AND j.state = 'pending' AND j.expires_at > ?2 ORDER BY j.id DESC LIMIT ?3",
            )
            .map_err(db)?;
        statement
            .query_map(
                params![caller.device, to_i(now), to_i(PENDING_PER_DEVICE)],
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
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    })?;
    rows.reverse();
    let mut lists: HashMap<String, Vec<crate::api::ListEntry>> = HashMap::new();
    let mut answers = Vec::with_capacity(rows.len());
    for (join_id, link_id, account, name, key, signature, created_at, expires_at) in rows {
        let device_list = match lists.get(&account) {
            Some(list) => list.clone(),
            None => {
                let list = hub
                    .directory
                    .store
                    .with(|conn| list_entries(conn, &account))?;
                lists.insert(account.clone(), list.clone());
                list
            }
        };
        answers.push(PeerPending {
            join_id: to_u(join_id),
            link_id: to_u(link_id),
            device_list,
            account_id: account,
            name,
            public_key: encode_b64(&key),
            signature: encode_b64(&signature),
            created_at: to_u(created_at),
            expires_at: to_u(expires_at),
        });
    }
    to_value(&answers)
}

/// The answer `join_id`, for the device that answered or the device that made the code
/// (404 for any other caller): its state, with `expired` for a pending answer past its
/// time, and whether `caller` made the code.
fn own_join(
    conn: &Connection,
    caller: &AccountCaller,
    join_id: u64,
    now: u64,
) -> RelayResult<(PeerJoinView, bool)> {
    let row: Option<(String, i64, String, String)> = conn
        .query_row(
            "SELECT j.state, j.expires_at, j.device_id, l.device_id FROM account_peer_join j \
             JOIN account_peer_link l ON l.id = j.link_id WHERE j.id = ?1",
            params![to_i(join_id)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(db)?;
    let (state, expires_at, answerer, maker) =
        row.ok_or_else(|| RelayError::not_found("answer"))?;
    if caller.device != answerer && caller.device != maker {
        return Err(RelayError::not_found("answer"));
    }
    let state = if state == "pending" && to_u(expires_at) <= now {
        "expired".to_owned()
    } else {
        state
    };
    Ok((
        PeerJoinView {
            join_id,
            state,
            expires_at: to_u(expires_at),
        },
        caller.device == maker,
    ))
}

/// `GET /v1/account/peers/join/{join_id}`.
fn join_state(hub: &Hub, caller: &AccountCaller, join_id: u64, now: u64) -> RelayResult<Value> {
    let (view, _) = hub
        .directory
        .store
        .with(|conn| own_join(conn, caller, join_id, now))?;
    to_value(&view)
}

/// `DELETE /v1/account/peers/join/{join_id}`: the device that made the code refuses the
/// answer, which ends its code at once (it no longer counts for the 3 codes of the
/// device), or the device that answered withdraws it (the code counts until it expires).
/// A decided answer stays as it is.
fn join_end(hub: &Hub, caller: &AccountCaller, join_id: u64, now: u64) -> RelayResult<Value> {
    let view = hub.directory.store.tx(|tx| {
        let (view, maker) = own_join(tx, caller, join_id, now)?;
        if view.state != "pending" {
            return Ok(view);
        }
        let state = if maker { "refused" } else { "cancelled" };
        tx.execute(
            "UPDATE account_peer_join SET state = ?2, decided_at = ?3 WHERE id = ?1",
            params![to_i(join_id), state, to_i(now)],
        )
        .map_err(db)?;
        if maker {
            tx.execute(
                "UPDATE account_peer_link SET expires_at = min(expires_at, ?2) \
                 WHERE id = (SELECT link_id FROM account_peer_join WHERE id = ?1)",
                params![to_i(join_id), to_i(now)],
            )
            .map_err(db)?;
        }
        Ok(PeerJoinView {
            state: state.to_owned(),
            ..view
        })
    })?;
    to_value(&view)
}

// ---- The lists of other accounts (section 16.4). ----

/// The accounts that joined a vault store that exists with `account`, `account` left out:
/// for each store that `account` made, every account that joined it; for each store that
/// `account` joined, the account that made it and every other account that joined it. An
/// account joined a store when its list has a `join` of it naming the account that made it
/// (active or ended), or Connect holds its join of it (`account_join_share`). A share that
/// was never answered gives nothing. It ends with the deletion of the store.
fn store_participants(conn: &Connection, account: &str) -> RelayResult<HashSet<String>> {
    let mut statement = conn
        .prepare(
            "WITH joins(team, account) AS ( \
               SELECT t.id, j.account_id FROM account_list j JOIN team t ON t.id = j.team_id \
               WHERE j.op = 'join' AND t.kind = 'account' AND j.peer_account = t.account_id \
               UNION SELECT t.id, js.account_id FROM account_join_share js JOIN team t ON t.id = js.team_id \
               WHERE t.kind = 'account'), \
             mine(team, owner) AS ( \
               SELECT id, account_id FROM team WHERE kind = 'account' AND account_id = ?1 \
               UNION SELECT t.id, t.account_id FROM joins j JOIN team t ON t.id = j.team \
               WHERE j.account = ?1) \
             SELECT owner FROM mine \
             UNION SELECT j.account FROM mine m JOIN joins j ON j.team = m.team",
        )
        .map_err(db)?;
    let mut accounts = statement
        .query_map(params![account], |row| row.get::<_, String>(0))
        .map_err(db)?
        .collect::<Result<HashSet<_>, _>>()
        .map_err(db)?;
    accounts.remove(account);
    Ok(accounts)
}

/// Whether `caller` may read the list of `account` (connect-account-v1 section 16.4):
/// both are active members of one group, or `account` is in `participants`, the accounts
/// that joined a store with the caller (`store_participants`).
fn may_read(
    hub: &Hub,
    caller: &AccountCaller,
    participants: &HashSet<String>,
    account: &str,
    now: u64,
) -> RelayResult<bool> {
    Ok(participants.contains(account) || same_group(hub, &caller.account, account, now)?)
}

/// `GET /v1/account/peers/{account_id}`: another account whose list the caller may read
/// (`may_read`: one group, or a vault store of both; 403 `not_in_group` otherwise), with
/// its name, its live device rows, its device list from version 1 (with its peers and the
/// stores it makes, shares, and joins), read in a lock of its own, and the void marks of
/// its shares (`void_shares`). Which of the rows is a device of it is the list's to say.
fn view(hub: &Hub, caller: &AccountCaller, account: &str, now: u64) -> RelayResult<Value> {
    if account == caller.account {
        return Err(RelayError::invalid(
            "That is this account. Read GET /v1/account.",
        ));
    }
    let participants = hub
        .directory
        .store
        .with(|conn| store_participants(conn, &caller.account))?;
    if !may_read(hub, caller, &participants, account, now)? {
        return Err(not_in_group());
    }
    let (name, devices, void) = hub.directory.store.with(|conn| {
        let name: String = conn
            .query_row(
                "SELECT name FROM account WHERE id = ?1",
                params![account],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| RelayError::not_found("account"))?;
        let mut statement = conn
            .prepare(
                "SELECT id, name, platform, public_key FROM account_device WHERE account_id = ?1 \
                 AND revoked_at IS NULL ORDER BY created_at, id",
            )
            .map_err(db)?;
        let devices = statement
            .query_map(params![account], |row| {
                let platform: String = row.get(2)?;
                let key: Vec<u8> = row.get(3)?;
                Ok(PeerDevice {
                    device_id: row.get(0)?,
                    name: row.get(1)?,
                    platform: Platform::parse(&platform).ok_or(rusqlite::Error::InvalidQuery)?,
                    public_key: encode_b64(&key),
                })
            })
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok((name, devices, void_between(conn, account, &caller.account)?))
    })?;
    let device_list = hub
        .directory
        .store
        .with(|conn| list_entries(conn, account))?;
    let reset_list = hub
        .directory
        .store
        .with(|conn| reset_entries(conn, account))?;
    to_value(&PeerView {
        account_id: account.to_string(),
        name,
        devices,
        device_list,
        void,
        reset_list,
    })
}

/// The void shares of the list of `owner` that name `caller` (`void_shares`): a read shows
/// only the shares between the two accounts.
fn void_between(conn: &Connection, owner: &str, caller: &str) -> RelayResult<Vec<VoidShare>> {
    let mut void = void_shares(conn, owner, None)?;
    void.retain(|share| share.account_id == caller);
    Ok(void)
}

/// The last list of `account` before its last recovery (`account_list_reset`), in the form
/// of a device list; `None` without one.
fn reset_entries(conn: &Connection, account: &str) -> RelayResult<Option<Vec<ListEntry>>> {
    let entries = crate::server::account::reset_list_entries(conn, account)?;
    Ok((!entries.is_empty()).then_some(entries))
}

/// The name of `account` and the version and hash of the head of its list, or `None` for
/// no such account.
fn named_head(conn: &Connection, account: &str) -> RelayResult<Option<(String, u64, String)>> {
    conn.query_row(
        "SELECT a.name, l.version, l.hash FROM account a JOIN account_list l ON l.account_id = a.id \
         WHERE a.id = ?1 ORDER BY l.version DESC LIMIT 1",
        params![account],
        |row| Ok((row.get(0)?, to_u(row.get(1)?), row.get(2)?)),
    )
    .optional()
    .map_err(db)
}

/// `POST /v1/account/peers/lists`: the lists of 1 to `LIST_READ_ACCOUNTS` other accounts
/// (distinct; 400 otherwise), each against the pin that the client holds (`version` and
/// `head`, `0` and `""` for none), answered in the asked order: `refused` for an account
/// that the caller may not read (`may_read`) or that does not exist; `same` with the void
/// marks when the head of its list is the pin; else `newer` with its name, its list from
/// version 1 (and its list before its last recovery, when it has one), and the void marks,
/// while the lists of the answer stay within `LIST_READ_BYTES` together (the first `newer`
/// list always comes). From the first list that does not fit on, every account whose head
/// differs from its pin is `later`, decided from its head row alone: no list of it is
/// read. Each account is read in locks of its own, and no lock is held while a list is
/// written out.
fn lists(
    hub: &Hub,
    caller: &AccountCaller,
    request: &PeerListsRequest,
    now: u64,
) -> RelayResult<Value> {
    let pins = &request.accounts;
    if pins.is_empty() || pins.len() > LIST_READ_ACCOUNTS {
        return Err(RelayError::invalid("Name 1 to 64 other accounts."));
    }
    let mut seen = HashSet::new();
    for pin in pins {
        if !is_connect_id(&pin.account_id, "acc_")
            || pin.account_id == caller.account
            || !seen.insert(pin.account_id.as_str())
        {
            return Err(RelayError::invalid(
                "Each account is another account, named once.",
            ));
        }
        if !pin.head.is_empty() && !valid_link_hash(&pin.head) {
            return Err(RelayError::invalid(
                "The head of a pin is a list hash, or empty for none.",
            ));
        }
    }
    let participants = hub
        .directory
        .store
        .with(|conn| store_participants(conn, &caller.account))?;
    let mut carried = 0usize;
    let mut newer = false;
    let mut full = false;
    let mut items = Vec::with_capacity(pins.len());
    for pin in pins {
        let item = |state: &str| PeerListItem {
            account_id: pin.account_id.clone(),
            state: state.to_owned(),
            name: None,
            device_list: None,
            void: None,
            reset_list: None,
        };
        if !may_read(hub, caller, &participants, &pin.account_id, now)? {
            items.push(item("refused"));
            continue;
        }
        let head = hub
            .directory
            .store
            .with(|conn| named_head(conn, &pin.account_id))?;
        let Some((name, version, hash)) = head else {
            items.push(item("refused"));
            continue;
        };
        let same = version == pin.version && hash == pin.head;
        if !same && full {
            // The answer is full: decided from the head row, no list is read.
            items.push(item("later"));
            continue;
        }
        let void = hub
            .directory
            .store
            .with(|conn| void_between(conn, &pin.account_id, &caller.account))?;
        if same {
            items.push(PeerListItem {
                void: Some(void),
                ..item("same")
            });
            continue;
        }
        let (device_list, reset_list) = hub.directory.store.with(|conn| {
            Ok((
                list_entries(conn, &pin.account_id)?,
                reset_entries(conn, &pin.account_id)?,
            ))
        })?;
        let written = |entries: &[ListEntry]| {
            serde_json::to_vec(entries)
                .map(|bytes| bytes.len())
                .map_err(|_| RelayError::internal("A device list cannot be written."))
        };
        let bytes =
            written(&device_list)?.saturating_add(reset_list.as_deref().map_or(Ok(0), written)?);
        if newer && carried.saturating_add(bytes) > LIST_READ_BYTES {
            full = true;
            items.push(item("later"));
            continue;
        }
        newer = true;
        carried = carried.saturating_add(bytes);
        items.push(PeerListItem {
            name: Some(name),
            device_list: Some(device_list),
            void: Some(void),
            reset_list,
            ..item("newer")
        });
    }
    to_value(&PeerLists { accounts: items })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_and_methods() {
        assert_eq!(route("POST", &["list"]).unwrap(), PeerEndpoint::Append);
        assert_eq!(
            route("POST", &["peers", "link"]).unwrap(),
            PeerEndpoint::Link
        );
        assert_eq!(
            route("POST", &["peers", "join"]).unwrap(),
            PeerEndpoint::Join
        );
        assert_eq!(
            route("GET", &["peers", "pending"]).unwrap(),
            PeerEndpoint::Pending
        );
        assert_eq!(
            route("GET", &["peers", "join", "7"]).unwrap(),
            PeerEndpoint::JoinState(7)
        );
        assert_eq!(
            route("DELETE", &["peers", "join", "7"]).unwrap(),
            PeerEndpoint::JoinEnd(7)
        );
        assert_eq!(
            route("GET", &["peers", "acc_k7m2q4x3ca"]).unwrap(),
            PeerEndpoint::View("acc_k7m2q4x3ca".into())
        );
        assert_eq!(
            route("POST", &["peers", "lists"]).unwrap(),
            PeerEndpoint::Lists
        );
        assert_eq!(
            route("GET", &["peers", "lists"]).unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert!(
            PeerEndpoint::Lists.is_read() && PeerEndpoint::View("acc_k7m2q4x3ca".into()).is_read()
        );
        assert!(!PeerEndpoint::Pending.is_read() && !PeerEndpoint::Append.is_read());
        assert_eq!(
            route("GET", &["list"]).unwrap_err().code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("POST", &["peers", "acc_k7m2q4x3ca"])
                .unwrap_err()
                .code,
            codes::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            route("GET", &["peers", "join", "x"]).unwrap_err().code,
            codes::NOT_FOUND
        );
        assert_eq!(
            route("GET", &["peers", "dev_k7m2q4x3ca"]).unwrap_err().code,
            codes::NOT_FOUND
        );
        assert_eq!(route("GET", &["peers"]).unwrap_err().code, codes::NOT_FOUND);
    }

    #[test]
    fn the_rules_of_a_list_follow_section_16() {
        let mut state = ListState::default();
        let (p, s) = ("acc_m3n5p7q2rb", "t_7k2m5q4x3c");
        let conflict =
            |result: RelayResult<()>| assert_eq!(result.unwrap_err().code, codes::CONFLICT);
        conflict(state.check(ListOp::Share, Some(p), Some(s), None));
        conflict(state.check(ListOp::Unpeer, Some(p), None, None));
        state.check(ListOp::Peer, Some(p), None, None).unwrap();
        state.take(ListOp::Peer, Some(p.into()), Some(vec![4; 65]), None);
        conflict(state.check(ListOp::Peer, Some(p), None, None));
        // A share needs the list's own `store` entry of the store.
        conflict(state.check(ListOp::Share, Some(p), Some(s), None));
        state.check(ListOp::Store, None, Some(s), None).unwrap();
        state.take(ListOp::Store, None, None, Some(s.into()));
        conflict(state.check(ListOp::Store, None, Some(s), None));
        state.check(ListOp::Share, Some(p), Some(s), None).unwrap();
        state.take(ListOp::Share, Some(p.into()), None, Some(s.into()));
        conflict(state.check(ListOp::Share, Some(p), Some(s), None));
        // A store that this list makes or shares is not one it joins, and a peer that a
        // share names is not unpinned.
        conflict(state.check(ListOp::Join, Some(p), Some(s), Some(&[1; 32])));
        conflict(state.check(ListOp::Unpeer, Some(p), None, None));
        state
            .check(ListOp::Unshare, Some(p), Some(s), None)
            .unwrap();
        state.take(ListOp::Unshare, Some(p.into()), None, Some(s.into()));
        conflict(state.check(ListOp::Unshare, Some(p), Some(s), None));
        conflict(state.check(ListOp::Leave, Some(p), Some(s), None));
        // The made store stays named after the share ends.
        conflict(state.check(ListOp::Join, Some(p), Some(s), Some(&[1; 32])));
        state.check(ListOp::Unpeer, Some(p), None, None).unwrap();
        // A field that the op does not take.
        let invalid =
            |result: RelayResult<()>| assert_eq!(result.unwrap_err().code, codes::INVALID_REQUEST);
        invalid(state.check(ListOp::Peer, Some(p), Some(s), None));
        invalid(state.check(ListOp::Share, Some(p), None, None));
        invalid(state.check(ListOp::Store, Some(p), Some(s), None));
    }

    #[test]
    fn a_join_names_one_share_and_a_newer_one_replaces_it() {
        let mut state = ListState::default();
        let (p, q, s) = ("acc_m3n5p7q2rb", "acc_n4p6q8r3sc", "t_7k2m5q4x3c");
        let conflict =
            |result: RelayResult<()>| assert_eq!(result.unwrap_err().code, codes::CONFLICT);
        for peer in [p, q] {
            state.take(ListOp::Peer, Some(peer.into()), Some(vec![4; 65]), None);
        }
        state
            .check(ListOp::Join, Some(p), Some(s), Some(&[1; 32]))
            .unwrap();
        state.take(
            ListOp::Join,
            Some(p.into()),
            Some(vec![1; 32]),
            Some(s.into()),
        );
        // The same share twice, and a join of the store with another account.
        conflict(state.check(ListOp::Join, Some(p), Some(s), Some(&[1; 32])));
        conflict(state.check(ListOp::Join, Some(q), Some(s), Some(&[2; 32])));
        // A join of the store that a list joins is no `store` of it.
        conflict(state.check(ListOp::Store, None, Some(s), None));
        // A newer share: the new join replaces the old one, and adds no count.
        state
            .check(ListOp::Join, Some(p), Some(s), Some(&[2; 32]))
            .unwrap();
        state.take(
            ListOp::Join,
            Some(p.into()),
            Some(vec![2; 32]),
            Some(s.into()),
        );
        assert_eq!(state.joins.len(), 1);
        // A join stored before joins named a share is replaced by any join of the pair.
        let mut earlier = ListState::default();
        earlier.take(ListOp::Peer, Some(p.into()), Some(vec![4; 65]), None);
        earlier.take(ListOp::Join, Some(p.into()), None, Some(s.into()));
        earlier
            .check(ListOp::Join, Some(p), Some(s), Some(&[1; 32]))
            .unwrap();
        // One leave ends the pair.
        state.check(ListOp::Leave, Some(p), Some(s), None).unwrap();
        state.take(ListOp::Leave, Some(p.into()), None, Some(s.into()));
        conflict(state.check(ListOp::Leave, Some(p), Some(s), None));
        // The same share is not joined again after the leave; a newer one is.
        conflict(state.check(ListOp::Join, Some(p), Some(s), Some(&[2; 32])));
        conflict(state.check(ListOp::Join, Some(p), Some(s), Some(&[1; 32])));
        state
            .check(ListOp::Join, Some(p), Some(s), Some(&[3; 32]))
            .unwrap();
    }
}
