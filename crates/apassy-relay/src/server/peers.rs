//! Vaults shared between the accounts of one family or team (ADR 0037 stage 7, contract
//! connect-account-v1 section 16, docs/SPEC.md section 33).
//!
//! The account that made a vault store is the only authority for it. What it says of
//! other accounts are entries of its own signed device list (`account_list`), in the
//! chain of its device entries: `peer` and `unpeer` (the root of another account, pinned
//! after six words), `share` and `unshare` (a store of this account, for another account),
//! `join` and `leave` (a store of another account that this account syncs). Each is
//! signed by a live device of the list over the hash of the entry before
//! (`apassy-connect share-list v1`). Connect keeps and serves the lists; the devices
//! verify them from the roots they pinned and take no signer from Connect's word.
//!
//! Connect checks, before it stores an entry, what the devices check (the signature, the
//! version, the room of the list, the rules of section 16), and the conditions of the
//! service: a `share` comes from the account that made the store and names an active
//! member of the same group with a plan that allows sharing; a `peer` names the root of
//! that account's list; a `join` names a store that the other account made and shares
//! with the caller. An `unshare` removes the other account's devices from the store, and
//! a `leave` the caller's, in the transaction of the entry. A device of another account
//! is in a store only while the owner's list shares it with that account and both are
//! active members of one group (`account::may_join_store`, `account::store_device_live`).
//!
//! The ceremony of section 16.2 meets here: `POST /v1/account/peers/link` keeps the hash
//! of a share code for one member (600 s, one use), `POST /v1/account/peers/join` takes
//! the signed answer of a device of that member, and `GET /v1/account/peers/pending`
//! shows it to the device that made the code, with the answering account's device list.
//! Connect never sees the code, so it cannot compute the six words.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::api::{
    AccountLinkCreated, AccountListAppend, AccountListAppended, EmptyRequest, ListOp, PeerDevice,
    PeerInviter, PeerJoinRequest, PeerJoinView, PeerJoined, PeerLinkRequest, PeerPending, PeerView,
    Platform, TeamKind,
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

/// The active peers, shares, and joins of a list at its head (the rules of section 16).
#[derive(Debug, Default)]
struct ListState {
    peers: Vec<(String, Vec<u8>)>,
    shares: Vec<(String, String)>,
    joins: Vec<(String, String)>,
}

impl ListState {
    fn is_peer(&self, account: &str) -> bool {
        self.peers.iter().any(|(held, _)| held == account)
    }

    fn names(&self, account: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(_, held)| held == account)
    }

    fn holds_store(&self, team: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(store, _)| store == team)
    }

    /// Apply one stored entry (they were checked when they were written).
    fn take(&mut self, op: ListOp, account: String, root: Option<Vec<u8>>, team: Option<String>) {
        match (op, team) {
            (ListOp::Peer, _) => self.peers.push((account, root.unwrap_or_default())),
            (ListOp::Unpeer, _) => self.peers.retain(|(held, _)| *held != account),
            (ListOp::Share, Some(team)) => self.shares.push((team, account)),
            (ListOp::Unshare, Some(team)) => self
                .shares
                .retain(|held| *held != (team.clone(), account.clone())),
            (ListOp::Join, Some(team)) => self.joins.push((team, account)),
            (ListOp::Leave, Some(team)) => self
                .joins
                .retain(|held| *held != (team.clone(), account.clone())),
            _ => {}
        }
    }

    /// Whether the rules of section 16 allow `op` for `account` (and `team`) now: 409
    /// `conflict` when the list does not allow it at its head, 403 `account_limit` over
    /// the counts.
    fn check(&self, op: ListOp, account: &str, team: Option<&str>) -> RelayResult<()> {
        let refused =
            || conflict("The device list does not allow this entry now. Read the account again.");
        let counted = self.shares.len() + self.joins.len();
        match (op, team) {
            (ListOp::Peer, None) => {
                if self.is_peer(account) {
                    return Err(refused());
                }
                if self.peers.len() as u64 >= MAX_PEERS {
                    return Err(account_limit("This account pins 64 other accounts."));
                }
            }
            (ListOp::Unpeer, None) => {
                if !self.is_peer(account) || self.names(account) {
                    return Err(refused());
                }
            }
            (ListOp::Share, Some(team)) => {
                let pair = (team.to_owned(), account.to_owned());
                if !self.is_peer(account)
                    || self.joins.iter().any(|(store, _)| store == team)
                    || self.shares.contains(&pair)
                {
                    return Err(refused());
                }
                if counted as u64 >= MAX_SHARED {
                    return Err(account_limit("This account has 128 shared vaults."));
                }
            }
            (ListOp::Join, Some(team)) => {
                if !self.is_peer(account) || self.holds_store(team) {
                    return Err(refused());
                }
                if counted as u64 >= MAX_SHARED {
                    return Err(account_limit("This account has 128 shared vaults."));
                }
            }
            (ListOp::Unshare, Some(team)) => {
                if !self.shares.contains(&(team.to_owned(), account.to_owned())) {
                    return Err(refused());
                }
            }
            (ListOp::Leave, Some(team)) => {
                if !self.joins.contains(&(team.to_owned(), account.to_owned())) {
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
             WHERE account_id = ?1 AND peer_account IS NOT NULL ORDER BY version",
        )
        .map_err(db)?;
    let rows = statement
        .query_map(params![account], |row| {
            let op: String = row.get(0)?;
            Ok((
                ListOp::parse(&op).ok_or(rusqlite::Error::InvalidQuery)?,
                row.get::<_, String>(1)?,
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

/// Whether the plan of `account` allows sharing: an entitled Family or Team plan.
fn shares_plan(hub: &Hub, account: &str, now: u64) -> RelayResult<bool> {
    let plan = hub
        .accounts
        .plans()
        .plan(&hub.directory.store, account, now)?;
    Ok(plan.entitled && matches!(plan.plan.as_deref(), Some("family" | "team")))
}

/// Whether `a` and `b` are active members of one group.
fn same_group(hub: &Hub, a: &str, b: &str, now: u64) -> RelayResult<bool> {
    hub.accounts
        .groups()
        .share_group(&hub.directory.store, a, b, now)
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

// ---- `POST /v1/account/list` (section 16.3). ----

/// `POST /v1/account/list`: an entry of section 16, signed by the calling device at the
/// version after the head. In this order: the shape (400), the group and the plan of a
/// `peer`, `share`, or `join` (403 `not_in_group`, 403 `plan_required`), then in one
/// transaction the version and the room (409, 403 `account_limit`), the signer (401 for a
/// device that is not in the list), the signature (400), the rules of section 16 (409),
/// and the conditions of each op; then the entry, and for an `unshare` or a `leave` the
/// removal of the store rows. Nothing is written on a refusal.
fn append(
    hub: &Hub,
    caller: &AccountCaller,
    request: &AccountListAppend,
    now: u64,
) -> RelayResult<Value> {
    let op = request.op;
    if !op.names_account() {
        return Err(RelayError::invalid(
            "This route takes the entries of section 16. A device is added by a confirmation and removed by a revoke.",
        ));
    }
    let peer = request.account_id.as_str();
    if !is_connect_id(peer, "acc_") || peer == caller.account {
        return Err(RelayError::invalid(
            "The account id is not another account.",
        ));
    }
    let root = match (op, request.root.as_deref()) {
        (ListOp::Peer, Some(root)) => Some(public_key_of(root)?),
        (ListOp::Peer, None) | (_, Some(_)) => {
            return Err(RelayError::invalid(
                "Only a peer entry names a root, and it must.",
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
                "Only a share, unshare, join, or leave entry names a store, and each must.",
            ));
        }
    };
    let statement = decode_b64(&request.statement, device::MAX_SIGNATURE_BYTES)
        .map_err(|_| RelayError::invalid("The statement is not valid."))?;
    // The conditions of the service that read the group and the plan seams.
    if matches!(op, ListOp::Peer | ListOp::Share | ListOp::Join)
        && !same_group(hub, &caller.account, peer, now)?
    {
        return Err(not_in_group());
    }
    if op == ListOp::Share
        && (!shares_plan(hub, &caller.account, now)? || !shares_plan(hub, peer, now)?)
    {
        return Err(plan_required());
    }
    let origin = hub.config.public_url.clone();
    let (removals, version) = hub.directory.store.tx(|tx| {
        let previous = next_entry(tx, caller, request.version, op, &caller.public_key)?;
        let root_b64 = root.as_ref().map(|key| encode_b64(key));
        let message = device::share_list_message(
            &origin,
            &caller.account,
            request.version,
            &previous,
            op.as_str(),
            peer,
            root_b64.as_deref().unwrap_or(device::LIST_NONE),
            team.as_ref().map_or(device::LIST_NONE, TeamId::as_str),
            &encode_b64(&caller.public_key),
        );
        if !device::verify(&caller.public_key, &message, &statement) {
            return Err(RelayError::invalid(
                "The statement is not the signature of this device over the next entry of the device list. Nothing changed.",
            ));
        }
        let state = list_state(tx, &caller.account)?;
        state.check(op, peer, team.as_ref().map(TeamId::as_str))?;
        let mut removals = Vec::new();
        match (op, team.as_ref()) {
            (ListOp::Peer, _) => {
                if Some(root_of(tx, peer)?.as_slice()) != root.as_ref().map(<[u8; 65]>::as_slice) {
                    return Err(conflict(
                        "That root is not the root of the other account's device list. Nothing changed.",
                    ));
                }
            }
            (ListOp::Share, Some(team)) => {
                if store_owner(tx, team)? != caller.account {
                    return Err(forbidden("Only the account that made a vault store shares it."));
                }
            }
            (ListOp::Join, Some(team)) => {
                if store_owner(tx, team)? != peer || !share_active(tx, peer, team.as_str(), &caller.account)? {
                    return Err(conflict("That account does not share this vault store with you. Nothing changed."));
                }
            }
            (ListOp::Unshare, Some(team)) => removals = queue_account_removals(tx, team, peer, now)?,
            (ListOp::Leave, Some(team)) => removals = queue_account_removals(tx, team, &caller.account, now)?,
            _ => {}
        }
        let hash = device::account_list_hash(&message);
        tx.execute(
            "INSERT INTO account_list (account_id, version, op, key, link_hash, name, by_key, signature, hash, created_at, peer_account, peer_root, team_id) \
             VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                caller.account,
                to_i(request.version),
                op.as_str(),
                caller.public_key,
                statement,
                hash,
                to_i(now),
                peer,
                root.as_ref().map(<[u8; 65]>::as_slice),
                team.as_ref().map(TeamId::as_str),
            ],
        )
        .map_err(db)?;
        if op == ListOp::Peer {
            // The answer of that account to a share code of this account is confirmed.
            tx.execute(
                "UPDATE account_peer_join SET state = 'confirmed', decided_at = ?3 WHERE state = 'pending' \
                 AND account_id = ?2 AND link_id IN (SELECT id FROM account_peer_link WHERE account_id = ?1)",
                params![caller.account, peer, to_i(now)],
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
/// for the member `account_id` of its group (403 `not_in_group` otherwise). One use, 600
/// s, at most 3 open codes of one device.
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
        let open: i64 = tx
            .query_row(
                "SELECT count(*) FROM account_peer_link WHERE device_id = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![caller.device, to_i(now)],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(open) >= LINKS_PER_DEVICE {
            return Err(account_limit("This device has 3 open share codes. Wait until one ends."));
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
/// result. The answer names the device that made the code and carries its account's
/// device list.
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
    let joined = hub.directory.store.tx(|tx| {
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
        Ok(PeerJoined {
            join_id: to_u(join_id),
            inviter: inviter(tx, link_id)?,
            expires_at: to_u(expires_at),
            device_list: list_entries(tx, &request.account_id)?,
        })
    })?;
    to_value(&joined)
}

/// One pending answer as `relay.db` holds it: the answer, the code, the account and its
/// name, the key and its signature, and the times.
type PendingRow = (i64, i64, String, String, Vec<u8>, Vec<u8>, i64, i64);

/// `GET /v1/account/peers/pending`: the pending answers to the share codes that this
/// device made, each with the answering account's device list.
fn pending(hub: &Hub, caller: &AccountCaller, now: u64) -> RelayResult<Value> {
    let answers = hub.directory.store.with(|conn| {
        let rows: Vec<PendingRow> = {
            let mut statement = conn
                .prepare(
                    "SELECT j.id, j.link_id, j.account_id, a.name, j.public_key, j.signature, j.created_at, j.expires_at \
                     FROM account_peer_join j JOIN account_peer_link l ON l.id = j.link_id JOIN account a ON a.id = j.account_id \
                     WHERE l.device_id = ?1 AND j.state = 'pending' AND j.expires_at > ?2 ORDER BY j.id",
                )
                .map_err(db)?;
            statement
                .query_map(params![caller.device, to_i(now)], |row| {
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
                })
                .map_err(db)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db)?
        };
        rows.into_iter()
            .map(|(join_id, link_id, account, name, key, signature, created_at, expires_at)| {
                Ok(PeerPending {
                    join_id: to_u(join_id),
                    link_id: to_u(link_id),
                    device_list: list_entries(conn, &account)?,
                    account_id: account,
                    name,
                    public_key: encode_b64(&key),
                    signature: encode_b64(&signature),
                    created_at: to_u(created_at),
                    expires_at: to_u(expires_at),
                })
            })
            .collect::<RelayResult<Vec<_>>>()
    })?;
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
/// answer, or the device that answered withdraws it. A decided answer stays as it is.
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
        Ok(PeerJoinView {
            state: state.to_owned(),
            ..view
        })
    })?;
    to_value(&view)
}

/// `GET /v1/account/peers/{account_id}`: another account of the caller's group (403
/// `not_in_group` outside one), with its name, its live device rows, and its device list
/// from version 1. Which of the rows is a device of it is the list's to say.
fn view(hub: &Hub, caller: &AccountCaller, account: &str, now: u64) -> RelayResult<Value> {
    if account == caller.account {
        return Err(RelayError::invalid(
            "That is this account. Read GET /v1/account.",
        ));
    }
    if !same_group(hub, &caller.account, account, now)? {
        return Err(not_in_group());
    }
    let view = hub.directory.store.with(|conn| {
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
        Ok(PeerView {
            account_id: account.to_string(),
            name,
            devices,
            device_list: list_entries(conn, account)?,
        })
    })?;
    to_value(&view)
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
        assert_eq!(
            state.check(ListOp::Share, p, Some(s)).unwrap_err().code,
            codes::CONFLICT
        );
        assert_eq!(
            state.check(ListOp::Unpeer, p, None).unwrap_err().code,
            codes::CONFLICT
        );
        state.check(ListOp::Peer, p, None).unwrap();
        state.take(ListOp::Peer, p.into(), Some(vec![4; 65]), None);
        assert_eq!(
            state.check(ListOp::Peer, p, None).unwrap_err().code,
            codes::CONFLICT
        );
        state.check(ListOp::Share, p, Some(s)).unwrap();
        state.take(ListOp::Share, p.into(), None, Some(s.into()));
        assert_eq!(
            state.check(ListOp::Share, p, Some(s)).unwrap_err().code,
            codes::CONFLICT
        );
        // A store that this list shares is not one it joins, and a peer that a share names
        // is not unpinned.
        assert_eq!(
            state.check(ListOp::Join, p, Some(s)).unwrap_err().code,
            codes::CONFLICT
        );
        assert_eq!(
            state.check(ListOp::Unpeer, p, None).unwrap_err().code,
            codes::CONFLICT
        );
        state.check(ListOp::Unshare, p, Some(s)).unwrap();
        state.take(ListOp::Unshare, p.into(), None, Some(s.into()));
        assert_eq!(
            state.check(ListOp::Unshare, p, Some(s)).unwrap_err().code,
            codes::CONFLICT
        );
        assert_eq!(
            state.check(ListOp::Leave, p, Some(s)).unwrap_err().code,
            codes::CONFLICT
        );
        state.check(ListOp::Unpeer, p, None).unwrap();
        // A field that the op does not take.
        assert_eq!(
            state.check(ListOp::Peer, p, Some(s)).unwrap_err().code,
            codes::INVALID_REQUEST
        );
        assert_eq!(
            state.check(ListOp::Share, p, None).unwrap_err().code,
            codes::INVALID_REQUEST
        );
    }
}
