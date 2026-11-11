//! The routes of a vault shared between accounts (contract connect-account-v1 section 16)
//! in the fake Connect: `POST /v1/account/list` (an entry signed by the calling device
//! over `apassy-connect share-list v1` with the hash of the head, at the next version),
//! the share codes (`POST /v1/account/peers/link`, `POST /v1/account/peers/join` with the
//! signed answer, `GET /v1/account/peers/pending`, `GET` and `DELETE
//! /v1/account/peers/join/{id}`), `GET /v1/account/peers/{account_id}` and the batch
//! `POST /v1/account/peers/lists` within one group or a store that both accounts share or
//! shared, and the `store` entry of `POST /v1/account/vaults`. An `unshare` or a `leave`
//! removes the store rows of the account. Void marks (`void_share`) show in the store and
//! peer views.
//!
//! It checks the shapes and the signatures, not the rules of section 16 or the share of a
//! store device: there it plays a Connect that lies, which the client must catch. Hooks
//! serve another list for an account, name another inviter in a join answer, and give the
//! answers to a share code another key.

use super::*;

pub(super) struct PeerLink {
    id: u64,
    account: String,
    device: String,
    peer: String,
    hash: String,
    expires_at: u64,
    used: bool,
}

pub(super) struct PeerJoin {
    id: u64,
    link_id: u64,
    account: String,
    device: String,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    state: String,
    expires_at: u64,
}

#[derive(Default)]
pub(super) struct ShareState {
    links: Vec<PeerLink>,
    joins: Vec<PeerJoin>,
    /// account → the list that `GET /v1/account/peers/{account}` serves instead.
    served: BTreeMap<String, Vec<Value>>,
    /// The `inviter` of the next join answers, instead of the device of the code.
    inviter: Option<Value>,
    /// The answering key of the pending answers, instead of the key that answered.
    pending_key: Option<Vec<u8>>,
    /// owner → the shares of its list that the fake counts as void: (store, member).
    void: BTreeMap<String, Vec<(String, String)>>,
}

impl FakeConnect {
    /// `GET /v1/account/peers/{account}` serves `list` for `account` from now on (`None`:
    /// its own list again).
    pub fn serve_peer_list(&self, account: &str, list: Option<Vec<Value>>) {
        let mut state = lock(&self.shared);
        match list {
            Some(list) => state.share.served.insert(account.to_owned(), list),
            None => state.share.served.remove(account),
        };
    }

    /// The next join answers name `inviter` as the device of the code.
    pub fn answer_inviter(&self, inviter: Option<Value>) {
        lock(&self.shared).share.inviter = inviter;
    }

    /// The pending answers name `key` as the answering device.
    pub fn answer_pending_key(&self, key: Option<Vec<u8>>) {
        lock(&self.shared).share.pending_key = key;
    }

    /// Append `entry` (JSON) to the list of `account` as Connect would serve it, with no
    /// check: a Connect that inserts an entry.
    pub fn push_list_entry(&self, account: &str, entry: Value, hash: String) {
        let mut state = lock(&self.shared);
        let entry_account = state.accounts.get_mut(account).expect("account");
        entry_account.list.push(entry);
        entry_account.hashes.push(hash);
    }

    /// `member` leaves the group of `owner` at Connect (an admin's removal), with nothing
    /// else changed.
    pub fn remove_member(&self, owner: &str, member: &str) {
        let mut state = lock(&self.shared);
        if let Some(group) = state.groups.iter_mut().find(|group| group.owner == owner) {
            group.members.retain(|held| held.account != member);
        }
    }

    /// The share of `team` by `owner` with `member` is void at Connect (a quick removal
    /// from the group and a new admission): the store view and the peer views say so.
    pub fn void_share(&self, owner: &str, team: &str, member: &str) {
        let mut state = lock(&self.shared);
        state
            .share
            .void
            .entry(owner.to_owned())
            .or_default()
            .push((team.to_owned(), member.to_owned()));
        if let Some(store) = state.stores.iter_mut().find(|store| store.team_id == team) {
            store.void.push(member.to_owned());
        }
    }

    /// The list hash of each entry of `account`'s list.
    pub fn list_hashes(&self, account: &str) -> Vec<String> {
        lock(&self.shared)
            .accounts
            .get(account)
            .map(|entry| entry.hashes.clone())
            .unwrap_or_default()
    }

    /// The hash of the head of `account`'s list.
    pub fn list_head(&self, account: &str) -> String {
        lock(&self.shared)
            .accounts
            .get(account)
            .and_then(|entry| entry.hashes.last().cloned())
            .unwrap_or_default()
    }
}

/// The `apassy-connect share-list v1` message.
#[allow(clippy::too_many_arguments)]
fn share_list_message(
    origin: &str,
    account: &str,
    version: u64,
    previous: &str,
    op: &str,
    peer: &str,
    root: &str,
    team: &str,
    by: &str,
) -> Vec<u8> {
    joined(&[
        "apassy-connect share-list v1",
        origin,
        account,
        &version.to_string(),
        previous,
        op,
        peer,
        root,
        team,
        by,
    ])
}

fn nullable(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Whether no store and no `store` entry of any list has the id `team`.
pub(super) fn store_id_free(state: &State, team: &str) -> bool {
    team.len() == 12
        && team.starts_with("t_")
        && !state.stores.iter().any(|store| store.team_id == team)
        && !state.accounts.values().any(|entry| {
            entry
                .list
                .iter()
                .any(|held| held["op"] == "store" && held["team_id"] == team)
        })
}

/// The `store` entry of `POST /v1/account/vaults` (`team_id`, `version`, `statement`):
/// the next version, signed by the caller over the hash of the head.
pub(super) fn append_store(
    state: &mut State,
    body: &Value,
    account: &str,
    device: &str,
    origin: &str,
) -> Result<(), Outgoing> {
    let version = body["version"]
        .as_u64()
        .ok_or_else(|| fail(400, "invalid_request"))?;
    let team = text(body, "team_id").to_owned();
    let key = caller_key(state, device);
    let entry = state
        .accounts
        .get(account)
        .ok_or_else(|| fail(401, "unauthenticated"))?;
    if version != entry.list.len() as u64 + 1 {
        return Err(fail(409, "conflict"));
    }
    if version > 822 {
        return Err(fail(403, "account_limit"));
    }
    let message = share_list_message(
        origin,
        account,
        version,
        entry.hashes.last().expect("a list"),
        "store",
        "-",
        "-",
        &team,
        &encode_b64u(&key),
    );
    let statement =
        decode_b64u(text(body, "statement")).ok_or_else(|| fail(400, "invalid_request"))?;
    if !verify(&key, &message, &statement) {
        return Err(fail(400, "invalid_request"));
    }
    let entry = state.accounts.get_mut(account).expect("account");
    entry.list.push(
        json!({"version": version, "op": "store", "key": null, "link_hash": null,
               "name": null, "by": encode_b64u(&key), "signature": encode_b64u(&statement),
               "account_id": null, "root": null, "team_id": team}),
    );
    entry.hashes.push(list_hash(&message));
    Ok(())
}

/// The accounts of the store `team` as its owner's list names them: the owner, and each
/// account of a `share` entry of it (also one that ended).
fn participants(state: &State, team: &str) -> Vec<String> {
    let Some(store) = state.stores.iter().find(|store| store.team_id == team) else {
        return Vec::new();
    };
    let mut accounts = vec![store.account.clone()];
    if let Some(entry) = state.accounts.get(&store.account) {
        for held in &entry.list {
            if held["op"] == "share"
                && held["team_id"] == team
                && let Some(peer) = held["account_id"].as_str()
            {
                accounts.push(peer.to_owned());
            }
        }
    }
    accounts
}

/// Whether `account` may read the list of `other`: one group, or a store that both are
/// or were in (connect-account-v1 section 16.4).
fn may_read(state: &State, account: &str, other: &str) -> bool {
    account != other
        && (same_group(state, account, other)
            || state.stores.iter().any(|store| {
                let held = participants(state, &store.team_id);
                held.iter().any(|held| held == account) && held.iter().any(|held| held == other)
            }))
}

/// The void marks of the list of `owner` in a peer view.
fn void_of(state: &State, owner: &str) -> Value {
    json!(
        state
            .share
            .void
            .get(owner)
            .map(|marks| marks
                .iter()
                .map(|(team, member)| json!({"team_id": team, "account_id": member}))
                .collect::<Vec<_>>())
            .unwrap_or_default()
    )
}

fn caller_key(state: &State, device: &str) -> Vec<u8> {
    state
        .devices
        .iter()
        .find(|entry| entry.id == device)
        .map(|entry| entry.public_key.clone())
        .unwrap_or_default()
}

/// The routes of section 16, or `None` for another path.
pub(super) fn route(
    state: &mut State,
    method: &str,
    rest: &[&str],
    body: &Value,
    account: &str,
    device: &str,
    origin: &str,
) -> Option<Outgoing> {
    let answer = match (method, rest) {
        ("POST", ["list"]) => append(state, body, account, device, origin),
        ("POST", ["peers", "link"]) => {
            if !strict(body, &["link_hash", "account_id"]) {
                return Some(fail(400, "invalid_request"));
            }
            let peer = text(body, "account_id").to_owned();
            if !same_group(state, account, &peer) || peer == account {
                return Some(fail(403, "not_in_group"));
            }
            state.next += 1;
            let id = state.next;
            let expires_at = now() + 600;
            state.share.links.push(PeerLink {
                id,
                account: account.to_owned(),
                device: device.to_owned(),
                peer,
                hash: text(body, "link_hash").to_owned(),
                expires_at,
                used: false,
            });
            ok(json!({"link_id": id, "expires_at": expires_at}))
        }
        ("POST", ["peers", "join"]) => {
            if !strict(body, &["account_id", "link_hash", "signature"]) {
                return Some(fail(400, "invalid_request"));
            }
            let inviter_account = text(body, "account_id").to_owned();
            let key = caller_key(state, device);
            let root = state
                .accounts
                .get(account)
                .and_then(|entry| entry.list.first())
                .and_then(|entry| entry["key"].as_str())
                .unwrap_or_default()
                .to_owned();
            let message = joined(&[
                "apassy-connect peer-join v1",
                origin,
                &inviter_account,
                text(body, "link_hash"),
                account,
                &root,
                &encode_b64u(&key),
            ]);
            let Some(signature) = decode_b64u(text(body, "signature")) else {
                return Some(fail(400, "invalid_request"));
            };
            if !verify(&key, &message, &signature) {
                return Some(fail(400, "invalid_request"));
            }
            let hash = text(body, "link_hash").to_owned();
            let Some(link) = state.share.links.iter_mut().find(|link| {
                link.account == inviter_account
                    && link.hash == hash
                    && link.peer == account
                    && !link.used
                    && link.expires_at > now()
            }) else {
                return Some(fail(403, "forbidden"));
            };
            link.used = true;
            let (link_id, link_device, expires_at) =
                (link.id, link.device.clone(), link.expires_at);
            state.next += 1;
            let join_id = state.next;
            state.share.joins.push(PeerJoin {
                id: join_id,
                link_id,
                account: account.to_owned(),
                device: device.to_owned(),
                public_key: key,
                signature,
                state: "pending".to_owned(),
                expires_at,
            });
            let inviter = state.share.inviter.clone().unwrap_or_else(|| {
                let maker = state
                    .devices
                    .iter()
                    .find(|entry| entry.id == link_device)
                    .expect("the maker");
                let name = state
                    .accounts
                    .get(&inviter_account)
                    .map(|entry| entry.name.clone())
                    .unwrap_or_default();
                json!({"account_id": inviter_account, "device_id": maker.id, "name": name,
                       "public_key": encode_b64u(&maker.public_key)})
            });
            ok(
                json!({"join_id": join_id, "inviter": inviter, "expires_at": expires_at,
                      "device_list": list_of(state, &inviter_account)}),
            )
        }
        ("GET", ["peers", "pending"]) => {
            let links: Vec<u64> = state
                .share
                .links
                .iter()
                .filter(|link| link.device == device)
                .map(|link| link.id)
                .collect();
            let answers: Vec<Value> = state
                .share
                .joins
                .iter()
                .filter(|join| links.contains(&join.link_id) && join.state == "pending" && join.expires_at > now())
                .map(|join| {
                    let name = state.accounts.get(&join.account).map(|entry| entry.name.clone()).unwrap_or_default();
                    let key = state.share.pending_key.clone().unwrap_or_else(|| join.public_key.clone());
                    json!({"join_id": join.id, "link_id": join.link_id, "account_id": join.account,
                           "name": name, "public_key": encode_b64u(&key),
                           "signature": encode_b64u(&join.signature), "created_at": now(),
                           "expires_at": join.expires_at, "device_list": list_of(state, &join.account)})
                })
                .collect();
            ok(json!(answers))
        }
        ("GET" | "DELETE", ["peers", "join", id]) => {
            let Ok(id) = id.parse::<u64>() else {
                return Some(fail(404, "not_found"));
            };
            let makers: Vec<(u64, String)> = state
                .share
                .links
                .iter()
                .map(|link| (link.id, link.device.clone()))
                .collect();
            let Some(join) = state.share.joins.iter_mut().find(|join| {
                join.id == id
                    && (join.device == device
                        || makers
                            .iter()
                            .any(|(link, maker)| *link == join.link_id && maker == device))
            }) else {
                return Some(fail(404, "not_found"));
            };
            if method == "DELETE" && join.state == "pending" {
                join.state = if join.device == device {
                    "cancelled".into()
                } else {
                    "refused".into()
                };
            }
            ok(json!({"join_id": join.id, "state": join.state, "expires_at": join.expires_at}))
        }
        ("POST", ["peers", "lists"]) => {
            let Some(asks) = body
                .as_object()
                .filter(|map| map.len() == 1)
                .and_then(|map| map.get("accounts"))
                .and_then(Value::as_array)
                .filter(|asks| !asks.is_empty() && asks.len() <= 64)
            else {
                return Some(fail(400, "invalid_request"));
            };
            let mut items = Vec::new();
            for ask in asks {
                let other = text(ask, "account_id").to_owned();
                let (version, head) = (
                    ask["version"].as_u64().unwrap_or(0),
                    text(ask, "head").to_owned(),
                );
                let Some(entry) = state
                    .accounts
                    .get(&other)
                    .filter(|_| may_read(state, account, &other))
                else {
                    items.push(json!({"account_id": other, "state": "refused"}));
                    continue;
                };
                let served = state.share.served.get(&other).cloned();
                let same = served.is_none()
                    && version == entry.list.len() as u64
                    && entry.hashes.last().is_some_and(|last| *last == head);
                if same {
                    items.push(json!({"account_id": other, "state": "same", "void": void_of(state, &other)}));
                } else {
                    let list = served.unwrap_or_else(|| entry.list.clone());
                    items.push(
                        json!({"account_id": other, "state": "newer", "name": entry.name,
                                      "device_list": list, "void": void_of(state, &other)}),
                    );
                }
            }
            ok(json!({"accounts": items}))
        }
        ("GET", ["peers", other]) => {
            if !may_read(state, account, other) {
                return Some(fail(403, "not_in_group"));
            }
            let Some(entry) = state.accounts.get(*other) else {
                return Some(fail(404, "not_found"));
            };
            let list = state
                .share
                .served
                .get(*other)
                .cloned()
                .unwrap_or_else(|| entry.list.clone());
            let devices: Vec<Value> = state
                .devices
                .iter()
                .filter(|device| device.live && device.account == *other)
                .map(|device| {
                    json!({"device_id": device.id, "name": device.name,
                                     "platform": device.platform,
                                     "public_key": encode_b64u(&device.public_key)})
                })
                .collect();
            ok(
                json!({"account_id": other, "name": entry.name, "devices": devices, "device_list": list,
                       "void": void_of(state, other)}),
            )
        }
        _ => return None,
    };
    Some(answer)
}

/// `POST /v1/account/list`: the next version, the caller's signature over the message
/// with the hash of the head; an `unshare` or a `leave` takes the account's devices out of
/// the store.
fn append(state: &mut State, body: &Value, account: &str, device: &str, origin: &str) -> Outgoing {
    let shaped = body.as_object().is_some_and(|map| {
        map.len() == 6
            && map.get("version").is_some_and(Value::is_u64)
            && ["op", "statement"]
                .iter()
                .all(|key| map.get(*key).is_some_and(Value::is_string))
            && ["account_id", "root", "team_id"].iter().all(|key| {
                map.get(*key)
                    .is_some_and(|value| value.is_string() || value.is_null())
            })
    });
    if !shaped {
        return fail(400, "invalid_request");
    }
    let version = body["version"].as_u64().unwrap_or(0);
    let op = text(body, "op").to_owned();
    if !matches!(
        op.as_str(),
        "peer" | "unpeer" | "share" | "unshare" | "join" | "leave" | "store"
    ) {
        return fail(400, "invalid_request");
    }
    // `null` exactly for a `store`.
    if (op == "store") != body["account_id"].is_null() {
        return fail(400, "invalid_request");
    }
    let peer = nullable(body, "account_id");
    let root = nullable(body, "root");
    let team = nullable(body, "team_id");
    let key = caller_key(state, device);
    let Some(entry) = state.accounts.get(account) else {
        return fail(401, "unauthenticated");
    };
    if version != entry.list.len() as u64 + 1 {
        return fail(409, "conflict");
    }
    if version > 1024
        || (matches!(op.as_str(), "peer" | "share" | "join" | "store") && version > 822)
    {
        return fail(403, "account_limit");
    }
    let message = share_list_message(
        origin,
        account,
        version,
        entry.hashes.last().expect("a list"),
        &op,
        peer.as_deref().unwrap_or("-"),
        root.as_deref().unwrap_or("-"),
        team.as_deref().unwrap_or("-"),
        &encode_b64u(&key),
    );
    let Some(statement) = decode_b64u(text(body, "statement")) else {
        return fail(400, "invalid_request");
    };
    if !verify(&key, &message, &statement) {
        return fail(400, "invalid_request");
    }
    let entry = state.accounts.get_mut(account).expect("account");
    entry.list.push(
        json!({"version": version, "op": op, "key": null, "link_hash": null,
                           "name": null, "by": encode_b64u(&key),
                           "signature": encode_b64u(&statement), "account_id": peer,
                           "root": root, "team_id": team}),
    );
    entry.hashes.push(list_hash(&message));
    let gone = match op.as_str() {
        "unshare" => peer.clone(),
        "leave" => Some(account.to_owned()),
        _ => None,
    };
    if let (Some(gone), Some(team)) = (gone, team.as_deref()) {
        let devices: Vec<String> = state
            .devices
            .iter()
            .filter(|entry| entry.account == gone)
            .map(|entry| entry.id.clone())
            .collect();
        if let Some(store) = state.stores.iter_mut().find(|store| store.team_id == team) {
            store.devices.retain(|(_, held)| !devices.contains(held));
        }
    }
    if op == "peer" {
        let links: Vec<u64> = state
            .share
            .links
            .iter()
            .filter(|link| link.account == account)
            .map(|link| link.id)
            .collect();
        for join in &mut state.share.joins {
            if Some(&join.account) == peer.as_ref()
                && links.contains(&join.link_id)
                && join.state == "pending"
            {
                join.state = "confirmed".into();
            }
        }
    }
    ok(json!({"version": version, "op": op}))
}
