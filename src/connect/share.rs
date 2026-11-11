//! A vault shared between the accounts of one family or team (contract connect-account-v1
//! section 16, ADR 0037 stage 7).
//!
//! **Authority.** The account that made a vault store is the only authority for it. What
//! it says of other accounts are entries of its own signed device list
//! ([`super::trust`]), in the same chain as its `add` and `remove` entries: they share
//! one order with the device changes, and a removed device signs none of them. No role in
//! a group carries trust: the group view of Connect, the `shared` flag of a store, and the
//! device rows of a store are hints only.
//!
//! - `peer P R` pins the root `R` of the account `P`, after a ceremony with six words on a
//!   device of each account, once for each pair of accounts ([`ConnectAccount::start_share`]
//!   to [`ConnectAccount::accept_share`]). `unpeer P` ends it.
//! - `share P S`: the store `S` of this account syncs with the devices of `P`. `unshare P
//!   S` ends it.
//! - `join P S`: this account syncs the store `S` that `P` made. `leave P S` ends it.
//!
//! **The trust store.** The account file keeps, for each other account that this account
//! pinned or that a store it joined names ([`PeerPin`]): its root, the version and the
//! hash of the newest list of it that verified from that root, its devices, and its keys
//! that left. It keeps, for each shared store ([`StoreShare`]): the account that made it,
//! its members (from the signed `share` entries of that account), and the keys that
//! ended there. [`store_signer_policy`] takes the signers of a store from these alone,
//! never from an answer of Connect.
//!
//! **What a lying Connect can do.** It can withhold the newest entries of a list (an
//! `unshare`, a `remove`) from a device until a head of an up-to-date device reaches it,
//! give an old prefix to a new device, or keep the devices apart. It cannot add a key, a
//! member, or a share: each needs a signature of a device of the list that made it, from a
//! root that this device pinned with the words. A served root other than the pinned one
//! suspends that account here until the people compare new words.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::account::AccountState;
use super::client::{ConnectClient, StoreDevice};
use super::device_key::{LIST_NONE, peer_join_message, share_list_message};
use super::trust::{self, ListEntry, Pin, Verified, point, valid_list_hash};
use super::words::{
    ShareCode, key_fingerprint, share_fingerprint, share_safety_words, valid_account_id,
    valid_device_id,
};
use super::{ConnectAccount, ConnectError};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::sync::relay_crypto::valid_team_id;
use crate::sync::{StoreSigners, decode_b64u, encode_b64u, verify_signature};

/// The most peers of an account: active `peer` entries of its list, and pins of the
/// account file.
pub const MAX_PEERS: usize = 64;
/// The most active `share` and `join` entries of a list together.
pub const MAX_SHARED: usize = 128;
/// The most devices of a peer that the account file keeps.
pub const MAX_PEER_KNOWN: usize = 16;
/// The most keys of a peer that left, that the account file keeps.
pub const MAX_PEER_LEFT: usize = 32;
/// The most shared stores that the account file keeps.
pub const MAX_STORES: usize = 192;
/// The most keys that ended in one shared store, that the account file keeps.
pub const MAX_ENDED: usize = 64;
/// The owner of a store that this account made, in [`StoreShare::owner`].
pub const OWNER_SELF: &str = "self";
/// A share code works this long (section 16.2).
pub const SHARE_LINK_SECS: u64 = 600;

/// The ops of section 16.
pub const PEER: &str = "peer";
pub const UNPEER: &str = "unpeer";
pub const SHARE: &str = "share";
pub const UNSHARE: &str = "unshare";
pub const JOIN: &str = "join";
pub const LEAVE: &str = "leave";

/// Whether `op` is an entry of section 16 (it names another account).
pub fn is_share_op(op: &str) -> bool {
    matches!(op, PEER | UNPEER | SHARE | UNSHARE | JOIN | LEAVE)
}

/// Whether the entry `op` adds something (an `add`, a `peer`, a `share`, a `join`): it
/// comes only while the list has room to end everything (`trust::MAX_ADD_VERSION`).
pub fn adds(op: &str) -> bool {
    matches!(op, "add" | PEER | SHARE | JOIN)
}

/// Whether `op` names a store.
fn names_store(op: &str) -> bool {
    matches!(op, SHARE | UNSHARE | JOIN | LEAVE)
}

/// The message of `entry` as version `version` of the list of `account_id` at `origin`,
/// after the entry with the list hash `previous`: `None` when the entry has fields that
/// its op does not take (a key, a link, a name; a root other than on a `peer`; a store
/// other than on a store op).
pub(super) fn entry_message(
    origin: &str,
    account_id: &str,
    version: u64,
    previous: &str,
    entry: &ListEntry,
) -> Option<Vec<u8>> {
    if entry.key.is_some() || entry.link_hash.is_some() || entry.name.is_some() {
        return None;
    }
    let peer = entry.account_id.as_deref()?;
    let root = entry.root.as_deref();
    let team = entry.team_id.as_deref();
    if (entry.op == PEER) != root.is_some() || names_store(&entry.op) != team.is_some() {
        return None;
    }
    Some(share_list_message(
        origin,
        account_id,
        version,
        previous,
        &entry.op,
        peer,
        root.unwrap_or(LIST_NONE),
        team.unwrap_or(LIST_NONE),
        &entry.by,
    ))
}

/// What a device list says of other accounts at a version: the rules of section 16.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListShares {
    /// The active peers: the account and the root (X9.63) that its `peer` pinned, in the
    /// order of the entries.
    pub peers: Vec<(String, Vec<u8>)>,
    /// The active shares: (store, account).
    pub shares: Vec<(String, String)>,
    /// The active joins: (store, account that made it).
    pub joins: Vec<(String, String)>,
}

impl ListShares {
    /// The root that the active `peer` of `account` pinned.
    pub fn root_of(&self, account: &str) -> Option<&[u8]> {
        self.peers
            .iter()
            .find(|(peer, _)| peer == account)
            .map(|(_, root)| root.as_slice())
    }

    /// The accounts that the active shares of `team` name.
    pub fn members_of(&self, team: &str) -> Vec<String> {
        self.shares
            .iter()
            .filter(|(store, _)| store == team)
            .map(|(_, account)| account.clone())
            .collect()
    }

    /// The account of the active join of `team`.
    pub fn owner_of(&self, team: &str) -> Option<&str> {
        self.joins
            .iter()
            .find(|(store, _)| store == team)
            .map(|(_, account)| account.as_str())
    }

    /// Whether an active share or join names `account`.
    fn names(&self, account: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(_, held)| held == account)
    }

    /// Whether an active share or join names `team`.
    fn holds_store(&self, team: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(store, _)| store == team)
    }

    /// Apply the entry `entry` of the list of `account_id`, when the rules of section 16
    /// allow it at this point of the list; `None` (the list does not verify) otherwise:
    ///
    /// - `peer P R`: `P` is another account, not a peer already; `R` is a point; at most
    ///   [`MAX_PEERS`] peers.
    /// - `unpeer P`: `P` is a peer, and no active share or join names it.
    /// - `share P S`: `P` is a peer; `S` is in no active join of this list (a store this
    ///   account joined is not its own); `(S, P)` is not active.
    /// - `join P S`: `P` is a peer; no active share or join names `S`.
    /// - `unshare P S`, `leave P S`: active.
    ///
    /// At most [`MAX_SHARED`] active shares and joins together.
    pub(super) fn apply(&mut self, account_id: &str, entry: &ListEntry) -> Option<()> {
        let peer = entry
            .account_id
            .as_deref()
            .filter(|id| valid_account_id(id))?;
        if peer == account_id {
            return None;
        }
        let team = entry.team_id.as_deref();
        if team.is_some_and(|team| !valid_team_id(team)) {
            return None;
        }
        let is_peer = self.root_of(peer).is_some();
        match (entry.op.as_str(), team) {
            (PEER, None) => {
                let root = point(entry.root.as_deref()?)?;
                if is_peer || self.peers.len() >= MAX_PEERS {
                    return None;
                }
                self.peers.push((peer.to_owned(), root));
            }
            (UNPEER, None) => {
                if !is_peer || self.names(peer) {
                    return None;
                }
                self.peers.retain(|(held, _)| held != peer);
            }
            (SHARE, Some(team)) => {
                let pair = (team.to_owned(), peer.to_owned());
                if !is_peer
                    || self.joins.iter().any(|(store, _)| store == team)
                    || self.shares.contains(&pair)
                    || self.shares.len() + self.joins.len() >= MAX_SHARED
                {
                    return None;
                }
                self.shares.push(pair);
            }
            (JOIN, Some(team)) => {
                if !is_peer
                    || self.holds_store(team)
                    || self.shares.len() + self.joins.len() >= MAX_SHARED
                {
                    return None;
                }
                self.joins.push((team.to_owned(), peer.to_owned()));
            }
            (UNSHARE, Some(team)) => {
                let pair = (team.to_owned(), peer.to_owned());
                let at = self.shares.iter().position(|held| *held == pair)?;
                self.shares.remove(at);
            }
            (LEAVE, Some(team)) => {
                let pair = (team.to_owned(), peer.to_owned());
                let at = self.joins.iter().position(|held| *held == pair)?;
                self.joins.remove(at);
            }
            _ => return None,
        }
        Some(())
    }
}

// ---- The account file (section 16.5). ----

/// Another account in the trust store of this account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPin {
    pub account_id: String,
    /// b64u of its root (X9.63): from this account's own `peer` entry, or from the `peer`
    /// entry of the account named in [`Self::via`].
    pub root: String,
    /// `None`: this account pinned the root itself, with the words. `Some(account)`: a
    /// co-member of a store that `account` made; its root comes from that account's `peer`
    /// entry and counts only in the stores of that account.
    pub via: Option<String>,
    /// The version and the list hash of the newest list of it that verified from
    /// [`Self::root`] here; 0 and empty before the first.
    pub list_version: u64,
    pub list_head: String,
    /// b64u of its devices at that version (at most [`MAX_PEER_KNOWN`]).
    pub known: Vec<String>,
    /// b64u of its keys that left (at most [`MAX_PEER_LEFT`], the oldest first out).
    pub left: Vec<String>,
    /// Connect served a list of another root: its keys sign nothing new here until the
    /// people compare new words.
    pub suspended: bool,
}

impl PeerPin {
    fn new(account_id: &str, root: &[u8], via: Option<&str>) -> Self {
        Self {
            account_id: account_id.to_owned(),
            root: encode_b64u(root),
            via: via.map(str::to_owned),
            list_version: 0,
            list_head: String::new(),
            known: Vec::new(),
            left: Vec::new(),
            suspended: false,
        }
    }

    fn root_key(&self) -> Vec<u8> {
        point(&self.root).unwrap_or_default()
    }

    fn pin(&self) -> Option<Pin<'_>> {
        (self.list_version > 0).then_some(Pin {
            version: self.list_version,
            head: &self.list_head,
        })
    }

    fn is_valid(&self) -> bool {
        valid_account_id(&self.account_id)
            && point(&self.root).is_some()
            && self.via.as_deref().is_none_or(valid_account_id)
            && self.via.as_deref() != Some(self.account_id.as_str())
            && ((self.list_version == 0 && self.list_head.is_empty())
                || (self.list_version > 0 && valid_list_hash(&self.list_head)))
            && self.known.len() <= MAX_PEER_KNOWN
            && self.left.len() <= MAX_PEER_LEFT
            && self
                .known
                .iter()
                .chain(&self.left)
                .all(|key| point(key).is_some())
    }

    /// Take `list`, verified from this root: the pin moves to its head, the devices become
    /// [`Self::known`], and every known key that is not a device any more, and every key
    /// that the list removed, goes to [`Self::left`]. Returns whether anything changed.
    fn learn(&mut self, list: &Verified) -> bool {
        let before = self.clone();
        let live: Vec<String> = list.live.iter().map(|key| encode_b64u(key)).collect();
        let removed = list.removed.iter().map(|key| encode_b64u(key));
        let gone: Vec<String> = self
            .known
            .iter()
            .filter(|key| !live.contains(key))
            .cloned()
            .chain(removed)
            .collect();
        for key in gone {
            if !self.left.contains(&key) {
                self.left.push(key);
            }
        }
        self.left.retain(|key| !live.contains(key));
        if self.left.len() > MAX_PEER_LEFT {
            let extra = self.left.len() - MAX_PEER_LEFT;
            self.left.drain(..extra);
        }
        self.known = live.into_iter().take(MAX_PEER_KNOWN).collect();
        self.list_version = list.version;
        self.list_head = list.head().to_owned();
        *self != before
    }
}

/// A vault store shared between accounts, in the trust store of this account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreShare {
    pub team_id: String,
    /// [`OWNER_SELF`] for a store of this account, else the account that made it.
    pub owner: String,
    /// The accounts that the active `share` entries of the owner name for this store (for
    /// a store that this account joined, this account among them while the share lasts).
    pub members: Vec<String>,
    /// b64u of the keys that ended in this store: devices of a member that left it (at
    /// most [`MAX_ENDED`], the oldest first out). Each signs only the versions that this
    /// device had merged when it learned it.
    pub ended: Vec<String>,
}

impl StoreShare {
    fn is_valid(&self, account_id: &str) -> bool {
        valid_team_id(&self.team_id)
            && (self.owner == OWNER_SELF
                || (valid_account_id(&self.owner) && self.owner != account_id))
            && self.members.len() <= MAX_PEERS
            && self.members.iter().all(|member| valid_account_id(member))
            && self.ended.len() <= MAX_ENDED
            && self.ended.iter().all(|key| point(key).is_some())
    }

    /// Whether this store is one that this account made.
    pub fn is_own(&self) -> bool {
        self.owner == OWNER_SELF
    }

    /// Move the known keys of `pins` to the keys that ended here.
    fn end_keys<'a>(&mut self, keys: impl Iterator<Item = &'a String>) {
        for key in keys {
            if !self.ended.contains(key) {
                self.ended.push(key.clone());
            }
        }
        if self.ended.len() > MAX_ENDED {
            let extra = self.ended.len() - MAX_ENDED;
            self.ended.drain(..extra);
        }
    }
}

/// Whether the peers and shared stores of an account file have their shape and bounds.
pub(super) fn valid_state(account_id: &str, peers: &[PeerPin], stores: &[StoreShare]) -> bool {
    let mut ids: Vec<&str> = peers.iter().map(|pin| pin.account_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut teams: Vec<&str> = stores.iter().map(|store| store.team_id.as_str()).collect();
    teams.sort_unstable();
    teams.dedup();
    peers.len() <= MAX_PEERS
        && ids.len() == peers.len()
        && peers
            .iter()
            .all(|pin| pin.is_valid() && pin.account_id != account_id)
        && stores.len() <= MAX_STORES
        && teams.len() == stores.len()
        && stores.iter().all(|store| store.is_valid(account_id))
}

fn peer<'a>(state: &'a AccountState, account: &str) -> Option<&'a PeerPin> {
    state.peers.iter().find(|pin| pin.account_id == account)
}

fn peer_mut<'a>(state: &'a mut AccountState, account: &str) -> Option<&'a mut PeerPin> {
    state.peers.iter_mut().find(|pin| pin.account_id == account)
}

fn store_mut<'a>(state: &'a mut AccountState, team: &str) -> &'a mut StoreShare {
    if let Some(at) = state.stores.iter().position(|store| store.team_id == team) {
        return &mut state.stores[at];
    }
    if state.stores.len() >= MAX_STORES {
        // The oldest store without members goes first; without one, the oldest.
        let at = state
            .stores
            .iter()
            .position(|store| store.members.is_empty())
            .unwrap_or(0);
        state.stores.remove(at);
    }
    state.stores.push(StoreShare {
        team_id: team.to_owned(),
        owner: OWNER_SELF.to_owned(),
        members: Vec::new(),
        ended: Vec::new(),
    });
    let last = state.stores.len() - 1;
    &mut state.stores[last]
}

/// Set the members of `team` (made by `owner`) to `members`: each account that leaves
/// them leaves its keys here as ended keys. Returns whether anything changed.
fn set_members(state: &mut AccountState, team: &str, owner: &str, members: Vec<String>) -> bool {
    let gone_keys: Vec<String> = state
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .map(|store| {
            store
                .members
                .iter()
                .filter(|member| !members.contains(member))
                .filter_map(|member| peer(state, member))
                .flat_map(|pin| pin.known.iter().chain(&pin.left).cloned())
                .collect()
        })
        .unwrap_or_default();
    let before = state
        .stores
        .iter()
        .find(|store| store.team_id == team)
        .cloned();
    let store = store_mut(state, team);
    store.owner = owner.to_owned();
    store.end_keys(gone_keys.iter());
    store.members = members;
    before.as_ref() != Some(store)
}

/// Learn what this account's own verified list says of other accounts (`shares`): its own
/// peers get a pin (a peer whose root this list pins anew starts again from that root),
/// a pin of a peer that it ended goes unless a store that this account joined names that
/// account, and the members of each of its own shared stores are those of its active
/// shares. An account that leaves a store's members leaves its keys there as ended keys.
/// A store that this account left has no members. Returns whether anything changed.
pub(super) fn learn_own(state: &mut AccountState, shares: &ListShares) -> bool {
    let before = (state.peers.clone(), state.stores.clone());
    for (account, root) in &shares.peers {
        let root_b64u = encode_b64u(root);
        let held = state.peers.len();
        match peer_mut(state, account) {
            Some(pin) if pin.root == root_b64u => pin.via = None,
            Some(pin) => {
                // A new root (after a recovery and new words): the old keys sign nothing
                // new; the new list counts from its root.
                let mut left: Vec<String> = pin.known.drain(..).chain(pin.left.drain(..)).collect();
                if left.len() > MAX_PEER_LEFT {
                    let extra = left.len() - MAX_PEER_LEFT;
                    left.drain(..extra);
                }
                *pin = PeerPin {
                    left,
                    ..PeerPin::new(account, root, None)
                };
            }
            None if held < MAX_PEERS => {
                state.peers.push(PeerPin::new(account, root, None));
            }
            None => {}
        }
    }
    // Own pins that the list ended: a pin through another account is kept only while a
    // store of that account names this account.
    let joined: Vec<String> = state
        .stores
        .iter()
        .filter(|store| !store.is_own())
        .flat_map(|store| store.members.iter().cloned().chain([store.owner.clone()]))
        .collect();
    state.peers.retain(|pin| {
        pin.via.is_some()
            || shares.root_of(&pin.account_id).is_some()
            || joined.contains(&pin.account_id)
    });
    // The members of each own store.
    let mut own: Vec<String> = shares.shares.iter().map(|(team, _)| team.clone()).collect();
    own.extend(
        state
            .stores
            .iter()
            .filter(|store| store.is_own())
            .map(|store| store.team_id.clone()),
    );
    own.sort();
    own.dedup();
    for team in own {
        set_members(state, &team, OWNER_SELF, shares.members_of(&team));
    }
    // A joined store that this list left (or never joined) has no members here.
    let left_stores: Vec<(String, String)> = state
        .stores
        .iter()
        .filter(|store| {
            !store.is_own() && shares.owner_of(&store.team_id) != Some(store.owner.as_str())
        })
        .map(|store| (store.team_id.clone(), store.owner.clone()))
        .collect();
    for (team, owner) in left_stores {
        set_members(state, &team, &owner, Vec::new());
    }
    // A store that this list joined starts with no members here until the list of its
    // owner verifies ([`ConnectAccount::refresh_shares`]).
    for (team, owner) in &shares.joins {
        if !state.stores.iter().any(|store| store.team_id == *team) {
            set_members(state, team, owner, Vec::new());
        }
    }
    (state.peers.clone(), state.stores.clone()) != before
}

/// Learn the verified list `list` of the account `owner` for the stores of it that this
/// account joined (`joined`): the members of each are the accounts of its active shares,
/// and each other member gets a pin through `owner` with the root of its `peer` entry
/// there. A member whose root differs from a root that this account pinned itself counts
/// for nothing in those stores. Returns the members that need a list.
fn learn_owner(
    state: &mut AccountState,
    owner: &str,
    list: &Verified,
    joined: &[String],
) -> Vec<String> {
    let me = state.account_id.clone();
    let mut wanted = Vec::new();
    for team in joined {
        let mut members = Vec::new();
        for member in list.shares.members_of(team) {
            if member == me {
                members.push(member);
                continue;
            }
            let Some(root) = list.shares.root_of(&member).map(<[u8]>::to_vec) else {
                continue;
            };
            let root_b64u = encode_b64u(&root);
            let held = state.peers.len();
            match peer_mut(state, &member) {
                Some(pin) if pin.root == root_b64u => {}
                Some(pin) if pin.via.as_deref() == Some(owner) => {
                    // The owner pinned that member anew: start again from its new root.
                    *pin = PeerPin::new(&member, &root, Some(owner));
                }
                // Another root than this account's own pin, or a pin through another
                // owner: not a signer of this store.
                Some(_) => continue,
                None if held < MAX_PEERS => {
                    state.peers.push(PeerPin::new(&member, &root, Some(owner)));
                }
                None => continue,
            }
            wanted.push(member.clone());
            members.push(member);
        }
        set_members(state, team, owner, members);
    }
    wanted
}

/// Drop the pins through another account that no store of that account needs any more.
fn drop_unused_pins(state: &mut AccountState) {
    let needed: Vec<(String, String)> = state
        .stores
        .iter()
        .filter(|store| !store.is_own())
        .flat_map(|store| {
            store
                .members
                .iter()
                .map(|member| (member.clone(), store.owner.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    state.peers.retain(|pin| match &pin.via {
        None => true,
        Some(owner) => needed
            .iter()
            .any(|(member, held)| *member == pin.account_id && held == owner),
    });
}

/// Take the list `entries` of the peer `account` that Connect served: when it verifies
/// from the pinned root and goes on from the pin, the pin learns it; when its version 1 is
/// another key than the pinned root, the peer is suspended (its keys sign nothing new
/// until new words). Any other list changes nothing. Returns the verified list, if it
/// counted, and whether the pin changed.
fn take_peer_list(
    pin: &mut PeerPin,
    origin: &str,
    entries: &[ListEntry],
) -> (Option<Verified>, bool) {
    let root = pin.root_key();
    let served_root = entries
        .first()
        .and_then(|entry| entry.key.as_deref())
        .and_then(point);
    if served_root.as_ref().is_some_and(|served| *served != root) {
        let changed = !pin.suspended;
        pin.suspended = true;
        return (None, changed);
    }
    let Some(list) = trust::verify_list(origin, &pin.account_id, &root, entries)
        .filter(|list| pin.pin().is_none_or(|held| held.accepts(list)))
    else {
        return (None, false);
    };
    let changed = pin.learn(&list);
    (Some(list), changed)
}

// ---- The signers of a shared store (section 16.6). ----

fn keys(texts: &[String]) -> Vec<Vec<u8>> {
    texts.iter().filter_map(|text| point(text)).collect()
}

fn push_new(into: &mut Vec<Vec<u8>>, keys: Vec<Vec<u8>>) {
    for key in keys {
        if !into.contains(&key) {
            into.push(key);
        }
    }
}

/// Which keys may sign the heads of the shared store `team_id`, from the account file
/// alone; `None` for a store that this account file holds no share of (the signers of the
/// account: `super::signer_policy`).
///
/// - A store that this account joined, made by `A`: the devices of `A`, of this account,
///   and of each other member of `A`'s active shares of it. When this account is not a
///   member any more, the store has ended here: no key signs a new version.
/// - A store of this account: its own devices and the devices of each member.
///
/// The devices of a suspended peer sign nothing new. The keys that left (this account's,
/// the owner's, each member's), the keys that ended in this store, and the devices of a
/// suspended peer sign only up to the anchor of the store, and below a head of an accepted
/// key. A key in none of these lists signs nothing.
pub fn store_signer_policy(state: &AccountState, team_id: &str) -> Option<StoreSigners> {
    let store = state.stores.iter().find(|store| store.team_id == team_id)?;
    let mut accepted = keys(&state.known);
    let mut left = keys(&state.left);
    let mut involved: Vec<&PeerPin> = Vec::new();
    if !store.is_own()
        && let Some(owner) = peer(state, &store.owner)
    {
        involved.push(owner);
    }
    for member in &store.members {
        if *member == state.account_id {
            continue;
        }
        if let Some(pin) = peer(state, member) {
            involved.push(pin);
        }
    }
    for pin in involved {
        if pin.suspended {
            push_new(&mut left, keys(&pin.known));
        } else {
            push_new(&mut accepted, keys(&pin.known));
        }
        push_new(&mut left, keys(&pin.left));
    }
    push_new(&mut left, keys(&store.ended));
    if !store.is_own() && !store.members.contains(&state.account_id) {
        // The share ended for this account: nothing new merges here.
        let all = std::mem::take(&mut accepted);
        push_new(&mut left, all);
    }
    left.retain(|key| !accepted.contains(key));
    Some(StoreSigners {
        team_id: team_id.to_owned(),
        accepted,
        left,
    })
}

/// The signers of every shared store of the account file.
pub(super) fn shared_signers(state: &AccountState) -> Vec<StoreSigners> {
    state
        .stores
        .iter()
        .filter_map(|store| store_signer_policy(state, &store.team_id))
        .collect()
}

// ---- The wire of section 16 (contract routes). ----

#[derive(Serialize)]
struct ListAppend<'a> {
    version: u64,
    op: &'a str,
    account_id: &'a str,
    root: Option<&'a str>,
    team_id: Option<&'a str>,
    statement: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct ListAppended {
    version: u64,
}

#[derive(Serialize)]
struct PeerLinkRequest<'a> {
    link_hash: &'a str,
    account_id: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerLinkAnswer {
    link_id: u64,
    expires_at: u64,
}

#[derive(Serialize)]
struct PeerJoinBody<'a> {
    account_id: &'a str,
    link_hash: &'a str,
    signature: &'a str,
}

/// The device of the inviting account that made a share code, as Connect names it.
#[derive(Debug, Clone, Deserialize)]
struct PeerInviter {
    account_id: String,
    device_id: String,
    name: String,
    public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerJoinAnswer {
    join_id: u64,
    inviter: PeerInviter,
    expires_at: u64,
    #[serde(default)]
    device_list: Vec<ListEntry>,
}

/// One answer of a share code, for the device that made the code.
#[derive(Debug, Clone, Deserialize)]
struct PeerPendingView {
    join_id: u64,
    link_id: u64,
    account_id: String,
    name: String,
    public_key: String,
    signature: String,
    expires_at: u64,
    #[serde(default)]
    device_list: Vec<ListEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerJoinState {
    join_id: u64,
    state: String,
}

/// A device of another account as Connect lists it (`GET /v1/account/peers/{id}`). Which
/// of them is a device of that account is the signed list's to say.
#[derive(Debug, Clone, Deserialize)]
struct PeerDevice {
    device_id: String,
    public_key: String,
}

/// `GET /v1/account/peers/{account_id}`.
#[derive(Debug, Clone, Deserialize)]
struct PeerView {
    account_id: String,
    name: String,
    #[serde(default)]
    devices: Vec<PeerDevice>,
    #[serde(default)]
    device_list: Vec<ListEntry>,
}

#[derive(Serialize)]
struct Empty {}

impl ConnectClient {
    fn append_list(
        &self,
        token: &str,
        body: &ListAppend<'_>,
    ) -> Result<ListAppended, ConnectError> {
        self.post_json("/v1/account/list", Some(token), body)
    }

    fn peer_link(
        &self,
        token: &str,
        body: &PeerLinkRequest<'_>,
    ) -> Result<PeerLinkAnswer, ConnectError> {
        self.post_json("/v1/account/peers/link", Some(token), body)
    }

    fn peer_join(
        &self,
        token: &str,
        body: &PeerJoinBody<'_>,
    ) -> Result<PeerJoinAnswer, ConnectError> {
        self.post_json("/v1/account/peers/join", Some(token), body)
    }

    fn peer_pending(&self, token: &str) -> Result<Vec<PeerPendingView>, ConnectError> {
        self.get_json("/v1/account/peers/pending", Some(token))
    }

    fn peer_join_state(&self, token: &str, join_id: u64) -> Result<PeerJoinState, ConnectError> {
        self.get_json(&format!("/v1/account/peers/join/{join_id}"), Some(token))
    }

    fn peer_join_end(&self, token: &str, join_id: u64) -> Result<PeerJoinState, ConnectError> {
        self.send_json(
            "DELETE",
            &format!("/v1/account/peers/join/{join_id}"),
            Some(token),
            &Empty {},
        )
    }

    fn peer_view(&self, token: &str, account_id: &str) -> Result<PeerView, ConnectError> {
        if !valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        self.get_json(&format!("/v1/account/peers/{account_id}"), Some(token))
    }
}

// ---- The ceremony (section 16.2). ----

/// "Share with…" on the device of the account that shares: the code in memory (Copy and
/// QR), its number at Connect, the person, and the store. Debug is redacted.
pub struct ShareLink {
    code: ShareCode,
    link_id: u64,
    expires_at: u64,
    peer_account: String,
    team_id: String,
}

impl fmt::Debug for ShareLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareLink")
            .field("link_id", &self.link_id)
            .field("peer_account", &self.peer_account)
            .field("team_id", &self.team_id)
            .field("code", &"[redacted]")
            .finish()
    }
}

impl ShareLink {
    /// The text of the code, for the Copy button and the QR code (error correction M).
    pub fn code(&self) -> &str {
        self.code.expose()
    }

    pub fn link_id(&self) -> u64 {
        self.link_id
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The account that the code is for.
    pub fn peer_account(&self) -> &str {
        &self.peer_account
    }

    /// The store that the code shares.
    pub fn team_id(&self) -> &str {
        &self.team_id
    }
}

/// An answer to a share code, as the device that made the code verified it: the other
/// account's list from its version 1, its device that answered, its signature over the
/// answer, and the six words.
#[derive(Debug, Clone)]
pub struct ShareRequest {
    pub join_id: u64,
    pub account_id: String,
    /// The person's name as Connect gives it.
    pub name: String,
    /// The name that the other account's list signed for its device.
    pub device_name: String,
    /// The answering device (X9.63).
    pub public_key: Vec<u8>,
    /// The other account's root (X9.63): version 1 of its list.
    pub root: Vec<u8>,
    /// The six words.
    pub words: String,
    pub expires_at: u64,
    list: Verified,
}

impl ShareRequest {
    /// The words line: `"<name>" (<device>) asks to share vaults with you. Both devices
    /// show: <words>.`
    pub fn line(&self) -> String {
        format!(
            "\"{}\" ({}) asks to share vaults with you. Both devices show: {}.",
            self.name, self.device_name, self.words
        )
    }
}

/// The answer of this device to a share code of another account: the inviting account
/// and device that the code named, its verified list, and the six words. Debug is
/// redacted.
pub struct SharePeerJoin {
    code: ShareCode,
    pub join_id: u64,
    pub account_id: String,
    /// The person's name as Connect gives it.
    pub name: String,
    /// The name that the inviting list signed for the inviting device.
    pub device_name: String,
    pub root: Vec<u8>,
    pub inviter_key: Vec<u8>,
    pub words: String,
    pub expires_at: u64,
    list: Verified,
}

impl fmt::Debug for SharePeerJoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharePeerJoin")
            .field("join_id", &self.join_id)
            .field("account_id", &self.account_id)
            .field("words", &self.words)
            .finish_non_exhaustive()
    }
}

/// A store that another account shares with this one and that this account has not
/// joined: "<vault>, shared by <name>: Join".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareOffer {
    pub team_id: String,
    pub owner: String,
    pub owner_name: String,
    /// The vault name, when Connect lists the store for this account.
    pub vault_name: Option<String>,
}

/// One member of a shared store of this account, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    pub account_id: String,
    pub name: String,
    /// The member's list holds its `join` of the store.
    pub joined: bool,
    /// The member's list did not verify from its pinned root (a reset account).
    pub suspended: bool,
}

/// A shared store and its state here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreStatus {
    pub team_id: String,
    /// `None`: this account made it.
    pub owner: Option<String>,
    pub owner_name: Option<String>,
    pub members: Vec<MemberStatus>,
    /// The share ended for this account (a store it joined).
    pub ended: bool,
    /// The owner of a store that this account joined was suspended here (it reset its
    /// account).
    pub owner_suspended: bool,
}

/// What [`ConnectAccount::refresh_shares`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareStatus {
    pub offers: Vec<ShareOffer>,
    pub stores: Vec<StoreStatus>,
    /// Peers whose list Connect gave from another root: they reset their account.
    pub suspended: Vec<String>,
    /// Peers that Connect shows outside the group of this account.
    pub outside_group: Vec<String>,
    /// The names of the peers, as Connect gives them.
    pub names: BTreeMap<String, String>,
}

impl ShareStatus {
    /// The name of `account`, or the account id.
    pub fn name_of(&self, account: &str) -> String {
        self.names
            .get(account)
            .cloned()
            .unwrap_or_else(|| account.to_owned())
    }
}

/// What a confirmation of a share did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareConfirmed {
    /// The devices of the other account that Connect added to the store.
    pub added: Vec<StoreDevice>,
    /// Devices of the other account that Connect did not add, with the reason.
    pub not_added: Vec<(String, String)>,
}

impl ConnectAccount {
    /// Sign the entry `op` of section 16 for `peer_account` (with `root` for a `peer` and
    /// the store `team_id` for a store op) after the head that this device verified, and
    /// append it with `POST /v1/account/list`. A `409` (the list moved) reads the list
    /// again and signs once more. A list that this device's own rules refuse the entry at
    /// is [`ConnectError::Conflict`], and nothing is sent. On success this device pins the
    /// entry it signed.
    fn share_entry(
        &mut self,
        op: &str,
        peer_account: &str,
        root: Option<&[u8]>,
        team_id: Option<&str>,
    ) -> Result<(), ConnectError> {
        let signer = self.signer()?;
        let root_b64u = root.map(encode_b64u);
        for round in 0..2 {
            self.verified_view()?;
            let mut shares = self
                .verified_list()
                .map(|list| list.shares.clone())
                .ok_or(ConnectError::BadAnswer)?;
            let (version, previous) = (
                self.state().list_version + 1,
                self.state().list_head.clone(),
            );
            if adds(op) && version > trust::MAX_ADD_VERSION {
                return Err(ConnectError::AccountLimit);
            }
            let entry = ListEntry {
                version,
                op: op.to_owned(),
                key: None,
                link_hash: None,
                name: None,
                by: signer.public_key_b64u(),
                signature: None,
                account_id: Some(peer_account.to_owned()),
                root: root_b64u.clone(),
                team_id: team_id.map(str::to_owned),
            };
            let account_id = self.state().account_id.clone();
            shares
                .apply(&account_id, &entry)
                .ok_or(ConnectError::Conflict)?;
            let (signature, hash) = signer.sign_share_entry(
                self.client().origin(),
                &account_id,
                (version, &previous),
                op,
                peer_account,
                root_b64u.as_deref(),
                team_id,
            )?;
            let statement = encode_b64u(&signature);
            let body = ListAppend {
                version,
                op,
                account_id: peer_account,
                root: root_b64u.as_deref(),
                team_id,
                statement: &statement,
            };
            match self.with_token(|client, token| client.append_list(token, &body)) {
                Ok(answer) if answer.version == version => {
                    let known = AccountState::keys(&self.state().known);
                    self.advance(version, &hash, &known, &[])?;
                    if learn_own(self.state_mut(), &shares) {
                        self.save_state()?;
                    }
                    self.forget_list();
                    return Ok(());
                }
                Ok(_) => return Err(ConnectError::BadAnswer),
                Err(ConnectError::Conflict) if round == 0 => {}
                Err(error) => return Err(error),
            }
        }
        Err(ConnectError::Conflict)
    }

    /// The list of the peer `account` from Connect, taken by its pin here (when it has
    /// one), with the name and the device rows that Connect gives.
    fn read_peer(&mut self, account: &str) -> Result<PeerView, ConnectError> {
        let view = self.with_token(|client, token| client.peer_view(token, account))?;
        if view.account_id != account {
            return Err(ConnectError::BadAnswer);
        }
        Ok(view)
    }

    /// "Share with…" for the member `peer_account` of the group and the store `team_id`
    /// of this account: a new share code in memory (it names the root of this account and
    /// this device) and its hash at Connect, for 10 minutes and one use. Show the code
    /// and its QR: "Send this to <name>." The code is for the pair of accounts: later
    /// shares between them need none.
    pub fn start_share(
        &mut self,
        peer_account: &str,
        team_id: &str,
    ) -> Result<ShareLink, ConnectError> {
        if !valid_account_id(peer_account)
            || peer_account == self.state().account_id
            || !valid_team_id(team_id)
        {
            return Err(ConnectError::Invalid);
        }
        let code = ShareCode::generate(
            &self.state().account_id,
            &self.root_key(),
            &self.own_public_key(),
        )?;
        let hash = code.link_hash();
        let body = PeerLinkRequest {
            link_hash: &hash,
            account_id: peer_account,
        };
        let answer = self.with_token(|client, token| client.peer_link(token, &body))?;
        Ok(ShareLink {
            code,
            link_id: answer.link_id,
            expires_at: answer.expires_at,
            peer_account: peer_account.to_owned(),
            team_id: team_id.to_owned(),
        })
    }

    /// The answers to `link`, each verified here: the other account's list verifies from
    /// its version 1, the answering key is a device of it, and that key signed the answer
    /// (`apassy-connect peer-join v1`) with the account, the root, and the hash of this
    /// code. Each comes with the six words that this device computes from the code it
    /// holds. An answer that fails a check is left out. Ask every 5 s while the sheet is
    /// open.
    pub fn share_requests(&mut self, link: &ShareLink) -> Result<Vec<ShareRequest>, ConnectError> {
        let pending = self.with_token(|client, token| client.peer_pending(token))?;
        let origin = self.client().origin().to_owned();
        let me = self.state().account_id.clone();
        let (my_root, my_key) = (self.root_key(), self.own_public_key());
        let hash = link.code.link_hash();
        Ok(pending
            .into_iter()
            .filter(|join| join.link_id == link.link_id && join.account_id == link.peer_account)
            .filter_map(|join| {
                let root = join
                    .device_list
                    .first()
                    .and_then(|entry| entry.key.as_deref())
                    .and_then(point)?;
                let list = trust::verify_list(&origin, &join.account_id, &root, &join.device_list)?;
                let key = point(&join.public_key).filter(|key| list.live.contains(key))?;
                let message = peer_join_message(
                    &origin,
                    &me,
                    &hash,
                    &join.account_id,
                    &encode_b64u(&root),
                    &join.public_key,
                );
                let signature = decode_b64u(&join.signature)?;
                if !verify_signature(&key, &message, &signature) {
                    return None;
                }
                let words = share_safety_words(
                    link.code.expose(),
                    (&me, &my_root, &my_key),
                    (&join.account_id, &root, &key),
                );
                Some(ShareRequest {
                    join_id: join.join_id,
                    account_id: join.account_id,
                    name: clean(&join.name),
                    device_name: list.name_of(&key).unwrap_or_default().to_owned(),
                    public_key: key,
                    root,
                    words,
                    expires_at: join.expires_at,
                    list,
                })
            })
            .collect())
    }

    /// The owner action of the confirmation of `request` for the store of `link`.
    pub fn share_action(&self, link: &ShareLink, request: &ShareRequest) -> OwnerAction {
        OwnerAction::ShareConnectVault {
            account_id: self.state().account_id.clone(),
            peer_account: request.account_id.clone(),
            peer_name: request.name.clone(),
            team_id: link.team_id.clone(),
            words: request.words.clone(),
            fingerprint: key_fingerprint(&request.root),
        }
    }

    /// "Confirm" of a share after a fresh owner check for [`Self::share_action`] in the
    /// vault session `epoch`: the words are computed again from the code and the keys
    /// (another request is [`ConnectError::WordsMismatch`], nothing is signed); this device
    /// signs `peer` for the other account's root (unless this account pinned that root
    /// already) and `share` of the store, pins the other account with the list that it
    /// verified, and adds that account's verified devices to the store. The proof is used
    /// up, also when the call fails.
    pub fn confirm_share(
        &mut self,
        link: &ShareLink,
        request: &ShareRequest,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<ShareConfirmed, ConnectError> {
        let me = self.state().account_id.clone();
        let words = share_safety_words(
            link.code.expose(),
            (&me, &self.root_key(), &self.own_public_key()),
            (&request.account_id, &request.root, &request.public_key),
        );
        if words != request.words || request.account_id != link.peer_account {
            return Err(ConnectError::WordsMismatch);
        }
        proof
            .check(&self.share_action(link, request), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.pin_peer(&request.account_id, &request.root, &request.list)?;
        self.share_store_with(&link.team_id, &request.account_id)
    }

    /// The owner action of a share of the store `team_id` with the pinned peer
    /// `peer_account`, without new words.
    pub fn share_again_action(
        &self,
        team_id: &str,
        peer_account: &str,
        peer_name: &str,
    ) -> OwnerAction {
        let fingerprint = peer(self.state(), peer_account)
            .map(|pin| key_fingerprint(&pin.root_key()))
            .unwrap_or_default();
        OwnerAction::ShareConnectVault {
            account_id: self.state().account_id.clone(),
            peer_account: peer_account.to_owned(),
            peer_name: peer_name.to_owned(),
            team_id: team_id.to_owned(),
            words: String::new(),
            fingerprint,
        }
    }

    /// Share the store `team_id` with `peer_account`, whose root this account pinned
    /// already (a pair of accounts compares words once), after a fresh owner check for
    /// [`Self::share_again_action`]. A peer that is not pinned here, or is suspended, is
    /// [`ConnectError::NotVerified`], and nothing is signed.
    pub fn share_again(
        &mut self,
        team_id: &str,
        peer_account: &str,
        peer_name: &str,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<ShareConfirmed, ConnectError> {
        proof
            .check(
                &self.share_again_action(team_id, peer_account, peer_name),
                epoch,
            )
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.refresh_shares()?;
        let pinned = peer(self.state(), peer_account)
            .is_some_and(|pin| pin.via.is_none() && !pin.suspended && pin.list_version > 0);
        if !pinned {
            return Err(ConnectError::NotVerified);
        }
        self.share_store_with(team_id, peer_account)
    }

    /// Whether this account pinned `peer_account` itself and its list verifies: a share
    /// with it needs no words.
    pub fn is_pinned_peer(&self, peer_account: &str) -> bool {
        peer(self.state(), peer_account)
            .is_some_and(|pin| pin.via.is_none() && !pin.suspended && pin.list_version > 0)
    }

    /// Sign `peer` for `root` of `account` unless this account's list pins it already, and
    /// pin `list` (verified from that root) in the account file.
    fn pin_peer(
        &mut self,
        account: &str,
        root: &[u8],
        list: &Verified,
    ) -> Result<(), ConnectError> {
        self.verified_view()?;
        let pinned = self
            .verified_list()
            .and_then(|own| own.shares.root_of(account).map(<[u8]>::to_vec));
        match pinned {
            Some(held) if held == root => {}
            Some(_) => {
                // Another root: the people compared new words for a reset account. The
                // old pin ends first; its shares and joins must have ended.
                self.share_entry(UNPEER, account, None, None)?;
                self.share_entry(PEER, account, Some(root), None)?;
            }
            None => self.share_entry(PEER, account, Some(root), None)?,
        }
        let state = self.state_mut();
        let pin = match peer_mut(state, account) {
            Some(pin) => pin,
            None => {
                if state.peers.len() >= MAX_PEERS {
                    return Err(ConnectError::AccountLimit);
                }
                state.peers.push(PeerPin::new(account, root, None));
                state.peers.last_mut().ok_or(ConnectError::Local)?
            }
        };
        if pin.root != encode_b64u(root) {
            *pin = PeerPin::new(account, root, None);
        }
        pin.via = None;
        pin.suspended = false;
        if pin.pin().is_none_or(|held| held.accepts(list)) {
            pin.learn(list);
        }
        self.save_state()
    }

    /// Sign `share` of `team_id` with `peer_account` (unless it is active), and add the
    /// verified devices of that account to the store.
    fn share_store_with(
        &mut self,
        team_id: &str,
        peer_account: &str,
    ) -> Result<ShareConfirmed, ConnectError> {
        self.verified_view()?;
        let active = self.verified_list().is_some_and(|own| {
            own.shares
                .shares
                .iter()
                .any(|(store, held)| store == team_id && held == peer_account)
        });
        if !active {
            self.share_entry(SHARE, peer_account, None, Some(team_id))?;
        }
        self.add_peer_devices(team_id, peer_account)
    }

    /// Add each device of `peer_account` that its list (verified here from its pinned
    /// root) holds to the store `team_id`, with the key that this device verified.
    fn add_peer_devices(
        &mut self,
        team_id: &str,
        peer_account: &str,
    ) -> Result<ShareConfirmed, ConnectError> {
        let view = self.read_peer(peer_account)?;
        let origin = self.client().origin().to_owned();
        let pin = peer_mut(self.state_mut(), peer_account).ok_or(ConnectError::NotVerified)?;
        let (list, _) = take_peer_list(pin, &origin, &view.device_list);
        let list = list.ok_or(ConnectError::NotVerified)?;
        self.save_state()?;
        let mut confirmed = ShareConfirmed {
            added: Vec::new(),
            not_added: Vec::new(),
        };
        for device in &view.devices {
            let Some(key) = point(&device.public_key).filter(|key| list.live.contains(key)) else {
                continue;
            };
            if !valid_device_id(&device.device_id) {
                continue;
            }
            let public_key = encode_b64u(&key);
            let device_id = device.device_id.clone();
            match self.with_token(|client, token| {
                client.add_store_device(token, team_id, &device_id, &public_key)
            }) {
                Ok(added) if added.device_id == device_id && added.account_id == peer_account => {
                    confirmed.added.push(added);
                }
                Ok(_) => confirmed
                    .not_added
                    .push((device_id, ConnectError::BadAnswer.to_string())),
                Err(error) => confirmed.not_added.push((device_id, error.to_string())),
            }
        }
        Ok(confirmed)
    }

    /// "Accept a Shared Vault…": the pasted `code` of another account. This device signs
    /// the answer with its account, its root, and its key; Connect names the account and
    /// the device of the code. The root of the list that Connect gives (its version 1)
    /// and the inviting key must give the fingerprint of the code, the list must verify
    /// from that root, and the inviting key must be a device of it: any other answer is
    /// [`ConnectError::ShareMismatch`] ("The code does not match the account that
    /// answered."), and the answer is withdrawn. Show the six words.
    pub fn accept_code(&mut self, code: &str) -> Result<SharePeerJoin, ConnectError> {
        let code = ShareCode::parse(code).ok_or(ConnectError::Invalid)?;
        if code.account_id() == self.state().account_id {
            return Err(ConnectError::Invalid);
        }
        let signer = self.signer()?;
        let hash = code.link_hash();
        let me = self.state().account_id.clone();
        let my_root = self.root_key();
        let signature = encode_b64u(&signer.sign_peer_join(
            self.client().origin(),
            code.account_id(),
            &hash,
            &me,
            &encode_b64u(&my_root),
        )?);
        let body = PeerJoinBody {
            account_id: code.account_id(),
            link_hash: &hash,
            signature: &signature,
        };
        let answer = self.with_token(|client, token| client.peer_join(token, &body))?;
        let origin = self.client().origin().to_owned();
        let checked = (answer.inviter.account_id == code.account_id())
            .then_some(())
            .and_then(|()| point(&answer.inviter.public_key))
            .and_then(|key| {
                let root = answer
                    .device_list
                    .first()
                    .and_then(|entry| entry.key.as_deref())
                    .and_then(point)?;
                if share_fingerprint(&root, &key) != code.fingerprint() {
                    return None;
                }
                let list =
                    trust::verify_list(&origin, code.account_id(), &root, &answer.device_list)?;
                list.live.contains(&key).then_some((root, key, list))
            });
        let Some((root, key, list)) = checked else {
            let join_id = answer.join_id;
            let _ = self.with_token(|client, token| client.peer_join_end(token, join_id));
            return Err(ConnectError::ShareMismatch);
        };
        let words = share_safety_words(
            code.expose(),
            (code.account_id(), &root, &key),
            (&me, &my_root, signer.public_key()),
        );
        let device_name = list.name_of(&key).unwrap_or_default().to_owned();
        let _ = valid_device_id(&answer.inviter.device_id);
        Ok(SharePeerJoin {
            join_id: answer.join_id,
            account_id: code.account_id().to_owned(),
            name: clean(&answer.inviter.name),
            device_name,
            root,
            inviter_key: key,
            words,
            expires_at: answer.expires_at,
            list,
            code,
        })
    }

    /// The owner action of "The Words Match" for `join`.
    pub fn accept_action(&self, join: &SharePeerJoin) -> OwnerAction {
        OwnerAction::AcceptConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: join.account_id.clone(),
            peer_name: join.name.clone(),
            words: join.words.clone(),
            fingerprint: key_fingerprint(&join.root),
        }
    }

    /// "The Words Match" after a fresh owner check for [`Self::accept_action`]: the words
    /// are computed again (another set is [`ConnectError::WordsMismatch`]); this device
    /// signs `peer` for the inviting account's root and pins its verified list. Its shared
    /// stores then show in [`Self::refresh_shares`] as offers. The proof is used up.
    pub fn accept_share(
        &mut self,
        join: &SharePeerJoin,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        let me = self.state().account_id.clone();
        let words = share_safety_words(
            join.code.expose(),
            (&join.account_id, &join.root, &join.inviter_key),
            (&me, &self.root_key(), &self.own_public_key()),
        );
        if words != join.words {
            return Err(ConnectError::WordsMismatch);
        }
        proof
            .check(&self.accept_action(join), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.pin_peer(&join.account_id, &join.root, &join.list)
    }

    /// Withdraw this device's answer to a share code (the words differ, or the person
    /// stopped).
    pub fn cancel_share_answer(&mut self, join: SharePeerJoin) -> Result<(), ConnectError> {
        let join_id = join.join_id;
        self.with_token(|client, token| client.peer_join_end(token, join_id))
            .map(drop)
    }

    /// Refuse an answer to this device's share code (the words differ).
    pub fn refuse_share_request(&mut self, request: &ShareRequest) -> Result<(), ConnectError> {
        let join_id = request.join_id;
        self.with_token(|client, token| client.peer_join_end(token, join_id))
            .map(drop)
    }

    /// The state of this device's answer `join` at Connect: `pending`, `confirmed` (the
    /// other account signed its `peer`), `refused`, or `expired`.
    pub fn share_answer_state(&mut self, join: &SharePeerJoin) -> Result<String, ConnectError> {
        let join_id = join.join_id;
        let state = self.with_token(|client, token| client.peer_join_state(token, join_id))?;
        if state.join_id != join_id {
            return Err(ConnectError::BadAnswer);
        }
        Ok(state.state)
    }

    /// Read the own list and the lists of the peers and of the accounts whose stores this
    /// account joined, and learn them (section 16.6): the pins move with the lists that
    /// verify from them, a list of another root suspends its account, the members of each
    /// joined store come from the active shares of its owner, and each co-member is pinned
    /// through the owner. Writes the account file when the trust store changed. A peer
    /// list that Connect does not give, or that does not verify, changes nothing of it.
    pub fn refresh_shares(&mut self) -> Result<ShareStatus, ConnectError> {
        self.verified_view()?;
        let own = self
            .verified_list()
            .map(|list| list.shares.clone())
            .ok_or(ConnectError::BadAnswer)?;
        let origin = self.client().origin().to_owned();
        let me = self.state().account_id.clone();
        let mut status = ShareStatus::default();
        let mut lists: BTreeMap<String, Verified> = BTreeMap::new();
        let mut changed = false;
        // The joined stores by owner.
        let mut by_owner: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (team, owner) in &own.joins {
            by_owner
                .entry(owner.clone())
                .or_default()
                .push(team.clone());
        }
        // First the own peers and the owners, then the co-members that the owners name.
        let mut queue: Vec<String> = own
            .peers
            .iter()
            .map(|(account, _)| account.clone())
            .collect();
        for owner in by_owner.keys() {
            if !queue.contains(owner) {
                queue.push(owner.clone());
            }
        }
        let mut done: Vec<String> = Vec::new();
        while let Some(account) = queue.first().cloned() {
            queue.remove(0);
            if done.contains(&account) || peer(self.state(), &account).is_none() {
                continue;
            }
            done.push(account.clone());
            let view = match self.read_peer(&account) {
                Ok(view) => view,
                Err(
                    ConnectError::NotInGroup | ConnectError::NotFound | ConnectError::Forbidden,
                ) => {
                    status.outside_group.push(account.clone());
                    continue;
                }
                Err(error @ (ConnectError::Revoked | ConnectError::SignedOut)) => {
                    return Err(error);
                }
                Err(_) => continue,
            };
            status.names.insert(account.clone(), clean(&view.name));
            let Some(pin) = peer_mut(self.state_mut(), &account) else {
                continue;
            };
            let (list, moved) = take_peer_list(pin, &origin, &view.device_list);
            changed |= moved;
            if let Some(list) = list {
                if let Some(teams) = by_owner.get(&account) {
                    let before = self.state().clone();
                    for member in learn_owner(self.state_mut(), &account, &list, teams) {
                        if !done.contains(&member) && !queue.contains(&member) {
                            queue.push(member);
                        }
                    }
                    changed |= *self.state() != before;
                }
                lists.insert(account.clone(), list);
            }
        }
        let before = self.state().clone();
        drop_unused_pins(self.state_mut());
        changed |= *self.state() != before;
        if changed {
            self.save_state()?;
        }
        // What the screens show.
        status.suspended = self
            .state()
            .peers
            .iter()
            .filter(|pin| pin.suspended)
            .map(|pin| pin.account_id.clone())
            .collect();
        let stores = self.vault_stores().unwrap_or_default();
        for (account, list) in &lists {
            for (team, member) in &list.shares.shares {
                if *member == me
                    && own.owner_of(team) != Some(account.as_str())
                    && !own.holds_store(team)
                {
                    status.offers.push(ShareOffer {
                        team_id: team.clone(),
                        owner: account.clone(),
                        owner_name: status.name_of(account),
                        vault_name: stores
                            .iter()
                            .find(|store| store.team_id == *team)
                            .map(|store| store.name.clone()),
                    });
                }
            }
        }
        for store in &self.state().stores {
            let members = store
                .members
                .iter()
                .filter(|member| **member != me)
                .map(|member| MemberStatus {
                    account_id: member.clone(),
                    name: status.name_of(member),
                    joined: lists
                        .get(member)
                        .is_some_and(|list| list.shares.owner_of(&store.team_id).is_some()),
                    suspended: peer(self.state(), member).is_some_and(|pin| pin.suspended),
                })
                .collect();
            let owner = (!store.is_own()).then(|| store.owner.clone());
            status.stores.push(StoreStatus {
                team_id: store.team_id.clone(),
                owner_name: owner.as_deref().map(|owner| status.name_of(owner)),
                owner_suspended: owner
                    .as_deref()
                    .and_then(|owner| peer(self.state(), owner))
                    .is_some_and(|pin| pin.suspended),
                ended: owner.is_some() && !store.members.contains(&me),
                owner,
                members,
            });
        }
        Ok(status)
    }

    /// "Join" of an offer: this device signs `join` of the store `team_id` of `owner`, a
    /// peer that this account pinned, whose active `share` names this account. Then the
    /// store's copy is downloaded with its passphrase (`RelaySync::joined_from_store`).
    pub fn join_shared_store(&mut self, team_id: &str, owner: &str) -> Result<(), ConnectError> {
        if !self.is_pinned_peer(owner) {
            return Err(ConnectError::NotVerified);
        }
        self.share_entry(JOIN, owner, None, Some(team_id))?;
        self.refresh_shares().map(drop)
    }

    /// The owner action of the end of a share: the owner's "Stop Sharing with <name>…"
    /// (`leave` false) or a member's "Leave This Shared Vault…" (`leave` true).
    pub fn end_share_action(
        &self,
        team_id: &str,
        peer_account: &str,
        peer_name: &str,
        leave: bool,
    ) -> OwnerAction {
        OwnerAction::EndConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: peer_account.to_owned(),
            peer_name: peer_name.to_owned(),
            team_id: team_id.to_owned(),
            leave,
        }
    }

    /// "Stop Sharing with <name>…": this device signs `unshare` of the store `team_id` for
    /// `peer_account`, and Connect removes that account's devices from the store in the
    /// same step. It needs a fresh owner check for [`Self::end_share_action`], unless
    /// Connect shows either account outside the group (`proof` `None`): ending a share
    /// gives no one access, so a lying Connect can end one this way, never start one. The
    /// pin of the peer stays: sharing again needs no words.
    pub fn stop_sharing(
        &mut self,
        team_id: &str,
        peer_account: &str,
        peer_name: &str,
        proof: Option<OwnerProof>,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        match proof {
            Some(proof) => {
                proof
                    .check(
                        &self.end_share_action(team_id, peer_account, peer_name, false),
                        epoch,
                    )
                    .map_err(ConnectError::OwnerCheck)?;
            }
            None => {
                if self.shares_group_with(peer_account)? {
                    return Err(ConnectError::OwnerCheck(
                        crate::broker::approvals::ProofRefusal::WrongAction,
                    ));
                }
            }
        }
        self.share_entry(UNSHARE, peer_account, None, Some(team_id))
    }

    /// Whether Connect shows this account and `peer_account` as active members of one
    /// group (`GET /v1/account/group`).
    fn shares_group_with(&mut self, peer_account: &str) -> Result<bool, ConnectError> {
        Ok(self.group()?.is_some_and(|group| {
            group
                .members
                .iter()
                .any(|member| member.account_id == peer_account && member.state == "active")
                && group.members.iter().any(|member| {
                    member.account_id == self.state().account_id && member.state == "active"
                })
        }))
    }

    /// "Leave This Shared Vault…": this device signs `leave` of the store `team_id` of
    /// `owner` after a fresh owner check for [`Self::end_share_action`]; Connect removes
    /// this account's devices from the store in the same step. The vault stays on this
    /// device; its sync with the store ends.
    pub fn leave_shared_store(
        &mut self,
        team_id: &str,
        owner: &str,
        owner_name: &str,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        proof
            .check(
                &self.end_share_action(team_id, owner, owner_name, true),
                epoch,
            )
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.share_entry(LEAVE, owner, None, Some(team_id))
    }

    /// Whether the account file holds a share of the store `team_id` that this device
    /// verified: a store of this account with shares (or that had shares), or a store of
    /// another account whose owner's list shares it with this account now.
    pub fn shares_store(&self, team_id: &str) -> bool {
        let me = &self.state().account_id;
        self.state()
            .stores
            .iter()
            .any(|store| store.team_id == team_id && (store.is_own() || store.members.contains(me)))
    }

    /// Whether the store `team_id` is one that this account joined (its list's active
    /// `join`), as the account file has it.
    pub fn joined_store_owner(&self, team_id: &str) -> Option<String> {
        self.state()
            .stores
            .iter()
            .find(|store| store.team_id == team_id && !store.is_own())
            .map(|store| store.owner.clone())
    }
}

/// A name of section 2 as the screens show it: trimmed, without control characters, at
/// most 64 bytes.
fn clean(text: &str) -> String {
    let mut name: String = text.trim().chars().filter(|c| !c.is_control()).collect();
    while name.len() > 64 {
        name.pop();
    }
    name
}

#[cfg(test)]
mod tests;
