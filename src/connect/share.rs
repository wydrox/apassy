//! A vault shared between the accounts of one family or team (contract connect-account-v1
//! section 16, ADR 0037 stage 7).
//!
//! **Authority.** The account that made a vault store is the authority for it. What it
//! says of other accounts are entries of its own signed device list ([`super::trust`]), in
//! the same chain as its `add` and `remove` entries: they share one order with the device
//! changes, and a removed device signs none of them. No role in a group carries trust: the
//! group view of Connect, the `shared` flag of a store, and the device rows of a store are
//! hints only. Which account made a store is Connect's word (no signed data names it):
//! this device takes a store as another account's only when its own list joined it from
//! that account, and never joins a store that its own list or this computer holds as its
//! own ([`ConnectAccount::join_shared_store`]).
//!
//! - `peer P R` pins the root `R` of the account `P`, after a ceremony with six words on a
//!   device of each account, once for each pair of accounts ([`ConnectAccount::start_share`]
//!   to [`ConnectAccount::accept_share`]). `unpeer P` ends it.
//! - `share P S`: the store `S` of this account syncs with the devices of `P`. `unshare P
//!   S` ends it.
//! - `join P S`: this account syncs the store `S` that `P` made. `leave P S` ends it.
//!
//! **The trust store.** The account file keeps a pin ([`PeerPin`]) for each pair of an
//! account and the list that named its root: `via` `None` for a root that this account
//! pinned itself with the words, `via` `A` for the root that the verified list of `A` names
//! for a co-member of a store of `A`. Each pin has its own list pin (version, head, devices,
//! keys that left). The file keeps, for each shared store ([`StoreShare`]): the account
//! that made it, its members, and the accounts whose share of it ended, all from the
//! verified list of the account that made it. [`store_signer_policy`] takes the signers of
//! a store from these alone, never from an answer of Connect: a root of `P` counts in `S`
//! only as the root that the owner of `S` named for `P` (or, for the owner itself and in
//! this account's own stores, the root that this account pinned with the words).
//!
//! **What a lying Connect can do.** It can withhold the newest entries of a list (an
//! `unshare`, a `remove`) from a device, give an old prefix to a new device, keep the
//! devices apart, or show a member outside the group (this device then ends the shares with
//! that member by itself: an end gives no one access). It cannot add a key, a member, or a
//! share: each needs a signature of a device of the list that made it, from a root that
//! this device pinned with the words. A served root other than the pinned one suspends that
//! pin here until the people compare new words.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::account::AccountState;
use super::client::{ConnectClient, GroupMember, StoreDevice};
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

/// The most active `peer` entries of a list, and so the most own pins of the account file
/// (pins that this account made with the words).
pub const MAX_PEERS: usize = 64;
/// The most pins through the owners of joined stores (co-members of those stores).
pub const MAX_VIA_PINS: usize = 256;
/// The most active `share` and `join` entries of a list together.
pub const MAX_SHARED: usize = 128;
/// The most devices of a peer that a pin keeps (more than the 10 live devices of a list).
pub const MAX_PEER_KNOWN: usize = 16;
/// The most keys of a peer that left, that a pin keeps (the oldest first out).
pub const MAX_PEER_LEFT: usize = 32;
/// The most shared stores that the account file keeps.
pub const MAX_STORES: usize = 192;
/// The most accounts whose share of one store ended, that the account file keeps (the
/// oldest end first out).
pub const MAX_ENDED: usize = 64;
/// The owner of a store that this account made, in [`StoreShare::owner`].
pub const OWNER_SELF: &str = "self";

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

/// Why the rules of section 16 refuse an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The entry does not follow the rules at this point of the list.
    Rule,
    /// It would pass a count: 64 peers, or 128 shares and joins together.
    Limit,
}

/// One store entry of a list (`share`, `unshare`, `join`, `leave`), in the order of the
/// list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOp {
    pub op: String,
    pub team: String,
    pub account: String,
    /// b64u of the device that signed it.
    pub by: String,
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
    /// Every store entry of the list, in its order: what ended, and who signed it.
    pub ops: Vec<StoreOp>,
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

    /// The accounts that had a share of `team` that ended (`unshare`) and have no active
    /// share of it now, in the order of their last `unshare`. Every device that verified
    /// this list computes the same.
    pub fn ended_of(&self, team: &str) -> Vec<String> {
        let members = self.members_of(team);
        let mut ended: Vec<String> = Vec::new();
        for op in self
            .ops
            .iter()
            .filter(|op| op.op == UNSHARE && op.team == team)
        {
            ended.retain(|held| *held != op.account);
            if !members.contains(&op.account) {
                ended.push(op.account.clone());
            }
        }
        ended
    }

    /// The account of the active join of `team`.
    pub fn owner_of(&self, team: &str) -> Option<&str> {
        self.joins
            .iter()
            .find(|(store, _)| store == team)
            .map(|(_, account)| account.as_str())
    }

    /// How many entries `op` of `team` for `account` the list holds.
    pub fn count(&self, op: &str, team: &str, account: &str) -> usize {
        self.ops
            .iter()
            .filter(|held| held.op == op && held.team == team && held.account == account)
            .count()
    }

    /// The last store entry of `team` for `account`.
    pub fn last_op(&self, team: &str, account: &str) -> Option<&StoreOp> {
        self.ops
            .iter()
            .rev()
            .find(|held| held.team == team && held.account == account)
    }

    /// Whether an active share or join names `account`.
    fn names(&self, account: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(_, held)| held == account)
    }

    /// Whether an active share or join names `team`.
    pub fn holds_store(&self, team: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(store, _)| store == team)
    }

    /// Whether the rules of section 16 allow the entry `entry` of the list of
    /// `account_id` at this point of the list:
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
    pub(super) fn check(&self, account_id: &str, entry: &ListEntry) -> Result<(), Refusal> {
        let peer = entry
            .account_id
            .as_deref()
            .filter(|id| valid_account_id(id))
            .ok_or(Refusal::Rule)?;
        if peer == account_id {
            return Err(Refusal::Rule);
        }
        let team = entry.team_id.as_deref();
        if team.is_some_and(|team| !valid_team_id(team)) {
            return Err(Refusal::Rule);
        }
        let is_peer = self.root_of(peer).is_some();
        let full = self.shares.len() + self.joins.len() >= MAX_SHARED;
        let rule = |ok: bool| if ok { Ok(()) } else { Err(Refusal::Rule) };
        match (entry.op.as_str(), team) {
            (PEER, None) => {
                entry.root.as_deref().and_then(point).ok_or(Refusal::Rule)?;
                rule(!is_peer)?;
                if self.peers.len() >= MAX_PEERS {
                    return Err(Refusal::Limit);
                }
                Ok(())
            }
            (UNPEER, None) => rule(is_peer && !self.names(peer)),
            (SHARE, Some(team)) => {
                let pair = (team.to_owned(), peer.to_owned());
                rule(
                    is_peer
                        && !self.joins.iter().any(|(store, _)| store == team)
                        && !self.shares.contains(&pair),
                )?;
                if full { Err(Refusal::Limit) } else { Ok(()) }
            }
            (JOIN, Some(team)) => {
                rule(is_peer && !self.holds_store(team))?;
                if full { Err(Refusal::Limit) } else { Ok(()) }
            }
            (UNSHARE, Some(team)) => {
                rule(self.shares.contains(&(team.to_owned(), peer.to_owned())))
            }
            (LEAVE, Some(team)) => rule(self.joins.contains(&(team.to_owned(), peer.to_owned()))),
            _ => Err(Refusal::Rule),
        }
    }

    /// Apply the entry `entry` of the list of `account_id` when [`Self::check`] allows it.
    pub(super) fn apply(&mut self, account_id: &str, entry: &ListEntry) -> Result<(), Refusal> {
        self.check(account_id, entry)?;
        let peer = entry.account_id.clone().unwrap_or_default();
        let team = entry.team_id.clone();
        match (entry.op.as_str(), team) {
            (PEER, None) => {
                let root = entry.root.as_deref().and_then(point).ok_or(Refusal::Rule)?;
                self.peers.push((peer, root));
            }
            (UNPEER, None) => self.peers.retain(|(held, _)| *held != peer),
            (op, Some(team)) => {
                let pair = (team.clone(), peer.clone());
                match op {
                    SHARE => self.shares.push(pair),
                    JOIN => self.joins.push(pair),
                    UNSHARE => self.shares.retain(|held| *held != pair),
                    _ => self.joins.retain(|held| *held != pair),
                }
                self.ops.push(StoreOp {
                    op: op.to_owned(),
                    team,
                    account: peer,
                    by: entry.by.clone(),
                });
            }
            _ => return Err(Refusal::Rule),
        }
        Ok(())
    }
}

// ---- The account file (section 16.5). ----

/// Another account in the trust store of this account, as one list names its root.
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
    /// The device name that the root signed in version 1 of its list (empty before the
    /// first list): the verified name that the owner checks show.
    #[serde(default)]
    pub name: String,
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
            name: String::new(),
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
            && (self.name.is_empty() || trust::valid_name(&self.name))
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
        bound_oldest(&mut self.left, MAX_PEER_LEFT);
        self.known = live.into_iter().take(MAX_PEER_KNOWN).collect();
        self.list_version = list.version;
        self.list_head = list.head().to_owned();
        self.name.clone_from(&list.root_name);
        *self != before
    }

    /// The list that named this account names another root now (after a reset and new
    /// words): the old devices and the keys that left stay as keys that left, the new root
    /// starts with no list.
    fn repin(&mut self, root: &[u8]) {
        let mut left: Vec<String> = std::mem::take(&mut self.left);
        for key in std::mem::take(&mut self.known) {
            if !left.contains(&key) {
                left.push(key);
            }
        }
        bound_oldest(&mut left, MAX_PEER_LEFT);
        *self = Self {
            left,
            ..Self::new(&self.account_id, root, self.via.as_deref())
        };
    }
}

/// Drop the oldest entries of `list` beyond `max`.
fn bound_oldest(list: &mut Vec<String>, max: usize) {
    if list.len() > max {
        let extra = list.len() - max;
        list.drain(..extra);
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
    /// The accounts whose share of this store ended in the owner's verified list (at most
    /// [`MAX_ENDED`], the oldest end first out). Their keys sign only the versions that
    /// this device had merged, and below a head of an accepted key.
    pub ended: Vec<String>,
}

impl StoreShare {
    fn is_valid(&self, account_id: &str) -> bool {
        valid_team_id(&self.team_id)
            && (self.owner == OWNER_SELF
                || (valid_account_id(&self.owner) && self.owner != account_id))
            && self.members.len() <= MAX_PEERS
            && self.ended.len() <= MAX_ENDED
            && self
                .members
                .iter()
                .chain(&self.ended)
                .all(|member| valid_account_id(member))
    }

    /// Whether this store is one that this account made.
    pub fn is_own(&self) -> bool {
        self.owner == OWNER_SELF
    }

    /// The `via` of the pins of the members of this store.
    fn via(&self) -> Option<&str> {
        (!self.is_own()).then_some(self.owner.as_str())
    }
}

/// Whether the peers and shared stores of an account file have their shape and bounds.
pub(super) fn valid_state(account_id: &str, peers: &[PeerPin], stores: &[StoreShare]) -> bool {
    let mut ids: Vec<(&str, Option<&str>)> = peers
        .iter()
        .map(|pin| (pin.account_id.as_str(), pin.via.as_deref()))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut teams: Vec<&str> = stores.iter().map(|store| store.team_id.as_str()).collect();
    teams.sort_unstable();
    teams.dedup();
    let own = peers.iter().filter(|pin| pin.via.is_none()).count();
    own <= MAX_PEERS
        && peers.len() - own <= MAX_VIA_PINS
        && ids.len() == peers.len()
        && peers
            .iter()
            .all(|pin| pin.is_valid() && pin.account_id != account_id)
        && peers
            .iter()
            .all(|pin| pin.via.as_deref() != Some(account_id))
        && stores.len() <= MAX_STORES
        && teams.len() == stores.len()
        && stores.iter().all(|store| store.is_valid(account_id))
}

fn pin_of<'a>(state: &'a AccountState, account: &str, via: Option<&str>) -> Option<&'a PeerPin> {
    state
        .peers
        .iter()
        .find(|pin| pin.account_id == account && pin.via.as_deref() == via)
}

fn pin_mut<'a>(
    state: &'a mut AccountState,
    account: &str,
    via: Option<&str>,
) -> Option<&'a mut PeerPin> {
    state
        .peers
        .iter_mut()
        .find(|pin| pin.account_id == account && pin.via.as_deref() == via)
}

/// Set the store `team` (made by `owner`) to `members` and `ended`, adding its entry when
/// it has none (the oldest store without members and without ends goes first when the
/// file is full).
fn set_store(
    state: &mut AccountState,
    team: &str,
    owner: &str,
    members: Vec<String>,
    mut ended: Vec<String>,
) {
    ended.retain(|account| !members.contains(account));
    bound_oldest(&mut ended, MAX_ENDED);
    if let Some(store) = state.stores.iter_mut().find(|store| store.team_id == team) {
        store.owner = owner.to_owned();
        store.members = members;
        store.ended = ended;
        return;
    }
    if state.stores.len() >= MAX_STORES {
        let at = state
            .stores
            .iter()
            .position(|store| store.members.is_empty() && store.ended.is_empty())
            .or_else(|| {
                state
                    .stores
                    .iter()
                    .position(|store| store.members.is_empty())
            })
            .unwrap_or(0);
        state.stores.remove(at);
    }
    state.stores.push(StoreShare {
        team_id: team.to_owned(),
        owner: owner.to_owned(),
        members,
        ended,
    });
}

/// Learn what this account's own verified list says of other accounts (`own`): its own
/// peers get a pin (a peer whose root the list pins anew keeps its old keys as keys that
/// left), the members and the ended accounts of each of its own shared stores are those
/// of its list, each store it joined has an entry (its members come from the list of its
/// owner, [`learn_lists`]), and a store it left has no members. Pins that no list and no
/// store needs go. Returns whether anything changed.
pub(super) fn learn_own(state: &mut AccountState, own: &ListShares) -> bool {
    let before = (state.peers.clone(), state.stores.clone());
    for (account, root) in &own.peers {
        let root_b64u = encode_b64u(root);
        match pin_mut(state, account, None) {
            Some(pin) if pin.root == root_b64u => {}
            Some(pin) => pin.repin(root),
            // At most 64 by the rules of the list ([`MAX_PEERS`]).
            None => state.peers.push(PeerPin::new(account, root, None)),
        }
    }
    // The own stores: every store that the list ever shared, and those of the file.
    let mut own_teams: Vec<String> = own
        .ops
        .iter()
        .filter(|op| op.op == SHARE || op.op == UNSHARE)
        .map(|op| op.team.clone())
        .chain(
            state
                .stores
                .iter()
                .filter(|store| store.is_own())
                .map(|store| store.team_id.clone()),
        )
        .collect();
    own_teams.sort();
    own_teams.dedup();
    for team in own_teams {
        if own.owner_of(&team).is_some() {
            continue;
        }
        set_store(
            state,
            &team,
            OWNER_SELF,
            own.members_of(&team),
            own.ended_of(&team),
        );
    }
    // The joined stores: an entry for each; its members come from its owner's list.
    for (team, owner) in &own.joins {
        let held = state
            .stores
            .iter()
            .any(|store| store.team_id == *team && store.owner == *owner);
        if !held {
            set_store(state, team, owner, Vec::new(), Vec::new());
        }
    }
    // A store that this list left (or never joined) has no members here.
    for store in state.stores.iter_mut().filter(|store| !store.is_own()) {
        if own.owner_of(&store.team_id) != Some(store.owner.as_str()) {
            store.members.clear();
        }
    }
    drop_unused_pins(state, own);
    (state.peers.clone(), state.stores.clone()) != before
}

/// Drop the pins that no list and no store needs: an own pin stays while the own list pins
/// it, or a store names its account (as the owner of a store that this account joined, or
/// as a member or an ended account of an own store); a pin through `A` stays while a store
/// of `A` names its account (as a member or an ended account).
fn drop_unused_pins(state: &mut AccountState, own: &ListShares) {
    let stores = state.stores.clone();
    state.peers.retain(|pin| match pin.via.as_deref() {
        None => {
            own.root_of(&pin.account_id).is_some()
                || stores.iter().any(|store| {
                    (!store.is_own() && store.owner == pin.account_id)
                        || (store.is_own()
                            && (store.members.contains(&pin.account_id)
                                || store.ended.contains(&pin.account_id)))
                })
        }
        Some(owner) => stores.iter().any(|store| {
            store.owner == owner
                && (store.members.contains(&pin.account_id)
                    || store.ended.contains(&pin.account_id))
        }),
    });
}

/// The lists verified within one refresh, by account and root (`None`: it did not verify).
type VerifiedLists = HashMap<(String, Vec<u8>), Option<Verified>>;

/// The lists verified within one refresh, by account and root: each list of a refresh is
/// checked once, also when several pins take it.
#[derive(Default)]
pub(super) struct ListCache(RefCell<VerifiedLists>);

impl ListCache {
    fn verify(
        &self,
        origin: &str,
        account: &str,
        root: &[u8],
        entries: &[ListEntry],
    ) -> Option<Verified> {
        self.0
            .borrow_mut()
            .entry((account.to_owned(), root.to_vec()))
            .or_insert_with(|| trust::verify_list(origin, account, root, entries))
            .clone()
    }
}

/// Take the list `entries` of the account of `pin` that Connect served: when it verifies
/// from the pinned root and goes on from the pin, the pin learns it; when its version 1 is
/// another key than the pinned root, the pin is suspended (its keys sign nothing new until
/// new words). Any other list changes nothing. Returns the verified list, if it counted,
/// and whether the pin changed.
fn take_peer_list(
    pin: &mut PeerPin,
    origin: &str,
    entries: &[ListEntry],
    cache: &ListCache,
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
    let Some(list) = cache
        .verify(origin, &pin.account_id, &root, entries)
        .filter(|list| pin.pin().is_none_or(|held| held.accepts(list)))
    else {
        return (None, false);
    };
    let changed = pin.learn(&list);
    (Some(list), changed)
}

/// What [`learn_lists`] found.
#[derive(Debug, Default)]
pub(super) struct Learned {
    /// The list of each account that verified from this account's own pin of it.
    pub own: BTreeMap<String, Verified>,
    /// Members of joined stores that got no pin: (store, account). The pins through owners
    /// are full ([`MAX_VIA_PINS`]); their keys sign nothing in that store.
    pub unpinned: Vec<(String, String)>,
}

/// Make sure of the pin of `member` through `owner` with `root` (the root that the verified
/// list of `owner` names for it): a pin with another root is pinned anew (its old keys stay
/// as keys that left). Returns whether the pin exists after it.
fn ensure_via_pin(state: &mut AccountState, member: &str, owner: &str, root: &[u8]) -> bool {
    let root_b64u = encode_b64u(root);
    match pin_mut(state, member, Some(owner)) {
        Some(pin) if pin.root == root_b64u => true,
        Some(pin) => {
            pin.repin(root);
            true
        }
        None => {
            let via = state.peers.iter().filter(|pin| pin.via.is_some()).count();
            if via >= MAX_VIA_PINS {
                return false;
            }
            state.peers.push(PeerPin::new(member, root, Some(owner)));
            true
        }
    }
}

/// Learn this account's own list (`own`) and the lists of other accounts that Connect
/// served (`served`, by account; an account that is missing keeps what it had): each own
/// pin takes the served list of its account; the members and the ended accounts of each
/// joined store come from the verified list of its owner, each with a pin through that
/// owner for the root that the owner's list names; each pin through an owner takes the
/// served list too. A pure function of the file and the lists: the tests and every device
/// compute the same.
pub(super) fn learn_lists(
    state: &mut AccountState,
    own: &ListShares,
    origin: &str,
    served: &BTreeMap<String, Vec<ListEntry>>,
    cache: &ListCache,
) -> Learned {
    learn_own(state, own);
    let mut learned = Learned::default();
    for pin in state.peers.iter_mut().filter(|pin| pin.via.is_none()) {
        if let Some(entries) = served.get(&pin.account_id)
            && let (Some(list), _) = take_peer_list(pin, origin, entries, cache)
        {
            learned.own.insert(pin.account_id.clone(), list);
        }
    }
    let me = state.account_id.clone();
    for (team, owner) in &own.joins {
        let Some(list) = learned.own.get(owner) else {
            // The owner's list did not verify in this round: the store keeps what it had.
            continue;
        };
        let mut members = Vec::new();
        for member in list.shares.members_of(team) {
            if member == me {
                members.push(member);
                continue;
            }
            let Some(root) = list.shares.root_of(&member).map(<[u8]>::to_vec) else {
                continue;
            };
            if ensure_via_pin(state, &member, owner, &root) {
                members.push(member);
            } else {
                learned.unpinned.push((team.clone(), member));
            }
        }
        let mut ended = Vec::new();
        for member in list.shares.ended_of(team) {
            if member == me {
                continue;
            }
            let pinned = match list.shares.root_of(&member).map(<[u8]>::to_vec) {
                Some(root) => ensure_via_pin(state, &member, owner, &root),
                None => pin_of(state, &member, Some(owner)).is_some(),
            };
            if pinned {
                ended.push(member);
            }
        }
        set_store(state, team, owner, members, ended);
    }
    for pin in state.peers.iter_mut().filter(|pin| pin.via.is_some()) {
        if let Some(entries) = served.get(&pin.account_id) {
            take_peer_list(pin, origin, entries, cache);
        }
    }
    drop_unused_pins(state, own);
    learned
}

/// The accounts whose lists a refresh reads: the accounts of every pin that [`learn_lists`]
/// keeps or makes with the lists served so far, and the owners of the joined stores.
pub(super) fn accounts_to_read(
    state: &AccountState,
    own: &ListShares,
    origin: &str,
    served: &BTreeMap<String, Vec<ListEntry>>,
    cache: &ListCache,
) -> Vec<String> {
    let mut trial = state.clone();
    learn_lists(&mut trial, own, origin, served, cache);
    let mut accounts: Vec<String> = trial
        .peers
        .iter()
        .map(|pin| pin.account_id.clone())
        .chain(own.joins.iter().map(|(_, owner)| owner.clone()))
        .collect();
    accounts.sort();
    accounts.dedup();
    accounts
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

/// The keys of `pin` into `accepted` (its devices, when `live` and it is not suspended) and
/// `left` (its keys that left; its devices when not live or suspended).
fn take_keys(pin: &PeerPin, live: bool, accepted: &mut Vec<Vec<u8>>, left: &mut Vec<Vec<u8>>) {
    if live && !pin.suspended {
        push_new(accepted, keys(&pin.known));
    } else {
        push_new(left, keys(&pin.known));
    }
    push_new(left, keys(&pin.left));
}

/// Which keys may sign the heads of the shared store `team_id`, from the account file
/// alone; `None` for a store that this account file holds no share of (the signers of the
/// account: `super::signer_policy`).
///
/// - A store that this account joined, made by `A`: the devices of `A` (its own pin), of
///   this account, and of each other member, each through the root that `A`'s list named
///   for it. When this account is not a member any more, the store has ended here: no key
///   signs a new version.
/// - A store of this account: its own devices and the devices of each member (its own
///   pins).
///
/// The devices of a suspended pin sign nothing new. The keys that left (this account's,
/// the owner's, each member's) and every key of an account whose share of the store ended
/// sign only up to the anchor of the store, and below a head of an accepted key. A key in
/// none of these lists signs nothing.
pub fn store_signer_policy(state: &AccountState, team_id: &str) -> Option<StoreSigners> {
    let store = state.stores.iter().find(|store| store.team_id == team_id)?;
    let mut accepted = keys(&state.known);
    let mut left = keys(&state.left);
    let via = store.via();
    if let Some(owner) = via
        && let Some(pin) = pin_of(state, owner, None)
    {
        take_keys(pin, true, &mut accepted, &mut left);
    }
    let me = state.account_id.as_str();
    for member in store.members.iter().filter(|member| *member != me) {
        if let Some(pin) = pin_of(state, member, via) {
            take_keys(pin, true, &mut accepted, &mut left);
        }
    }
    for member in store.ended.iter().filter(|member| *member != me) {
        if let Some(pin) = pin_of(state, member, via) {
            take_keys(pin, false, &mut accepted, &mut left);
        }
    }
    if !store.is_own() && !store.members.iter().any(|member| member == me) {
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

// ---- What the screens and the owner checks name. ----

/// The names that the screens and the owner checks show beside what this device verified:
/// the local name of each vault (from this computer's vault list; else the name that
/// Connect gives the store), and the name that Connect gives each person (a hint only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareNames {
    /// Store id → the vault name to show.
    pub vaults: BTreeMap<String, String>,
    /// Account id → the person's name at Connect.
    pub people: BTreeMap<String, String>,
}

impl ShareNames {
    /// The name to show for the store `team`.
    pub fn vault(&self, team: &str) -> String {
        self.vaults
            .get(team)
            .cloned()
            .unwrap_or_else(|| "this vault".to_owned())
    }

    /// The name that Connect gives `account`, or empty.
    pub fn hint(&self, account: &str) -> String {
        self.people.get(account).cloned().unwrap_or_default()
    }
}

/// A person of another account, as this device verified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub account_id: String,
    /// The device name that the root of the account's verified list signed; empty before
    /// this device verified a list of it.
    pub name: String,
    /// The short fingerprint of the root that this device pinned.
    pub fingerprint: String,
    /// The person's name at Connect: a hint beside the verified name.
    pub hint: String,
}

impl Person {
    /// The name that a row shows: the verified name, with the name at Connect beside it;
    /// never the account id.
    pub fn label(&self) -> String {
        label(&self.name, &self.hint)
    }
}

/// The verified `name` with the `hint` of Connect beside it.
pub fn label(name: &str, hint: &str) -> String {
    match (name.is_empty(), hint.is_empty()) {
        (false, true) => format!("\u{201c}{name}\u{201d}"),
        (false, false) if name == hint => format!("\u{201c}{name}\u{201d}"),
        (false, false) => format!("\u{201c}{name}\u{201d} ({hint})"),
        (true, false) => format!("{hint} (not verified yet)"),
        (true, true) => "a person of your family or team".to_owned(),
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

    /// When Connect ends the code (Connect checks its 600 s; this device shows the time).
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
    /// The person's name as Connect gives it (a hint).
    pub name: String,
    /// The name that the other account's list signed for its device.
    pub device_name: String,
    /// The name that the root of the other account's list signed.
    pub root_name: String,
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
            "{} ({}) asks to share vaults with you. Both devices show: {}.",
            label(&self.root_name, &self.name),
            self.device_name,
            self.words
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
    /// The person's name as Connect gives it (a hint).
    pub name: String,
    /// The name that the inviting list signed for the inviting device.
    pub device_name: String,
    /// The name that the root of the inviting list signed.
    pub root_name: String,
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
    /// The owner's verified name with its name at Connect ([`label`]).
    pub owner_name: String,
    /// The vault name, when Connect lists the store for this account (a hint).
    pub vault_name: Option<String>,
}

/// One member of a shared store of this account, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    pub account_id: String,
    /// The verified name with its name at Connect ([`label`]).
    pub name: String,
    /// The member's list holds its `join` of the store.
    pub joined: bool,
    /// The member's list did not verify from its pinned root (a reset account).
    pub suspended: bool,
    /// The member's verified list pins this account (its `peer` with this account's root):
    /// without it the member has not finished the words, and a new code is shown.
    pub accepted: bool,
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

/// What [`ConnectAccount::refresh_shares`] found, and what it signed by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareStatus {
    pub offers: Vec<ShareOffer>,
    pub stores: Vec<StoreStatus>,
    /// Peers whose list Connect gave from another root: they reset their account.
    pub suspended: Vec<String>,
    /// Peers that Connect shows outside the group of this account.
    pub outside_group: Vec<String>,
    /// The names that Connect gives the peers (hints).
    pub names: BTreeMap<String, String>,
    /// Each pinned person with the name that this device verified.
    pub people: BTreeMap<String, Person>,
    /// The stores that this account's list left: (store, the name of the device that
    /// signed the `leave`). The vault of such a store syncs no more on this device.
    pub left: Vec<(String, String)>,
    /// What this refresh signed by itself, in words: "<name> left this vault." and
    /// "Sharing with <name> ended: no longer in your family or team."
    pub notes: Vec<String>,
    /// The members of the group as Connect shows them; `None` when it gave no answer.
    pub group: Option<Vec<GroupMember>>,
    /// Members of joined stores that this device could not pin (the pins are full).
    pub unpinned: Vec<(String, String)>,
}

impl ShareStatus {
    /// The name of `account` as a row shows it: the verified name with the name at Connect
    /// beside it; never the account id.
    pub fn name_of(&self, account: &str) -> String {
        match self.people.get(account) {
            Some(person) => person.label(),
            None => label("", self.names.get(account).map_or("", String::as_str)),
        }
    }

    /// The names of the people, for the owner checks of the next steps ([`ShareNames`]).
    pub fn hints(&self) -> BTreeMap<String, String> {
        self.names.clone()
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

/// The entries of a new pin of `account` after its reset (unit C8): the ends of its old
/// root first, then the new `peer`, and the `share` of a store when one is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repin {
    /// The stores of this account shared with the old root, ended by `unshare`.
    pub unshares: Vec<String>,
    /// The stores of the old root that this account joined, ended by `leave`.
    pub leaves: Vec<String>,
    /// The short fingerprint of the old root.
    pub old_fingerprint: String,
}

impl Repin {
    /// How many entries the re-pin signs: the ends, the `unpeer`, the `peer`, and the
    /// `share` when `share` is true.
    fn entries(&self, share: bool) -> u64 {
        (self.unshares.len() + self.leaves.len() + 2 + usize::from(share)) as u64
    }
}

impl ConnectAccount {
    /// Sign the entry `op` of section 16 for `peer_account` (with `root` for a `peer` and
    /// the store `team_id` for a store op) after the head that this device verified, and
    /// append it with `POST /v1/account/list`. A `409` (the list moved) reads the list
    /// again and signs once more. A list that this device's own rules refuse the entry at
    /// is [`ConnectError::Conflict`] (over a count [`ConnectError::AccountLimit`]), and
    /// nothing is sent. On success this device pins the entry it signed.
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
            if version > trust::MAX_LIST as u64 || (adds(op) && version > trust::MAX_ADD_VERSION) {
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
                .map_err(|refusal| match refusal {
                    Refusal::Limit => ConnectError::AccountLimit,
                    Refusal::Rule => ConnectError::Conflict,
                })?;
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

    /// The list of the peer `account` from Connect, with the name and the device rows that
    /// Connect gives.
    fn read_peer(&mut self, account: &str) -> Result<PeerView, ConnectError> {
        let view = self.with_token(|client, token| client.peer_view(token, account))?;
        if view.account_id != account {
            return Err(ConnectError::BadAnswer);
        }
        Ok(view)
    }

    /// The own list's shares, from a fresh view whose list verified.
    fn own_shares(&mut self) -> Result<ListShares, ConnectError> {
        self.verified_view()?;
        self.verified_list()
            .map(|list| list.shares.clone())
            .ok_or(ConnectError::BadAnswer)
    }

    /// The verified name and the short root fingerprint of `account` as its pin through
    /// `via` holds it (empty without a pin).
    fn person(&self, account: &str, via: Option<&str>) -> (String, String) {
        pin_of(self.state(), account, via).map_or_else(Default::default, |pin| {
            (pin.name.clone(), key_fingerprint(&pin.root_key()))
        })
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

    /// Whether "Share with…" for `peer_account` needs a share code and the words: the
    /// account is not pinned here (or is suspended), or its verified list does not pin this
    /// account yet (the person did not finish the words; a new code lets them, and nothing
    /// is signed twice). `false`: one owner check shares without words.
    pub fn needs_share_code(&mut self, peer_account: &str) -> Result<bool, ConnectError> {
        if !self.is_pinned_peer(peer_account) {
            return Ok(true);
        }
        let view = self.read_peer(peer_account)?;
        let origin = self.client().origin().to_owned();
        let (me, my_root) = (self.state().account_id.clone(), self.root_key());
        let pin = pin_mut(self.state_mut(), peer_account, None).ok_or(ConnectError::NotVerified)?;
        let (list, changed) =
            take_peer_list(pin, &origin, &view.device_list, &ListCache::default());
        if changed {
            self.save_state()?;
        }
        let list = list.ok_or(ConnectError::NotVerified)?;
        Ok(list.shares.root_of(&me) != Some(my_root.as_slice()))
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
                    root_name: list.root_name.clone(),
                    public_key: key,
                    root,
                    words,
                    expires_at: join.expires_at,
                    list,
                })
            })
            .collect())
    }

    /// The re-pin that pinning `root` for `account` needs, when this account's own verified
    /// list pins another root for it (the other account was reset and the people compared
    /// new words); `None` when the list pins `root` already or pins nothing of `account`.
    pub fn repin_of(&self, account: &str, root: &[u8]) -> Option<Repin> {
        let own = &self.verified_list()?.shares;
        let held = own.root_of(account)?;
        if held == root {
            return None;
        }
        Some(Repin {
            unshares: own
                .shares
                .iter()
                .filter(|(_, member)| member == account)
                .map(|(team, _)| team.clone())
                .collect(),
            leaves: own
                .joins
                .iter()
                .filter(|(_, owner)| owner == account)
                .map(|(team, _)| team.clone())
                .collect(),
            old_fingerprint: key_fingerprint(held),
        })
    }

    /// The owner check of a re-pin of `account` with `root` and `words`, sharing `team`
    /// after it when one is named.
    #[allow(clippy::too_many_arguments)]
    fn repin_action(
        &self,
        account: &str,
        (root, root_name, hint): (&[u8], &str, &str),
        words: &str,
        repin: &Repin,
        team: Option<&str>,
        names: &ShareNames,
    ) -> OwnerAction {
        OwnerAction::RepinConnectPeer {
            account_id: self.state().account_id.clone(),
            peer_account: account.to_owned(),
            peer_name: root_name.to_owned(),
            peer_hint: hint.to_owned(),
            old_fingerprint: repin.old_fingerprint.clone(),
            fingerprint: key_fingerprint(root),
            words: words.to_owned(),
            ends: repin
                .unshares
                .iter()
                .chain(&repin.leaves)
                .map(|team| names.vault(team))
                .collect(),
            team_id: team.map(str::to_owned),
            vault_name: team.map(|team| names.vault(team)),
        }
    }

    /// The owner action of the confirmation of `request` for the store of `link`: a share
    /// with the words, or a re-pin of an account that was reset (which says which shares
    /// end, and shares the store after it).
    pub fn share_action(
        &self,
        link: &ShareLink,
        request: &ShareRequest,
        names: &ShareNames,
    ) -> OwnerAction {
        if let Some(repin) = self.repin_of(&request.account_id, &request.root) {
            return self.repin_action(
                &request.account_id,
                (&request.root, &request.root_name, &request.name),
                &request.words,
                &repin,
                Some(&link.team_id),
                names,
            );
        }
        OwnerAction::ShareConnectVault {
            account_id: self.state().account_id.clone(),
            peer_account: request.account_id.clone(),
            peer_name: request.root_name.clone(),
            peer_hint: request.name.clone(),
            fingerprint: key_fingerprint(&request.root),
            team_id: link.team_id.clone(),
            vault_name: names.vault(&link.team_id),
            words: request.words.clone(),
        }
    }

    /// "Confirm" of a share after a fresh owner check for [`Self::share_action`] in the
    /// vault session `epoch`: the words are computed again from the code and the keys
    /// (another request is [`ConnectError::WordsMismatch`], nothing is signed); this device
    /// signs `peer` for the other account's root (unless this account pinned that root
    /// already; after a reset, under the re-pin's own check, the ends of the old root
    /// first) and `share` of the store, pins the other account with the list that it
    /// verified, and adds that account's verified devices to the store. The proof is used
    /// up, also when the call fails.
    pub fn confirm_share(
        &mut self,
        link: &ShareLink,
        request: &ShareRequest,
        names: &ShareNames,
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
            .check(&self.share_action(link, request, names), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.pin_peer(
            &request.account_id,
            &request.root,
            &request.list,
            Some(&link.team_id),
        )?;
        self.share_store_with(&link.team_id, &request.account_id)
    }

    /// The owner action of a share of the store `team_id` with the pinned peer
    /// `peer_account`, without new words.
    pub fn share_again_action(
        &self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
    ) -> OwnerAction {
        let (name, fingerprint) = self.person(peer_account, None);
        OwnerAction::ShareConnectVault {
            account_id: self.state().account_id.clone(),
            peer_account: peer_account.to_owned(),
            peer_name: name,
            peer_hint: names.hint(peer_account),
            fingerprint,
            team_id: team_id.to_owned(),
            vault_name: names.vault(team_id),
            words: String::new(),
        }
    }

    /// Share the store `team_id` with `peer_account`, whose root this account pinned
    /// already and whose list pins this account (a pair of accounts compares words once),
    /// after a fresh owner check for [`Self::share_again_action`]. A peer that is not
    /// pinned here, or is suspended, is [`ConnectError::NotVerified`], and nothing is
    /// signed.
    pub fn share_again(
        &mut self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<ShareConfirmed, ConnectError> {
        proof
            .check(
                &self.share_again_action(team_id, peer_account, names),
                epoch,
            )
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        if self.is_own_store_of_other(team_id) {
            return Err(ConnectError::Invalid);
        }
        if !self.is_pinned_peer(peer_account) {
            return Err(ConnectError::NotVerified);
        }
        self.share_store_with(team_id, peer_account)
    }

    /// Whether this account pinned `peer_account` itself and its list verifies: a share
    /// with it needs no words.
    pub fn is_pinned_peer(&self, peer_account: &str) -> bool {
        pin_of(self.state(), peer_account, None)
            .is_some_and(|pin| !pin.suspended && pin.list_version > 0)
    }

    /// Whether `team_id` is a store that this account joined from another account (its
    /// file holds it as another's): it shares no such store.
    fn is_own_store_of_other(&self, team_id: &str) -> bool {
        self.state()
            .stores
            .iter()
            .any(|store| store.team_id == team_id && !store.is_own())
    }

    /// Sign `peer` for `root` of `account` unless this account's list pins it already
    /// (after a reset: the re-pin, which checks the room for all of its entries first), and
    /// pin `list` (verified from that root) in the account file. `share` is the store that
    /// the re-pin shares after it, for its room.
    fn pin_peer(
        &mut self,
        account: &str,
        root: &[u8],
        list: &Verified,
        share: Option<&str>,
    ) -> Result<(), ConnectError> {
        let own = self.own_shares()?;
        match own.root_of(account) {
            Some(held) if held == root => {}
            Some(_) => {
                let repin = self
                    .repin_of(account, root)
                    .ok_or(ConnectError::BadAnswer)?;
                // The room for the whole sequence before its first entry: the `peer` and
                // a `share` after it are adding entries.
                let head = self.state().list_version;
                let last = head + repin.entries(share.is_some());
                if last > trust::MAX_ADD_VERSION || last > trust::MAX_LIST as u64 {
                    return Err(ConnectError::AccountLimit);
                }
                for team in &repin.unshares {
                    self.share_entry(UNSHARE, account, None, Some(team))?;
                }
                for team in &repin.leaves {
                    self.share_entry(LEAVE, account, None, Some(team))?;
                }
                self.share_entry(UNPEER, account, None, None)?;
                self.share_entry(PEER, account, Some(root), None)?;
            }
            None => self.share_entry(PEER, account, Some(root), None)?,
        }
        let state = self.state_mut();
        let pin = match pin_mut(state, account, None) {
            Some(pin) => pin,
            None => {
                state.peers.push(PeerPin::new(account, root, None));
                state.peers.last_mut().ok_or(ConnectError::Local)?
            }
        };
        if pin.root != encode_b64u(root) {
            pin.repin(root);
        }
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
        let own = self.own_shares()?;
        if !own
            .shares
            .contains(&(team_id.to_owned(), peer_account.to_owned()))
        {
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
        let pin = pin_mut(self.state_mut(), peer_account, None).ok_or(ConnectError::NotVerified)?;
        let (list, _) = take_peer_list(pin, &origin, &view.device_list, &ListCache::default());
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
        Ok(SharePeerJoin {
            join_id: answer.join_id,
            account_id: code.account_id().to_owned(),
            name: clean(&answer.inviter.name),
            device_name: list.name_of(&key).unwrap_or_default().to_owned(),
            root_name: list.root_name.clone(),
            root,
            inviter_key: key,
            words,
            expires_at: answer.expires_at,
            list,
            code,
        })
    }

    /// The owner action of "The Words Match" for `join`: an accept, or a re-pin of an
    /// account that was reset (which says which shares and joins end).
    pub fn accept_action(&self, join: &SharePeerJoin, names: &ShareNames) -> OwnerAction {
        if let Some(repin) = self.repin_of(&join.account_id, &join.root) {
            return self.repin_action(
                &join.account_id,
                (&join.root, &join.root_name, &join.name),
                &join.words,
                &repin,
                None,
                names,
            );
        }
        OwnerAction::AcceptConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: join.account_id.clone(),
            peer_name: join.root_name.clone(),
            peer_hint: join.name.clone(),
            fingerprint: key_fingerprint(&join.root),
            words: join.words.clone(),
        }
    }

    /// "The Words Match" after a fresh owner check for [`Self::accept_action`]: the words
    /// are computed again (another set is [`ConnectError::WordsMismatch`]); this device
    /// signs `peer` for the inviting account's root and pins its verified list. Its shared
    /// stores then show in [`Self::refresh_shares`] as offers. The proof is used up.
    pub fn accept_share(
        &mut self,
        join: &SharePeerJoin,
        names: &ShareNames,
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
            .check(&self.accept_action(join, names), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.pin_peer(&join.account_id, &join.root, &join.list, None)
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

    /// Read the own list and the lists of the peers, of the accounts whose stores this
    /// account joined, and of their co-members, and learn them ([`learn_lists`], section
    /// 16.6). `local_teams` are the stores that this computer's vaults sync: none of them is
    /// offered. Then the ends that this device signs by itself, without an owner check
    /// (an end gives no one access, so a lying Connect can cause one, never a grant), at
    /// most one entry for each share:
    ///
    /// - a member whose verified list left a store of this account (more `leave`s of it
    ///   than this list's `unshare`s for it, and no active `join`): `unshare`, "<name> left
    ///   this vault.";
    /// - a member that Connect shows outside the group (or this account in none): `unshare`
    ///   of each share with it, "Sharing with <name> ended: no longer in your family or
    ///   team."
    ///
    /// Writes the account file when the trust store changed. A peer list that Connect does
    /// not give, or that does not verify, changes nothing of it.
    pub fn refresh_shares(&mut self, local_teams: &[String]) -> Result<ShareStatus, ConnectError> {
        let own = self.own_shares()?;
        let origin = self.client().origin().to_owned();
        let mut status = ShareStatus::default();
        let cache = ListCache::default();
        let mut served: BTreeMap<String, Vec<ListEntry>> = BTreeMap::new();
        let mut tried: BTreeSet<String> = BTreeSet::new();
        // The own peers and the owners first, then the co-members that the owners name.
        for _ in 0..4 {
            let wanted = accounts_to_read(self.state(), &own, &origin, &served, &cache);
            let missing: Vec<String> = wanted
                .into_iter()
                .filter(|account| !tried.contains(account))
                .collect();
            if missing.is_empty() {
                break;
            }
            for account in missing {
                tried.insert(account.clone());
                match self.read_peer(&account) {
                    Ok(view) => {
                        status.names.insert(account.clone(), clean(&view.name));
                        served.insert(account, view.device_list);
                    }
                    Err(
                        ConnectError::NotInGroup | ConnectError::NotFound | ConnectError::Forbidden,
                    ) => status.outside_group.push(account),
                    Err(error @ (ConnectError::Revoked | ConnectError::SignedOut)) => {
                        return Err(error);
                    }
                    Err(_) => {}
                }
            }
        }
        let before = self.state().clone();
        let learned = learn_lists(self.state_mut(), &own, &origin, &served, &cache);
        if *self.state() != before {
            self.save_state()?;
        }
        status.unpinned.clone_from(&learned.unpinned);
        let group = self.group().ok();
        status.group = group.as_ref().map(|group| {
            group
                .as_ref()
                .map(|g| g.members.clone())
                .unwrap_or_default()
        });
        let own = self.end_by_itself(&own, &learned, group.as_ref(), &mut status)?;
        self.fill_status(&own, &learned, local_teams, &mut status);
        Ok(status)
    }

    /// The ends of [`Self::refresh_shares`] that this device signs by itself. Returns the
    /// own list's shares after them.
    fn end_by_itself(
        &mut self,
        own: &ListShares,
        learned: &Learned,
        group: Option<&Option<super::GroupDetail>>,
        status: &mut ShareStatus,
    ) -> Result<ListShares, ConnectError> {
        let me = self.state().account_id.clone();
        let mut ends: Vec<(String, String, bool)> = Vec::new();
        for (team, member) in &own.shares {
            if let Some(group) = group {
                let active = |account: &str| {
                    group.as_ref().is_some_and(|group| {
                        group
                            .members
                            .iter()
                            .any(|held| held.account_id == account && held.state == "active")
                    })
                };
                if !active(&me) || !active(member) {
                    ends.push((team.clone(), member.clone(), false));
                    continue;
                }
            }
            if let Some(list) = learned.own.get(member) {
                let joined = list.shares.owner_of(team) == Some(me.as_str());
                let leaves = list.shares.count(LEAVE, team, &me);
                if !joined && leaves > own.count(UNSHARE, team, member) {
                    ends.push((team.clone(), member.clone(), true));
                }
            }
        }
        if ends.is_empty() {
            return Ok(own.clone());
        }
        for (team, member, left) in ends {
            match self.share_entry(UNSHARE, &member, None, Some(&team)) {
                Ok(()) => {
                    let name = status_name(self.state(), &status.names, &member);
                    status.notes.push(if left {
                        format!("{name} left this vault.")
                    } else {
                        format!("Sharing with {name} ended: no longer in your family or team.")
                    });
                }
                // Another device of this account ended it first.
                Err(ConnectError::Conflict) => {}
                Err(error @ (ConnectError::Revoked | ConnectError::SignedOut)) => {
                    return Err(error);
                }
                Err(_) => {}
            }
        }
        self.own_shares()
    }

    /// The parts of the status that the screens show.
    fn fill_status(
        &self,
        own: &ListShares,
        learned: &Learned,
        local_teams: &[String],
        status: &mut ShareStatus,
    ) {
        let me = self.state().account_id.clone();
        let my_root = self.root_key();
        for pin in &self.state().peers {
            status
                .people
                .entry(pin.account_id.clone())
                .or_insert_with(|| Person {
                    account_id: pin.account_id.clone(),
                    name: pin.name.clone(),
                    fingerprint: key_fingerprint(&pin.root_key()),
                    hint: status
                        .names
                        .get(&pin.account_id)
                        .cloned()
                        .unwrap_or_default(),
                });
            if pin.via.is_none() && pin.suspended {
                status.suspended.push(pin.account_id.clone());
            }
        }
        // The stores that this list left: the last entry of the store for its owner is a
        // `leave`, and no join is active.
        let own_list = self.verified_list();
        for op in &own.ops {
            if op.op != LEAVE
                || own.owner_of(&op.team).is_some()
                || own.last_op(&op.team, &op.account) != Some(op)
                || status.left.iter().any(|(team, _)| *team == op.team)
            {
                continue;
            }
            let device = point(&op.by)
                .and_then(|key| own_list.and_then(|list| list.name_of(&key)))
                .map_or_else(|| "another device".to_owned(), str::to_owned);
            status.left.push((op.team.clone(), device));
        }
        for (account, list) in &learned.own {
            for (team, member) in &list.shares.shares {
                let answered =
                    own.count(LEAVE, team, account) <= list.shares.count(UNSHARE, team, &me);
                if *member == me
                    && answered
                    && own.owner_of(team) != Some(account.as_str())
                    && !own.holds_store(team)
                    && !local_teams.contains(team)
                    && !self.is_own_store(team)
                {
                    status.offers.push(ShareOffer {
                        team_id: team.clone(),
                        owner: account.clone(),
                        owner_name: status.name_of(account),
                        vault_name: None,
                    });
                }
            }
        }
        for store in &self.state().stores {
            let via = store.via();
            let members = store
                .members
                .iter()
                .filter(|member| **member != me)
                .map(|member| {
                    let list = if via.is_none() {
                        learned.own.get(member)
                    } else {
                        None
                    };
                    MemberStatus {
                        account_id: member.clone(),
                        name: status.name_of(member),
                        joined: list.is_some_and(|list| {
                            list.shares.owner_of(&store.team_id) == Some(me.as_str())
                        }),
                        suspended: pin_of(self.state(), member, via)
                            .is_some_and(|pin| pin.suspended),
                        accepted: list.is_some_and(|list| {
                            list.shares.root_of(&me) == Some(my_root.as_slice())
                        }),
                    }
                })
                .collect();
            let owner = (!store.is_own()).then(|| store.owner.clone());
            status.stores.push(StoreStatus {
                team_id: store.team_id.clone(),
                owner_name: owner.as_deref().map(|owner| status.name_of(owner)),
                owner_suspended: owner
                    .as_deref()
                    .and_then(|owner| pin_of(self.state(), owner, None))
                    .is_some_and(|pin| pin.suspended),
                ended: owner.is_some() && !store.members.contains(&me),
                owner,
                members,
            });
        }
    }

    /// Whether the store `team_id` is one of this account: its file holds it as its own,
    /// or its verified list shares it.
    fn is_own_store(&self, team_id: &str) -> bool {
        self.state()
            .stores
            .iter()
            .any(|store| store.team_id == team_id && store.is_own())
            || self
                .verified_list()
                .is_some_and(|list| list.shares.shares.iter().any(|(team, _)| team == team_id))
    }

    /// The owner action of "Join" of the store `team_id` of `owner`.
    pub fn join_action(&self, team_id: &str, owner: &str, names: &ShareNames) -> OwnerAction {
        let (name, fingerprint) = self.person(owner, None);
        OwnerAction::JoinConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: owner.to_owned(),
            peer_name: name,
            peer_hint: names.hint(owner),
            fingerprint,
            team_id: team_id.to_owned(),
            vault_name: names.vault(team_id),
        }
    }

    /// "Join" of an offer after a fresh owner check for [`Self::join_action`]: this device
    /// signs `join` of the store `team_id` of `owner`, a peer that this account pinned,
    /// whose verified list shares the store with this account now. A store that this
    /// account holds as its own (its file, its own list, or `local_teams`: the stores that
    /// this computer's vaults sync) is [`ConnectError::Invalid`], and nothing is signed.
    /// Then the store's copy is downloaded with its passphrase
    /// (`RelaySync::joined_from_store`).
    pub fn join_shared_store(
        &mut self,
        team_id: &str,
        owner: &str,
        local_teams: &[String],
        names: &ShareNames,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        if local_teams.iter().any(|team| team == team_id) || self.is_own_store(team_id) {
            return Err(ConnectError::Invalid);
        }
        if !self.is_pinned_peer(owner) {
            return Err(ConnectError::NotVerified);
        }
        proof
            .check(&self.join_action(team_id, owner, names), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let own = self.own_shares()?;
        if self.is_own_store(team_id) || own.holds_store(team_id) {
            return Err(ConnectError::Invalid);
        }
        let view = self.read_peer(owner)?;
        let origin = self.client().origin().to_owned();
        let me = self.state().account_id.clone();
        let pin = pin_mut(self.state_mut(), owner, None).ok_or(ConnectError::NotVerified)?;
        let (list, changed) =
            take_peer_list(pin, &origin, &view.device_list, &ListCache::default());
        if changed {
            self.save_state()?;
        }
        let list = list.ok_or(ConnectError::NotVerified)?;
        let offered = list.shares.members_of(team_id).contains(&me)
            && own.count(LEAVE, team_id, owner) <= list.shares.count(UNSHARE, team_id, &me);
        if !offered {
            return Err(ConnectError::NotVerified);
        }
        self.share_entry(JOIN, owner, None, Some(team_id))?;
        // The members of the joined store come from the owner's list that was read now
        // (the co-members' lists at the next refresh).
        let own = self.own_shares()?;
        let served = BTreeMap::from([(owner.to_owned(), view.device_list)]);
        let before = self.state().clone();
        learn_lists(
            self.state_mut(),
            &own,
            &origin,
            &served,
            &ListCache::default(),
        );
        if *self.state() != before {
            self.save_state()?;
        }
        Ok(())
    }

    /// The owner action of the end of a share: the owner's "Stop Sharing with <name>…"
    /// (`leave` false) or a member's "Leave This Shared Vault…" (`leave` true).
    pub fn end_share_action(
        &self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
        leave: bool,
    ) -> OwnerAction {
        let (name, fingerprint) = self.person(peer_account, None);
        OwnerAction::EndConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: peer_account.to_owned(),
            peer_name: name,
            peer_hint: names.hint(peer_account),
            fingerprint,
            team_id: team_id.to_owned(),
            vault_name: names.vault(team_id),
            leave,
        }
    }

    /// "Stop Sharing with <name>…": this device signs `unshare` of the store `team_id` for
    /// `peer_account` after a fresh owner check for [`Self::end_share_action`], and
    /// Connect removes that account's devices from the store in the same step. (The ends
    /// without an owner check are [`Self::refresh_shares`]'s.) The pin of the peer stays:
    /// sharing again needs no words.
    pub fn stop_sharing(
        &mut self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        proof
            .check(
                &self.end_share_action(team_id, peer_account, names, false),
                epoch,
            )
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.share_entry(UNSHARE, peer_account, None, Some(team_id))
    }

    /// "Leave This Shared Vault…": this device signs `leave` of the store `team_id` of
    /// `owner` after a fresh owner check for [`Self::end_share_action`]; Connect removes
    /// this account's devices from the store in the same step. The vault stays on this
    /// device; its sync with the store ends here, and on the other devices of this account
    /// when they read the `leave` ([`ShareStatus::left`]).
    pub fn leave_shared_store(
        &mut self,
        team_id: &str,
        owner: &str,
        names: &ShareNames,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        proof
            .check(&self.end_share_action(team_id, owner, names, true), epoch)
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

/// The name of `account` for a note of a refresh: its verified name with its name at
/// Connect.
fn status_name(state: &AccountState, names: &BTreeMap<String, String>, account: &str) -> String {
    let verified = pin_of(state, account, None).map_or("", |pin| pin.name.as_str());
    label(verified, names.get(account).map_or("", String::as_str))
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
