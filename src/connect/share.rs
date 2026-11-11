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
use crate::broker::approvals::{OwnerAction, OwnerProof, ShareEntry};
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
/// "This account made the vault store S": the only entry of section 16 that names no
/// other account. A `share` of S comes only after it, and the account never joins S.
pub const STORE: &str = "store";

/// Whether `op` is an entry of section 16 (it names another account, or a store that
/// this account made).
pub fn is_share_op(op: &str) -> bool {
    matches!(op, PEER | UNPEER | SHARE | UNSHARE | JOIN | LEAVE | STORE)
}

/// Whether the entry `op` adds something (an `add`, a `peer`, a `share`, a `join`, a
/// `store`): it comes only while the list has room to end everything
/// (`trust::MAX_ADD_VERSION`). A `store` never needs an end, so it takes no room of the
/// ends.
pub fn adds(op: &str) -> bool {
    matches!(op, "add" | PEER | SHARE | JOIN | STORE)
}

/// Whether `op` names a store.
fn names_store(op: &str) -> bool {
    matches!(op, SHARE | UNSHARE | JOIN | LEAVE | STORE)
}

/// The message of `entry` as version `version` of the list of `account_id` at `origin`,
/// after the entry with the list hash `previous`: `None` when the entry has fields that
/// its op does not take (a key, a link, a name; an account on a `store`, or none on
/// another op; a root field other than the root of a `peer` or the list hash of the
/// `share` that a `join` answers; a store other than on a store op).
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
    let peer = match (entry.op.as_str(), entry.account_id.as_deref()) {
        (STORE, None) => LIST_NONE,
        (STORE, Some(_)) | (_, None) => return None,
        (_, Some(peer)) => peer,
    };
    let root = entry.root.as_deref();
    let team = entry.team_id.as_deref();
    let root_fits = match entry.op.as_str() {
        PEER => root.is_some(),
        // A `join` names the share that it answers (a join written before this rule has
        // none: it verifies, and counts for nothing).
        JOIN => root.is_none_or(valid_list_hash),
        _ => root.is_none(),
    };
    if !root_fits || names_store(&entry.op) != team.is_some() {
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
    /// The `share` that the entry is about, by the list hash of its entry in the list of
    /// the account that made the store: a `share` names itself, an `unshare` the share
    /// that it ended, a `join` the share that it answers, a `leave` the share of the join
    /// that it ended (`None` for a join without one and for the end of such a join).
    pub share: Option<String>,
}

/// What a device list says of other accounts at a version: the rules of section 16.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListShares {
    /// The active peers: the account and the root (X9.63) that its `peer` pinned, in the
    /// order of the entries.
    pub peers: Vec<(String, Vec<u8>)>,
    /// The vault stores that this account made (its `store` entries), in their order.
    pub stores: Vec<String>,
    /// The active shares: (store, account). A share counts only for a store of
    /// [`Self::stores`] ([`Self::members_of`]).
    pub shares: Vec<(String, String)>,
    /// The active joins: (store, account that made it), one for each pair.
    pub joins: Vec<(String, String)>,
    /// Every store entry of the list, in its order: what ended, who signed it, and which
    /// share each one is about.
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

    /// Whether this account made the store `team` (its list holds `store team`).
    pub fn made(&self, team: &str) -> bool {
        self.stores.iter().any(|store| store == team)
    }

    /// The accounts that the active shares of `team` name, when this account made `team`
    /// (a share before the `store` entry counts for nothing until the list holds it).
    pub fn members_of(&self, team: &str) -> Vec<String> {
        if !self.made(team) {
            return Vec::new();
        }
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

    /// The last store entry `op` of `team` for `account`.
    fn last(&self, op: &str, team: &str, account: &str) -> Option<&StoreOp> {
        self.ops
            .iter()
            .rev()
            .find(|held| held.op == op && held.team == team && held.account == account)
    }

    /// The list hash of the active `share` of `team` with `account`, when this account
    /// made `team`: the share that a join of `account` must name.
    pub fn share_hash(&self, team: &str, account: &str) -> Option<&str> {
        if !self.made(team)
            || !self
                .shares
                .iter()
                .any(|(store, held)| store == team && held == account)
        {
            return None;
        }
        self.last(SHARE, team, account)
            .and_then(|op| op.share.as_deref())
    }

    /// The share that the active join of `team` from `owner` answers.
    pub fn join_share(&self, team: &str, owner: &str) -> Option<&str> {
        if !self
            .joins
            .iter()
            .any(|(store, held)| store == team && held == owner)
        {
            return None;
        }
        self.last(JOIN, team, owner)
            .and_then(|op| op.share.as_deref())
    }

    /// Whether this list left the share `share` of `team` from `owner`: a `leave` ended a
    /// join that answered it. That share is not joined again; a new `share` is.
    pub fn left_share(&self, team: &str, owner: &str, share: &str) -> bool {
        self.ops.iter().any(|held| {
            held.op == LEAVE
                && held.team == team
                && held.account == owner
                && held.share.as_deref() == Some(share)
        })
    }

    /// Whether an active share or join names `account`.
    fn names(&self, account: &str) -> bool {
        self.shares
            .iter()
            .chain(&self.joins)
            .any(|(_, held)| held == account)
    }

    /// Whether an active share or join names `team`, or this account made it.
    pub fn holds_store(&self, team: &str) -> bool {
        self.made(team)
            || self
                .shares
                .iter()
                .chain(&self.joins)
                .any(|(store, _)| store == team)
    }

    /// Whether the rules of section 16 allow the entry `entry` of the list of
    /// `account_id` at this point of the list:
    ///
    /// - `store S`: no account; this list holds no `store S` and no active join of S.
    /// - `peer P R`: `P` is another account, not a peer already; `R` is a point; at most
    ///   [`MAX_PEERS`] peers.
    /// - `unpeer P`: `P` is a peer, and no active share or join names it.
    /// - `share P S`: `P` is a peer; `S` is in no active join of this list (a store this
    ///   account joined is not its own); `(S, P)` is not active. (Signing one also needs
    ///   `store S` before it: [`ConnectAccount`] checks that.)
    /// - `join P S h`: `P` is a peer; this list holds no `store S`, no active share of S,
    ///   and no active join of S from another account; `h` is the list hash of the share
    ///   that it answers. An active join of `(S, P)` that names another share is replaced
    ///   (one join for each pair); the same share is not joined twice.
    /// - `unshare P S`, `leave P S`: active.
    ///
    /// At most [`MAX_SHARED`] active shares and joins together.
    pub(super) fn check(&self, account_id: &str, entry: &ListEntry) -> Result<(), Refusal> {
        let team = entry.team_id.as_deref();
        if team.is_some_and(|team| !valid_team_id(team)) {
            return Err(Refusal::Rule);
        }
        let rule = |ok: bool| if ok { Ok(()) } else { Err(Refusal::Rule) };
        if entry.op == STORE {
            let team = team.ok_or(Refusal::Rule)?;
            return rule(
                entry.account_id.is_none()
                    && entry.root.is_none()
                    && !self.made(team)
                    && !self.joins.iter().any(|(store, _)| store == team),
            );
        }
        let peer = entry
            .account_id
            .as_deref()
            .filter(|id| valid_account_id(id))
            .ok_or(Refusal::Rule)?;
        if peer == account_id {
            return Err(Refusal::Rule);
        }
        let is_peer = self.root_of(peer).is_some();
        let full = self.shares.len() + self.joins.len() >= MAX_SHARED;
        match (entry.op.as_str(), team) {
            (PEER, None) => {
                entry.root.as_deref().and_then(point).ok_or(Refusal::Rule)?;
                rule(!is_peer)?;
                if self.peers.len() >= MAX_PEERS {
                    return Err(Refusal::Limit);
                }
                Ok(())
            }
            (UNPEER, None) => rule(entry.root.is_none() && is_peer && !self.names(peer)),
            (SHARE, Some(team)) => {
                let pair = (team.to_owned(), peer.to_owned());
                rule(
                    entry.root.is_none()
                        && is_peer
                        && !self.joins.iter().any(|(store, _)| store == team)
                        && !self.shares.contains(&pair),
                )?;
                if full { Err(Refusal::Limit) } else { Ok(()) }
            }
            (JOIN, Some(team)) => {
                let share = entry.root.as_deref();
                rule(
                    share.is_none_or(valid_list_hash)
                        && is_peer
                        && !self.made(team)
                        && !self.shares.iter().any(|(store, _)| store == team),
                )?;
                match self.owner_of(team) {
                    // A join of a newer share of the same owner replaces the one before.
                    Some(owner) => rule(
                        owner == peer && share.is_some() && self.join_share(team, peer) != share,
                    ),
                    None if full => Err(Refusal::Limit),
                    None => Ok(()),
                }
            }
            (UNSHARE, Some(team)) => rule(
                entry.root.is_none() && self.shares.contains(&(team.to_owned(), peer.to_owned())),
            ),
            (LEAVE, Some(team)) => rule(
                entry.root.is_none() && self.joins.contains(&(team.to_owned(), peer.to_owned())),
            ),
            _ => Err(Refusal::Rule),
        }
    }

    /// Apply the entry `entry` of the list of `account_id`, whose list hash is `hash`,
    /// when [`Self::check`] allows it.
    pub(super) fn apply(
        &mut self,
        account_id: &str,
        entry: &ListEntry,
        hash: &str,
    ) -> Result<(), Refusal> {
        self.check(account_id, entry)?;
        let peer = entry.account_id.clone().unwrap_or_default();
        let team = entry.team_id.clone();
        match (entry.op.as_str(), team) {
            (STORE, Some(team)) => self.stores.push(team),
            (PEER, None) => {
                let root = entry.root.as_deref().and_then(point).ok_or(Refusal::Rule)?;
                self.peers.push((peer, root));
            }
            (UNPEER, None) => self.peers.retain(|(held, _)| *held != peer),
            (op, Some(team)) => {
                let pair = (team.clone(), peer.clone());
                let share = match op {
                    SHARE => {
                        self.shares.push(pair);
                        Some(hash.to_owned())
                    }
                    JOIN => {
                        if !self.joins.contains(&pair) {
                            self.joins.push(pair);
                        }
                        entry.root.clone()
                    }
                    UNSHARE => {
                        let ended = self.share_hash_any(&team, &peer);
                        self.shares.retain(|held| *held != pair);
                        ended
                    }
                    _ => {
                        let ended = self.join_share(&team, &peer).map(str::to_owned);
                        self.joins.retain(|held| *held != pair);
                        ended
                    }
                };
                self.ops.push(StoreOp {
                    op: op.to_owned(),
                    team,
                    account: peer,
                    by: entry.by.clone(),
                    share,
                });
            }
            _ => return Err(Refusal::Rule),
        }
        Ok(())
    }

    /// The list hash of the active share of `(team, account)`, also before `store team`.
    fn share_hash_any(&self, team: &str, account: &str) -> Option<String> {
        self.shares
            .iter()
            .any(|(store, held)| store == team && held == account)
            .then(|| self.last(SHARE, team, account))
            .flatten()
            .and_then(|op| op.share.clone())
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

/// Drop the entries of the ended accounts of `stores` that are no account id (the first
/// build of version 4 kept keys there). Returns whether one went.
pub(super) fn drop_ended_keys(stores: &mut [StoreShare]) -> bool {
    let mut dropped = false;
    for store in stores {
        let before = store.ended.len();
        store.ended.retain(|account| valid_account_id(account));
        dropped |= store.ended.len() != before;
    }
    dropped
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
/// owner, [`learn_lists`]), and a store that it left (no active join) goes from the file.
/// Pins that no list and no store needs go. Returns whether anything changed.
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
    // A store that this list left (or never joined) goes, with the pins that only it
    // needed; each store that it joins has an entry (its members come from its owner's
    // list).
    state.stores.retain(|store| {
        store.is_own() || own.owner_of(&store.team_id) == Some(store.owner.as_str())
    });
    for (team, owner) in &own.joins {
        let held = state
            .stores
            .iter()
            .any(|store| store.team_id == *team && store.owner == *owner);
        if !held {
            set_store(state, team, owner, Vec::new(), Vec::new());
        }
    }
    drop_unused_pins(state, own);
    (state.peers.clone(), state.stores.clone()) != before
}

/// Whether a store of the account file needs the pin of `account` through `via`: an own
/// pin while a store names its account (as the owner of a store that this account joined,
/// or as a member or an ended account of an own store); a pin through `A` while a store of
/// `A` names its account (as a member or an ended account).
fn store_needs(stores: &[StoreShare], account: &str, via: Option<&str>) -> bool {
    stores.iter().any(|store| match via {
        None => {
            (!store.is_own() && store.owner == account)
                || (store.is_own()
                    && (store.members.iter().any(|held| held == account)
                        || store.ended.iter().any(|held| held == account)))
        }
        Some(owner) => {
            store.owner == owner
                && (store.members.iter().any(|held| held == account)
                    || store.ended.iter().any(|held| held == account))
        }
    })
}

/// Drop the pins that no list and no store needs: an own pin stays while the own list pins
/// it or a store needs it, a pin through an owner while a store needs it
/// ([`store_needs`]). A pin that goes starts again from no list when it comes back.
fn drop_unused_pins(state: &mut AccountState, own: &ListShares) {
    let stores = state.stores.clone();
    state.peers.retain(|pin| {
        (pin.via.is_none() && own.root_of(&pin.account_id).is_some())
            || store_needs(&stores, &pin.account_id, pin.via.as_deref())
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
    /// are full ([`MAX_VIA_PINS`]) with pins that stores need; their keys sign nothing in
    /// that store.
    pub unpinned: Vec<(String, String)>,
    /// The signed device names of the keys of other accounts in the verified lists of this
    /// round: b64u key → (account, device name).
    pub names: BTreeMap<String, (String, String)>,
}

/// The shares of other accounts that Connect counts as void (`account_share_void`), as
/// the peer views say: owner → (store, member). Only an end is ever taken from them.
pub(super) type VoidShares = BTreeMap<String, Vec<(String, String)>>;

/// Make sure of the pin of `member` through `owner` with `root` (the root that the verified
/// list of `owner` names for it): a pin with another root is pinned anew (its old keys stay
/// as keys that left). Returns whether the pin exists after it (no new pin past
/// [`MAX_VIA_PINS`]).
fn ensure_via_pin(state: &mut AccountState, member: &str, owner: &str, root: &[u8]) -> bool {
    let root_b64u = encode_b64u(root);
    match pin_mut(state, member, Some(owner)) {
        Some(pin) if pin.root == root_b64u => true,
        Some(pin) => {
            pin.repin(root);
            true
        }
        None => {
            if state.peers.iter().filter(|pin| pin.via.is_some()).count() >= MAX_VIA_PINS {
                return false;
            }
            state.peers.push(PeerPin::new(member, root, Some(owner)));
            true
        }
    }
}

/// Whether the join of this account (`own`) of the store `team` of `owner` counts: it
/// names the share of `team` with this account (`me`) that `owner`'s verified list
/// (`list`) holds active now, `owner` made `team`, and Connect does not count that share
/// as void. A share that ended, or a newer share that this account did not join yet,
/// leaves the join over: no key signs a new version of the store here.
pub(super) fn join_counts(
    own: &ListShares,
    list: &ListShares,
    void: &VoidShares,
    team: &str,
    owner: &str,
    me: &str,
) -> bool {
    let void_here = void.get(owner).is_some_and(|marks| {
        marks
            .iter()
            .any(|(store, member)| store == team && member == me)
    });
    !void_here
        && list
            .share_hash(team, me)
            .is_some_and(|share| own.join_share(team, owner) == Some(share))
}

/// Learn this account's own list (`own`) and the lists of other accounts that Connect
/// served (`served`, by account; an account that is missing keeps what it had): each own
/// pin takes the served list of its account; the members and the ended accounts of each
/// joined store come from the verified list of its owner, each with a pin through that
/// owner for the root that the owner's list names, while the join counts
/// ([`join_counts`]; else the store has ended here and keeps no member); each pin through
/// an owner takes the served list too. Every store is set before any new pin is made, so
/// the pins that no store needs any more go first, and a pin past [`MAX_VIA_PINS`] is
/// refused only while the stores need every pin. A pure function of the file, the lists,
/// and the void marks: the tests and every device compute the same.
pub(super) fn learn_lists(
    state: &mut AccountState,
    own: &ListShares,
    origin: &str,
    served: &BTreeMap<String, Vec<ListEntry>>,
    void: &VoidShares,
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
    // The members and the ended accounts of each joined store, with the root that its
    // owner names for each, before any pin changes.
    type Named = Vec<(String, Option<Vec<u8>>)>;
    let mut plans: Vec<(String, String, Named, Named)> = Vec::new();
    for (team, owner) in &own.joins {
        let Some(list) = learned.own.get(owner) else {
            // The owner's list did not verify in this round: the store keeps what it had.
            continue;
        };
        if !join_counts(own, &list.shares, void, team, owner, &me) {
            plans.push((team.clone(), owner.clone(), Vec::new(), Vec::new()));
            continue;
        }
        let named = |accounts: Vec<String>| -> Named {
            accounts
                .into_iter()
                .map(|account| {
                    let root = list.shares.root_of(&account).map(<[u8]>::to_vec);
                    (account, root)
                })
                .collect()
        };
        let members = named(list.shares.members_of(team));
        let ended = named(
            list.shares
                .ended_of(team)
                .into_iter()
                .filter(|account| *account != me)
                .collect(),
        );
        plans.push((team.clone(), owner.clone(), members, ended));
    }
    // Every store first: a member without a root counts for nothing; an ended account
    // without a root keeps only a pin that it had.
    for (team, owner, members, ended) in &plans {
        let members = members
            .iter()
            .filter(|(account, root)| *account == me || root.is_some())
            .map(|(account, _)| account.clone())
            .collect();
        let ended = ended
            .iter()
            .filter(|(account, root)| {
                root.is_some() || pin_of(state, account, Some(owner)).is_some()
            })
            .map(|(account, _)| account.clone())
            .collect();
        set_store(state, team, owner, members, ended);
    }
    drop_unused_pins(state, own);
    // Then the pins: an account that finds them full leaves its store here.
    for (team, owner, members, ended) in &plans {
        let mut refused: Vec<String> = Vec::new();
        for (account, root) in members.iter().chain(ended) {
            let Some(root) = root.as_deref().filter(|_| *account != me) else {
                continue;
            };
            if !ensure_via_pin(state, account, owner, root) {
                refused.push(account.clone());
            }
        }
        if refused.is_empty() {
            continue;
        }
        if let Some(store) = state.stores.iter_mut().find(|store| store.team_id == *team) {
            for account in &refused {
                if store.members.contains(account) {
                    learned.unpinned.push((team.clone(), account.clone()));
                }
            }
            store.members.retain(|account| !refused.contains(account));
            store.ended.retain(|account| !refused.contains(account));
        }
    }
    for pin in state.peers.iter_mut().filter(|pin| pin.via.is_some()) {
        if let Some(entries) = served.get(&pin.account_id)
            && let (Some(list), _) = take_peer_list(pin, origin, entries, cache)
        {
            note_names(&mut learned.names, &pin.account_id, &list);
        }
    }
    for (account, list) in &learned.own {
        note_names(&mut learned.names, account, list);
    }
    drop_unused_pins(state, own);
    learned
}

/// The signed name of each key of `list` (its devices and its keys that left), for the
/// prompts that name a device of another account.
fn note_names(names: &mut BTreeMap<String, (String, String)>, account: &str, list: &Verified) {
    for (key, name) in list
        .live
        .iter()
        .zip(&list.names)
        .chain(list.removed.iter().zip(&list.removed_names))
    {
        names.insert(encode_b64u(key), (account.to_owned(), name.clone()));
    }
}

/// The accounts whose lists a refresh reads: the accounts of every pin that [`learn_lists`]
/// keeps or makes with the lists served so far, and the owners of the joined stores.
pub(super) fn accounts_to_read(
    state: &AccountState,
    own: &ListShares,
    origin: &str,
    served: &BTreeMap<String, Vec<ListEntry>>,
    void: &VoidShares,
    cache: &ListCache,
) -> Vec<String> {
    let mut trial = state.clone();
    learn_lists(&mut trial, own, origin, served, void, cache);
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
    /// `None` exactly for a `store`.
    account_id: Option<&'a str>,
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

/// A share of the list of a peer that Connect counts as void (`account_share_void`): a
/// client takes it only to end that share, never to start anything.
#[derive(Debug, Clone, Deserialize)]
struct VoidMark {
    team_id: String,
    account_id: String,
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
    #[serde(default)]
    void: Vec<VoidMark>,
}

/// One account of `POST /v1/account/peers/lists`, with the pin of its list that this
/// device holds in memory (`0` and empty for none).
#[derive(Serialize)]
struct PeerListAsk<'a> {
    account_id: &'a str,
    version: u64,
    head: &'a str,
}

#[derive(Serialize)]
struct PeerListsRequest<'a> {
    accounts: Vec<PeerListAsk<'a>>,
}

/// One account of the answer: `newer` (its list follows), `same` (the asked pin is its
/// head), `refused` (this account may not read it), or `later` (ask again).
#[derive(Debug, Clone, Deserialize)]
struct PeerListItem {
    account_id: String,
    state: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    device_list: Vec<ListEntry>,
    #[serde(default)]
    void: Vec<VoidMark>,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerListsAnswer {
    accounts: Vec<PeerListItem>,
}

/// The most accounts of one `POST /v1/account/peers/lists`.
pub const LISTS_PER_READ: usize = 64;
/// The most entries of the lists that a device keeps in memory between two refreshes
/// (to ask Connect only for lists that changed); over it, a list is asked again whole.
const MAX_HELD_ENTRIES: usize = 100_000;

/// What the shared vaults of an account keep in memory between two refreshes: the lists
/// that Connect served last (so the next refresh asks only for newer ones), when Connect
/// asked to wait (`429` with `Retry-After`), and where the next read starts. Nothing of it
/// is a decision: the account file is ([`learn_lists`]).
#[derive(Debug, Default)]
pub struct ShareMemory {
    /// Account → its list as Connect served it last, with its head (version, hash).
    lists: HashMap<String, (u64, String, Vec<ListEntry>)>,
    /// Account → the name that Connect gives it (a hint).
    names: BTreeMap<String, String>,
    /// The void marks of the last read of each account.
    void: VoidShares,
    /// Unix seconds before which no list is read again (Connect asked to wait).
    wait_until: u64,
    /// The turn of the reads: each refresh starts its order at another account.
    turn: usize,
}

impl ShareMemory {
    fn held_entries(&self) -> usize {
        self.lists
            .values()
            .map(|(_, _, entries)| entries.len())
            .sum()
    }

    fn keep(&mut self, account: &str, entries: Vec<ListEntry>, head: (u64, String)) {
        self.lists.remove(account);
        if self.held_entries() + entries.len() <= MAX_HELD_ENTRIES {
            self.lists
                .insert(account.to_owned(), (head.0, head.1, entries));
        }
    }
}

/// The version and the list hash of the head of `entries` as served (not verified: the
/// pin that the next read names).
fn served_head(origin: &str, account: &str, entries: &[ListEntry]) -> Option<(u64, String)> {
    let root = entries
        .first()
        .and_then(|entry| entry.key.as_deref())
        .and_then(point)?;
    let list = trust::verify_list(origin, account, &root, entries)?;
    Some((list.version, list.head().to_owned()))
}

#[derive(Serialize)]
struct Empty {}

/// The budget of Connect for the ceremony routes of section 16, and for the reads of lists
/// (connect-account-v1 sections 3 and 13): a `429` of one holds back only its own calls.
const CEREMONY: &str = "peer-calls";
const READS: &str = "peer-reads";

impl ConnectClient {
    fn append_list(
        &self,
        token: &str,
        body: &ListAppend<'_>,
    ) -> Result<ListAppended, ConnectError> {
        self.send_json_in_scope("POST", "/v1/account/list", Some(token), body, CEREMONY)
    }

    fn peer_link(
        &self,
        token: &str,
        body: &PeerLinkRequest<'_>,
    ) -> Result<PeerLinkAnswer, ConnectError> {
        self.send_json_in_scope(
            "POST",
            "/v1/account/peers/link",
            Some(token),
            body,
            CEREMONY,
        )
    }

    fn peer_join(
        &self,
        token: &str,
        body: &PeerJoinBody<'_>,
    ) -> Result<PeerJoinAnswer, ConnectError> {
        self.send_json_in_scope(
            "POST",
            "/v1/account/peers/join",
            Some(token),
            body,
            CEREMONY,
        )
    }

    fn peer_pending(&self, token: &str) -> Result<Vec<PeerPendingView>, ConnectError> {
        self.get_json_in_scope("/v1/account/peers/pending", Some(token), CEREMONY)
    }

    fn peer_join_state(&self, token: &str, join_id: u64) -> Result<PeerJoinState, ConnectError> {
        self.get_json_in_scope(
            &format!("/v1/account/peers/join/{join_id}"),
            Some(token),
            CEREMONY,
        )
    }

    fn peer_join_end(&self, token: &str, join_id: u64) -> Result<PeerJoinState, ConnectError> {
        self.send_json_in_scope(
            "DELETE",
            &format!("/v1/account/peers/join/{join_id}"),
            Some(token),
            &Empty {},
            CEREMONY,
        )
    }

    fn peer_view(&self, token: &str, account_id: &str) -> Result<PeerView, ConnectError> {
        if !valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        self.get_json_in_scope(
            &format!("/v1/account/peers/{account_id}"),
            Some(token),
            READS,
        )
    }

    fn peer_lists(
        &self,
        token: &str,
        body: &PeerListsRequest<'_>,
    ) -> Result<PeerListsAnswer, ConnectError> {
        self.send_json_in_scope("POST", "/v1/account/peers/lists", Some(token), body, READS)
    }
}

// ---- What the screens and the owner checks name. ----

/// The names that the screens and the owner checks show beside what this device verified:
/// the local name of each vault (from this computer's vault list), the name that Connect
/// gives each store (a hint: the account that made it chose it), and the name that
/// Connect gives each person (a hint only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareNames {
    /// Store id → the name of the vault of this computer that syncs it.
    pub vaults: BTreeMap<String, String>,
    /// Store id → the name that Connect gives the store.
    pub stores: BTreeMap<String, String>,
    /// Account id → the person's name at Connect.
    pub people: BTreeMap<String, String>,
}

impl ShareNames {
    /// The name to show for the store `team` in a step of the account that made it: its
    /// name on this computer, else the name at Connect (that account chose it).
    pub fn vault(&self, team: &str) -> String {
        self.vaults
            .get(team)
            .or_else(|| self.stores.get(team))
            .cloned()
            .unwrap_or_else(|| "this vault".to_owned())
    }

    /// The name of the vault of this computer that syncs `team`, or empty.
    pub fn local(&self, team: &str) -> String {
        self.vaults.get(team).cloned().unwrap_or_default()
    }

    /// The name that Connect gives the store `team`, or empty: a hint only.
    pub fn store_hint(&self, team: &str) -> String {
        self.stores.get(team).cloned().unwrap_or_default()
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

/// An account whose share of a store of this account ended, as the owner sees it: the
/// row offers "Share with <name> Again…".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndedMember {
    pub account_id: String,
    /// The verified name with its name at Connect ([`label`]).
    pub name: String,
    /// The member's verified list left the share that ended ("<name> left this vault.").
    pub left: bool,
}

/// One member of a shared store of this account, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    pub account_id: String,
    /// The verified name with its name at Connect ([`label`]).
    pub name: String,
    /// The member's list holds a `join` of the share that is active now.
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
    /// A store of this account: the accounts whose share ended, newest last.
    pub ended_members: Vec<EndedMember>,
    /// The share ended for this account (a store it joined): the owner's list ended it, or
    /// shares it anew and this account did not join that share yet.
    pub ended: bool,
    /// Connect counts the share of this store with this account as void (the owner or this
    /// account left the family or team): the store has ended here.
    pub void: bool,
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
    /// The stores that this account's list left: (store, the owner, the name of the device
    /// that signed the `leave`, whether this device signed it). The vault of such a store
    /// syncs no more on this device. From the list: it holds after a restart too.
    pub left: Vec<LeftStore>,
    /// What this refresh signed by itself, in words: "<name> left this vault." and
    /// "Sharing with <name> ended: no longer in your family or team."
    pub notes: Vec<String>,
    /// The members of the group as Connect shows them; `None` when it gave no answer.
    pub group: Option<Vec<GroupMember>>,
    /// Members of joined stores that this device could not pin (the pins are full).
    pub unpinned: Vec<(String, String)>,
    /// The vault stores of Connect for this account, when it listed them in this refresh.
    pub vault_stores: Option<Vec<super::VaultStoreView>>,
    /// The signed names of the devices of other accounts that this refresh verified: b64u
    /// key → (account, device name). The prompts of a copy that one of them left name it.
    pub devices: BTreeMap<String, (String, String)>,
    /// Connect asked to wait: the lists are read again after this many seconds.
    pub wait: Option<u64>,
    /// The devices of members that this refresh added to the stores of this account.
    pub added: Vec<StoreDevice>,
}

/// A store that this account's list left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftStore {
    pub team_id: String,
    pub owner: String,
    /// The signed name of the device that signed the `leave`.
    pub device: String,
    /// This device signed the `leave`.
    pub here: bool,
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

    /// The device of another account that signed with `key` (X9.63), by the name that its
    /// verified list signed, with the person: "“MacBook” of “Ola”".
    pub fn device_of(&self, key: &[u8]) -> Option<String> {
        let (account, device) = self.devices.get(&encode_b64u(key))?;
        Some(format!(
            "\u{201c}{device}\u{201d} of {}",
            self.name_of(account)
        ))
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
    /// The entries of the re-pin of `account`: the ends of the old root (`unshare`,
    /// `leave`), `unpeer`, and `peer` of the new root.
    fn entries(&self, account: &str) -> Vec<ShareEntry> {
        self.unshares
            .iter()
            .map(|team| ShareEntry::new(UNSHARE, Some(account), Some(team)))
            .chain(
                self.leaves
                    .iter()
                    .map(|team| ShareEntry::new(LEAVE, Some(account), Some(team))),
            )
            .chain([
                ShareEntry::new(UNPEER, Some(account), None),
                ShareEntry::new(PEER, Some(account), None),
            ])
            .collect()
    }
}

/// A share of `team` needs the `store team` of the own list `own` (the account made the
/// store): [`ConnectError::Conflict`] otherwise, before any owner check. The stores that
/// this computer syncs as its own get it at the next refresh
/// ([`ConnectAccount::refresh_shares`]).
fn share_needs_store(own: &ListShares, team: &str) -> Result<(), ConnectError> {
    if own.made(team) {
        Ok(())
    } else {
        Err(ConnectError::Conflict)
    }
}

/// The re-pin that pinning `root` for `account` needs, when the own list `own` pins
/// another root for it (the other account was reset and the people compared new words);
/// `None` when the list pins `root` already or pins nothing of `account`.
fn repin_in(own: &ListShares, account: &str, root: &[u8]) -> Option<Repin> {
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

/// The entries that pinning `root` of `account` and sharing `team` with it (when one is
/// named) sign on top of the own list `own`, in their order: the re-pin of a reset account
/// or the `peer` of a new one (none for a pinned root), then `share` unless one is active
/// (a re-pin ends it first). A share needs `store team` in the list already
/// ([`share_needs_store`]): no step claims a store on its own.
fn pin_and_share_entries(
    own: &ListShares,
    account: &str,
    root: Option<&[u8]>,
    team: Option<&str>,
) -> Vec<ShareEntry> {
    let repin = root.and_then(|root| repin_in(own, account, root));
    let mut entries = match (&repin, root) {
        (Some(repin), _) => repin.entries(account),
        (None, Some(_)) if own.root_of(account).is_none() => {
            vec![ShareEntry::new(PEER, Some(account), None)]
        }
        _ => Vec::new(),
    };
    if let Some(team) = team {
        let active = own.shares.contains(&(team.to_owned(), account.to_owned()));
        if !active
            || repin
                .as_ref()
                .is_some_and(|repin| repin.unshares.iter().any(|held| held == team))
        {
            entries.push(ShareEntry::new(SHARE, Some(account), Some(team)));
        }
    }
    entries
}

impl ConnectAccount {
    /// Sign the entry `op` of section 16 for `peer_account` (none for a `store`; with
    /// `root` for a `peer` and the list hash of the answered share for a `join`, and the
    /// store `team_id` for a store op) after the head that this device verified, and append
    /// it with `POST /v1/account/list`. A `409` (the list moved) reads the list again and
    /// signs once more. A list that this device's own rules refuse the entry at (also a
    /// `share` of a store whose `store` the list does not hold) is
    /// [`ConnectError::Conflict`] (over a count [`ConnectError::AccountLimit`]), and nothing
    /// is sent. On success this device pins the entry it signed.
    fn share_entry(
        &mut self,
        op: &str,
        peer_account: Option<&str>,
        root: Option<&str>,
        team_id: Option<&str>,
    ) -> Result<(), ConnectError> {
        let signer = self.signer()?;
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
                account_id: peer_account.map(str::to_owned),
                root: root.map(str::to_owned),
                team_id: team_id.map(str::to_owned),
            };
            let account_id = self.state().account_id.clone();
            shares
                .check(&account_id, &entry)
                .map_err(|refusal| match refusal {
                    Refusal::Limit => ConnectError::AccountLimit,
                    Refusal::Rule => ConnectError::Conflict,
                })?;
            if op == SHARE && !team_id.is_some_and(|team| shares.made(team)) {
                return Err(ConnectError::Conflict);
            }
            let (signature, hash) = signer.sign_share_entry(
                self.client().origin(),
                &account_id,
                (version, &previous),
                op,
                peer_account.unwrap_or(LIST_NONE),
                root,
                team_id,
            )?;
            let statement = encode_b64u(&signature);
            let body = ListAppend {
                version,
                op,
                account_id: peer_account,
                root,
                team_id,
                statement: &statement,
            };
            match self.with_token(|client, token| client.append_list(token, &body)) {
                Ok(answer) if answer.version == version => {
                    shares
                        .apply(&account_id, &entry, &hash)
                        .map_err(|_| ConnectError::Local)?;
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

    /// Sign exactly `entries`, in their order, on top of the list that this device verifies
    /// before each one: the entries that an owner check named. `root` is the root of a
    /// `peer`, `share` the answered share of a `join`. The list must have room for every
    /// adding entry before the first is signed ([`ConnectError::AccountLimit`]); an entry
    /// that the list does not allow when its turn comes stops the sequence
    /// ([`ConnectError::Conflict`]): nothing else is signed in its place.
    fn sign_entries(
        &mut self,
        entries: &[ShareEntry],
        root: Option<&[u8]>,
        share: Option<&str>,
    ) -> Result<(), ConnectError> {
        let head = self.state().list_version;
        for (index, entry) in entries.iter().enumerate() {
            let version = head + 1 + index as u64;
            if version > trust::MAX_LIST as u64
                || (adds(&entry.op) && version > trust::MAX_ADD_VERSION)
            {
                return Err(ConnectError::AccountLimit);
            }
        }
        let root = root.map(encode_b64u);
        for entry in entries {
            let root = match entry.op.as_str() {
                PEER => Some(root.as_deref().ok_or(ConnectError::Invalid)?),
                JOIN => Some(share.ok_or(ConnectError::Invalid)?),
                _ => None,
            };
            self.share_entry(
                &entry.op,
                entry.account.as_deref(),
                root,
                entry.team.as_deref(),
            )?;
        }
        Ok(())
    }

    /// The list of the peer `account` from Connect, with the name and the device rows that
    /// Connect gives.
    fn read_peer(&mut self, account: &str) -> Result<PeerView, ConnectError> {
        let view = self.with_token(|client, token| client.peer_view(token, account))?;
        if view.account_id != account {
            return Err(ConnectError::BadAnswer);
        }
        self.share_memory()
            .names
            .insert(account.to_owned(), clean(&view.name));
        Ok(view)
    }

    /// The own list's shares, from a fresh view whose list verified.
    fn own_shares(&mut self) -> Result<ListShares, ConnectError> {
        self.verified_view()?;
        self.verified_list()
            .map(|list| list.shares.clone())
            .ok_or(ConnectError::BadAnswer)
    }

    /// The verified name and the short root fingerprint of `account` as this account's
    /// own pin holds it (empty without a pin).
    pub fn person_of(&self, account: &str) -> (String, String) {
        self.person(account, None)
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
        repin_in(&self.verified_list()?.shares, account, root)
    }

    /// The owner check of a re-pin of `account` with `root` and `words`, sharing `team`
    /// after it when one is named, with the `entries` that it signs.
    #[allow(clippy::too_many_arguments)]
    fn repin_action(
        &self,
        account: &str,
        (root, root_name, hint): (&[u8], &str, &str),
        words: &str,
        repin: &Repin,
        team: Option<&str>,
        names: &ShareNames,
        entries: Vec<ShareEntry>,
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
            entries,
        }
    }

    /// The owner check of the confirmation of `request` for the store of `link`: a share
    /// with the words, or a re-pin of an account that was reset (which says which shares
    /// end, and shares the store after it). It names the entries that the confirmation
    /// signs, from the own list as Connect serves it now.
    pub fn share_action(
        &mut self,
        link: &ShareLink,
        request: &ShareRequest,
        names: &ShareNames,
    ) -> Result<OwnerAction, ConnectError> {
        let own = self.own_shares()?;
        share_needs_store(&own, &link.team_id)?;
        Ok(self.share_action_on(&own, link, request, names))
    }

    /// [`Self::share_action`] on the own list `own`.
    fn share_action_on(
        &self,
        own: &ListShares,
        link: &ShareLink,
        request: &ShareRequest,
        names: &ShareNames,
    ) -> OwnerAction {
        let entries = pin_and_share_entries(
            own,
            &request.account_id,
            Some(&request.root),
            Some(&link.team_id),
        );
        if let Some(repin) = repin_in(own, &request.account_id, &request.root) {
            return self.repin_action(
                &request.account_id,
                (&request.root, &request.root_name, &request.name),
                &request.words,
                &repin,
                Some(&link.team_id),
                names,
                entries,
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
            entries,
        }
    }

    /// "Confirm" of a share after a fresh owner check for [`Self::share_action`] in the
    /// vault session `epoch`: the words are computed again from the code and the keys
    /// (another request is [`ConnectError::WordsMismatch`], nothing is signed); the own
    /// list is read again, and the check must name exactly the entries that it needs now
    /// (else the proof does not cover the step, and nothing is signed); this device signs
    /// them (`peer` for the other account's root unless this account pinned it already, or
    /// after a reset the ends of the old root first; `store` and `share` of the store),
    /// pins the other account with the list that it verified, and adds that account's
    /// verified devices to the store. The proof is used up, also when the call fails.
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
        let own = self.own_shares()?;
        share_needs_store(&own, &link.team_id)?;
        let action = self.share_action_on(&own, link, request, names);
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        let entries = share_entries_of(&action);
        self.sign_entries(&entries, Some(&request.root), None)?;
        self.pin_list(&request.account_id, &request.root, &request.list)?;
        self.add_peer_devices(&link.team_id, &request.account_id)
    }

    /// The owner check of a share of the store `team_id` with the pinned peer
    /// `peer_account`, without new words: it names the entries (`store` when the own list
    /// does not hold it, and `share`), from the own list as Connect serves it now.
    pub fn share_again_action(
        &mut self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
    ) -> Result<OwnerAction, ConnectError> {
        let own = self.own_shares()?;
        share_needs_store(&own, team_id)?;
        Ok(self.share_again_action_on(&own, team_id, peer_account, names))
    }

    fn share_again_action_on(
        &self,
        own: &ListShares,
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
            entries: pin_and_share_entries(own, peer_account, None, Some(team_id)),
        }
    }

    /// Share the store `team_id` with `peer_account`, whose root this account pinned
    /// already and whose list pins this account (a pair of accounts compares words once),
    /// after a fresh owner check for [`Self::share_again_action`] that names the entries
    /// that the own list needs now. A peer that is not pinned here, or is suspended, is
    /// [`ConnectError::NotVerified`], and nothing is signed.
    pub fn share_again(
        &mut self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<ShareConfirmed, ConnectError> {
        let own = self.own_shares()?;
        share_needs_store(&own, team_id)?;
        let action = self.share_again_action_on(&own, team_id, peer_account, names);
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        if self.is_own_store_of_other(team_id) || own.owner_of(team_id).is_some() {
            return Err(ConnectError::Invalid);
        }
        if !self.is_pinned_peer(peer_account) {
            return Err(ConnectError::NotVerified);
        }
        self.sign_entries(&share_entries_of(&action), None, None)?;
        self.add_peer_devices(team_id, peer_account)
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

    /// Pin `list` of `account` (verified from `root`) in the account file, after this
    /// device signed the `peer` of `root` (or found it in its list).
    fn pin_list(
        &mut self,
        account: &str,
        root: &[u8],
        list: &Verified,
    ) -> Result<(), ConnectError> {
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

    /// The owner check of "The Words Match" for `join`: an accept, or a re-pin of an
    /// account that was reset (which says which shares and joins end). It names the
    /// entries that it signs, from the own list as Connect serves it now.
    pub fn accept_action(
        &mut self,
        join: &SharePeerJoin,
        names: &ShareNames,
    ) -> Result<OwnerAction, ConnectError> {
        let own = self.own_shares()?;
        Ok(self.accept_action_on(&own, join, names))
    }

    fn accept_action_on(
        &self,
        own: &ListShares,
        join: &SharePeerJoin,
        names: &ShareNames,
    ) -> OwnerAction {
        let entries = pin_and_share_entries(own, &join.account_id, Some(&join.root), None);
        if let Some(repin) = repin_in(own, &join.account_id, &join.root) {
            return self.repin_action(
                &join.account_id,
                (&join.root, &join.root_name, &join.name),
                &join.words,
                &repin,
                None,
                names,
                entries,
            );
        }
        OwnerAction::AcceptConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: join.account_id.clone(),
            peer_name: join.root_name.clone(),
            peer_hint: join.name.clone(),
            fingerprint: key_fingerprint(&join.root),
            words: join.words.clone(),
            entries,
        }
    }

    /// "The Words Match" after a fresh owner check for [`Self::accept_action`]: the words
    /// are computed again (another set is [`ConnectError::WordsMismatch`]); the own list is
    /// read again and the check must name exactly the entries that it needs now; this
    /// device signs them (the `peer` for the inviting account's root) and pins its verified
    /// list. Its shared stores then show in [`Self::refresh_shares`] as offers. The proof
    /// is used up.
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
        let own = self.own_shares()?;
        let action = self.accept_action_on(&own, join, names);
        proof
            .check(&action, epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        self.sign_entries(&share_entries_of(&action), Some(&join.root), None)?;
        self.pin_list(&join.account_id, &join.root, &join.list)
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
    /// account joined, and of their co-members (also of members whose share ended), and
    /// learn them ([`learn_lists`], section 16.6). `local_teams` are the stores that this
    /// computer's vaults sync: none of them is offered (except a newer share of a store
    /// that this account joined from the same owner), and each that this account syncs as
    /// its own and whose `store` its list does not hold gets it (no owner check: it adds no
    /// signer). Then the ends that this device signs by itself, without an owner check (an
    /// end gives no one access, so a lying Connect can cause one, never a grant), at most
    /// one entry for each share ([`Self::end_by_itself`]), and the verified devices of each
    /// member that joined and that the store does not hold yet go into the store.
    ///
    /// Writes the account file when the trust store changed. A peer list that Connect does
    /// not give, or that does not verify, changes nothing of it; a refusal, an error, or a
    /// `429` of a read ends nothing.
    pub fn refresh_shares(&mut self, local_teams: &[String]) -> Result<ShareStatus, ConnectError> {
        let mut own = self.own_shares()?;
        if self.claim_own_stores(&own, local_teams)? {
            own = self.own_shares()?;
        }
        let origin = self.client().origin().to_owned();
        let mut status = ShareStatus::default();
        let cache = ListCache::default();
        let (served, void) = self.read_lists(&own, &cache, &mut status)?;
        let before = self.state().clone();
        let learned = learn_lists(self.state_mut(), &own, &origin, &served, &void, &cache);
        if *self.state() != before {
            self.save_state()?;
        }
        status.unpinned.clone_from(&learned.unpinned);
        status.devices.clone_from(&learned.names);
        let group = self.group();
        status.group = group.as_ref().ok().map(|group| {
            group
                .as_ref()
                .map(|g| g.members.clone())
                .unwrap_or_default()
        });
        status.vault_stores = self.vault_stores().ok();
        let own = self.end_by_itself(&own, &learned, &group, &mut status)?;
        self.add_member_devices(&own, &learned, &void, &mut status);
        self.fill_status(&own, &learned, &void, local_teams, &mut status);
        Ok(status)
    }

    /// Append `store` for each store of `local_teams` that this computer syncs as its own
    /// and whose `store` the own list `own` does not hold (stores made before the entry
    /// existed): not a store that the list joins or ever joined, and not one that the
    /// account file holds as another's. Connect checks that this account made it; a store
    /// it refuses gets nothing. Returns whether one was appended.
    fn claim_own_stores(
        &mut self,
        own: &ListShares,
        local_teams: &[String],
    ) -> Result<bool, ConnectError> {
        let mut claimed = false;
        for team in local_teams {
            let joined_ever = own
                .ops
                .iter()
                .any(|op| op.team == *team && (op.op == JOIN || op.op == LEAVE));
            if !valid_team_id(team)
                || own.made(team)
                || joined_ever
                || self.is_own_store_of_other(team)
            {
                continue;
            }
            match self.share_entry(STORE, None, None, Some(team)) {
                Ok(()) => claimed = true,
                Err(error @ (ConnectError::Revoked | ConnectError::SignedOut)) => {
                    return Err(error);
                }
                // Not a store of this account, no such store, or the list moved: nothing
                // is claimed now.
                Err(_) => {}
            }
        }
        Ok(claimed)
    }

    /// Read the lists that a refresh needs ([`accounts_to_read`]): the own peers and the
    /// owners first, then the co-members that the owners name, in rounds. Each round asks
    /// Connect with `POST /v1/account/peers/lists` in batches of [`LISTS_PER_READ`], in an
    /// order that starts at another account at each refresh, for the lists that changed
    /// since the ones that this device holds in memory (`same` gives the held one). A `429`
    /// stops the reads of this refresh (`status.wait`), and so does an error: the lists that
    /// were not read are the held ones, or missing (an account that is missing keeps what
    /// it had). `refused` only notes the account ([`ShareStatus::outside_group`]).
    fn read_lists(
        &mut self,
        own: &ListShares,
        cache: &ListCache,
        status: &mut ShareStatus,
    ) -> Result<(BTreeMap<String, Vec<ListEntry>>, VoidShares), ConnectError> {
        let origin = self.client().origin().to_owned();
        let now = self.now();
        let mut served: BTreeMap<String, Vec<ListEntry>> = BTreeMap::new();
        let mut tried: BTreeSet<String> = BTreeSet::new();
        let mut stopped = now < self.share_memory().wait_until;
        if stopped {
            status.wait = Some(self.share_memory().wait_until - now);
        }
        let turn = {
            let memory = self.share_memory();
            memory.turn = memory.turn.wrapping_add(1);
            memory.turn
        };
        for _ in 0..4 {
            let void = self.share_memory().void.clone();
            let wanted: Vec<String> =
                accounts_to_read(self.state(), own, &origin, &served, &void, cache)
                    .into_iter()
                    .filter(|account| !tried.contains(account))
                    .collect();
            if wanted.is_empty() {
                break;
            }
            let mut order = wanted.clone();
            if !order.is_empty() {
                let at = turn.wrapping_mul(LISTS_PER_READ) % order.len();
                order.rotate_left(at);
            }
            let mut later = Vec::new();
            for batch in order.chunks(LISTS_PER_READ) {
                if stopped {
                    break;
                }
                let asks: Vec<(String, u64, String)> = batch
                    .iter()
                    .map(|account| {
                        let held = self.share_memory().lists.get(account);
                        let (version, head) =
                            held.map_or((0, String::new()), |(v, h, _)| (*v, h.clone()));
                        (account.clone(), version, head)
                    })
                    .collect();
                let body = PeerListsRequest {
                    accounts: asks
                        .iter()
                        .map(|(account, version, head)| PeerListAsk {
                            account_id: account,
                            version: *version,
                            head,
                        })
                        .collect(),
                };
                let answer = match self.with_token(|client, token| client.peer_lists(token, &body))
                {
                    Ok(answer) => answer,
                    Err(ConnectError::RateLimited(seconds)) => {
                        self.share_memory().wait_until = now.saturating_add(seconds);
                        status.wait = Some(seconds);
                        stopped = true;
                        break;
                    }
                    Err(error @ (ConnectError::Revoked | ConnectError::SignedOut)) => {
                        return Err(error);
                    }
                    Err(_) => {
                        stopped = true;
                        break;
                    }
                };
                for item in answer.accounts {
                    if !batch.contains(&item.account_id) {
                        continue;
                    }
                    match item.state.as_str() {
                        "newer" => {
                            let head = served_head(&origin, &item.account_id, &item.device_list)
                                .unwrap_or_default();
                            self.share_memory()
                                .names
                                .insert(item.account_id.clone(), clean(&item.name));
                            self.share_memory().keep(
                                &item.account_id,
                                item.device_list.clone(),
                                head,
                            );
                            self.note_void(&item.account_id, &item.void);
                            served.insert(item.account_id.clone(), item.device_list);
                        }
                        "same" => {
                            self.note_void(&item.account_id, &item.void);
                            // The held list is the head: it counts in this round.
                            if let Some((_, _, entries)) =
                                self.share_memory().lists.get(&item.account_id)
                            {
                                served.insert(item.account_id.clone(), entries.clone());
                            }
                        }
                        "refused" => status.outside_group.push(item.account_id.clone()),
                        "later" => later.push(item.account_id.clone()),
                        _ => {}
                    }
                }
            }
            for account in &wanted {
                if !later.contains(account) {
                    tried.insert(account.clone());
                }
            }
            if stopped {
                break;
            }
        }
        // The lists that this round did not serve anew: the ones held in memory.
        let memory = self.share_memory();
        for (account, (_, _, entries)) in &memory.lists {
            served
                .entry(account.clone())
                .or_insert_with(|| entries.clone());
        }
        status.names.clone_from(&memory.names);
        Ok((served, memory.void.clone()))
    }

    /// The void marks that Connect gave with the list of `owner` (only ends are taken from
    /// them).
    fn note_void(&mut self, owner: &str, marks: &[VoidMark]) {
        let marks: Vec<(String, String)> = marks
            .iter()
            .filter(|mark| valid_team_id(&mark.team_id) && valid_account_id(&mark.account_id))
            .map(|mark| (mark.team_id.clone(), mark.account_id.clone()))
            .collect();
        let void = &mut self.share_memory().void;
        if marks.is_empty() {
            void.remove(owner);
        } else {
            void.insert(owner.to_owned(), marks);
        }
    }

    /// The ends of [`Self::refresh_shares`] that this device signs by itself, for the
    /// active shares of the own list `own`. Returns the own list's shares after them.
    ///
    /// - The member's verified list left the share that is active now (a `leave` of a join
    ///   that named it): "<name> left this vault."
    /// - The group answer shows this account as an active member of its group and does
    ///   not show the member (or names it as removed): "Sharing with <name> ended: no
    ///   longer in your family or team." An error, an empty answer, or an answer without
    ///   this account ends nothing.
    /// - Connect counts the share as void (the store view of the store says so): the same
    ///   note.
    fn end_by_itself(
        &mut self,
        own: &ListShares,
        learned: &Learned,
        group: &Result<Option<super::GroupDetail>, ConnectError>,
        status: &mut ShareStatus,
    ) -> Result<ListShares, ConnectError> {
        let me = self.state().account_id.clone();
        let members = match group {
            Ok(Some(group))
                if group
                    .members
                    .iter()
                    .any(|held| held.account_id == me && held.state == "active") =>
            {
                Some(&group.members)
            }
            _ => None,
        };
        let void_of = |team: &str, member: &str| {
            status.vault_stores.as_ref().is_some_and(|stores| {
                stores.iter().any(|store| {
                    store.team_id == team && store.void.iter().any(|held| held == member)
                })
            })
        };
        let mut ends: Vec<(String, String, bool)> = Vec::new();
        for (team, member) in &own.shares {
            let outside = members.is_some_and(|members| {
                members
                    .iter()
                    .find(|held| held.account_id == *member)
                    .is_none_or(|held| held.state == "removed")
            });
            if outside || void_of(team, member) {
                ends.push((team.clone(), member.clone(), false));
                continue;
            }
            if let (Some(list), Some(share)) =
                (learned.own.get(member), own.share_hash(team, member))
                && list.shares.left_share(team, &me, share)
                && list.shares.join_share(team, &me) != Some(share)
            {
                ends.push((team.clone(), member.clone(), true));
            }
        }
        if ends.is_empty() {
            return Ok(own.clone());
        }
        for (team, member, left) in ends {
            match self.share_entry(UNSHARE, Some(&member), None, Some(&team)) {
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

    /// Add the verified devices of each member whose join of a store of this account
    /// counts and that the store does not hold yet (a device that joined that account after
    /// the share), with the keys that this device verified, without an owner check: the
    /// share that the owner checked covers that account's verified devices. What Connect
    /// refuses waits for the next refresh.
    fn add_member_devices(
        &mut self,
        own: &ListShares,
        learned: &Learned,
        void: &VoidShares,
        status: &mut ShareStatus,
    ) {
        let me = self.state().account_id.clone();
        let Some(stores) = status.vault_stores.clone() else {
            return;
        };
        for (team, member) in &own.shares {
            let (Some(list), Some(store)) = (
                learned.own.get(member),
                stores.iter().find(|store| store.team_id == *team),
            ) else {
                continue;
            };
            if !join_counts(&list.shares, own, void, team, &me, member) {
                continue;
            }
            let held = store
                .devices
                .iter()
                .filter(|device| device.account_id == *member)
                .count();
            if held >= list.live.len() {
                continue;
            }
            // What Connect refuses waits for the next refresh.
            if let Ok(confirmed) = self.add_peer_devices(team, member) {
                status.added.extend(confirmed.added);
            }
        }
    }

    /// The parts of the status that the screens show, from the lists alone (so they hold
    /// after a restart): the people, the offers, the stores with their members and ended
    /// members, and the stores that this list left.
    fn fill_status(
        &self,
        own: &ListShares,
        learned: &Learned,
        void: &VoidShares,
        local_teams: &[String],
        status: &mut ShareStatus,
    ) {
        let me = self.state().account_id.clone();
        let my_root = self.root_key();
        let my_key = encode_b64u(&self.own_public_key());
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
        for op in own.ops.iter().filter(|op| op.op == LEAVE) {
            if own.owner_of(&op.team).is_some()
                || own.last(LEAVE, &op.team, &op.account) != Some(op)
                || own
                    .ops
                    .iter()
                    .rev()
                    .find(|held| held.team == op.team && held.account == op.account)
                    != Some(op)
                || status.left.iter().any(|left| left.team_id == op.team)
            {
                continue;
            }
            let device = point(&op.by)
                .and_then(|key| {
                    own_list.and_then(|list| list.name_of(&key).or_else(|| list.removed_name(&key)))
                })
                .map_or_else(|| "another device".to_owned(), str::to_owned);
            status.left.push(LeftStore {
                team_id: op.team.clone(),
                owner: op.account.clone(),
                device,
                here: op.by == my_key,
            });
        }
        for (account, list) in &learned.own {
            for (team, member) in &list.shares.shares {
                if *member != me {
                    continue;
                }
                let Some(share) = list.shares.share_hash(team, &me) else {
                    continue;
                };
                let void_here = void.get(account).is_some_and(|marks| {
                    marks
                        .iter()
                        .any(|(store, held)| store == team && *held == me)
                });
                let rejoin = own.owner_of(team) == Some(account.as_str());
                if void_here
                    || own.join_share(team, account) == Some(share)
                    || own.left_share(team, account, share)
                    || own.made(team)
                    || own.shares.iter().any(|(store, _)| store == team)
                    || (own.owner_of(team).is_some() && !rejoin)
                    || (local_teams.contains(team) && !rejoin)
                    || self.is_own_store(team)
                {
                    continue;
                }
                status.offers.push(ShareOffer {
                    team_id: team.clone(),
                    owner: account.clone(),
                    owner_name: status.name_of(account),
                    vault_name: None,
                });
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
                            join_counts(&list.shares, own, void, &store.team_id, &me, member)
                        }),
                        suspended: pin_of(self.state(), member, via)
                            .is_some_and(|pin| pin.suspended),
                        accepted: list.is_some_and(|list| {
                            list.shares.root_of(&me) == Some(my_root.as_slice())
                        }),
                    }
                })
                .collect();
            let ended_members = if store.is_own() {
                own.ended_of(&store.team_id)
                    .into_iter()
                    .map(|member| {
                        let ended = own
                            .last(UNSHARE, &store.team_id, &member)
                            .and_then(|op| op.share.clone());
                        let left = learned.own.get(&member).is_some_and(|list| {
                            ended.as_deref().is_some_and(|share| {
                                list.shares.left_share(&store.team_id, &me, share)
                            })
                        });
                        EndedMember {
                            name: status.name_of(&member),
                            account_id: member,
                            left,
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let owner = (!store.is_own()).then(|| store.owner.clone());
            let void_here = owner.as_deref().is_some_and(|owner| {
                void.get(owner).is_some_and(|marks| {
                    marks
                        .iter()
                        .any(|(team, held)| *team == store.team_id && *held == me)
                })
            });
            status.stores.push(StoreStatus {
                team_id: store.team_id.clone(),
                owner_name: owner.as_deref().map(|owner| status.name_of(owner)),
                owner_suspended: owner
                    .as_deref()
                    .and_then(|owner| pin_of(self.state(), owner, None))
                    .is_some_and(|pin| pin.suspended),
                ended: owner.is_some() && !store.members.contains(&me),
                void: void_here,
                owner,
                members,
                ended_members,
            });
        }
    }

    /// Whether the store `team_id` is one of this account: its file holds it as its own, or
    /// its verified list made it or shares it.
    fn is_own_store(&self, team_id: &str) -> bool {
        self.state()
            .stores
            .iter()
            .any(|store| store.team_id == team_id && store.is_own())
            || self.verified_list().is_some_and(|list| {
                list.shares.made(team_id)
                    || list.shares.shares.iter().any(|(team, _)| team == team_id)
            })
    }

    /// The owner check of "Join" of the store `team_id` of `owner`: the person by the name
    /// that its verified list signed, the vault by its name on this computer when a vault
    /// here syncs the store (a newer share of a store that this account joined before),
    /// else as "a vault shared by" the person, with Connect's name of the store as a hint.
    pub fn join_action(&self, team_id: &str, owner: &str, names: &ShareNames) -> OwnerAction {
        let (name, fingerprint) = self.person(owner, None);
        OwnerAction::JoinConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: owner.to_owned(),
            peer_name: name,
            peer_hint: names.hint(owner),
            fingerprint,
            team_id: team_id.to_owned(),
            vault_name: names.local(team_id),
            entries: vec![ShareEntry::new(JOIN, Some(owner), Some(team_id))],
            vault_hint: names.store_hint(team_id),
        }
    }

    /// "Join" of an offer after a fresh owner check for [`Self::join_action`]: this device
    /// reads the owner's list (the share of the store with this account must be active,
    /// not one that this account joined or left already), signs `join` of the store
    /// `team_id` of `owner` naming that share, and reads the lists of the co-members of the
    /// store before it returns, so the first download already knows their keys. A store
    /// that this account holds as its own (its file, its own list, or `local_teams`: the
    /// stores that this computer's vaults sync, except a store that this account joined
    /// from `owner` before) is [`ConnectError::Invalid`], and nothing is signed. Then the
    /// store's copy is downloaded with its passphrase (`RelaySync::joined_from_store`), or
    /// the vault of this computer that synced the store syncs it again.
    pub fn join_shared_store(
        &mut self,
        team_id: &str,
        owner: &str,
        local_teams: &[String],
        names: &ShareNames,
        proof: OwnerProof,
        epoch: &[u8; 32],
    ) -> Result<(), ConnectError> {
        proof
            .check(&self.join_action(team_id, owner, names), epoch)
            .map_err(ConnectError::OwnerCheck)?;
        drop(proof);
        if !self.is_pinned_peer(owner) {
            return Err(ConnectError::NotVerified);
        }
        let own = self.own_shares()?;
        let rejoin = own.owner_of(team_id) == Some(owner);
        if self.is_own_store(team_id)
            || own.made(team_id)
            || own.shares.iter().any(|(store, _)| store == team_id)
            || (own.owner_of(team_id).is_some() && !rejoin)
            || (local_teams.iter().any(|team| team == team_id) && !rejoin)
        {
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
        let void = view
            .void
            .iter()
            .any(|mark| mark.team_id == team_id && mark.account_id == me);
        let share = list
            .shares
            .share_hash(team_id, &me)
            .filter(|share| {
                !void
                    && own.join_share(team_id, owner) != Some(*share)
                    && !own.left_share(team_id, owner, share)
            })
            .map(str::to_owned)
            .ok_or(ConnectError::NotVerified)?;
        self.sign_entries(
            &[ShareEntry::new(JOIN, Some(owner), Some(team_id))],
            None,
            Some(&share),
        )?;
        // The co-members of the store: their lists before the first download.
        let own = self.own_shares()?;
        let cache = ListCache::default();
        let mut status = ShareStatus::default();
        let (mut served, void) = self.read_lists(&own, &cache, &mut status)?;
        served.insert(owner.to_owned(), view.device_list);
        let before = self.state().clone();
        learn_lists(self.state_mut(), &own, &origin, &served, &void, &cache);
        if *self.state() != before {
            self.save_state()?;
        }
        Ok(())
    }

    /// The owner check of the end of a share: the owner's "Stop Sharing with <name>…"
    /// (`leave` false, it signs `unshare`) or a member's "Leave This Shared Vault…" (`leave`
    /// true, it signs `leave`).
    pub fn end_share_action(
        &self,
        team_id: &str,
        peer_account: &str,
        names: &ShareNames,
        leave: bool,
    ) -> OwnerAction {
        let (name, fingerprint) = self.person(peer_account, None);
        let op = if leave { LEAVE } else { UNSHARE };
        OwnerAction::EndConnectShare {
            account_id: self.state().account_id.clone(),
            peer_account: peer_account.to_owned(),
            peer_name: name,
            peer_hint: names.hint(peer_account),
            fingerprint,
            team_id: team_id.to_owned(),
            vault_name: names.vault(team_id),
            leave,
            entries: vec![ShareEntry::new(op, Some(peer_account), Some(team_id))],
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
        self.share_entry(UNSHARE, Some(peer_account), None, Some(team_id))
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
        self.share_entry(LEAVE, Some(owner), None, Some(team_id))
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

/// The entries that the owner check `action` of a shared vault names.
fn share_entries_of(action: &OwnerAction) -> Vec<ShareEntry> {
    match action {
        OwnerAction::ShareConnectVault { entries, .. }
        | OwnerAction::AcceptConnectShare { entries, .. }
        | OwnerAction::RepinConnectPeer { entries, .. }
        | OwnerAction::JoinConnectShare { entries, .. }
        | OwnerAction::EndConnectShare { entries, .. } => entries.clone(),
        _ => Vec::new(),
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
