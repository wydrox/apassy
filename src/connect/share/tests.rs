//! The rules of section 16 on lists that a test builds as Connect would keep them, and
//! the trust store and the signers of a shared store after each list.

use super::*;
use crate::connect::device_key::{list_hash, list_message};
use crate::sync::DeviceKey;

const ORIGIN: &str = "https://connect.example.test";
const STORE: &str = "t_7k2m5q4x3c";
/// The op `store` (the name `STORE` is the store of these tests).
const STORE_OP: &str = super::STORE;
const OTHER_STORE: &str = "t_aaaaaaaaaa";

fn key() -> DeviceKey {
    DeviceKey::generate().unwrap()
}

fn b64(key: &DeviceKey) -> String {
    encode_b64u(key.public_key())
}

/// One account's signed list, as Connect keeps it.
struct List {
    id: String,
    root: DeviceKey,
    entries: Vec<ListEntry>,
    hashes: Vec<String>,
}

impl List {
    fn new(id: &str) -> Self {
        let root = key();
        let mut list = Self {
            id: id.to_owned(),
            root,
            entries: Vec::new(),
            hashes: Vec::new(),
        };
        let root_key =
            DeviceKey::from_pkcs8(zeroize::Zeroizing::new(list.root.pkcs8().unwrap().to_vec()))
                .unwrap();
        list.device(&root_key, "root", &root_key, None, Some("Synthetic root"));
        list
    }

    fn previous(&self) -> String {
        self.hashes
            .last()
            .cloned()
            .unwrap_or_else(|| LIST_NONE.to_owned())
    }

    fn device(
        &mut self,
        by: &DeviceKey,
        op: &str,
        key: &DeviceKey,
        link: Option<String>,
        name: Option<&str>,
    ) {
        let version = self.entries.len() as u64 + 1;
        let message = list_message(
            ORIGIN,
            &self.id,
            version,
            &self.previous(),
            op,
            &b64(key),
            link.as_deref().unwrap_or(LIST_NONE),
            name.unwrap_or(LIST_NONE),
            &b64(by),
        );
        self.entries.push(ListEntry {
            version,
            op: op.into(),
            key: Some(b64(key)),
            link_hash: link,
            name: name.map(str::to_owned),
            by: b64(by),
            signature: Some(encode_b64u(&by.sign(&message).unwrap())),
            account_id: None,
            root: None,
            team_id: None,
        });
        self.hashes.push(list_hash(&message));
    }

    fn add(&mut self, key: &DeviceKey, seed: u8) {
        let root = self.root_signer();
        self.device(
            &root,
            "add",
            key,
            Some(encode_b64u(&[seed; 32])),
            Some("Synthetic device"),
        );
    }

    fn root_signer(&self) -> DeviceKey {
        DeviceKey::from_pkcs8(zeroize::Zeroizing::new(self.root.pkcs8().unwrap().to_vec())).unwrap()
    }

    fn share_by(
        &mut self,
        by: &DeviceKey,
        op: &str,
        peer: &str,
        root: Option<&[u8]>,
        team: Option<&str>,
    ) {
        self.entry_by(by, op, Some(peer), root.map(encode_b64u), team);
    }

    /// An entry of section 16 signed by `by`: `peer` none for a `store`, `root` the root
    /// of a `peer` or the share hash of a `join` (b64u).
    fn entry_by(
        &mut self,
        by: &DeviceKey,
        op: &str,
        peer: Option<&str>,
        root: Option<String>,
        team: Option<&str>,
    ) {
        let version = self.entries.len() as u64 + 1;
        let message = share_list_message(
            ORIGIN,
            &self.id,
            version,
            &self.previous(),
            op,
            peer.unwrap_or(LIST_NONE),
            root.as_deref().unwrap_or(LIST_NONE),
            team.unwrap_or(LIST_NONE),
            &b64(by),
        );
        self.entries.push(ListEntry {
            version,
            op: op.into(),
            key: None,
            link_hash: None,
            name: None,
            by: b64(by),
            signature: Some(encode_b64u(&by.sign(&message).unwrap())),
            account_id: peer.map(str::to_owned),
            root,
            team_id: team.map(str::to_owned),
        });
        self.hashes.push(list_hash(&message));
    }

    fn share(&mut self, op: &str, peer: &str, root: Option<&[u8]>, team: Option<&str>) {
        let root_key = self.root_signer();
        self.share_by(&root_key, op, peer, root, team);
    }

    fn peer(&mut self, other: &List) {
        self.share(PEER, &other.id.clone(), Some(other.root.public_key()), None);
    }

    /// `store team`: this account made the store.
    fn store(&mut self, team: &str) {
        let root_key = self.root_signer();
        self.entry_by(&root_key, STORE_OP, None, None, Some(team));
    }

    /// `share peer team`, after `store team` when the list does not hold it yet.
    fn share_store(&mut self, peer: &str, team: &str) {
        if !self.verified().is_some_and(|list| list.shares.made(team)) {
            self.store(team);
        }
        self.share(SHARE, peer, None, Some(team));
    }

    /// The list hash of the last `share team member` of this list.
    fn share_hash(&self, team: &str, member: &str) -> String {
        let at = self
            .entries
            .iter()
            .rposition(|entry| {
                entry.op == SHARE
                    && entry.team_id.as_deref() == Some(team)
                    && entry.account_id.as_deref() == Some(member)
            })
            .expect("a share");
        self.hashes[at].clone()
    }

    /// `join owner team` naming the last share of `owner`'s list for this account.
    fn join(&mut self, owner: &List, team: &str) {
        let share = owner.share_hash(team, &self.id);
        let root_key = self.root_signer();
        self.entry_by(&root_key, JOIN, Some(&owner.id), Some(share), Some(team));
    }

    fn verified(&self) -> Option<Verified> {
        trust::verify_list(ORIGIN, &self.id, self.root.public_key(), &self.entries)
    }
}

fn state_of(list: &List) -> AccountState {
    let mut state = AccountState::for_root(
        ORIGIN,
        &list.id,
        "dev_m2k7q3x4ab",
        "Synthetic root",
        &b64(&list.root),
        1_790_000_000,
    );
    let verified = list.verified().unwrap();
    state.list_version = verified.version;
    state.list_head = verified.head().to_owned();
    state.known = verified.live.iter().map(|key| encode_b64u(key)).collect();
    learn_own(&mut state, &verified.shares);
    state
}

/// The account file of `list` after it read `peers` (each verified from its pinned root)
/// and the lists of the owners of its joined stores.
fn refreshed(list: &List, peers: &[&List]) -> AccountState {
    refresh_again(state_of(list), list, peers)
}

/// `state` (an account file of `list` from an earlier refresh) after it read `peers`.
fn refresh_again(mut state: AccountState, list: &List, peers: &[&List]) -> AccountState {
    let own = list.verified().unwrap();
    let served: BTreeMap<String, Vec<ListEntry>> = peers
        .iter()
        .map(|other| (other.id.clone(), other.entries.clone()))
        .collect();
    learn_lists(
        &mut state,
        &own.shares,
        ORIGIN,
        &served,
        &VoidShares::default(),
        &ListCache::default(),
    );
    assert!(state.is_valid_for_test(), "{state:?}");
    state
}

impl AccountState {
    fn is_valid_for_test(&self) -> bool {
        valid_state(&self.account_id, &self.peers, &self.stores)
    }
}

fn accepted(state: &AccountState, team: &str, key: &DeviceKey) -> bool {
    crate::connect::signer_policy(state)
        .for_team(team)
        .accepts(key.public_key())
}

fn left(state: &AccountState, team: &str, key: &DeviceKey) -> bool {
    crate::connect::signer_policy(state)
        .for_team(team)
        .left_key(key.public_key())
}

/// A, X, and Y of one family: A shares its store with X and Y, both join.
fn family() -> (List, List, List) {
    let (mut a, mut x, mut y) = (
        List::new("acc_aaaaaaaaab"),
        List::new("acc_xxxxxxxxxb"),
        List::new("acc_yyyyyyyyyb"),
    );
    a.peer(&x);
    a.peer(&y);
    a.share_store(&x.id.clone(), STORE);
    a.share_store(&y.id.clone(), STORE);
    x.peer(&a);
    x.join(&a, STORE);
    y.peer(&a);
    y.join(&a, STORE);
    (a, x, y)
}

#[test]
fn the_entries_of_section_16_follow_their_rules() {
    let (mut a, x) = (List::new("acc_aaaaaaaaab"), List::new("acc_xxxxxxxxxb"));
    // A share before the peer, a join before the peer, an unpeer of no peer: refused.
    for (op, team) in [
        (SHARE, Some(STORE)),
        (JOIN, Some(STORE)),
        (UNPEER, None),
        (UNSHARE, Some(STORE)),
        (LEAVE, Some(STORE)),
    ] {
        let mut early = List::new("acc_aaaaaaaaab");
        early.share(op, &x.id, None, team);
        assert!(early.verified().is_none(), "{op}");
    }
    a.peer(&x);
    let shares = a.verified().unwrap().shares;
    assert_eq!(shares.root_of(&x.id), Some(x.root.public_key()));
    // A second peer of the same account, a peer of itself: refused.
    let mut twice = List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries.clone(),
        hashes: a.hashes.clone(),
    };
    twice.peer(&x);
    assert!(twice.verified().is_none());
    let mut itself = List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries.clone(),
        hashes: a.hashes.clone(),
    };
    itself.share(PEER, &a.id.clone(), Some(a.root.public_key()), None);
    assert!(itself.verified().is_none());
    a.share_store(&x.id.clone(), STORE);
    // A store that this list shares is not one it joins; the same share again, and an
    // unpeer while a share names the peer, are refused.
    for (op, team) in [(JOIN, Some(STORE)), (SHARE, Some(STORE)), (UNPEER, None)] {
        let mut bad = List {
            id: a.id.clone(),
            root: a.root_signer(),
            entries: a.entries.clone(),
            hashes: a.hashes.clone(),
        };
        bad.share(op, &x.id, None, team);
        assert!(bad.verified().is_none(), "{op}");
    }
    let verified = a.verified().unwrap();
    assert_eq!(
        verified.shares.members_of(STORE),
        std::slice::from_ref(&x.id)
    );
    a.share(UNSHARE, &x.id.clone(), None, Some(STORE));
    a.share(UNPEER, &x.id.clone(), None, None);
    let verified = a.verified().unwrap();
    assert!(verified.shares.peers.is_empty() && verified.shares.shares.is_empty());
    // A root on a share, no root on a peer, a store on a peer, no store on a share, a key
    // on a share entry, an account on a device entry: refused.
    let shapes: [(&str, Option<String>, Option<String>); 4] = [
        (SHARE, Some(b64(&x.root)), Some(STORE.into())),
        (PEER, None, None),
        (PEER, Some(b64(&x.root)), Some(STORE.into())),
        (SHARE, None, None),
    ];
    for (op, root, team) in shapes {
        let mut bad = List::new("acc_aaaaaaaaab");
        bad.peer(&x);
        let mut entry = bad.entries.last().unwrap().clone();
        entry.version += 1;
        entry.op = op.into();
        entry.root = root;
        entry.team_id = team;
        bad.entries.push(entry);
        assert!(bad.verified().is_none(), "{op}");
    }
    let mut keyed = List::new("acc_aaaaaaaaab");
    keyed.peer(&x);
    keyed.entries[1].key = Some(b64(&x.root));
    assert!(keyed.verified().is_none());
    let mut named = List::new("acc_aaaaaaaaab");
    named.add(&key(), 1);
    named.entries[1].account_id = Some(x.id.clone());
    assert!(named.verified().is_none());
}

#[test]
fn a_removed_device_and_a_stranger_sign_no_share() {
    let x = List::new("acc_xxxxxxxxxb");
    let mut a = List::new("acc_aaaaaaaaab");
    let second = key();
    a.add(&second, 1);
    a.peer(&x);
    // The second device shares while it is a device.
    a.share_by(&second, SHARE, &x.id, None, Some(STORE));
    assert!(a.verified().is_some());
    // After its removal it signs nothing.
    let root = a.root_signer();
    a.device(&root, "remove", &second, None, None);
    let mut late = List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries.clone(),
        hashes: a.hashes.clone(),
    };
    late.share_by(&second, UNSHARE, &x.id, None, Some(STORE));
    assert!(late.verified().is_none());
    // A key that was never a device, and the service's own key, sign nothing.
    let mut stranger = List::new("acc_aaaaaaaaab");
    stranger.peer(&x);
    stranger.share_by(&key(), SHARE, &x.id, None, Some(STORE));
    assert!(stranger.verified().is_none());
    // A share signed by a device of the other account is no entry of this list.
    let mut by_x = List::new("acc_aaaaaaaaab");
    by_x.peer(&x);
    by_x.share_by(&x.root_signer(), SHARE, &x.id, None, Some(STORE));
    assert!(by_x.verified().is_none());
}

#[test]
fn old_share_bytes_at_another_version_or_in_another_list_are_refused() {
    let x = List::new("acc_xxxxxxxxxb");
    let mut a = List::new("acc_aaaaaaaaab");
    a.peer(&x);
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
    let share = a.entries.last().unwrap().clone();
    a.share(UNSHARE, &x.id.clone(), None, Some(STORE));
    assert!(a.verified().is_some());
    // The old share again, at the next version: its signature names the old version and
    // the hash before it.
    let mut replay = List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries.clone(),
        hashes: a.hashes.clone(),
    };
    let mut again = share.clone();
    again.version = replay.entries.len() as u64 + 1;
    replay.entries.push(again);
    assert!(replay.verified().is_none());
    // A share moved to another store or account: refused.
    for change in [
        |entry: &mut ListEntry| entry.team_id = Some(OTHER_STORE.into()),
        |entry: &mut ListEntry| entry.account_id = Some("acc_yyyyyyyyyb".into()),
    ] {
        let mut moved = List {
            id: a.id.clone(),
            root: a.root_signer(),
            entries: a.entries[..3].to_vec(),
            hashes: a.hashes[..3].to_vec(),
        };
        change(moved.entries.last_mut().unwrap());
        assert!(moved.verified().is_none());
    }
    // The list of another account with A's entry in it.
    let mut other = List::new("acc_bbbbbbbbbb");
    other.peer(&x);
    let mut taken = share;
    taken.version = 3;
    other.entries.push(taken);
    assert!(other.verified().is_none());
}

/// P1: devices of another account sign nothing in a store without a signed `share`, also
/// when Connect marks the store shared, lists the member's devices in it, and shows an
/// active group.
#[test]
fn without_a_share_entry_the_heads_of_another_account_are_refused() {
    let (mut a, x) = (List::new("acc_aaaaaaaaab"), List::new("acc_xxxxxxxxxb"));
    a.peer(&x);
    let state = refreshed(&a, &[&x]);
    // A is pinned to X (a peer), but no share names the store: X signs nothing there.
    assert!(store_signer_policy(&state, STORE).is_none());
    assert!(!accepted(&state, STORE, &x.root));
    assert!(!left(&state, STORE, &x.root));
    assert!(accepted(&state, STORE, &a.root));
    // With the share, X's verified devices sign.
    a.share_store(&x.id.clone(), STORE);
    let state = refreshed(&a, &[&x]);
    assert!(accepted(&state, STORE, &x.root));
    // Another store of A still takes none of X's keys.
    assert!(!accepted(&state, OTHER_STORE, &x.root));
}

/// P1: with a share, a list of X from another root suspends X, and a list with an extra
/// key that no device of X signed is not taken.
#[test]
fn a_list_of_another_root_or_with_an_unsigned_key_counts_for_nothing() {
    let (mut a, mut x) = (List::new("acc_aaaaaaaaab"), List::new("acc_xxxxxxxxxb"));
    let x2 = key();
    a.peer(&x);
    a.share_store(&x.id.clone(), STORE);
    let mut state = refreshed(&a, &[&x]);
    assert!(accepted(&state, STORE, &x.root));
    // An extra key in X's list that no device of X signed: the list does not verify, the
    // pin stays, and the key signs nothing.
    let mut forged = List {
        id: x.id.clone(),
        root: x.root_signer(),
        entries: x.entries.clone(),
        hashes: x.hashes.clone(),
    };
    forged.add(&x2, 1);
    forged.entries.last_mut().unwrap().signature = Some(encode_b64u(
        &x2.sign(b"apassy-connect device-list v1\0other").unwrap(),
    ));
    let pin = pin_mut(&mut state, &x.id, None).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &forged.entries, &ListCache::default());
    assert!(list.is_none() && !changed);
    assert!(!accepted(&state, STORE, &x2));
    // X's list from another root (Connect gives a new list): X is suspended. Its keys
    // sign only what this device had merged, and nothing of the new root signs.
    let reset = List::new("acc_xxxxxxxxxb");
    let pin = pin_mut(&mut state, &x.id, None).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &reset.entries, &ListCache::default());
    assert!(list.is_none() && changed);
    assert!(pin_of(&state, &x.id, None).unwrap().suspended);
    assert!(!accepted(&state, STORE, &x.root));
    assert!(left(&state, STORE, &x.root));
    assert!(!accepted(&state, STORE, &reset.root));
    assert!(!left(&state, STORE, &reset.root));
    // A real second device of X counts once X's own list signs it.
    x.add(&x2, 2);
    let state = refreshed(&a, &[&x]);
    assert!(accepted(&state, STORE, &x2));
}

/// P2: a second device of A and of X take the share from the lists, with no ceremony.
#[test]
fn a_second_device_of_each_person_reads_the_lists() {
    let (a, x, _) = family();
    // The second device of A has only A's list and X's list: the store's signers are A's
    // and X's devices.
    let a_second = refreshed(&a, &[&x]);
    assert!(accepted(&a_second, STORE, &x.root));
    assert!(accepted(&a_second, STORE, &a.root));
    // The second device of X: its own list joins A's store; A's list shares it with X.
    let x_second = refreshed(&x, &[&a]);
    let store = x_second
        .stores
        .iter()
        .find(|store| store.team_id == STORE)
        .unwrap();
    assert_eq!(store.owner, a.id);
    assert!(store.members.contains(&x.id));
    assert!(accepted(&x_second, STORE, &a.root));
    assert!(accepted(&x_second, STORE, &x.root));
}

/// A co-member's root comes from the owner's `peer` entry, and counts only in the
/// owner's stores: in a store of A, Y counts with the root that A's list names, also when
/// this account pinned another root for Y itself (that pin counts in this account's own
/// stores only).
#[test]
fn a_co_member_is_pinned_through_the_owner_only() {
    let (a, x, y) = family();
    let x_state = refreshed(&x, &[&a, &y]);
    let pin = pin_of(&x_state, &y.id, Some(&a.id)).unwrap();
    assert_eq!(pin.via.as_deref(), Some(a.id.as_str()));
    assert!(pin_of(&x_state, &y.id, None).is_none());
    assert!(accepted(&x_state, STORE, &y.root));
    assert!(!accepted(&x_state, OTHER_STORE, &y.root));
    // X pinned another root for Y itself: in A's store, A's naming counts.
    let other_y = List::new("acc_yyyyyyyyyb");
    let mut x_pins = List {
        id: x.id.clone(),
        root: x.root_signer(),
        entries: x.entries.clone(),
        hashes: x.hashes.clone(),
    };
    x_pins.peer(&other_y);
    let state = refreshed(&x_pins, &[&a, &y]);
    assert!(accepted(&state, STORE, &y.root));
    assert!(!accepted(&state, STORE, &other_y.root));
    assert!(state.stores[0].members.contains(&y.id));
}

/// P3 (unit): after `unshare`, X's keys move to the keys that ended in the store: a head
/// at the anchor stays, a later one is refused; on a co-member too. A `remove` in X's
/// list does the same for that device.
#[test]
fn an_unshare_and_a_remove_end_the_keys_of_the_store() {
    let (mut a, mut x, y) = family();
    let x2 = key();
    x.add(&x2, 3);
    let a_state = refreshed(&a, &[&x, &y]);
    assert!(accepted(&a_state, STORE, &x2));
    let mut y_state = refreshed(&y, &[&a, &x]);
    assert!(accepted(&y_state, STORE, &x2));
    assert!(accepted(&y_state, STORE, &x.root));
    // X removes its second device: it left X's list.
    let root = x.root_signer();
    x.device(&root, "remove", &x2, None, None);
    let a_state = refreshed(&a, &[&x, &y]);
    assert!(!accepted(&a_state, STORE, &x2) && left(&a_state, STORE, &x2));
    // A unshares the store with X: on A's second device X's keys ended.
    a.share(UNSHARE, &x.id.clone(), None, Some(STORE));
    let a_second = refreshed(&a, &[&x, &y]);
    // A's own list ended X's share: a fresh device takes X's keys as ended keys.
    assert!(!accepted(&a_second, STORE, &x.root) && left(&a_second, STORE, &x.root));
    let mut a_before = refreshed(&a_before_unshare(&a), &[&x, &y]);
    assert!(accepted(&a_before, STORE, &x.root));
    learn_own(&mut a_before, &a.verified().unwrap().shares);
    assert!(!accepted(&a_before, STORE, &x.root) && left(&a_before, STORE, &x.root));
    // The co-member Y learns it from A's list: X's keys ended there too.
    y_state = refresh_again(y_state, &y, &[&a, &x]);
    assert!(!accepted(&y_state, STORE, &x.root) && left(&y_state, STORE, &x.root));
    assert!(accepted(&y_state, STORE, &a.root));
    // X itself: the share ended here, nothing new merges.
    let x_state = refreshed(&x, &[&a, &y]);
    let policy = store_signer_policy(&x_state, STORE).unwrap();
    assert!(policy.accepted.is_empty());
    assert!(policy.left.contains(&a.root.public_key().to_vec()));
}

/// `a` without its last entry (the `unshare` of the test above).
fn a_before_unshare(a: &List) -> List {
    let keep = a.entries.len() - 1;
    List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries[..keep].to_vec(),
        hashes: a.hashes[..keep].to_vec(),
    }
}

/// P4: a share from another account than the owner of the store counts for nothing for
/// it: X joined A's store, and B's list also names that store for X.
#[test]
fn another_peer_naming_the_store_gives_it_no_signer() {
    let (a, mut x, _) = family();
    let mut b = List::new("acc_bbbbbbbbbb");
    b.peer(&x);
    b.share_store(&x.id.clone(), STORE);
    x.peer(&b);
    let state = refreshed(&x, &[&a, &b]);
    assert!(accepted(&state, STORE, &a.root));
    assert!(!accepted(&state, STORE, &b.root));
    assert!(!left(&state, STORE, &b.root));
    // And a join of the same store from another owner is refused by the list itself.
    x.join(&b, STORE);
    assert!(x.verified().is_none());
}

/// P4: a forked list, a cut list, and an older list of the owner are not taken: the pin
/// keeps what it had.
#[test]
fn a_fork_or_an_older_list_of_a_peer_is_not_taken() {
    let (a, x, _) = family();
    let mut state = refreshed(&x, &[&a]);
    let before = state.clone();
    // A's list cut before its last entry: older than the pin.
    let pin = pin_mut(&mut state, &a.id, None).unwrap();
    let (list, changed) = take_peer_list(
        pin,
        ORIGIN,
        &a.entries[..a.entries.len() - 1],
        &ListCache::default(),
    );
    assert!(list.is_none() && !changed);
    // Another history of A from version 2 on.
    let mut fork = List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries[..1].to_vec(),
        hashes: a.hashes[..1].to_vec(),
    };
    fork.add(&key(), 9);
    let pin = pin_mut(&mut state, &a.id, None).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &fork.entries, &ListCache::default());
    assert!(list.is_none() && !changed);
    assert_eq!(state, before);
}

#[test]
fn the_account_file_bounds_its_peers_and_stores() {
    let (a, x, y) = family();
    let state = refreshed(&a, &[&x, &y]);
    assert!(state.is_valid_for_test());
    let mut bad = state.clone();
    bad.peers.push(bad.peers[0].clone());
    assert!(!bad.is_valid_for_test());
    let mut bad = state.clone();
    bad.peers[0].known = vec![b64(&x.root); MAX_PEER_KNOWN + 1];
    assert!(!bad.is_valid_for_test());
    let mut bad = state.clone();
    bad.stores[0].owner = a.id.clone();
    assert!(!bad.is_valid_for_test());
    let mut bad = state;
    bad.stores[0].ended = vec![x.id.clone(); MAX_ENDED + 1];
    assert!(!bad.is_valid_for_test());
}

// ---- Second pass: the pins of co-members, the ended keys, and the bounds. ----

const S1: &str = "t_s3aaaaaaaa";
const S2: &str = "t_s4aaaaaaaa";

/// X joined S1 of A and S2 of B; A shares S1 with X and `y_a`, B shares S2 with X and
/// `y_b` (two lists of one account Y, or the same list).
fn two_owners(y_a: &List, y_b: &List) -> (List, List, List) {
    let (mut a, mut b, mut x) = (
        List::new("acc_aaaaaaaaab"),
        List::new("acc_bbbbbbbbbb"),
        List::new("acc_xxxxxxxxxb"),
    );
    for (owner, y, team) in [(&mut a, y_a, S1), (&mut b, y_b, S2)] {
        owner.peer(&x);
        owner.peer(y);
        owner.share_store(&x.id.clone(), team);
        owner.share_store(&y.id.clone(), team);
    }
    x.peer(&a);
    x.peer(&b);
    x.join(&a, S1);
    x.join(&b, S2);
    (a, b, x)
}

/// C1: a co-member that two owners name with one root counts in both stores.
#[test]
fn two_owners_naming_one_co_member_with_one_root_count_in_both_stores() {
    let y = List::new("acc_yyyyyyyyyb");
    let (a, b, x) = two_owners(&y, &y);
    let state = refreshed(&x, &[&a, &b, &y]);
    assert!(accepted(&state, S1, &y.root));
    assert!(accepted(&state, S2, &y.root));
}

/// C1: two owners that name different roots for one co-member (Y reset its account, B
/// pinned the new root, A not yet): each root counts only in the stores of the owner
/// that named it. The new root signs in B's store; in A's store the old root's pin is
/// suspended by the new list, and the new key signs nothing.
#[test]
fn conflicting_roots_of_one_co_member_stay_apart() {
    let y_old = List::new("acc_yyyyyyyyyb");
    let y_new = List::new("acc_yyyyyyyyyb");
    let (a, b, x) = two_owners(&y_old, &y_new);
    let state = refreshed(&x, &[&a, &b, &y_new]);
    assert!(
        accepted(&state, S2, &y_new.root),
        "B's naming counts in B's store"
    );
    assert!(!accepted(&state, S1, &y_new.root), "not in A's store");
    assert!(!accepted(&state, S1, &y_old.root));
}

/// C1: when an owner pins a co-member anew (after its reset), the old keys of that
/// co-member are kept as keys that left in that owner's store, not forgotten.
#[test]
fn a_re_pin_by_the_owner_keeps_the_old_keys_as_keys_that_left() {
    let y_old = List::new("acc_yyyyyyyyyb");
    let (mut a, mut x) = (List::new("acc_aaaaaaaaab"), List::new("acc_xxxxxxxxxb"));
    a.peer(&x);
    a.peer(&y_old);
    a.share_store(&x.id.clone(), S1);
    a.share_store(&y_old.id.clone(), S1);
    x.peer(&a);
    x.join(&a, S1);
    let state = refreshed(&x, &[&a, &y_old]);
    assert!(accepted(&state, S1, &y_old.root));
    // Y resets; A pins the new root after new words and shares again. X's next refresh
    // takes A's new naming of Y.
    let y_new = List::new("acc_yyyyyyyyyb");
    let y_id = y_new.id.clone();
    a.share(UNSHARE, &y_id, None, Some(S1));
    a.share(UNPEER, &y_id, None, None);
    a.peer(&y_new);
    a.share(SHARE, &y_id, None, Some(S1));
    let state = refresh_again(state, &x, &[&a, &y_new]);
    assert!(accepted(&state, S1, &y_new.root));
    assert!(
        left(&state, S1, &y_old.root),
        "the old key signs what was merged before"
    );
}

/// C1: a co-member that one owner stops naming keeps the pin that another owner's store
/// needs, with its version: a cut list of it is not taken afterwards.
#[test]
fn a_pin_that_another_store_needs_stays_when_one_owner_drops_the_member() {
    let mut y = List::new("acc_yyyyyyyyyb");
    let (mut a, b, x) = two_owners(&y, &y);
    let y2 = key();
    y.add(&y2, 4);
    let root = y.root_signer();
    let before_removal = y.entries.clone();
    y.device(&root, "remove", &y2, None, None);
    // X read Y's list with the removal of y2.
    let state = refreshed(&x, &[&a, &b, &y]);
    assert!(accepted(&state, S2, &y.root) && !accepted(&state, S2, &y2));
    // A stops sharing S1 with Y; B still shares S2 with Y. Then Connect serves Y's list
    // cut before the removal: the pin that S2 needs keeps its version and takes nothing.
    a.share(UNSHARE, &y.id.clone(), None, Some(S1));
    let cut = List {
        id: y.id.clone(),
        root: y.root_signer(),
        entries: before_removal,
        hashes: Vec::new(),
    };
    let state = refresh_again(state, &x, &[&a, &b, &cut]);
    assert!(accepted(&state, S2, &y.root), "B still shares S2 with Y");
    assert!(
        !accepted(&state, S2, &y2),
        "a cut list brings no removed key back"
    );
    assert!(!accepted(&state, S1, &y.root));
}

/// C1: a round in which one owner's list is not served changes nothing of that owner's
/// store or of the other owner's store.
#[test]
fn one_owners_list_missing_in_a_round_leaves_the_other_store_alone() {
    let y = List::new("acc_yyyyyyyyyb");
    let (a, b, x) = two_owners(&y, &y);
    let state = refreshed(&x, &[&a, &b, &y]);
    assert!(accepted(&state, S1, &y.root) && accepted(&state, S2, &y.root));
    let without_a = refresh_again(state, &x, &[&b, &y]);
    assert!(accepted(&without_a, S1, &y.root));
    assert!(accepted(&without_a, S2, &y.root));
}

/// C5: a device of the owner that reads the `share` and the `unshare` of a member at
/// once (it was offline in between) holds that member's keys as ended keys of the store:
/// the member's heads below an accepted head stay in the chain.
#[test]
fn a_device_that_reads_a_share_and_its_end_at_once_holds_the_ended_keys() {
    let (mut a, x, y) = family();
    a.share(UNSHARE, &x.id.clone(), None, Some(STORE));
    let fresh = refreshed(&a, &[&x, &y]);
    assert!(!accepted(&fresh, STORE, &x.root));
    assert!(
        left(&fresh, STORE, &x.root),
        "the member's key signs below an accepted head and up to the anchor"
    );
}

/// C8: the own pins (one for each `peer` of the own list, at most 64) have a cap of
/// their own beside the pins through the owners of joined stores.
#[test]
fn own_pins_and_pins_through_owners_have_caps_of_their_own() {
    let mut a = List::new("acc_aaaaaaaaab");
    let mut x = List::new("acc_xxxxxxxxxb");
    let members: Vec<List> = (0..4)
        .map(|index| List::new(&format!("acc_mmmmmmmm{}b", ["a", "b", "c", "d"][index])))
        .collect();
    a.peer(&x);
    a.share_store(&x.id.clone(), STORE);
    for member in &members {
        a.peer(member);
        a.share_store(&member.id.clone(), STORE);
    }
    x.peer(&a);
    x.join(&a, STORE);
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let others: Vec<List> = (0..63)
        .map(|index| {
            let (hi, lo) = (index / 32, index % 32);
            List::new(&format!(
                "acc_pppppppp{}{}",
                &alphabet[hi..=hi],
                &alphabet[lo..=lo]
            ))
        })
        .collect();
    for other in &others {
        x.peer(other);
    }
    let mut all: Vec<&List> = vec![&a];
    all.extend(members.iter());
    let state = refreshed(&x, &all);
    let own = state.peers.iter().filter(|pin| pin.via.is_none()).count();
    assert_eq!(own, 64, "every peer of the own list is pinned");
    for member in &members {
        assert!(accepted(&state, STORE, &member.root));
    }
}

/// A copy of `list` to go on with.
fn fork(list: &List) -> List {
    List {
        id: list.id.clone(),
        root: list.root_signer(),
        entries: list.entries.clone(),
        hashes: list.hashes.clone(),
    }
}

/// An account id of section 2 for the number `index` (below 1024), with the prefix `p`.
fn numbered(prefix: &str, index: usize) -> String {
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let (hi, lo) = (index / 32, index % 32);
    format!("acc_{prefix}{}{}", &alphabet[hi..=hi], &alphabet[lo..=lo])
}

const S3: &str = "t_s5aaaaaaaa";

/// C8: an entry that adds something (`add`, `peer`, `share`, `join`) comes at version 822
/// at most, on the client as on Connect; with 10 live devices, 64 peers, and 128 shares at
/// 822, every one of them can be ended up to version 1024, the last device by itself.
#[test]
fn the_adding_entries_stop_at_822_and_the_ends_go_on_to_1024() {
    let mut base = List::new("acc_aaaaaaaaab");
    let devices: Vec<DeviceKey> = (0..9).map(|_| key()).collect();
    for (index, device) in devices.iter().enumerate() {
        base.add(device, index as u8 + 1);
    }
    let peers: Vec<List> = (0..MAX_PEERS)
        .map(|index| List::new(&numbered("qqqqqqqq", index)))
        .collect();
    for peer in &peers {
        base.peer(peer);
    }
    base.store(S1);
    base.store(S2);
    for peer in &peers {
        base.share(SHARE, &peer.id.clone(), None, Some(S1));
        base.share(SHARE, &peer.id.clone(), None, Some(S2));
    }
    assert_eq!(base.entries.len(), 1 + 9 + MAX_PEERS + 2 + MAX_SHARED);
    let first = peers[0].id.clone();
    let second = peers[1].id.clone();
    while base.entries.len() < 818 {
        base.share(UNSHARE, &first, None, Some(S1));
        base.share(SHARE, &first, None, Some(S1));
    }
    let full = base.verified().expect("full at 818");
    assert_eq!(
        (
            full.live.len(),
            full.shares.peers.len(),
            full.shares.shares.len()
        ),
        (10, 64, 128)
    );
    // Each adding kind at 822 is taken.
    let mut share_822 = fork(&base);
    for op in [UNSHARE, SHARE, UNSHARE, SHARE] {
        share_822.share(op, &first, None, Some(S1));
    }
    assert_eq!(share_822.entries.len(), 822);
    assert!(share_822.verified().is_some(), "a share at 822");
    let mut join_822 = fork(&base);
    join_822.share(UNSHARE, &first, None, Some(S1));
    join_822.share(UNSHARE, &first, None, Some(S2));
    join_822.share(UNSHARE, &second, None, Some(S1));
    join_822.share(JOIN, &second, None, Some(S3));
    assert!(join_822.verified().is_some(), "a join at 822");
    let mut peer_822 = fork(&base);
    peer_822.share(UNSHARE, &first, None, Some(S1));
    peer_822.share(UNSHARE, &first, None, Some(S2));
    peer_822.share(UNPEER, &first, None, None);
    peer_822.peer(&peers[0]);
    assert!(peer_822.verified().is_some(), "a peer at 822");
    let mut add_822 = fork(&base);
    add_822.share(UNSHARE, &first, None, Some(S1));
    add_822.share(UNSHARE, &first, None, Some(S2));
    let root = add_822.root_signer();
    add_822.device(&root, "remove", &devices[0], None, None);
    add_822.add(&key(), 200);
    assert!(add_822.verified().is_some(), "an add at 822");
    let mut store_822 = fork(&base);
    for op in [UNSHARE, SHARE, UNSHARE] {
        store_822.share(op, &first, None, Some(S1));
    }
    store_822.store(S3);
    assert_eq!(store_822.entries.len(), 822);
    assert!(store_822.verified().is_some(), "a store at 822");
    // At 823 each adding kind is refused, also with room in the counts.
    let mut late = fork(&base);
    late.share(UNSHARE, &first, None, Some(S1));
    late.share(UNSHARE, &first, None, Some(S2));
    late.share(UNPEER, &first, None, None);
    let late_root = late.root_signer();
    late.device(&late_root, "remove", &devices[0], None, None);
    assert!(late.verified().is_some());
    let refused = |step: &dyn Fn(&mut List)| {
        let mut list = fork(&late);
        step(&mut list);
        assert_eq!(list.entries.len(), 823);
        list.verified().is_none()
    };
    assert!(refused(&|list| list.peer(&peers[0])), "a peer at 823");
    assert!(
        refused(&|list| list.share(SHARE, &second, None, Some(S3))),
        "a share at 823"
    );
    assert!(
        refused(&|list| list.share(JOIN, &second, None, Some(S3))),
        "a join at 823"
    );
    assert!(refused(&|list| list.add(&key(), 201)), "an add at 823");
    assert!(refused(&|list| list.store(S3)), "a store at 823");
    // From the full state at 822, every share, peer, and device ends up to 1024.
    let mut ends = share_822;
    for peer in &peers {
        ends.share(UNSHARE, &peer.id.clone(), None, Some(S1));
        ends.share(UNSHARE, &peer.id.clone(), None, Some(S2));
    }
    for peer in &peers {
        ends.share(UNPEER, &peer.id.clone(), None, None);
    }
    let root = ends.root_signer();
    for device in &devices {
        ends.device(&root, "remove", device, None, None);
    }
    let root_key = ends.root_signer();
    ends.device(&root_key, "remove", &root_key, None, None);
    assert_eq!(ends.entries.len(), trust::MAX_LIST);
    let ended = ends.verified().expect("the ends up to 1024");
    assert!(ended.live.is_empty() && ended.shares.peers.is_empty());
}

/// C8: the keys that left a pin keep the newest (32) and never a live key; the ended
/// accounts of a store keep the newest ends (64).
#[test]
fn the_keys_that_left_and_the_ended_accounts_keep_their_newest() {
    let mut x = List::new("acc_xxxxxxxxxb");
    let live = key();
    x.add(&live, 1);
    let passing: Vec<DeviceKey> = (0..40).map(|_| key()).collect();
    let root = x.root_signer();
    for (index, device) in passing.iter().enumerate() {
        x.add(device, index as u8 + 2);
        x.device(&root, "remove", device, None, None);
    }
    let mut a = List::new("acc_aaaaaaaaab");
    a.peer(&x);
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
    let state = refreshed(&a, &[&x]);
    let pin = pin_of(&state, &x.id, None).unwrap();
    assert_eq!(pin.left.len(), MAX_PEER_LEFT);
    assert!(pin.left.contains(&b64(&passing[39])));
    assert!(!pin.left.contains(&b64(&passing[0])));
    assert!(!pin.left.contains(&b64(&live)) && pin.known.contains(&b64(&live)));
    // 65 accounts each shared and ended in one store: the oldest end goes.
    let mut owner = List::new("acc_aaaaaaaaab");
    let members: Vec<List> = (0..=MAX_ENDED)
        .map(|index| List::new(&numbered("rrrrrrrr", index)))
        .collect();
    for member in &members {
        owner.peer(member);
        owner.share(SHARE, &member.id.clone(), None, Some(STORE));
        owner.share(UNSHARE, &member.id.clone(), None, Some(STORE));
        owner.share(UNPEER, &member.id.clone(), None, None);
    }
    let state = state_of(&owner);
    let store = state
        .stores
        .iter()
        .find(|store| store.team_id == STORE)
        .unwrap();
    assert_eq!(store.ended.len(), MAX_ENDED);
    assert!(!store.ended.contains(&members[0].id));
    assert!(store.ended.contains(&members[MAX_ENDED].id));
}

// ---- Third pass: the `store` entry, the share that a join answers, the cleanup. ----

/// F10: `store S` comes once and never for a store that the list joins; a share of S
/// counts only once the list holds `store S`; a store that the list made is never joined.
#[test]
fn a_store_entry_makes_the_shares_of_a_store_count() {
    let (mut a, mut x) = (List::new("acc_aaaaaaaaab"), List::new("acc_xxxxxxxxxb"));
    a.peer(&x);
    // A share before the store entry (a list of an earlier build) verifies, and counts for
    // nothing: no member, no share for a join to name, no signer.
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
    let shares = a.verified().unwrap().shares;
    assert!(shares.members_of(STORE).is_empty());
    assert!(shares.share_hash(STORE, &x.id).is_none());
    assert!(!accepted(&refreshed(&a, &[&x]), STORE, &x.root));
    a.store(STORE);
    let shares = a.verified().unwrap().shares;
    assert_eq!(shares.members_of(STORE), vec![x.id.clone()]);
    assert!(shares.made(STORE));
    assert!(accepted(&refreshed(&a, &[&x]), STORE, &x.root));
    // The same store twice, a store that names an account or a root: refused.
    let mut twice = fork(&a);
    twice.store(STORE);
    assert!(twice.verified().is_none());
    for (peer, root) in [(Some(x.id.as_str()), None), (None, Some(b64(&x.root)))] {
        let mut named = fork(&a);
        let signer = named.root_signer();
        named.entry_by(&signer, STORE_OP, peer, root, Some(OTHER_STORE));
        assert!(named.verified().is_none(), "{peer:?}");
    }
    // X: a store that it joined is not one that it made, and one that it made is not joined.
    x.peer(&a);
    x.join(&a, STORE);
    let mut claims = fork(&x);
    claims.store(STORE);
    assert!(claims.verified().is_none());
    let mut made_first = List::new("acc_xxxxxxxxxb");
    made_first.peer(&a);
    made_first.store(STORE);
    made_first.join(&a, STORE);
    assert!(made_first.verified().is_none());
}

/// F2: a join names the share that it answers. After the owner's `unshare` the join is over
/// without a `leave`, a new share leaves it over until the member joins that share, and the
/// same share is not joined twice. A join without a share (an earlier build) counts for
/// nothing.
#[test]
fn a_join_counts_only_while_the_share_it_answers_is_active() {
    let (mut a, mut x, y) = family();
    let state = refreshed(&x, &[&a, &y]);
    assert!(accepted(&state, STORE, &a.root) && accepted(&state, STORE, &y.root));
    let mut twice = fork(&x);
    twice.join(&a, STORE);
    assert!(twice.verified().is_none(), "the same share twice");
    // A ends the share with X: X's join is over, though X signed no leave.
    a.share(UNSHARE, &x.id.clone(), None, Some(STORE));
    let state = refresh_again(state, &x, &[&a, &y]);
    let policy = store_signer_policy(&state, STORE).unwrap();
    assert!(policy.accepted.is_empty(), "{policy:?}");
    assert!(
        pin_of(&state, &y.id, Some(&a.id)).is_none(),
        "no co-member pin"
    );
    // A shares again: X's join answers the old share, so the store stays ended here.
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
    let state = refresh_again(state, &x, &[&a, &y]);
    assert!(
        store_signer_policy(&state, STORE)
            .unwrap()
            .accepted
            .is_empty()
    );
    // X joins the new share: one join for the pair, and the store signs again.
    x.join(&a, STORE);
    let shares = x.verified().unwrap().shares;
    assert_eq!(shares.joins, vec![(STORE.to_owned(), a.id.clone())]);
    assert_eq!(
        shares.join_share(STORE, &a.id),
        Some(a.share_hash(STORE, &x.id).as_str())
    );
    let state = refresh_again(state, &x, &[&a, &y]);
    assert!(accepted(&state, STORE, &a.root) && accepted(&state, STORE, &y.root));
    // A join of another owner's store while one is active is refused, as before.
    let mut b = List::new("acc_bbbbbbbbbb");
    b.peer(&x);
    b.share_store(&x.id.clone(), STORE);
    let mut other = fork(&x);
    other.peer(&b);
    other.join(&b, STORE);
    assert!(other.verified().is_none());
    // A join without the share that it answers.
    let mut legacy = List::new("acc_xxxxxxxxxb");
    legacy.peer(&a);
    legacy.share(JOIN, &a.id.clone(), None, Some(STORE));
    let state = refreshed(&legacy, &[&a, &y]);
    assert!(
        store_signer_policy(&state, STORE)
            .unwrap()
            .accepted
            .is_empty()
    );
    // A leave names the share of the join that it ended.
    x.share(LEAVE, &a.id.clone(), None, Some(STORE));
    let shares = x.verified().unwrap().shares;
    assert!(shares.left_share(STORE, &a.id, &a.share_hash(STORE, &x.id)));
}

/// F8: a store that this account left goes from the file, with the pins that only it
/// needed; the own pin of its owner stays while the own list pins it.
#[test]
fn a_left_store_goes_with_its_pins() {
    let (a, mut x, y) = family();
    let state = refreshed(&x, &[&a, &y]);
    assert!(pin_of(&state, &y.id, Some(&a.id)).is_some());
    x.share(LEAVE, &a.id.clone(), None, Some(STORE));
    let state = refresh_again(state, &x, &[&a, &y]);
    assert!(state.stores.iter().all(|store| store.team_id != STORE));
    assert!(pin_of(&state, &y.id, Some(&a.id)).is_none());
    assert!(store_signer_policy(&state, STORE).is_none());
    assert!(pin_of(&state, &a.id, None).is_some());
}

/// F8: at 256 pins through owners the pins that no store needs any more go before a new
/// co-member is refused: X joined O0's store, whose 63 co-members ended (their pins hold
/// their keys as ended keys), and O1 to O3's (63 co-members each, 252 pins); X leaves O0's
/// store, and O4 shares with 63 new co-members in the same round.
#[test]
fn at_the_pin_cap_the_pins_that_no_store_needs_go_first() {
    let teams = [
        "t_saaaaaaaaa",
        "t_sbaaaaaaaa",
        "t_scaaaaaaaa",
        "t_sdaaaaaaaa",
        "t_seaaaaaaaa",
    ];
    let mut x = List::new("acc_xxxxxxxxxb");
    let mut owners: Vec<List> = (0..5)
        .map(|i| List::new(&numbered("oooooooo", i)))
        .collect();
    let members: Vec<Vec<List>> = (0..5)
        .map(|i| {
            let prefix = format!("mmmmmmm{}", ["a", "b", "c", "d", "e"][i]);
            (0..63).map(|j| List::new(&numbered(&prefix, j))).collect()
        })
        .collect();
    for (i, owner) in owners.iter_mut().enumerate() {
        owner.peer(&x);
        owner.share_store(&x.id.clone(), teams[i]);
        if i < 4 {
            for member in &members[i] {
                owner.peer(member);
                owner.share(SHARE, &member.id.clone(), None, Some(teams[i]));
            }
        }
    }
    for member in &members[0] {
        owners[0].share(UNSHARE, &member.id.clone(), None, Some(teams[0]));
    }
    for (i, owner) in owners.iter().enumerate() {
        x.peer(owner);
        x.join(owner, teams[i]);
    }
    let via = |state: &AccountState| state.peers.iter().filter(|pin| pin.via.is_some()).count();
    let state = refreshed(&x, &owners.iter().collect::<Vec<_>>());
    assert_eq!(via(&state), 252);
    for member in &members[0] {
        assert!(
            pin_of(&state, &member.id, Some(&owners[0].id)).is_some(),
            "the pin of an ended account"
        );
    }
    // One round: X leaves O0's store, and O4 shares with 63 new co-members.
    x.share(LEAVE, &owners[0].id.clone(), None, Some(teams[0]));
    for member in &members[4] {
        owners[4].peer(member);
        owners[4].share(SHARE, &member.id.clone(), None, Some(teams[4]));
    }
    let mut state = state;
    let own = x.verified().unwrap();
    let lists: BTreeMap<String, Vec<ListEntry>> = owners
        .iter()
        .map(|list| (list.id.clone(), list.entries.clone()))
        .collect();
    let learned = learn_lists(
        &mut state,
        &own.shares,
        ORIGIN,
        &lists,
        &VoidShares::default(),
        &ListCache::default(),
    );
    assert!(
        learned.unpinned.is_empty(),
        "{} unpinned",
        learned.unpinned.len()
    );
    let store = state
        .stores
        .iter()
        .find(|store| store.team_id == teams[4])
        .unwrap();
    for member in &members[4] {
        assert!(pin_of(&state, &member.id, Some(&owners[4].id)).is_some());
        assert!(store.members.contains(&member.id));
    }
    assert_eq!(via(&state), 252);
}
