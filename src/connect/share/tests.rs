//! The rules of section 16 on lists that a test builds as Connect would keep them, and
//! the trust store and the signers of a shared store after each list.

use super::*;
use crate::connect::device_key::{list_hash, list_message};
use crate::sync::DeviceKey;

const ORIGIN: &str = "https://connect.example.test";
const STORE: &str = "t_7k2m5q4x3c";
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
        let version = self.entries.len() as u64 + 1;
        let root_b64u = root.map(encode_b64u);
        let message = share_list_message(
            ORIGIN,
            &self.id,
            version,
            &self.previous(),
            op,
            peer,
            root_b64u.as_deref().unwrap_or(LIST_NONE),
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
            account_id: Some(peer.to_owned()),
            root: root_b64u,
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
    let mut state = state_of(list);
    let own = list.verified().unwrap();
    for _ in 0..2 {
        for other in peers {
            let Some(pin) = peer_mut(&mut state, &other.id) else {
                continue;
            };
            let (verified, _) = take_peer_list(pin, ORIGIN, &other.entries);
            if let Some(verified) = verified {
                let teams: Vec<String> = own
                    .shares
                    .joins
                    .iter()
                    .filter(|(_, owner)| *owner == other.id)
                    .map(|(team, _)| team.clone())
                    .collect();
                learn_owner(&mut state, &other.id, &verified, &teams);
            }
        }
    }
    drop_unused_pins(&mut state);
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
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
    a.share(SHARE, &y.id.clone(), None, Some(STORE));
    x.peer(&a);
    x.share(JOIN, &a.id.clone(), None, Some(STORE));
    y.peer(&a);
    y.share(JOIN, &a.id.clone(), None, Some(STORE));
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
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
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
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
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
    a.share(SHARE, &x.id.clone(), None, Some(STORE));
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
    let pin = peer_mut(&mut state, &x.id).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &forged.entries);
    assert!(list.is_none() && !changed);
    assert!(!accepted(&state, STORE, &x2));
    // X's list from another root (Connect gives a new list): X is suspended. Its keys
    // sign only what this device had merged, and nothing of the new root signs.
    let reset = List::new("acc_xxxxxxxxxb");
    let pin = peer_mut(&mut state, &x.id).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &reset.entries);
    assert!(list.is_none() && changed);
    assert!(peer(&state, &x.id).unwrap().suspended);
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
/// owner's stores; a root that differs from this account's own pin of it counts for
/// nothing there.
#[test]
fn a_co_member_is_pinned_through_the_owner_only() {
    let (a, x, y) = family();
    let x_state = refreshed(&x, &[&a, &y]);
    let pin = peer(&x_state, &y.id).unwrap();
    assert_eq!(pin.via.as_deref(), Some(a.id.as_str()));
    assert!(accepted(&x_state, STORE, &y.root));
    assert!(!accepted(&x_state, OTHER_STORE, &y.root));
    // X pinned another root for Y itself: Y signs nothing in A's store.
    let other_y = List::new("acc_yyyyyyyyyb");
    let mut x_pins = List {
        id: x.id.clone(),
        root: x.root_signer(),
        entries: x.entries.clone(),
        hashes: x.hashes.clone(),
    };
    x_pins.peer(&other_y);
    let state = refreshed(&x_pins, &[&a, &y]);
    assert!(!accepted(&state, STORE, &y.root));
    assert!(!state.stores[0].members.contains(&y.id));
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
    let mut a_second = state_of(&a);
    for other in [&x, &y] {
        let pin = peer_mut(&mut a_second, &other.id).unwrap();
        take_peer_list(pin, ORIGIN, &other.entries);
    }
    // A's own list dropped X from the members before X's list was read: the keys that
    // a fresh device learns later are not X's to sign any more either.
    assert!(!accepted(&a_second, STORE, &x.root));
    let mut a_before = refreshed(&a_before_unshare(&a), &[&x, &y]);
    assert!(accepted(&a_before, STORE, &x.root));
    learn_own(&mut a_before, &a.verified().unwrap().shares);
    assert!(!accepted(&a_before, STORE, &x.root) && left(&a_before, STORE, &x.root));
    // The co-member Y learns it from A's list: X's keys ended there too.
    let pin = peer_mut(&mut y_state, &a.id).unwrap();
    let (verified, _) = take_peer_list(pin, ORIGIN, &a.entries);
    learn_owner(&mut y_state, &a.id, &verified.unwrap(), &[STORE.to_owned()]);
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
    b.share(SHARE, &x.id.clone(), None, Some(STORE));
    x.peer(&b);
    let state = refreshed(&x, &[&a, &b]);
    assert!(accepted(&state, STORE, &a.root));
    assert!(!accepted(&state, STORE, &b.root));
    assert!(!left(&state, STORE, &b.root));
    // And a join of the same store from another owner is refused by the list itself.
    x.share(JOIN, &b.id.clone(), None, Some(STORE));
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
    let pin = peer_mut(&mut state, &a.id).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &a.entries[..a.entries.len() - 1]);
    assert!(list.is_none() && !changed);
    // Another history of A from version 2 on.
    let mut fork = List {
        id: a.id.clone(),
        root: a.root_signer(),
        entries: a.entries[..1].to_vec(),
        hashes: a.hashes[..1].to_vec(),
    };
    fork.add(&key(), 9);
    let pin = peer_mut(&mut state, &a.id).unwrap();
    let (list, changed) = take_peer_list(pin, ORIGIN, &fork.entries);
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
    bad.stores[0].ended = vec![b64(&x.root); MAX_ENDED + 1];
    assert!(!bad.is_valid_for_test());
}
