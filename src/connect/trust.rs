//! The device list of a Connect account is a signed list with a cryptographic root
//! (contract connect-account-v1 section 7.5): this device checks it itself, and Connect
//! only carries it.
//!
//! - The **list** ([`ListEntry`]): version 1 is the root key (the device that made the
//!   account, or the device of the last recovery), signed by that key over its own name.
//!   Each later version is one change, an `add` (through a link, with the name of the new
//!   device) or a `remove`, signed by a device that the list holds at the version before,
//!   over `apassy-connect device-list v1` with the hash of the entry before
//!   (`super::device_key::list_message`). So every change names the whole history before
//!   it, a name stays with the key it was signed for, and a device confirmed by a device
//!   that left later stays a device: its `add` precedes the `remove`. A key that was in the
//!   list is never added again, and an `add` comes only while every device can still be
//!   removed before the list is full ([`MAX_ADD_VERSION`]).
//! - The same list holds the entries that name another account (section 16,
//!   `super::share`): `peer` and `unpeer` (the pinned root of another account), `share`
//!   and `unshare` (a vault store of this account and that account), `join` and `leave` (a
//!   store of that account that this account syncs), and `store` (a vault store that this
//!   account made). They share the version and the `previous` hash of the device entries,
//!   so a removed device signs none of them, and every entry that adds something (`add`,
//!   `peer`, `share`, `join`, `store`) leaves room to end every device, peer, share, and
//!   join before the list is full.
//! - The **pin** of this device (in the account file): the root, and the highest version
//!   and the hash of the list that it verified. [`verify_list`] takes a list only when it
//!   starts at the pinned root and every entry verifies; [`Pin::accepts`] takes it only when
//!   it is not older than the pin and holds the pinned entry at its version (no fork).
//! - [`learn`] then moves the known keys (the devices of the list at the pin) and the keys
//!   that this device knew and that left.
//!
//! Every key taken from Connect must be a point of P-256 ([`valid_key`]).

use serde::Deserialize;

use super::device_key::{LIST_NONE, list_hash, list_message};
use super::share::{self, ListShares, MAX_PEERS, MAX_SHARED};
use crate::sync::{decode_b64u, encode_b64u, verify_signature};

/// The most entries of a device list (the relay's limit).
pub const MAX_LIST: usize = 1024;
/// The most live devices of an account (contract section 13).
pub const MAX_LIVE: usize = 10;
/// The highest version of an entry that adds something (`add`, `peer`, `share`, `join`,
/// `store`): the list keeps room to end every live device (also the last one, by itself),
/// every peer, and every share and join before it is full (1024 − 10 − 64 − 128 = 822; a
/// `store` needs no end), and a recovery starts a new list.
pub const MAX_ADD_VERSION: u64 = (MAX_LIST - MAX_LIVE - MAX_PEERS - MAX_SHARED) as u64;
/// The list is nearly full when this many versions or fewer are left for an `add`: the
/// app says so ahead of time.
pub const ADDS_LEFT_WARNING: u64 = 20;
/// The most bytes of a device name (section 2).
const MAX_NAME_BYTES: usize = 64;
/// The most keys of the known devices in the trust store.
pub const MAX_KNOWN: usize = 64;
/// The most keys of devices that left the account in the trust store. A key that drops
/// out signs nothing here any more: that is the safe side.
pub const MAX_LEFT: usize = 128;

/// One entry of the device list, as Connect carries it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ListEntry {
    pub version: u64,
    /// `root`, `add`, or `remove`; or one of section 16: `peer`, `unpeer`, `share`,
    /// `unshare`, `join`, `leave`, `store`.
    pub op: String,
    /// b64u of the key that the entry adds or removes (the root key for `root`); `None`
    /// for an entry of section 16.
    #[serde(default)]
    pub key: Option<String>,
    /// The link of an `add`, else `None`.
    #[serde(default)]
    pub link_hash: Option<String>,
    /// The device name that a `root` or an `add` signed, else `None`.
    #[serde(default)]
    pub name: Option<String>,
    /// b64u of the key that signed the entry (the root key for `root`).
    pub by: String,
    /// b64u of the DER signature.
    #[serde(default)]
    pub signature: Option<String>,
    /// The other account of an entry of section 16 (none on a `store`), else `None`.
    #[serde(default)]
    pub account_id: Option<String>,
    /// b64u of the root that a `peer` pins; on a `join`, the list hash of the `share`
    /// entry of the other account's list that it answers; else `None`.
    #[serde(default)]
    pub root: Option<String>,
    /// The vault store of a `share`, `unshare`, `join`, `leave`, or `store`, else `None`.
    #[serde(default)]
    pub team_id: Option<String>,
}

/// The canonical form of a person's name or a device name (section 2): trimmed of white
/// space, 1 to 64 bytes of UTF-8, no control character (so no NUL, the separator of the
/// signed messages), and never `-` (the placeholder of the device-list message). `None`
/// for any other text. A device signs, sends, and compares only this form; Connect keeps
/// the same form.
pub fn canonical_name(text: &str) -> Option<&str> {
    let name = text.trim();
    (!name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != LIST_NONE
        && !name.chars().any(char::is_control))
    .then_some(name)
}

/// A name that is already in its canonical form ([`canonical_name`]).
pub fn valid_name(name: &str) -> bool {
    canonical_name(name) == Some(name)
}

/// Whether `bytes` is a P-256 public key in X9.63 uncompressed form whose point is on the
/// curve.
pub fn valid_key(bytes: &[u8]) -> bool {
    bytes.len() == 65 && bytes[0] == 0x04 && p256::PublicKey::from_sec1_bytes(bytes).is_ok()
}

/// The P-256 public key of its b64u, when it is a point of the curve.
pub fn point(b64u: &str) -> Option<Vec<u8>> {
    decode_b64u(b64u).filter(|key| valid_key(key))
}

/// A link hash: b64u of 32 bytes.
fn valid_link_hash(text: &str) -> bool {
    decode_b64u(text).is_some_and(|hash| hash.len() == 32)
}

/// A list hash: b64u of 32 bytes (43 characters).
pub fn valid_list_hash(text: &str) -> bool {
    text.len() == 43 && valid_link_hash(text)
}

/// A device list that verified from its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The version of its head.
    pub version: u64,
    /// The list hash of each version, from version 1.
    pub hashes: Vec<String>,
    /// The devices of the list at its head (X9.63), in the order they were added.
    pub live: Vec<Vec<u8>>,
    /// The name that each device of [`Self::live`] was signed with (the same order).
    pub names: Vec<String>,
    /// For each device of [`Self::live`], the key that signed its entry: itself for the
    /// root, the confirming device for an `add`.
    pub added_by: Vec<Vec<u8>>,
    /// The link hash of each `add` of [`Self::live`] (`None` for the root).
    pub links: Vec<Option<String>>,
    /// The keys that the list removed, in the order of their removal: each was a device of
    /// the account before.
    pub removed: Vec<Vec<u8>>,
    /// What the list says of other accounts at its head (section 16): the active peers,
    /// shares, and joins, and every store entry in the order of the list.
    pub shares: ListShares,
    /// The device name that the root signed in version 1 (also after the root left).
    pub root_name: String,
    /// The name that each key of [`Self::removed`] was signed with in its `root` or `add`
    /// (the same order).
    pub removed_names: Vec<String>,
}

impl Verified {
    /// The list hash of its head.
    pub fn head(&self) -> &str {
        self.hashes.last().map_or("", String::as_str)
    }

    /// The signed name of the live device `key`.
    pub fn name_of(&self, key: &[u8]) -> Option<&str> {
        self.position(key).map(|index| self.names[index].as_str())
    }

    /// The signed name of `key` when the list removed it: the name of its `root` or `add`.
    pub fn removed_name(&self, key: &[u8]) -> Option<&str> {
        self.removed
            .iter()
            .position(|held| held == key)
            .map(|index| self.removed_names[index].as_str())
    }

    /// Whether `key` is a live device that `by` added with the link `link_hash`.
    pub fn added(&self, key: &[u8], by: &[u8], link_hash: &str) -> bool {
        self.position(key).is_some_and(|index| {
            self.added_by[index] == by && self.links[index].as_deref() == Some(link_hash)
        })
    }

    fn position(&self, key: &[u8]) -> Option<usize> {
        self.live.iter().position(|held| held == key)
    }
}

/// The list `entries` of `account_id` at `origin` when it starts at `root` (X9.63) and
/// each entry verifies: version 1 is the root, signed by itself over its name; each later
/// entry is signed by a device of the list at the version before, over its message with
/// the hash of the entry before; an `add` names a link, a name, and a key that was never
/// in the list, at most at [`MAX_ADD_VERSION`] and while fewer than [`MAX_LIVE`] devices are
/// live; a `remove` names a key that the list holds.
/// `None` for anything else: another root, a gap, a bad signature, a bad name, a key that
/// is not a point, a list of more than [`MAX_LIST`] entries.
pub fn verify_list(
    origin: &str,
    account_id: &str,
    root: &[u8],
    entries: &[ListEntry],
) -> Option<Verified> {
    if entries.is_empty() || entries.len() > MAX_LIST {
        return None;
    }
    let mut hashes: Vec<String> = Vec::with_capacity(entries.len());
    let mut list = Verified {
        version: entries.len() as u64,
        hashes: Vec::new(),
        live: Vec::new(),
        names: Vec::new(),
        added_by: Vec::new(),
        links: Vec::new(),
        removed: Vec::new(),
        shares: ListShares::default(),
        root_name: String::new(),
        removed_names: Vec::new(),
    };
    // Every key that was in the list: none is added again.
    let mut ever: Vec<Vec<u8>> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let version = index as u64 + 1;
        if entry.version != version {
            return None;
        }
        let previous = hashes.last().map_or(LIST_NONE, String::as_str);
        if share::is_share_op(&entry.op) {
            // An entry that names another account: signed by a device of the list at the
            // version before, and valid for what the list says of other accounts so far.
            let by = point(&entry.by)?;
            if version == 1 || !list.live.contains(&by) {
                return None;
            }
            let message = share::entry_message(origin, account_id, version, previous, entry)?;
            let signature = decode_b64u(entry.signature.as_deref()?)?;
            if !verify_signature(&by, &message, &signature)
                || (share::adds(&entry.op) && version > MAX_ADD_VERSION)
            {
                return None;
            }
            let hash = list_hash(&message);
            list.shares.apply(account_id, entry, &hash).ok()?;
            hashes.push(hash);
            continue;
        }
        if entry.account_id.is_some() || entry.root.is_some() || entry.team_id.is_some() {
            return None;
        }
        let key_text = entry.key.as_deref()?;
        let key = point(key_text)?;
        let by = point(&entry.by)?;
        let link_hash = entry.link_hash.as_deref();
        let name = entry.name.as_deref();
        let message = list_message(
            origin,
            account_id,
            version,
            previous,
            &entry.op,
            key_text,
            link_hash.unwrap_or(LIST_NONE),
            name.unwrap_or(LIST_NONE),
            &entry.by,
        );
        let signature = decode_b64u(entry.signature.as_deref()?)?;
        if version == 1 {
            // The root: the key that this device pinned, signed by itself over its name.
            // Its authority is the pin; the signature binds its name.
            let name = name.filter(|name| valid_name(name))?;
            if entry.op != "root"
                || key != root
                || by != root
                || link_hash.is_some()
                || !verify_signature(&by, &message, &signature)
            {
                return None;
            }
            list.names.push(name.to_owned());
            name.clone_into(&mut list.root_name);
            list.added_by.push(key.clone());
            list.links.push(None);
            ever.push(key.clone());
            list.live.push(key);
        } else {
            if !list.live.contains(&by) || !verify_signature(&by, &message, &signature) {
                return None;
            }
            match (entry.op.as_str(), link_hash, name) {
                ("add", Some(link), Some(name))
                    if valid_link_hash(link)
                        && valid_name(name)
                        && version <= MAX_ADD_VERSION
                        && !ever.contains(&key) =>
                {
                    // The room of [`MAX_ADD_VERSION`] counts [`MAX_LIVE`] live devices.
                    if list.live.len() >= MAX_LIVE {
                        return None;
                    }
                    list.names.push(name.to_owned());
                    list.added_by.push(by);
                    list.links.push(Some(link.to_owned()));
                    ever.push(key.clone());
                    list.live.push(key);
                }
                ("remove", None, None) if list.live.contains(&key) => {
                    let at = list.live.iter().position(|held| *held == key)?;
                    list.live.remove(at);
                    let name = list.names.remove(at);
                    list.added_by.remove(at);
                    list.links.remove(at);
                    list.removed.push(key);
                    list.removed_names.push(name);
                }
                _ => return None,
            }
        }
        hashes.push(list_hash(&message));
    }
    list.hashes = hashes;
    Some(list)
}

/// What this device pinned of the list: the version and the hash of the newest list that
/// it verified.
#[derive(Debug, Clone, Copy)]
pub struct Pin<'a> {
    pub version: u64,
    pub head: &'a str,
}

impl Pin<'_> {
    /// Whether `list` goes on from this pin: not older, and its entry at the pinned version
    /// is the pinned one. An older list (a rollback) or another history (a fork) is not
    /// taken.
    pub fn accepts(&self, list: &Verified) -> bool {
        self.version >= 1
            && list.version >= self.version
            && usize::try_from(self.version - 1)
                .ok()
                .and_then(|index| list.hashes.get(index))
                .is_some_and(|hash| hash == self.head)
    }
}

/// Update the trust store after a list that the pin accepts: the known keys become the
/// devices of the list (`live`), and every key that was known and is not among them moves
/// to the keys that left, and so does every key that the list removed (`removed`), also one
/// that this device never knew as a device (at most [`MAX_LEFT`], the oldest first out). A
/// key that is a device again leaves `left`. Returns whether anything changed.
pub fn learn(
    known: &mut Vec<Vec<u8>>,
    left: &mut Vec<Vec<u8>>,
    live: &[Vec<u8>],
    removed: &[Vec<u8>],
) -> bool {
    let before = (known.clone(), left.clone());
    for key in known.iter().chain(removed) {
        if !live.contains(key) && !left.contains(key) {
            left.push(key.clone());
        }
    }
    left.retain(|key| !live.contains(key));
    if left.len() > MAX_LEFT {
        let extra = left.len() - MAX_LEFT;
        left.drain(..extra);
    }
    *known = live.iter().take(MAX_KNOWN).cloned().collect();
    (known.clone(), left.clone()) != before
}

/// The list hash of the entry of version 1 of a list with `root` (X9.63) named `name`:
/// what a device that makes or recovers an account pins.
pub fn root_hash(origin: &str, account_id: &str, root: &[u8], name: &str) -> String {
    let key = encode_b64u(root);
    list_hash(&list_message(
        origin, account_id, 1, LIST_NONE, "root", &key, LIST_NONE, name, &key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::DeviceKey;

    const ORIGIN: &str = "https://connect.example.test";
    const ACCOUNT: &str = "acc_k7m2q4x3ca";

    fn key() -> DeviceKey {
        DeviceKey::generate().unwrap()
    }

    fn b64(key: &DeviceKey) -> String {
        encode_b64u(key.public_key())
    }

    fn link(seed: u8) -> String {
        encode_b64u(&[seed; 32])
    }

    /// A list under construction, as a relay would keep it.
    struct List {
        entries: Vec<ListEntry>,
        hashes: Vec<String>,
    }

    impl List {
        fn new(root: &DeviceKey) -> Self {
            let mut list = Self {
                entries: Vec::new(),
                hashes: Vec::new(),
            };
            list.change(root, "root", root, None, Some("Synthetic root"));
            assert_eq!(
                list.hashes[0],
                root_hash(ORIGIN, ACCOUNT, root.public_key(), "Synthetic root")
            );
            list
        }

        fn change(
            &mut self,
            by: &DeviceKey,
            op: &str,
            key: &DeviceKey,
            link_hash: Option<String>,
            name: Option<&str>,
        ) {
            let version = self.entries.len() as u64 + 1;
            let message = list_message(
                ORIGIN,
                ACCOUNT,
                version,
                self.hashes.last().map_or(LIST_NONE, String::as_str),
                op,
                &b64(key),
                link_hash.as_deref().unwrap_or(LIST_NONE),
                name.unwrap_or(LIST_NONE),
                &b64(by),
            );
            self.entries.push(ListEntry {
                version,
                op: op.into(),
                key: Some(b64(key)),
                link_hash,
                name: name.map(str::to_owned),
                by: b64(by),
                signature: Some(encode_b64u(&by.sign(&message).unwrap())),
                account_id: None,
                root: None,
                team_id: None,
            });
            self.hashes.push(list_hash(&message));
        }

        fn add(&mut self, by: &DeviceKey, key: &DeviceKey, seed: u8) {
            self.change(by, "add", key, Some(link(seed)), Some("Synthetic device"));
        }

        fn remove(&mut self, by: &DeviceKey, key: &DeviceKey) {
            self.change(by, "remove", key, None, None);
        }
    }

    #[test]
    fn a_list_starts_at_the_pinned_root_and_each_entry_names_the_one_before() {
        let (root, b, c) = (key(), key(), key());
        let mut list = List::new(&root);
        list.add(&root, &b, 1);
        list.add(&b, &c, 2);
        let verified = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert_eq!(verified.version, 3);
        assert_eq!(verified.hashes, list.hashes);
        assert_eq!(
            verified.live,
            [root.public_key(), b.public_key(), c.public_key()]
        );
        // Another root, origin, or account verifies nothing.
        assert!(verify_list(ORIGIN, ACCOUNT, b.public_key(), &list.entries).is_none());
        assert!(
            verify_list(
                "https://other.example.test",
                ACCOUNT,
                root.public_key(),
                &list.entries
            )
            .is_none()
        );
        assert!(verify_list(ORIGIN, "acc_aaaaaaaaaa", root.public_key(), &list.entries).is_none());
        // A changed link, a gap, an entry signed by a key that is not in the list, an
        // entry that names another entry before it: refused.
        let mut moved = list.entries.clone();
        moved[1].link_hash = Some(link(9));
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &moved).is_none());
        let mut gap = list.entries.clone();
        gap.remove(1);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &gap).is_none());
        let stranger = key();
        let mut by_stranger = List::new(&root);
        by_stranger.add(&stranger, &b, 1);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &by_stranger.entries).is_none());
        let mut swapped = list.entries.clone();
        swapped.swap(1, 2);
        swapped[1].version = 2;
        swapped[2].version = 3;
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &swapped).is_none());
        // A root without its signature, a root or an add whose name was changed, a name
        // on a remove, or a later root, is refused too.
        let mut unsigned_root = list.entries.clone();
        unsigned_root[0].signature = None;
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &unsigned_root).is_none());
        let mut renamed = list.entries.clone();
        renamed[0].name = Some("Other name".into());
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &renamed).is_none());
        let mut renamed = list.entries.clone();
        renamed[1].name = Some("Other name".into());
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &renamed).is_none());
        let mut nameless = list.entries.clone();
        nameless[2].name = None;
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &nameless).is_none());
        assert_eq!(verified.name_of(b.public_key()), Some("Synthetic device"));
        assert_eq!(verified.name_of(root.public_key()), Some("Synthetic root"));
        assert!(verified.added(c.public_key(), b.public_key(), &link(2)));
        assert!(!verified.added(c.public_key(), root.public_key(), &link(2)));
        let mut second_root = list.entries.clone();
        second_root[2].op = "root".into();
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &second_root).is_none());
        // An empty list and a list that is too long.
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &[]).is_none());
        let long = vec![list.entries[0].clone(); MAX_LIST + 1];
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &long).is_none());
    }

    #[test]
    fn a_device_added_before_its_confirmer_left_stays_a_device() {
        let (root, b, c) = (key(), key(), key());
        let mut list = List::new(&root);
        list.add(&root, &b, 1);
        list.add(&b, &c, 2);
        list.remove(&root, &b);
        let verified = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert_eq!(verified.live, [root.public_key(), c.public_key()]);
        // After it left, the device signs no change any more.
        let d = key();
        let mut late = list;
        late.add(&b, &d, 3);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &late.entries).is_none());
        // A removal of a key that the list does not hold, and an add of one that it holds.
        let mut list = List::new(&root);
        list.remove(&root, &b);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).is_none());
        let mut list = List::new(&root);
        list.add(&root, &root, 1);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).is_none());
        // A key that left is never added again.
        let mut list = List::new(&root);
        list.add(&root, &b, 1);
        list.remove(&root, &b);
        list.add(&root, &b, 2);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).is_none());
        // A device removes itself; the last device too.
        let mut list = List::new(&root);
        list.remove(&root, &root);
        let verified = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert!(verified.live.is_empty());
    }

    #[test]
    fn the_pin_refuses_an_older_list_and_another_history() {
        let (root, b, c) = (key(), key(), key());
        let mut list = List::new(&root);
        list.add(&root, &b, 1);
        let at_two = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        let pin = Pin {
            version: 2,
            head: at_two.head(),
        };
        assert!(pin.accepts(&at_two));
        list.add(&b, &c, 2);
        let at_three = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert!(pin.accepts(&at_three));
        // An older list: refused.
        let at_one = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries[..1]).unwrap();
        assert!(!pin.accepts(&at_one));
        // Another history from version 2 on: refused.
        let mut fork = List::new(&root);
        fork.add(&root, &c, 7);
        let forked = verify_list(ORIGIN, ACCOUNT, root.public_key(), &fork.entries).unwrap();
        assert!(!pin.accepts(&forked));
        assert!(
            !Pin {
                version: 0,
                head: ""
            }
            .accepts(&at_three)
        );
    }

    /// An `add` may come only while every device, peer, share, and join of the list can
    /// still be ended before the list is full: at most version 822 (1024 entries, 10
    /// devices, 64 peers, 128 shares and joins); a `remove` may come up to version 1024,
    /// also the last device's own.
    #[test]
    fn an_add_leaves_room_to_remove_every_device() {
        assert_eq!(MAX_ADD_VERSION, 822);
        let root = key();
        let mut list = List::new(&root);
        let mut seed = 0u8;
        // Adds and removes of a passing device up to version 813.
        while list.entries.len() < 813 {
            let passing = key();
            seed = seed.wrapping_add(1);
            list.add(&root, &passing, seed);
            list.remove(&root, &passing);
        }
        // Nine more devices: ten live devices at version 822.
        let others: Vec<DeviceKey> = (0..9).map(|_| key()).collect();
        for (index, other) in others.iter().enumerate() {
            list.add(&root, other, 200 + index as u8);
        }
        assert_eq!(list.entries.len(), 822);
        let at_822 = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert_eq!(at_822.live.len(), 10);
        // An add at 823 is past the room.
        let mut late = List {
            entries: list.entries.clone(),
            hashes: list.hashes.clone(),
        };
        late.add(&root, &key(), 251);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &late.entries).is_none());
        // Every device is removed after it, the root last, by itself; removals of passing
        // devices fill the list up to version 1024 (a remove is never refused for room).
        for other in &others {
            list.remove(&root, other);
        }
        assert_eq!(list.entries.len(), 831);
        list.remove(&root, &root);
        let full = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert!(full.live.is_empty());
        // A list longer than 1024 entries is refused.
        let long = vec![list.entries[0].clone(); MAX_LIST + 1];
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &long).is_none());
    }

    /// The room arithmetic of [`MAX_ADD_VERSION`] counts [`MAX_LIVE`] live devices: a list
    /// with more live devices than that does not verify.
    #[test]
    fn a_list_holds_at_most_ten_live_devices() {
        let root = key();
        let mut list = List::new(&root);
        for seed in 0..(MAX_LIVE as u8 - 1) {
            list.add(&root, &key(), seed + 1);
        }
        let ten = verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).unwrap();
        assert_eq!(ten.live.len(), MAX_LIVE);
        list.add(&root, &key(), 99);
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &list.entries).is_none());
    }

    #[test]
    fn only_points_of_the_curve_are_keys() {
        let good = key();
        assert!(valid_key(good.public_key()));
        let mut off = good.public_key().to_vec();
        off[64] ^= 1;
        assert!(!valid_key(&off));
        assert!(!valid_key(&[4; 65]));
        assert!(!valid_key(&good.public_key()[..64]));
        let mut compressed = good.public_key().to_vec();
        compressed[0] = 2;
        assert!(!valid_key(&compressed));
        assert!(point(&b64(&good)).is_some());
        assert!(point(&encode_b64u(&off)).is_none());
    }

    #[test]
    fn the_trust_store_learns_the_devices_and_keeps_the_ones_that_left() {
        let (own, b, c) = (vec![1u8], vec![2u8], vec![3u8]);
        let mut known = vec![own.clone(), b.clone()];
        let mut left = Vec::new();
        assert!(learn(
            &mut known,
            &mut left,
            &[own.clone(), b.clone(), c.clone()],
            &[]
        ));
        assert_eq!(known, [own.clone(), b.clone(), c.clone()]);
        assert!(!learn(
            &mut known,
            &mut left,
            &[own.clone(), b.clone(), c.clone()],
            &[]
        ));
        // `b` is not in the list any more: it left the account.
        assert!(learn(&mut known, &mut left, &[own.clone(), c.clone()], &[]));
        assert_eq!(known, [own.clone(), c.clone()]);
        assert_eq!(left, std::slice::from_ref(&b));
        // A key that comes back by a new `add` is known again and leaves `left`.
        assert!(learn(
            &mut known,
            &mut left,
            &[own.clone(), c.clone(), b.clone()],
            &[]
        ));
        assert!(left.is_empty());
        // The keys that left are bounded, oldest out first.
        for index in 0..(MAX_LEFT as u16 + 5) {
            known.push(index.to_be_bytes().to_vec());
            learn(&mut known, &mut left, std::slice::from_ref(&own), &[]);
        }
        assert_eq!(left.len(), MAX_LEFT);
        assert_eq!(known, std::slice::from_ref(&own));
        // A key that the list removed counts as one that left, also unknown here before.
        let (mut known, mut left) = (vec![own.clone()], Vec::new());
        let gone = vec![9u8];
        assert!(learn(
            &mut known,
            &mut left,
            std::slice::from_ref(&own),
            std::slice::from_ref(&gone)
        ));
        assert_eq!(left, [gone]);
    }
}
