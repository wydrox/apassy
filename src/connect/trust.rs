//! The device list of a Connect account is a signed list with a cryptographic root
//! (contract connect-account-v1 section 7.5): this device checks it itself, and Connect
//! only carries it.
//!
//! - The **list** ([`ListEntry`]): version 1 is the root key (the device that made the
//!   account, or the device of the last recovery). Each later version is one change, an
//!   `add` (through a link) or a `remove`, signed by a device that the list holds at the
//!   version before, over `apassy-connect device-list v1` with the hash of the entry before
//!   (`super::device_key::list_message`). So every change names the whole history before
//!   it, and a device confirmed by a device that left later stays a device: its `add`
//!   precedes the `remove`.
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
use crate::sync::{decode_b64u, encode_b64u, verify_signature};

/// The most entries of a device list (the relay's limit).
pub const MAX_LIST: usize = 256;
/// The most keys of the known devices in the trust store.
pub const MAX_KNOWN: usize = 64;
/// The most keys of devices that left the account in the trust store. A key that drops
/// out signs nothing here any more: that is the safe side.
pub const MAX_LEFT: usize = 128;

/// One entry of the device list, as Connect carries it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ListEntry {
    pub version: u64,
    /// `root`, `add`, or `remove`.
    pub op: String,
    /// b64u of the key that the entry adds or removes (the root key for `root`).
    pub key: String,
    /// The link of an `add`, else `None`.
    #[serde(default)]
    pub link_hash: Option<String>,
    /// b64u of the key that signed the entry (the root key for `root`).
    pub by: String,
    /// b64u of the DER signature; `None` for `root`.
    #[serde(default)]
    pub signature: Option<String>,
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
}

impl Verified {
    /// The list hash of its head.
    pub fn head(&self) -> &str {
        self.hashes.last().map_or("", String::as_str)
    }
}

/// The list `entries` of `account_id` at `origin` when it starts at `root` (X9.63) and
/// each entry verifies: version 1 is the root; each later entry is signed by a device of
/// the list at the version before, over its message with the hash of the entry before; an
/// `add` names a link and a key that the list does not hold, a `remove` a key that it
/// holds. `None` for anything else: another root, a gap, a bad signature, a key that is not
/// a point, a list of more than [`MAX_LIST`] entries.
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
    let mut live: Vec<Vec<u8>> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let version = index as u64 + 1;
        if entry.version != version {
            return None;
        }
        let key = point(&entry.key)?;
        let by = point(&entry.by)?;
        let previous = hashes.last().map_or(LIST_NONE, String::as_str);
        let link_hash = entry.link_hash.as_deref();
        let message = list_message(
            origin,
            account_id,
            version,
            previous,
            &entry.op,
            &entry.key,
            link_hash.unwrap_or(LIST_NONE),
            &entry.by,
        );
        if version == 1 {
            // The root: the key that this device pinned. Its authority is the pin.
            if entry.op != "root"
                || key != root
                || by != root
                || link_hash.is_some()
                || entry.signature.is_some()
            {
                return None;
            }
            live.push(key);
        } else {
            let signature = decode_b64u(entry.signature.as_deref()?)?;
            if !live.contains(&by) || !verify_signature(&by, &message, &signature) {
                return None;
            }
            match (entry.op.as_str(), link_hash) {
                ("add", Some(link)) if valid_link_hash(link) && !live.contains(&key) => {
                    if live.len() >= MAX_KNOWN {
                        return None;
                    }
                    live.push(key);
                }
                ("remove", None) if live.contains(&key) => live.retain(|held| *held != key),
                _ => return None,
            }
        }
        hashes.push(list_hash(&message));
    }
    Some(Verified {
        version: entries.len() as u64,
        hashes,
        live,
    })
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
/// to the keys that left (at most [`MAX_LEFT`], the oldest first out). A key that is a
/// device again leaves `left`. Returns whether anything changed.
pub fn learn(known: &mut Vec<Vec<u8>>, left: &mut Vec<Vec<u8>>, live: &[Vec<u8>]) -> bool {
    let before = (known.clone(), left.clone());
    for key in known.iter() {
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

/// The entry of version 1 of a list with `root` (X9.63): what a device that makes or
/// recovers an account pins, and its list hash.
pub fn root_hash(origin: &str, account_id: &str, root: &[u8]) -> String {
    let key = encode_b64u(root);
    list_hash(&list_message(
        origin, account_id, 1, LIST_NONE, "root", &key, LIST_NONE, &key,
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
            let entry = ListEntry {
                version: 1,
                op: "root".into(),
                key: b64(root),
                link_hash: None,
                by: b64(root),
                signature: None,
            };
            Self {
                entries: vec![entry],
                hashes: vec![root_hash(ORIGIN, ACCOUNT, root.public_key())],
            }
        }

        fn change(&mut self, by: &DeviceKey, op: &str, key: &DeviceKey, link_hash: Option<String>) {
            let version = self.entries.len() as u64 + 1;
            let message = list_message(
                ORIGIN,
                ACCOUNT,
                version,
                self.hashes.last().unwrap(),
                op,
                &b64(key),
                link_hash.as_deref().unwrap_or(LIST_NONE),
                &b64(by),
            );
            self.entries.push(ListEntry {
                version,
                op: op.into(),
                key: b64(key),
                link_hash,
                by: b64(by),
                signature: Some(encode_b64u(&by.sign(&message).unwrap())),
            });
            self.hashes.push(list_hash(&message));
        }

        fn add(&mut self, by: &DeviceKey, key: &DeviceKey, seed: u8) {
            self.change(by, "add", key, Some(link(seed)));
        }

        fn remove(&mut self, by: &DeviceKey, key: &DeviceKey) {
            self.change(by, "remove", key, None);
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
        // A root with a signature, or a later root, is refused too.
        let mut signed_root = list.entries.clone();
        signed_root[0].signature = Some(encode_b64u(&[1; 70]));
        assert!(verify_list(ORIGIN, ACCOUNT, root.public_key(), &signed_root).is_none());
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
            &[own.clone(), b.clone(), c.clone()]
        ));
        assert_eq!(known, [own.clone(), b.clone(), c.clone()]);
        assert!(!learn(
            &mut known,
            &mut left,
            &[own.clone(), b.clone(), c.clone()]
        ));
        // `b` is not in the list any more: it left the account.
        assert!(learn(&mut known, &mut left, &[own.clone(), c.clone()]));
        assert_eq!(known, [own.clone(), c.clone()]);
        assert_eq!(left, std::slice::from_ref(&b));
        // A key that comes back by a new `add` is known again and leaves `left`.
        assert!(learn(
            &mut known,
            &mut left,
            &[own.clone(), c.clone(), b.clone()]
        ));
        assert!(left.is_empty());
        // The keys that left are bounded, oldest out first.
        for index in 0..(MAX_LEFT as u16 + 5) {
            known.push(index.to_be_bytes().to_vec());
            learn(&mut known, &mut left, std::slice::from_ref(&own));
        }
        assert_eq!(left.len(), MAX_LEFT);
        assert_eq!(known, [own]);
    }
}
