//! The device list of a Connect account has a cryptographic root (contract
//! connect-account-v1, the device statements): every device but the first one was added
//! by a statement of the device that confirmed it, and this device checks the statements
//! itself. Connect only carries them.
//!
//! - The **chain** of a device ([`ChainEntry`]): entry `i` is the statement that added key
//!   `K_i` (`K_0` is the device's own key), signed by `K_{i+1}`, the entry's
//!   `confirmer_key`, over `apassy-connect device v1` (origin, account id, link hash,
//!   `K_i`). The root key of a device is the last `confirmer_key`, or its own key for an
//!   empty chain (the device that made the account, or recovered it).
//! - The **trust store** of this device (in the account file): the pinned root, the keys
//!   it knows as devices of the account, and the keys it saw leave the account.
//! - [`verify_devices`]: a device is verified when its chain ends at the pinned root, its
//!   key never left the account, and it is known here, or it was confirmed by a device
//!   that is verified. [`learn`] then updates the trust store from the list.
//!
//! Every key taken from Connect must be a point of P-256 ([`valid_key`]).

use serde::Deserialize;

use super::device_key::device_message;
use crate::sync::{decode_b64u, encode_b64u, verify_signature};

/// The most entries of a chain.
pub const MAX_CHAIN: usize = 64;
/// The most keys of the known devices in the trust store.
pub const MAX_KNOWN: usize = 64;
/// The most keys of devices that left the account in the trust store.
pub const MAX_REVOKED: usize = 128;

/// One statement of a chain, as Connect carries it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChainEntry {
    /// The link hash of the link through which the key was added.
    pub link_hash: String,
    /// b64u of the key of the device that confirmed, which signed the statement.
    pub confirmer_key: String,
    /// b64u of the DER signature over the `apassy-connect device v1` message.
    pub statement: String,
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

/// The root key of the device with `public_key` (b64u) when every statement of `chain`
/// verifies for `origin` and `account_id`. `None` for a chain of more than
/// [`MAX_CHAIN`] entries, a key that is not a point, or a statement that does not verify.
pub fn chain_root(
    origin: &str,
    account_id: &str,
    public_key: &str,
    chain: &[ChainEntry],
) -> Option<Vec<u8>> {
    if chain.len() > MAX_CHAIN {
        return None;
    }
    let mut key = point(public_key)?;
    for entry in chain {
        let confirmer = point(&entry.confirmer_key)?;
        let statement = decode_b64u(&entry.statement)?;
        if !valid_link_hash(&entry.link_hash) {
            return None;
        }
        let message = device_message(origin, account_id, &entry.link_hash, &encode_b64u(&key));
        if !verify_signature(&confirmer, &message, &statement) {
            return None;
        }
        key = confirmer;
    }
    Some(key)
}

/// One device of a list, as [`verify_devices`] reads it.
#[derive(Debug, Clone, Copy)]
pub struct Listed<'a> {
    pub public_key: &'a str,
    pub chain: &'a [ChainEntry],
}

/// What this device trusts: the pinned root, the known keys, and the keys that left the
/// account (X9.63 each).
#[derive(Debug, Clone, Copy)]
pub struct Trust<'a> {
    pub root: &'a [u8],
    pub known: &'a [Vec<u8>],
    pub revoked: &'a [Vec<u8>],
}

/// Which devices of `list` are verified, in the order of the list:
///
/// 1. A device is chain-valid when its chain verifies and ends at the pinned root.
/// 2. The verified set starts with the chain-valid devices whose key never left the
///    account and that are known here (or are the root). A chain-valid device whose key
///    never left the account joins the set when the first statement of its chain was
///    signed by a device of the set; this repeats until nothing changes.
pub fn verify_devices(
    origin: &str,
    account_id: &str,
    list: &[Listed<'_>],
    trust: Trust<'_>,
) -> Vec<bool> {
    let keys: Vec<Option<Vec<u8>>> = list.iter().map(|device| point(device.public_key)).collect();
    let candidate: Vec<bool> = list
        .iter()
        .zip(&keys)
        .map(|(device, key)| {
            key.as_ref().is_some_and(|key| {
                !trust.revoked.contains(key)
                    && chain_root(origin, account_id, device.public_key, device.chain)
                        .is_some_and(|root| root == trust.root)
            })
        })
        .collect();
    let mut verified: Vec<bool> = keys
        .iter()
        .zip(&candidate)
        .map(|(key, candidate)| {
            *candidate
                && key
                    .as_ref()
                    .is_some_and(|key| key == trust.root || trust.known.contains(key))
        })
        .collect();
    loop {
        let mut changed = false;
        for (index, device) in list.iter().enumerate() {
            if verified[index] || !candidate[index] {
                continue;
            }
            let Some(confirmer) = device
                .chain
                .first()
                .and_then(|entry| point(&entry.confirmer_key))
            else {
                continue;
            };
            let by_verified = keys
                .iter()
                .zip(&verified)
                .any(|(key, verified)| *verified && key.as_ref() == Some(&confirmer));
            if by_verified {
                verified[index] = true;
                changed = true;
            }
        }
        if !changed {
            return verified;
        }
    }
}

/// Update the trust store after a list: the keys of the verified devices are known, and
/// every known key that is not among them (except `own`, the key of this device) moves to
/// the keys that left the account. Returns whether anything changed.
pub fn learn(
    known: &mut Vec<Vec<u8>>,
    revoked: &mut Vec<Vec<u8>>,
    own: &[u8],
    verified_keys: &[Vec<u8>],
) -> bool {
    let known_before = known.clone();
    let mut next: Vec<Vec<u8>> = Vec::with_capacity(verified_keys.len() + 1);
    if known.iter().any(|key| key == own) {
        next.push(own.to_vec());
    }
    for key in verified_keys {
        if !next.contains(key) && next.len() < MAX_KNOWN {
            next.push(key.clone());
        }
    }
    for key in known.iter() {
        if !next.contains(key) && !revoked.contains(key) {
            revoked.push(key.clone());
        }
    }
    if revoked.len() > MAX_REVOKED {
        let extra = revoked.len() - MAX_REVOKED;
        revoked.drain(..extra);
    }
    // A key that moved to the keys that left is gone from the known keys too.
    *known = next;
    *known != known_before
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

    fn hash(seed: u8) -> String {
        encode_b64u(&[seed; 32])
    }

    /// The statement by `confirmer` that adds `added` through the link `seed`.
    fn statement(confirmer: &DeviceKey, added: &DeviceKey, seed: u8) -> ChainEntry {
        let message = device_message(
            ORIGIN,
            ACCOUNT,
            &hash(seed),
            &encode_b64u(added.public_key()),
        );
        ChainEntry {
            link_hash: hash(seed),
            confirmer_key: encode_b64u(confirmer.public_key()),
            statement: encode_b64u(&confirmer.sign(&message).unwrap()),
        }
    }

    fn b64(key: &DeviceKey) -> String {
        encode_b64u(key.public_key())
    }

    #[test]
    fn a_chain_ends_at_the_key_that_made_the_account() {
        let (root, b, c) = (key(), key(), key());
        let chain_b = vec![statement(&root, &b, 1)];
        let chain_c = vec![statement(&b, &c, 2), statement(&root, &b, 1)];
        assert_eq!(
            chain_root(ORIGIN, ACCOUNT, &b64(&root), &[]).unwrap(),
            root.public_key()
        );
        assert_eq!(
            chain_root(ORIGIN, ACCOUNT, &b64(&b), &chain_b).unwrap(),
            root.public_key()
        );
        assert_eq!(
            chain_root(ORIGIN, ACCOUNT, &b64(&c), &chain_c).unwrap(),
            root.public_key()
        );
        // A statement for another key, origin, or account, or a changed link hash.
        assert!(chain_root(ORIGIN, ACCOUNT, &b64(&c), &chain_b).is_none());
        assert!(chain_root("https://other.example.test", ACCOUNT, &b64(&b), &chain_b).is_none());
        assert!(chain_root(ORIGIN, "acc_aaaaaaaaaa", &b64(&b), &chain_b).is_none());
        let mut moved = chain_b.clone();
        moved[0].link_hash = hash(9);
        assert!(chain_root(ORIGIN, ACCOUNT, &b64(&b), &moved).is_none());
        // A key that is not a point of the curve, and a chain that is too long.
        let mut off = vec![4u8];
        off.extend_from_slice(&[9; 64]);
        assert!(chain_root(ORIGIN, ACCOUNT, &encode_b64u(&off), &[]).is_none());
        let long = vec![statement(&root, &root, 1); MAX_CHAIN + 1];
        assert!(chain_root(ORIGIN, ACCOUNT, &b64(&root), &long).is_none());
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
    fn a_device_is_verified_through_the_root_and_the_known_keys() {
        let (root, b, c, stranger) = (key(), key(), key(), key());
        let chains = [
            vec![],
            vec![statement(&root, &b, 1)],
            vec![statement(&b, &c, 2), statement(&root, &b, 1)],
            // A device with a chain that does not end at the root.
            vec![statement(&stranger, &stranger, 3)],
        ];
        let keys = [b64(&root), b64(&b), b64(&c), b64(&stranger)];
        let list: Vec<Listed<'_>> = keys
            .iter()
            .zip(&chains)
            .map(|(public_key, chain)| Listed { public_key, chain })
            .collect();
        let known = vec![root.public_key().to_vec()];
        let trust = Trust {
            root: root.public_key(),
            known: &known,
            revoked: &[],
        };
        assert_eq!(
            verify_devices(ORIGIN, ACCOUNT, &list, trust),
            [true, true, true, false]
        );
        // A key that left the account is not verified, and neither is a device that only
        // it confirmed and that is not known here.
        let revoked = vec![b.public_key().to_vec()];
        let trust = Trust {
            root: root.public_key(),
            known: &known,
            revoked: &revoked,
        };
        assert_eq!(
            verify_devices(ORIGIN, ACCOUNT, &list, trust),
            [true, false, false, false]
        );
        let known_c = vec![root.public_key().to_vec(), c.public_key().to_vec()];
        let trust = Trust {
            root: root.public_key(),
            known: &known_c,
            revoked: &revoked,
        };
        assert_eq!(
            verify_devices(ORIGIN, ACCOUNT, &list, trust),
            [true, false, true, false]
        );
        // Another pinned root verifies nothing of this account.
        let trust = Trust {
            root: stranger.public_key(),
            known: &known,
            revoked: &[],
        };
        assert_eq!(
            verify_devices(ORIGIN, ACCOUNT, &list[..3], trust),
            [false, false, false]
        );
    }

    #[test]
    fn the_trust_store_learns_the_verified_keys_and_keeps_the_ones_that_left() {
        let (own, b, c) = (vec![1u8], vec![2u8], vec![3u8]);
        let mut known = vec![own.clone(), b.clone()];
        let mut revoked = Vec::new();
        assert!(learn(
            &mut known,
            &mut revoked,
            &own,
            &[own.clone(), b.clone(), c.clone()]
        ));
        assert_eq!(known, [own.clone(), b.clone(), c.clone()]);
        assert!(!learn(
            &mut known,
            &mut revoked,
            &own,
            &[own.clone(), b.clone(), c.clone()]
        ));
        // `b` is gone from the verified list: it left the account. This device stays.
        assert!(learn(
            &mut known,
            &mut revoked,
            &own,
            std::slice::from_ref(&c)
        ));
        assert_eq!(known, [own.clone(), c.clone()]);
        assert_eq!(revoked, std::slice::from_ref(&b));
        // The list of the keys that left is bounded, oldest out first.
        for index in 0..(MAX_REVOKED as u16 + 5) {
            known.push(index.to_be_bytes().to_vec());
            learn(&mut known, &mut revoked, &own, &[]);
        }
        assert_eq!(revoked.len(), MAX_REVOKED);
        assert!(!revoked.contains(&b));
        assert_eq!(known, [own]);
    }
}
