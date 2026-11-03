//! The tailnet peer behind each connection that a TLS front pumps to its target (N8-1).
//!
//! The front connects to the relay's tailnet listener from the loopback, so the relay
//! sees every peer as `127.0.0.1`. The front and the relay run in one process (the Mac
//! app, `apassy serve`), so the front writes down here, for each pumped connection, the
//! loopback address pair of its connection to the target and the peer that it serves.
//! The relay's tailnet listener looks up the remote address of a request here and counts
//! failed authentications per peer.
//!
//! This is process memory only: no header, no first line, nothing that a local process
//! that connects to the listener itself could forge. A connection that the table does
//! not know (a local process that bypasses the front) is keyed by its own address, the
//! loopback. With the Serve fallback (`FrontRoute::ServeTcp`) every peer is Tailscale's
//! daemon on the loopback, so the peers share one key there.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

type Key = (SocketAddr, SocketAddr);

fn table() -> MutexGuard<'static, HashMap<Key, IpAddr>> {
    static TABLE: OnceLock<Mutex<HashMap<Key, IpAddr>>> = OnceLock::new();
    TABLE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn key(source: SocketAddr, target: SocketAddr) -> Key {
    (
        SocketAddr::new(source.ip().to_canonical(), source.port()),
        SocketAddr::new(target.ip().to_canonical(), target.port()),
    )
}

/// The entry of one pumped connection. Drop removes it.
#[derive(Debug)]
pub struct PeerEntry {
    key: Key,
}

impl Drop for PeerEntry {
    fn drop(&mut self) {
        table().remove(&self.key);
    }
}

/// Write down that the connection from `source` to `target` (both on the loopback, as
/// the target connection's `local_addr` and `peer_addr`) carries the bytes of `peer`.
/// The entry lives until the returned value drops.
pub fn register(source: SocketAddr, target: SocketAddr, peer: IpAddr) -> PeerEntry {
    let key = key(source, target);
    table().insert(key, peer.to_canonical());
    PeerEntry { key }
}

/// The peer of the connection from `source` to the listener at `target`, while a front
/// pumps it. `None`: no front of this process made that connection.
pub fn peer_of(source: SocketAddr, target: SocketAddr) -> Option<IpAddr> {
    table().get(&key(source, target)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_names_its_peer_until_it_drops() {
        let source: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        let peer: IpAddr = "100.64.0.9".parse().unwrap();
        assert_eq!(peer_of(source, target), None);
        let entry = register(source, target, peer);
        assert_eq!(peer_of(source, target), Some(peer));
        // Another listener with the same source port is another connection.
        let other: SocketAddr = "127.0.0.1:50003".parse().unwrap();
        assert_eq!(peer_of(source, other), None);
        drop(entry);
        assert_eq!(peer_of(source, target), None);
    }

    #[test]
    fn a_mapped_loopback_address_is_the_same_key() {
        let source: SocketAddr = "[::ffff:127.0.0.1]:50011".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:50012".parse().unwrap();
        let peer: IpAddr = "::ffff:100.64.0.10".parse().unwrap();
        let _entry = register(source, target, peer);
        assert_eq!(
            peer_of("127.0.0.1:50011".parse().unwrap(), target),
            Some("100.64.0.10".parse().unwrap())
        );
    }
}
